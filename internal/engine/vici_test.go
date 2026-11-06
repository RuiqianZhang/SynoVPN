package engine

import (
	"context"
	"errors"
	"github.com/strongswan/govici/vici"
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/pki"
	"testing"
	"time"
)

type fakeControl struct {
	keys          []string
	sas           []*vici.Message
	calls         []string
	failTerminate bool
	retain        bool
	failCRL       bool
}

func (f *fakeControl) Call(ctx context.Context, name string, m *vici.Message) (*vici.Message, error) {
	f.calls = append(f.calls, name)
	if name == "load-cert" && value(m, "type") == "X509_CRL" && f.failCRL {
		return nil, errors.New("CRL load failed")
	}
	if name == "get-shared" {
		return message(map[string]any{"keys": f.keys}), nil
	}
	if name == "terminate" {
		if f.failTerminate {
			return nil, errors.New("terminate failure")
		}
		if !f.retain {
			uid := value(m, "ike-id")
			remaining := []*vici.Message{}
			for _, x := range f.sas {
				sa, _ := x.Get(Connection).(*vici.Message)
				if sa == nil || value(sa, "uniqueid") != uid {
					remaining = append(remaining, x)
				}
			}
			f.sas = remaining
		}
	}
	return message(map[string]any{"success": "yes"}), nil
}
func TestGatewayWaitsForSnapshotAndUsesStrictCertificateAuthentication(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.PKIDir = dir
	c.Domain = "vpn.example.test"
	c.Routes = []string{"192.168.1.0/24"}
	c.DNS = []string{"192.168.1.1"}
	if e := pki.Init(dir, c.Domain); e != nil {
		t.Fatal(e)
	}
	a, e := pki.OpenAuthority(dir)
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeControl{}
	g := &Gateway{C: c, Control: f, Authority: a}
	if e = g.Initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	d := issue(t, g, "aaaaaaaaaaaaaaaaaaaaaa", time.Now().Add(time.Hour).Unix())
	if _, e = g.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(f.calls, ","), "load-conn") {
		t.Fatal("accepted VPN connections before snapshot")
	}
	if _, e = g.Sync(context.Background(), []Device{d}); e != nil {
		t.Fatal(e)
	}
	remote := g.conn.Get(Connection).(*vici.Message).Get("remote").(*vici.Message)
	if value(remote, "auth") != "pubkey" || value(remote, "revocation") != "strict" {
		t.Fatal("not strict device certificate authentication")
	}
	for _, call := range f.calls {
		if call == "load-shared" {
			t.Fatal("password credential loaded")
		}
	}
}
func TestCRLFailureDoesNotAcknowledgeOrTerminateBeforeRevocation(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	f := &fakeControl{sas: []*vici.Message{sa(id, "7")}}
	g := testGateway(t, f)
	d := issue(t, g, id, time.Now().Add(time.Hour).Unix())
	g.allowed[id] = d
	f.failCRL = true
	if _, e := g.Revoke(context.Background(), id); e == nil {
		t.Fatal("failed CRL publication acknowledged")
	}
	if strings.Contains(strings.Join(f.calls, ","), "terminate") {
		t.Fatal("terminated before CRL publication")
	}
	f.failCRL = false
	if s, e := g.Revoke(context.Background(), id); e != nil || !s.Applied[id] {
		t.Fatal("revocation did not recover")
	}
}
func (f *fakeControl) SAs(context.Context) ([]*vici.Message, error) {
	f.calls = append(f.calls, "list-sas")
	return f.sas, nil
}
func sa(id, unique string) *vici.Message {
	return message(map[string]any{Connection: message(map[string]any{"remote-id": "CN=" + Identity(id), "uniqueid": unique, "state": "ESTABLISHED"})})
}
func testGateway(t *testing.T, f *fakeControl) *Gateway {
	t.Helper()
	a, e := pki.OpenAuthority(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return &Gateway{Control: f, Authority: a, ready: true, enabled: true, allowed: map[string]Device{}}
}
func issue(t *testing.T, g *Gateway, id string, expires int64) Device {
	t.Helper()
	_, csr, e := pki.NewKey(id)
	if e != nil {
		t.Fatal(e)
	}
	v, e := g.Issue(context.Background(), pki.IssueRequest{ID: id, CSR: csr, Expires: expires})
	if e != nil {
		t.Fatal(e)
	}
	return Device{ID: id, Certificate: v.Certificate, Active: true, Expires: expires}
}
func TestRevokeUnloadsBeforeSelectiveTerminate(t *testing.T) {
	active := "aaaaaaaaaaaaaaaaaaaaaa"
	revoked := "bbbbbbbbbbbbbbbbbbbbbb"
	f := &fakeControl{keys: []string{Identity(active), Identity(revoked)}, sas: []*vici.Message{sa(active, "1"), sa(revoked, "2")}}
	g := testGateway(t, f)
	d := issue(t, g, active, time.Now().Add(time.Hour).Unix())
	issue(t, g, revoked, time.Now().Add(time.Hour).Unix())
	s, e := g.Sync(context.Background(), []Device{d, {ID: revoked, Active: false}})
	if e != nil {
		t.Fatal(e)
	}
	if !s.Online[active] || s.Online[revoked] || !s.Applied[revoked] {
		t.Fatal("wrong device acknowledged")
	}
	order := strings.Join(f.calls, ",")
	if strings.Index(order, "unload-shared") > strings.Index(order, "terminate") {
		t.Fatal("terminated before removing credential")
	}
	if strings.Index(order, "load-cert") > strings.Index(order, "terminate") {
		t.Fatal("terminated before publishing revocation")
	}
	if len(f.sas) != 1 || value(f.sas[0].Get(Connection).(*vici.Message), "uniqueid") != "1" {
		t.Fatal("unrelated SA was terminated")
	}
}
func TestFailedDisconnectNeverAcknowledgesRevoke(t *testing.T) {
	id := "bbbbbbbbbbbbbbbbbbbbbb"
	for _, retain := range []bool{false, true} {
		f := &fakeControl{keys: []string{Identity(id)}, sas: []*vici.Message{sa(id, "2")}, failTerminate: !retain, retain: retain}
		g := testGateway(t, f)
		issue(t, g, id, time.Now().Add(time.Hour).Unix())
		if _, e := g.Sync(context.Background(), []Device{{ID: id}}); e == nil {
			t.Fatal("failed/ineffective disconnect acknowledged")
		}
	}
}
func TestExpiryAndLateArrivingSA(t *testing.T) {
	id := "bbbbbbbbbbbbbbbbbbbbbb"
	f := &fakeControl{keys: []string{Identity(id)}}
	g := testGateway(t, f)
	d := issue(t, g, id, time.Now().Add(time.Hour).Unix())
	d.Expires = time.Now().Unix() - 1
	g.allowed[id] = d
	if _, e := g.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(g.allowed) != 0 {
		t.Fatal("expired credential retained")
	}
	f.sas = []*vici.Message{sa(id, "9")}
	if _, e := g.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.sas) != 0 {
		t.Fatal("late revoked SA survived")
	}
}

func TestLiveAppleFQDNIdentityIsOnlineAndTerminatesBySAID(t *testing.T) {
	id := "JRmmSyVr-yHlZ4AKYZAvBw"
	remote := "device-4a526d6d537956722d79486c5a34414b595a41764277.synovpn.invalid"
	f := &fakeControl{sas: []*vici.Message{message(map[string]any{Connection: message(map[string]any{"remote-id": remote, "uniqueid": "17", "state": "ESTABLISHED"})})}}
	g := testGateway(t, f)
	d := issue(t, g, id, time.Now().Add(time.Hour).Unix())
	status, err := g.Sync(context.Background(), []Device{d})
	if err != nil || !status.Online[id] {
		t.Fatalf("Apple FQDN lost from live status: %v", err)
	}
	status, err = g.Revoke(context.Background(), id)
	if err != nil || status.Online[id] || len(f.sas) != 0 {
		t.Fatalf("Apple FQDN session not revoked: %v", err)
	}
}
