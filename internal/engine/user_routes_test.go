package engine

import (
	"context"
	"github.com/strongswan/govici/vici"
	"slices"
	"synovpn/internal/config"
	"synovpn/internal/pki"
	"testing"
	"time"
)

type policyControl struct {
	fakeControl
	loaded []*vici.Message
}

func (f *policyControl) Call(ctx context.Context, name string, m *vici.Message) (*vici.Message, error) {
	if name == "load-conn" {
		f.loaded = append(f.loaded, cloneMessage(m))
	}
	return f.fakeControl.Call(ctx, name, m)
}
func TestDevicePoliciesBindCertificateIdentitySelectorsAndFirewall(t *testing.T) {
	f := &policyControl{}
	g := routingGateway(t, f)
	g.C.Pool = "10.77.0.0/24"
	_ = g.conn.Get(Connection).(*vici.Message).Set("remote", message(map[string]any{"auth": "pubkey"}))
	g.enabled = false
	alice := Device{ID: "aaaaaaaaaaaaaaaaaaaaaa", Active: true, Routes: []string{"192.168.1.10", "8.8.8.0/24"}}
	bob := Device{ID: "bbbbbbbbbbbbbbbbbbbbbb", Active: true, Routes: []string{"192.168.1.20"}}
	updates := 0
	g.ApplyDeviceFirewall = func(c config.Config, ds []Device) error {
		updates++
		if len(ds) != 2 {
			t.Fatal("missing devices")
		}
		if DeviceReqID(ds[0].ID) == DeviceReqID(ds[1].ID) {
			t.Fatal("shared reqid")
		}
		return nil
	}
	if err := g.syncDeviceRoutes(context.Background(), []Device{alice, bob}); err != nil {
		t.Fatal(err)
	}
	if len(f.loaded) != 4 {
		t.Fatal("missing native identity variants", len(f.loaded))
	}
	for _, loaded := range f.loaded {
		name := loaded.Keys()[0]
		conn := loaded.Get(name).(*vici.Message)
		remote := conn.Get("remote").(*vici.Message)
		child := conn.Get("children").(*vici.Message).Get("synovpn-net").(*vici.Message)
		id := alice.ID
		want := []string{"192.168.1.10/32", "8.8.8.0/24"}
		if name == deviceConnection(bob.ID, "-dns") || name == deviceConnection(bob.ID, "-dn") {
			id = bob.ID
			want = []string{"192.168.1.20/32"}
		}
		identity := value(remote, "id")
		if identity != pki.DNSIdentity(id) && identity != "CN="+pki.Identity(id) {
			t.Fatal("wildcard or wrong identity", identity)
		}
		if value(child, "reqid") != DeviceReqID(id) || !slices.Equal(child.Get("local_ts").([]string), want) {
			t.Fatal("policy divergence")
		}
	}
	if err := g.syncDeviceRoutes(context.Background(), []Device{alice, bob}); err != nil || updates != 1 || len(f.loaded) != 4 {
		t.Fatal("idempotent policy reapplied")
	}
	// Alice loses every permission; Bob's connection must survive unchanged.
	f.sas = []*vici.Message{
		message(map[string]any{deviceConnection(alice.ID, "-dns"): sa(alice.ID, "7").Get(Connection)}),
		message(map[string]any{deviceConnection(bob.ID, "-dns"): sa(bob.ID, "8").Get(Connection)}),
	}
	alice.Routes = []string{}
	if err := g.syncDeviceRoutes(context.Background(), []Device{alice, bob}); err != nil {
		t.Fatal(err)
	}
	if len(f.loaded) != 4 || len(f.sas) != 1 {
		t.Fatal("unrelated user interrupted or denied connection loaded")
	}
	remaining, _ := sessionMessage(f.sas[0])
	if saDevice(remaining) != bob.ID {
		t.Fatal("wrong user disconnected")
	}
}
func TestScopedPolicyRequiresExplicitRoutesAndRejectsPool(t *testing.T) {
	f := &fakeControl{}
	g := routingGateway(t, f)
	g.C.Pool = "10.77.0.0/24"
	applied := false
	g.ApplyDeviceFirewall = func(config.Config, []Device) error { applied = true; return nil }
	for _, routes := range [][]string{nil, {"10.77.0.1"}, {"0.0.0.0/0"}} {
		if err := g.syncDeviceRoutes(context.Background(), []Device{{ID: "aaaaaaaaaaaaaaaaaaaaaa", Active: true, Routes: routes}}); err == nil || applied {
			t.Fatal("invalid or missing policy applied")
		}
	}
}

func TestPendingCredentialsCannotLoadAnAuthorizedConnection(t *testing.T) {
	f := &fakeControl{}
	g := testGateway(t, f)
	g.C.Pool = "10.77.0.0/24"
	g.ApplyDeviceFirewall = func(c config.Config, ds []Device) error {
		if len(ds) != 0 {
			t.Fatal("pending device reached firewall")
		}
		return nil
	}
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	d := issue(t, g, id, time.Now().Add(time.Hour).Unix())
	d.Certificate = nil
	d.Pending = true
	d.Routes = []string{"192.168.1.10/32"}
	if _, err := g.Sync(context.Background(), []Device{d}); err != nil {
		t.Fatal(err)
	}
	if len(g.allowed) != 0 || len(g.devicePolicies) != 0 {
		t.Fatal("pending device authorized")
	}
	for _, call := range f.calls {
		if call == "load-conn" {
			t.Fatal("pending peer configuration loaded")
		}
	}
}
func TestLegacyEngineRejectsScopedPolicyInsteadOfIgnoringIt(t *testing.T) {
	g := testGateway(t, &fakeControl{})
	d := issue(t, g, "aaaaaaaaaaaaaaaaaaaaaa", time.Now().Add(time.Hour).Unix())
	d.Routes = []string{"192.168.1.10/32"}
	if _, err := g.Sync(context.Background(), []Device{d}); err == nil {
		t.Fatal("unsupported engine silently widened access")
	}
}

func TestLateSessionOfDeniedUserIsTerminated(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	f := &fakeControl{sas: []*vici.Message{message(map[string]any{deviceConnection(id, "-dns"): sa(id, "7").Get(Connection)})}}
	g := testGateway(t, f)
	g.allowed[id] = issue(t, g, id, time.Now().Add(time.Hour).Unix())
	g.devicePolicies = map[string][]string{id: {}}
	g.ApplyDeviceFirewall = func(config.Config, []Device) error { return nil }
	status, err := g.Status(context.Background())
	if err != nil || status.Online[id] || len(f.sas) != 0 {
		t.Fatal("denied late session survived", err)
	}
}
