package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"
	"synovpn/internal/config"
	"synovpn/internal/pki"
)

type Control interface {
	Call(context.Context, string, *vici.Message) (*vici.Message, error)
	SAs(context.Context) ([]*vici.Message, error)
}
type VICI struct{ Path string }

func (v VICI) Call(ctx context.Context, name string, m *vici.Message) (*vici.Message, error) {
	s, e := vici.NewSession(vici.WithSocketPath(v.Path))
	if e != nil {
		return nil, e
	}
	defer s.Close()
	out, e := s.Call(ctx, name, m)
	if e != nil {
		return nil, e
	}
	if x := out.Get("success"); x != nil && x != "yes" {
		return nil, fmt.Errorf("VICI %s rejected request", name)
	}
	return out, nil
}
func (v VICI) SAs(ctx context.Context) ([]*vici.Message, error) {
	s, e := vici.NewSession(vici.WithSocketPath(v.Path))
	if e != nil {
		return nil, e
	}
	defer s.Close()
	out := []*vici.Message{}
	for m, e := range s.CallStreaming(ctx, "list-sas", "list-sa", nil) {
		if e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, nil
}
func message(fields map[string]any) *vici.Message {
	m := vici.NewMessage()
	for k, v := range fields {
		if e := m.Set(k, v); e != nil {
			panic(e)
		}
	}
	return m
}

const Connection = "synovpn"
const ReqID = "43177"

type Gateway struct {
	mu                  sync.Mutex
	C                   config.Config
	Control             Control
	allowed             map[string]Device
	ready               bool
	Authority           *pki.Authority
	conn                *vici.Message
	enabled             bool
	loadedCRL           []byte
	lastSATrace         string
	ApplyRouteFirewall  func(config.Config) error
	OnRouteFailure      func(error)
	ApplyDeviceFirewall func(config.Config, []Device) error
	devicePolicies      map[string][]string
}

func (g *Gateway) Initialize(ctx context.Context) error {
	var e error
	if g.Authority == nil {
		g.Authority, e = pki.OpenAuthority(g.C.PKIDir)
		if e != nil {
			return e
		}
	}
	// The package runs a dedicated charon with no external secrets or config includes.
	for _, item := range []struct{ file, cmd, kind, flag string }{{"ca.pem", "load-cert", "X509", "CA"}, {"client-ca.pem", "load-cert", "X509", "CA"}, {"server.pem", "load-cert", "X509", "NONE"}, {"server.key", "load-key", "rsa", ""}} {
		b, e := pki.DER(filepath.Join(g.C.PKIDir, item.file))
		if e != nil {
			return e
		}
		f := map[string]any{"type": item.kind, "data": string(b)}
		if item.flag != "" {
			f["flag"] = item.flag
		}
		if _, e = g.Control.Call(ctx, item.cmd, message(f)); e != nil {
			return e
		}
	}
	cert, e := pki.DER(filepath.Join(g.C.PKIDir, "server.pem"))
	if e != nil {
		return e
	}
	pool := message(map[string]any{"addrs": g.C.Pool, "dns": g.C.DNS})
	if _, e = g.Control.Call(ctx, "load-pool", message(map[string]any{Connection: pool})); e != nil {
		return e
	}
	child := message(map[string]any{"local_ts": g.C.TrafficRoutes(), "remote_ts": []string{"dynamic"}, "esp_proposals": []string{"aes256gcm16", "aes256-sha256", "aes128-sha256"}, "reqid": ReqID, "dpd_action": "clear", "rekey_time": "1h"})
	clientCA, e := pki.DER(filepath.Join(g.C.PKIDir, "client-ca.pem"))
	if e != nil {
		return e
	}
	conn := message(map[string]any{"version": "2", "local_addrs": []string{"%any"}, "remote_addrs": []string{"%any"}, "proposals": []string{"aes256-sha256-modp2048", "aes128-sha256-modp2048", "aes256gcm16-prfsha256-ecp256"}, "pools": []string{Connection}, "unique": "replace", "encap": "yes", "fragmentation": "yes", "mobike": "yes", "dpd_delay": "30s", "reauth_time": "1h", "send_cert": "always", "local": message(map[string]any{"auth": "pubkey", "id": g.C.Domain, "certs": []string{string(cert)}}), "remote": message(map[string]any{"auth": "pubkey", "cacerts": []string{string(clientCA)}, "revocation": "strict"}), "children": message(map[string]any{"synovpn-net": child})})
	g.conn = message(map[string]any{Connection: conn})
	// Do not accept connections until the durable device snapshot has been reconciled.
	if e = g.applyCRL(ctx); e != nil {
		return e
	}
	g.allowed = map[string]Device{}
	g.ready = true
	return nil
}

func (g *Gateway) Sync(ctx context.Context, ds []Device) (Status, error) {
	if e := Validate(ds); e != nil {
		return Status{}, e
	}
	if g.ApplyDeviceFirewall == nil {
		for _, d := range ds {
			if d.Routes != nil {
				return Status{}, errors.New("engine does not support certificate-bound access policies")
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready {
		return Status{}, errors.New("gateway not initialized")
	}
	desired := map[string]Device{}
	blocked := []string{}
	pending := []string{}
	for _, d := range ds {
		if d.Pending {
			pending = append(pending, d.ID)
			continue
		}
		if d.Active {
			desired[d.ID] = d
		} else {
			blocked = append(blocked, d.ID)
		}
	}
	if e := g.Authority.RevokeIDs(blocked); e != nil {
		return Status{}, e
	}
	active := []pki.ActiveCertificate{}
	for _, d := range desired {
		active = append(active, pki.ActiveCertificate{ID: d.ID, Certificate: d.Certificate, Expires: d.Expires})
	}
	// The ledger permanently records revocation before the new signed CRL is loaded.
	if _, e := g.Authority.ReconcilePending(active, pending); e != nil {
		return Status{}, e
	}
	g.allowed = desired
	if e := g.applyCRL(ctx); e != nil {
		return Status{}, e
	}
	// Remove all legacy EAP secrets; this release never authenticates passwords.
	keys, e := g.Control.Call(ctx, "get-shared", nil)
	if e != nil {
		return Status{}, e
	}
	if list, ok := keys.Get("keys").([]string); ok {
		for _, key := range list {
			if DeviceID(key) != "" {
				if _, e = g.Control.Call(ctx, "unload-shared", message(map[string]any{"id": key})); e != nil {
					return Status{}, e
				}
			}
		}
	}
	if g.ApplyDeviceFirewall != nil {
		if e = g.syncDeviceRoutes(ctx, ds); e != nil {
			return Status{}, e
		}
	} else if !g.enabled {
		if _, e = g.Control.Call(ctx, "load-conn", g.conn); e != nil {
			return Status{}, e
		}
		g.enabled = true
	}
	status, e := g.sweep(ctx)
	if e != nil {
		return status, e
	}
	status.Applied = map[string]bool{}
	for _, d := range ds {
		status.Applied[d.ID] = !d.Pending
	}
	return status, nil
}
func (g *Gateway) Status(ctx context.Context) (Status, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sweep(ctx)
}
func (g *Gateway) sweep(ctx context.Context) (Status, error) {
	out := Status{Ready: g.ready, Online: map[string]bool{}}
	if !g.ready {
		return out, errors.New("gateway not initialized")
	}
	if !g.enabled {
		return out, nil
	}
	for id, d := range g.allowed {
		if d.Expires <= time.Now().Unix() {
			delete(g.allowed, id)
		}
	}
	if e := g.Authority.Expire(); e != nil {
		return Status{}, e
	}
	if e := g.applyCRL(ctx); e != nil {
		return Status{}, e
	}
	sas, e := g.Control.SAs(ctx)
	if e != nil {
		return Status{}, e
	}
	trace := fmt.Sprintf("sessions=%d allowed=%d", len(sas), len(g.allowed))
	for _, m := range sas {
		trace += fmt.Sprintf(" roots=%q", m.Keys())
		if sa, ok := sessionMessage(m); ok {
			id := saDevice(sa)
			_, allowed := g.allowed[id]
			trace += fmt.Sprintf(" state=%q identity=%q mapped=%t allowed=%t", value(sa, "state"), value(sa, "remote-id"), id != "", allowed)
		}
	}
	if trace != g.lastSATrace {
		log.Printf("VPN session inspection: %s", trace)
		g.lastSATrace = trace
	}
	terminated := false
	for _, m := range sas {
		sa, ok := sessionMessage(m)
		if !ok {
			continue
		}
		id := saDevice(sa)
		if id == "" {
			continue
		}
		if g.connectionAllowed(id) {
			if value(sa, "state") == "ESTABLISHED" {
				out.Online[id] = true
			}
			continue
		}
		unique := value(sa, "uniqueid")
		if _, e = strconv.ParseUint(unique, 10, 64); e != nil {
			return Status{}, errors.New("invalid SA identifier")
		}
		if _, e = g.Control.Call(ctx, "terminate", message(map[string]any{"ike-id": unique, "force": "yes", "timeout": "1000", "loglevel": "-1"})); e != nil {
			return Status{}, e
		}
		terminated = true
	}
	if terminated {
		check, e := g.Control.SAs(ctx)
		if e != nil {
			return Status{}, e
		}
		for _, m := range check {
			sa, ok := sessionMessage(m)
			if !ok {
				continue
			}
			id := saDevice(sa)
			if id != "" {
				if !g.connectionAllowed(id) {
					return Status{}, errors.New("revoked device still has an IKE SA")
				}
			}
		}
	}
	return out, nil
}
func value(m *vici.Message, k string) string { s, _ := m.Get(k).(string); return s }
func (g *Gateway) Maintain(ctx context.Context, onFailure func(error)) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			_, e := g.Status(c)
			cancel()
			if e != nil {
				onFailure(e)
				return
			}
		}
	}
}

func saDevice(sa *vici.Message) string {
	if id := DeviceID(value(sa, "remote-id")); id != "" {
		return id
	}
	return DeviceID(value(sa, "remote-eap-id"))
}
func (g *Gateway) Issue(ctx context.Context, r pki.IssueRequest) (pki.Issued, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready || g.Authority == nil {
		return pki.Issued{}, errors.New("authority unavailable")
	}
	return g.Authority.Issue(r)
}
func (g *Gateway) Revoke(ctx context.Context, id string) (Status, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready {
		return Status{}, errors.New("gateway unavailable")
	}
	if e := g.Authority.RevokeIDs([]string{id}); e != nil {
		return Status{}, e
	}
	delete(g.allowed, id)
	if e := g.applyCRL(ctx); e != nil {
		return Status{}, e
	}
	s, e := g.sweep(ctx)
	if e == nil {
		s.Applied = map[string]bool{id: true}
	}
	return s, e
}
func (g *Gateway) applyCRL(ctx context.Context) error {
	der, e := g.Authority.CRL()
	if e != nil {
		return e
	}
	if bytes.Equal(der, g.loadedCRL) {
		return nil
	}
	if _, e = g.Control.Call(ctx, "load-cert", message(map[string]any{"type": "X509_CRL", "data": string(der)})); e != nil {
		return e
	}
	if _, e = g.Control.Call(ctx, "flush-certs", message(map[string]any{"type": "X509"})); e != nil {
		return e
	}
	g.loadedCRL = append([]byte(nil), der...)
	return nil
}

func (g *Gateway) connectionAllowed(id string) bool {
	if _, ok := g.allowed[id]; !ok {
		return false
	}
	return g.ApplyDeviceFirewall == nil || len(g.devicePolicies[id]) > 0
}
