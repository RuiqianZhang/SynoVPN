package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/strongswan/govici/vici"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"synovpn/internal/config"
	"testing"
)

func routingGateway(t *testing.T, control Control) *Gateway {
	t.Helper()
	child := message(map[string]any{"local_ts": []string{"192.168.1.0/24"}})
	return &Gateway{C: config.Config{Routes: []string{"192.168.1.0/24"}, PKIDir: t.TempDir()}, Control: control, ready: true, enabled: true, conn: message(map[string]any{Connection: message(map[string]any{"children": message(map[string]any{"synovpn-net": child})})})}
}
func TestRoutingUpdatePersistsSelectorsAndReconnects(t *testing.T) {
	f := &fakeControl{sas: []*vici.Message{sa("aaaaaaaaaaaaaaaaaaaaaa", "7")}}
	g := routingGateway(t, f)
	applied := 0
	g.ApplyRouteFirewall = func(c config.Config) error {
		applied++
		if !slices.Equal(c.TrafficRoutes(), []string{"192.168.1.0/24", "8.8.8.8/32"}) {
			t.Fatal("firewall policy mismatch")
		}
		return nil
	}
	if err := g.SetPublicRoutes(context.Background(), []string{"8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls, []string{"load-conn", "list-sas", "terminate", "list-sas"}) {
		t.Fatalf("connections not refreshed: %v", f.calls)
	}
	selectors := g.conn.Get(Connection).(*vici.Message).Get("children").(*vici.Message).Get("synovpn-net").(*vici.Message).Get("local_ts").([]string)
	if !slices.Equal(selectors, g.C.TrafficRoutes()) {
		t.Fatal("selectors diverged")
	}
	raw, err := os.ReadFile(filepath.Join(g.C.PKIDir, "public-routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved []string
	if json.Unmarshal(raw, &saved) != nil || !slices.Equal(saved, g.C.PublicRoutes) {
		t.Fatal("policy not durable")
	}
	if err := g.SetPublicRoutes(context.Background(), saved); err != nil || applied != 1 || len(f.calls) != 4 {
		t.Fatal("periodic reconciliation disconnects clients")
	}
}
func TestRoutingFailureNeverAcknowledgesOrPersistsPolicy(t *testing.T) {
	for _, stage := range []string{"firewall", "terminate", "persistence"} {
		t.Run(stage, func(t *testing.T) {
			f := &fakeControl{failTerminate: stage == "terminate", sas: []*vici.Message{sa("aaaaaaaaaaaaaaaaaaaaaa", "7")}}
			g := routingGateway(t, f)
			notified := false
			g.OnRouteFailure = func(error) { notified = true }
			g.ApplyRouteFirewall = func(config.Config) error {
				if stage == "firewall" {
					return errors.New("failed")
				}
				return nil
			}
			if stage == "persistence" {
				g.C.PKIDir = filepath.Join(g.C.PKIDir, "missing")
			}
			if err := g.SetPublicRoutes(context.Background(), []string{"8.8.8.8"}); err == nil || g.ready || !notified {
				t.Fatal("partial policy acknowledged")
			}
			if len(g.C.PublicRoutes) != 0 {
				t.Fatal("failed policy committed")
			}
			if _, err := os.Stat(filepath.Join(g.C.PKIDir, "public-routes.json")); !os.IsNotExist(err) {
				t.Fatal("failed policy persisted")
			}
		})
	}
}
func TestAgentPublicRoutesValidateBeforeEngine(t *testing.T) {
	f := &fakeControl{}
	g := routingGateway(t, f)
	called := false
	g.ApplyRouteFirewall = func(config.Config) error { called = true; return nil }
	for _, body := range []string{`["0.0.0.0/0"]`, `["10.0.0.1"]`, `["8.8.8.8;reboot"]`} {
		req := httptest.NewRequest("POST", "/public-routes", strings.NewReader(body))
		w := httptest.NewRecorder()
		AgentHandler(g).ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest || called {
			t.Fatal("invalid policy reached firewall")
		}
	}
}

func TestRoutingUpdateWithNoConnectedClients(t *testing.T) {
	f := &fakeControl{}
	g := routingGateway(t, f)
	g.ApplyRouteFirewall = func(config.Config) error { return nil }
	if err := g.SetPublicRoutes(context.Background(), []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls, "terminate") {
		t.Fatal("terminated an empty session set")
	}
}

func TestRouteEndpointRequiresEngineToken(t *testing.T) {
	token := bytes.Repeat([]byte{0x71}, 32)
	handler, err := ProtectedAgent(&Demo{}, token, Trust{})
	if err != nil {
		t.Fatal(err)
	}
	for _, authorized := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/public-routes", strings.NewReader(`["8.8.8.8"]`))
		req.RemoteAddr = "127.0.0.1:12345"
		if authorized {
			req.Header.Set("Authorization", "Bearer "+hex.EncodeToString(token))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		want := 401
		if authorized {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("authorized=%v got %d", authorized, w.Code)
		}
	}
}
