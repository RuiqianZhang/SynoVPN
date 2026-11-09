package web

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"synovpn/internal/store"
	"testing"
)

type routeTestEngine struct {
	*testEngine
	routes    []string
	updates   int
	routeDown bool
}

func (e *routeTestEngine) SetPublicRoutes(ctx context.Context, routes []string) error {
	if e.routeDown {
		return errors.New("down")
	}
	e.routes = append([]string{}, routes...)
	e.updates++
	return nil
}
func TestPublicRoutesAdminPersistenceRetryAndIsolation(t *testing.T) {
	a, base := app(t)
	vpn := &routeTestEngine{testEngine: base}
	a.Engine = vpn
	for _, user := range []string{"", "alice", "bob"} {
		for _, method := range []string{"GET", "POST"} {
			w := req(a, method, "/api/admin/public-routes", user, `{"routes":["8.8.8.8"]}`)
			if w.Code != 401 && w.Code != 403 {
				t.Fatalf("%s %s allowed: %d", user, method, w.Code)
			}
		}
	}
	if vpn.updates != 0 {
		t.Fatal("unauthorized update reached engine")
	}
	if w := portalReq(a, "POST", "/api/admin/public-routes", "nas.example.test:5001", "https://evil.example", "", "manager", `{"routes":["8.8.8.8"]}`); w.Code != 403 {
		t.Fatal("cross-origin update allowed")
	}
	for _, bad := range []string{`{}`, `{"routes":null}`, `{"routes":["0.0.0.0/0"]}`, `{"routes":["192.168.1.1"]}`, `{"routes":["::1"]}`} {
		if w := req(a, "POST", "/api/admin/public-routes", "manager", bad); w.Code != 400 {
			t.Fatal("invalid policy accepted")
		}
	}
	vpn.routeDown = true
	w := req(a, "POST", "/api/admin/public-routes", "manager", `{"routes":["8.8.8.8","8.8.8.8/32"]}`)
	if w.Code != 202 {
		t.Fatalf("failure claimed success: %d %s", w.Code, w.Body.String())
	}
	saved, err := a.DB.PublicRoutes()
	if err != nil || !slices.Equal(saved, []string{"8.8.8.8/32"}) {
		t.Fatal("desired policy not durable")
	}
	var actor, policy string
	if err = a.DB.DB.QueryRow("SELECT actor,device FROM audit WHERE action='public-routes'").Scan(&actor, &policy); err != nil || actor != "manager" || policy != `["8.8.8.8/32"]` {
		t.Fatal("audit missing")
	}
	vpn.routeDown = false
	a.sync(context.Background())
	if a.routeError != "" || !slices.Equal(vpn.routes, saved) {
		t.Fatal("pending policy not retried")
	}
	reopened, err := store.Open(a.C.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	restored, err := reopened.PublicRoutes()
	if err != nil || !slices.Equal(restored, saved) {
		t.Fatal("restart lost policy")
	}
	w = req(a, "GET", "/api/admin/public-routes", "manager", "")
	var out struct {
		Routes  []string
		Applied bool
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Applied || !slices.Equal(out.Routes, saved) {
		t.Fatal("status mismatch")
	}
	if w = req(a, "POST", "/api/admin/public-routes", "manager", `{"routes":[]}`); w.Code != 200 || len(vpn.routes) != 0 {
		t.Fatal("could not remove public policy")
	}
	if !slices.Equal(a.C.Routes, []string{"192.168.1.0/24"}) {
		t.Fatal("private routes changed")
	}
}
func TestPublicRoutesAuditFailureIsAtomic(t *testing.T) {
	a, base := app(t)
	vpn := &routeTestEngine{testEngine: base}
	a.Engine = vpn
	if _, err := a.DB.DB.Exec("CREATE TRIGGER reject_route_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL,'fail'); END"); err != nil {
		t.Fatal(err)
	}
	w := req(a, "POST", "/api/admin/public-routes", "manager", `{"routes":["8.8.8.8"]}`)
	if w.Code != 500 || vpn.updates != 0 {
		t.Fatal("failed audit reached engine")
	}
	saved, err := a.DB.PublicRoutes()
	if err != nil || len(saved) != 0 {
		t.Fatal("failed transaction changed policy")
	}
}
