package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
)

func TestPerUserPoliciesReplaceDefaultsAndReachAllOwnedDevices(t *testing.T) {
	a, vpn := app(t)
	alice := phone(t, a)
	bob := bobPhone(t, a)
	// Both devices belong to the same authenticated user; policy is never selected by a browser owner field.
	second := create(t, a)
	route := `{"owner":"alice","routes":["192.168.1.10","8.8.8.7/24"]}`
	for _, user := range []string{"alice", "bob", ""} {
		w := req(a, "POST", "/api/admin/user-routes", user, route)
		if w.Code != 403 && w.Code != 401 {
			t.Fatal("non-admin edited rules")
		}
	}
	if w := req(a, "POST", "/api/admin/user-routes", "manager", route); w.Code != 200 {
		t.Fatalf("save failed %d %s", w.Code, w.Body.String())
	}
	want := []string{"192.168.1.10/32", "8.8.8.0/24"}
	seen := 0
	for _, d := range vpn.devices {
		switch d.ID {
		case alice.ID, second.ID:
			seen++
			if !slices.Equal(d.Routes, want) {
				t.Fatal("owner policy not applied", d.Routes)
			}
		case bob.ID:
			if !slices.Equal(d.Routes, []string{"192.168.1.0/24"}) {
				t.Fatal("other user changed")
			}
		}
	}
	if seen != 2 {
		t.Fatal("missing owner devices")
	}
	if !slices.Equal(a.effectiveRoutes("alice"), want) {
		t.Fatal("personal config diverged")
	}
	w := req(a, "GET", "/api/admin/user-routes?owner=alice", "manager", "")
	var out struct {
		Routes  []string
		Inherit bool
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Inherit || !slices.Equal(out.Routes, want) {
		t.Fatal("stored policy mismatch")
	}
	// Explicit empty is deny-all, while reset restores inheritance.
	if w = req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","routes":[]}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if len(a.effectiveRoutes("alice")) != 0 {
		t.Fatal("deny-all inherited the LAN")
	}
	if _, status, _ := a.deviceProfile("alice", alice.ID); status != 403 {
		t.Fatal("denied user downloaded usable profile")
	}
	for _, d := range vpn.devices {
		if d.ID == alice.ID && d.Routes == nil {
			t.Fatal("deny-all lost across snapshot")
		}
	}
	if w = req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","inherit":true}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if !slices.Equal(a.effectiveRoutes("alice"), a.C.TrafficRoutes()) {
		t.Fatal("reset did not restore default")
	}
	if w = req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"invented","routes":[]}`); w.Code != 404 {
		t.Fatal("invented owner accepted")
	}
	if w = req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","routes":["10.77.0.1"]}`); w.Code != 400 {
		t.Fatal("VPN pool allowed")
	}
}
func TestPendingIssuanceDoesNotDelayPermissionRemoval(t *testing.T) {
	a, vpn := app(t)
	existing := phone(t, a)
	vpn.issueDown = true
	create(t, a)
	if w := req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","routes":[]}`); w.Code != 200 {
		t.Fatalf("pending issuance blocked permission removal: %d %s", w.Code, w.Body.String())
	}
	found := false
	for _, d := range vpn.devices {
		if d.ID == existing.ID {
			found = true
			if len(d.Routes) != 0 {
				t.Fatal("old permission retained")
			}
		}
	}
	if !found {
		t.Fatal("existing device missing")
	}
}
func TestUserPolicyAuditFailureRollsBack(t *testing.T) {
	a, _ := app(t)
	phone(t, a)
	if _, err := a.DB.DB.Exec("CREATE TRIGGER reject_user_policy_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(FAIL,'fail'); END"); err != nil {
		t.Fatal(err)
	}
	if w := req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","routes":[]}`); w.Code != 500 {
		t.Fatal("audit failure ignored")
	}
	if _, custom, err := a.DB.UserRoutes("alice"); err != nil || custom {
		t.Fatal("failed save changed permissions")
	}
	a.sync(context.Background())
}

func TestWindowsExportUsesOnlyTheOwnersEffectiveRoutes(t *testing.T) {
	a, _ := app(t)
	d := create(t, a)
	if w := req(a, "POST", "/api/admin/user-routes", "manager", `{"owner":"alice","routes":["192.168.1.10","8.8.8.0/24"]}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	file, status, err := a.deviceProfile("alice", d.ID)
	if err != nil || status != 200 {
		t.Fatal(status, err)
	}
	z, err := zip.NewReader(bytes.NewReader(file.Data), int64(len(file.Data)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range z.File {
		if entry.Name != "certificate.json" {
			continue
		}
		r, e := entry.Open()
		if e != nil {
			t.Fatal(e)
		}
		var meta struct{ Routes []string }
		e = json.NewDecoder(r).Decode(&meta)
		r.Close()
		if e != nil || !slices.Equal(meta.Routes, []string{"192.168.1.10/32", "8.8.8.0/24"}) {
			t.Fatal("export leaked inherited subnet", meta.Routes, e)
		}
		found = true
	}
	if !found {
		t.Fatal("missing route metadata")
	}
}
