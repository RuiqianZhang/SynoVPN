package web

import (
	"strings"
	"testing"
)

func TestDeleteRecordAuthorizationAndRevocation(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	if req(a, "POST", "/api/devices/"+d.ID+"/delete", "bob", "{}").Code != 404 {
		t.Fatal("cross-owner delete allowed")
	}
	if req(a, "POST", "/api/admin/devices/"+d.ID+"/delete", "alice", "{}").Code != 403 {
		t.Fatal("nonadmin allowed")
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/delete", "alice", "{}").Code != 409 {
		t.Fatal("active device hidden")
	}
	if err := a.DB.Revoke("alice", d.ID); err != nil {
		t.Fatal(err)
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/delete", "alice", "{}").Code != 409 {
		t.Fatal("pending revocation hidden")
	}
	if err := a.DB.FinishRevoke(d.ID); err != nil {
		t.Fatal(err)
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/delete", "alice", "{}").Code != 200 {
		t.Fatal("revoked record not removed")
	}
	if strings.Contains(req(a, "GET", "/api/devices", "alice", "").Body.String(), d.ID) || strings.Contains(req(a, "GET", "/api/admin/devices", "manager", "").Body.String(), d.ID) {
		t.Fatal("deleted record visible")
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/delete", "alice", "{}").Code != 404 {
		t.Fatal("duplicate deletion accepted")
	}
	var state, actor string
	if err := a.DB.DB.QueryRow("SELECT state FROM devices WHERE id=?", d.ID).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("revocation tombstone lost")
	}
	if err := a.DB.DB.QueryRow("SELECT actor FROM audit WHERE device=? AND action='delete-record'", d.ID).Scan(&actor); err != nil || actor != "alice" {
		t.Fatal("audit missing")
	}
	b := bobPhone(t, a)
	a.DB.Revoke("bob", b.ID)
	a.DB.FinishRevoke(b.ID)
	if req(a, "POST", "/api/admin/devices/"+b.ID+"/delete", "manager", "{}").Code != 200 {
		t.Fatal("admin cleanup failed")
	}
	if err := a.DB.DB.QueryRow("SELECT actor FROM audit WHERE device=? AND action='admin-delete-record'", b.ID).Scan(&actor); err != nil || actor != "manager" {
		t.Fatal("admin actor missing")
	}
	if _, err := a.DB.Get("bob", b.ID); err == nil {
		t.Fatal("hidden record still readable")
	}
}
func TestDeleteRecordRequiresCSRF(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	w := portalReq(a, "POST", "/api/devices/"+d.ID+"/delete", "nas.example.test:5001", a.C.Origin, "", "alice", "{}")
	if w.Code != 403 {
		t.Fatal("delete bypassed CSRF")
	}
}
