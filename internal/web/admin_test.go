package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"synovpn/internal/auth"
	"synovpn/internal/store"
	"testing"
)

func bobPhone(t *testing.T, a *App) store.Device {
	t.Helper()
	w := req(a, "POST", "/api/devices", "bob", `{"name":"Bob phone","platform":"ios"}`)
	var d store.Device
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &d) != nil {
		t.Fatal("Bob fixture failed")
	}
	return d
}
func TestAdminListMetadataAndOwnerIsolation(t *testing.T) {
	a, vpn := app(t)
	alice := phone(t, a)
	bob := bobPhone(t, a)
	vpn.online = map[string]bool{alice.ID: true}
	w := req(a, "GET", "/api/me", "manager", "")
	if !strings.Contains(w.Body.String(), `"is_admin":true`) {
		t.Fatal("missing admin role")
	}
	w = req(a, "GET", "/api/admin/devices", "manager", "")
	var out struct {
		Devices []adminDevice `json:"devices"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Devices) != 2 {
		t.Fatal("admin list missing devices")
	}
	owners := map[string]bool{}
	for _, d := range out.Devices {
		owners[d.OwnerName] = true
		if d.ID == alice.ID && !d.Online {
			t.Fatal("online status lost")
		}
	}
	if !owners["alice"] || !owners["bob"] {
		t.Fatal("missing owner names")
	}
	for _, key := range []string{"private_key", `"certificate":`, "password", "ticket", "qr"} {
		if strings.Contains(w.Body.String(), key) {
			t.Fatalf("admin metadata leaked %s", key)
		}
	}
	metadata, err := a.DB.AllMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range metadata {
		if len(d.PrivateKey) != 0 || len(d.Certificate) != 0 {
			t.Fatal("admin query fetched credentials")
		}
	}
	w = req(a, "GET", "/api/devices", "manager", "")
	if strings.Contains(w.Body.String(), alice.ID) || strings.Contains(w.Body.String(), bob.ID) {
		t.Fatal("personal admin view lost ownership restriction")
	}
	for _, action := range []string{"export", "enroll", "enroll-cancel"} {
		if req(a, "POST", "/api/admin/devices/"+alice.ID+"/"+action, "manager", "{}").Code != 404 {
			t.Fatal("unsupported admin credential operation")
		}
	}
	if req(a, "POST", "/api/devices/"+alice.ID+"/export", "manager", "{}").Code != 404 {
		t.Fatal("admin can export another user's key")
	}
	for _, cookie := range []string{"alice", "bob"} {
		if req(a, "GET", "/api/admin/devices", cookie, "").Code != 403 || req(a, "POST", "/api/admin/devices/"+alice.ID+"/revoke", cookie, "{}").Code != 403 {
			t.Fatal("ordinary user has admin access")
		}
	}
}
func TestAdminRevocationAuditAndCredentialInvalidation(t *testing.T) {
	a, _ := app(t)
	alice := phone(t, a)
	bob := bobPhone(t, a)
	token := grant(t, a, alice.ID)
	w := req(a, "POST", "/api/devices/"+alice.ID+"/export", "alice", "{}")
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	json.Unmarshal(w.Body.Bytes(), &ticket)
	w = req(a, "POST", "/api/admin/devices/"+alice.ID+"/revoke", "manager", `{"owner":"bob"}`)
	if w.Code != 200 {
		t.Fatalf("admin revoke %d %s", w.Code, w.Body.String())
	}
	d, _ := a.DB.Get("alice", alice.ID)
	if d.State != "revoked" || len(d.PrivateKey) != 0 {
		t.Fatal("target certificate not revoked")
	}
	d, _ = a.DB.Get("bob", bob.ID)
	if d.State != "active" {
		t.Fatal("unrelated device revoked")
	}
	if claim(a, token, a.C.Origin).Code != 403 || req(a, "GET", "/api/download?ticket="+ticket.Ticket, "alice", "").Code != 403 {
		t.Fatal("old grants survived admin revoke")
	}
	if len(a.tickets) != 0 {
		t.Fatal("download ticket retained")
	}
	var actor, action, owner string
	var at int64
	err := a.DB.DB.QueryRow("SELECT audit.actor,audit.action,audit.at,devices.owner FROM audit JOIN devices ON devices.id=audit.device WHERE audit.action='admin-revoke' AND audit.device=?", alice.ID).Scan(&actor, &action, &at, &owner)
	if err != nil || actor != "manager" || owner != "alice" || at <= 0 {
		t.Fatal("admin audit lacks actor, time or target owner")
	}
}

type changingAdminAuth struct{ admin bool }

func (a *changingAdminAuth) Authenticate(r *http.Request) (auth.User, error) {
	u, err := (testAuth{}).Authenticate(r)
	u.Admin = u.Admin && a.admin
	return u, err
}
func TestAdminRoleCSRFSessionAndLANOriginAreCheckedPerRequest(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	roles := &changingAdminAuth{true}
	a.Auth = roles
	if req(a, "GET", "/api/admin/devices", "manager", "").Code != 200 {
		t.Fatal("admin denied")
	}
	r := httptest.NewRequest("POST", "/api/admin/devices/"+d.ID+"/revoke", strings.NewReader("{}"))
	r.Header.Set("Cookie", "manager")
	r.Header.Set("Origin", a.C.Origin)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if req(a, "GET", "/api/admin/devices", "", "").Code != 401 {
		t.Fatal("anonymous admin access")
	}
	r = httptest.NewRequest("GET", "/api/admin/devices?is_admin=true", nil)
	r.Header.Set("Cookie", "alice")
	r.Header.Set("X-DSM-Admin", "true")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("browser admin flag accepted")
	}
	roles.admin = false
	if req(a, "GET", "/api/admin/devices", "manager", "").Code != 403 || req(a, "POST", "/api/admin/devices/"+d.ID+"/revoke", "manager", "{}").Code != 403 {
		t.Fatal("demoted role retained access")
	}
	roles.admin = true
	host := "192.168.10.10:5001"
	w = portalReq(a, "GET", "/api/me", host, "", "", "manager", "")
	var me struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &me)
	if portalReq(a, "POST", "/api/admin/devices/"+d.ID+"/revoke", host, "https://evil.test", me.CSRF, "manager", "{}").Code != 403 {
		t.Fatal("cross-site admin action accepted")
	}
	w = portalReq(a, "POST", "/api/admin/devices/"+d.ID+"/revoke", host, "https://"+host, me.CSRF, "manager", "{}")
	if w.Code != 200 {
		t.Fatalf("LAN admin revoke failed %d", w.Code)
	}
}
func TestAdminPendingRevocationDoesNotClaimSuccess(t *testing.T) {
	a, vpn := app(t)
	d := phone(t, a)
	vpn.down = true
	w := req(a, "POST", "/api/admin/devices/"+d.ID+"/revoke", "manager", "{}")
	if w.Code != 202 {
		t.Fatalf("backend failure falsely completed: %d", w.Code)
	}
	stored, _ := a.DB.Get("alice", d.ID)
	if stored.State != "revoking" {
		t.Fatal("revocation not persisted")
	}
	vpn.down = false
	a.sync(httptest.NewRequest("GET", "/", nil).Context())
	stored, _ = a.DB.Get("alice", d.ID)
	if stored.State != "revoked" {
		t.Fatal("pending admin revoke did not recover")
	}
}

func TestAdminAuditFailureRollsBackRevocation(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	_, err := a.DB.DB.Exec(`CREATE TRIGGER deny_admin_audit BEFORE INSERT ON audit WHEN NEW.action='admin-revoke' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
	if err != nil {
		t.Fatal(err)
	}
	w := req(a, "POST", "/api/admin/devices/"+d.ID+"/revoke", "manager", "{}")
	if w.Code != 500 {
		t.Fatalf("audit failure acknowledged: %d", w.Code)
	}
	stored, _ := a.DB.Get("alice", d.ID)
	if stored.State != "active" || len(stored.PrivateKey) == 0 {
		t.Fatal("revoked without durable admin audit")
	}
}
