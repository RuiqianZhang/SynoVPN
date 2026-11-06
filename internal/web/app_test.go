package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"synovpn/internal/auth"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/pki"
	"synovpn/internal/secure"
	"synovpn/internal/store"
	"testing"
	"time"
)

type testAuth struct{}

func (testAuth) Authenticate(r *http.Request) (auth.User, error) {
	if r.Header.Get("Cookie") == "manager" {
		return auth.User{ID: "manager", Name: "Manager", Admin: true}, nil
	}
	if r.Header.Get("Cookie") == "alice" {
		return auth.User{ID: "alice", Name: "Alice"}, nil
	}
	if r.Header.Get("Cookie") == "bob" {
		return auth.User{ID: "bob", Name: "Bob"}, nil
	}
	return auth.User{}, auth.ErrLogin
}

type testEngine struct {
	authority *pki.Authority
	issueDown bool
	down      bool
	devices   []engine.Device
	online    map[string]bool
}

func (e *testEngine) Issue(ctx context.Context, r pki.IssueRequest) (pki.Issued, error) {
	if e.down || e.issueDown {
		return pki.Issued{}, errors.New("unavailable")
	}
	return e.authority.Issue(r)
}
func TestPendingIssuanceDoesNotBlockAnotherDeviceRevocation(t *testing.T) {
	a, vpn := app(t)
	d := create(t, a)
	vpn.issueDown = true
	pending := create(t, a)
	if pending.Applied {
		t.Fatal("failed issuance acknowledged")
	}
	w := req(a, "POST", "/api/devices/"+d.ID+"/revoke", "alice", "{}")
	if w.Code != 200 {
		t.Fatalf("issuance failure blocked revocation: %d %s", w.Code, w.Body.String())
	}
	stored, _ := a.DB.Get("alice", d.ID)
	if stored.State != "revoked" {
		t.Fatal("revocation intent blocked")
	}
}
func (e *testEngine) Revoke(ctx context.Context, id string) (engine.Status, error) {
	if e.down {
		return engine.Status{}, errors.New("unavailable")
	}
	if err := e.authority.RevokeIDs([]string{id}); err != nil {
		return engine.Status{}, err
	}
	return engine.Status{Ready: true, Applied: map[string]bool{id: true}}, nil
}
func (e *testEngine) Sync(ctx context.Context, ds []engine.Device) (engine.Status, error) {
	e.devices = ds
	if e.down {
		return engine.Status{}, errors.New("unavailable")
	}
	out := engine.Status{Ready: true, Online: map[string]bool{}, Applied: map[string]bool{}}
	for _, d := range ds {
		out.Applied[d.ID] = true
	}
	return out, nil
}
func (e *testEngine) Status(ctx context.Context) (engine.Status, error) {
	if e.down {
		return engine.Status{}, errors.New("unavailable")
	}
	return engine.Status{Ready: true, Online: e.online}, nil
}
func app(t *testing.T) (*App, *testEngine) {
	t.Helper()
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Domain = "vpn.example.test"
	c.Origin = "https://nas.example.test:5001"
	c.Routes = []string{"192.168.1.0/24"}
	c.DNS = []string{"192.168.1.1"}
	db, e := store.Open(c.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.DB.Close() })
	key := []byte("12345678901234567890123456789012")
	authority, e := pki.OpenAuthority(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = pki.Init(filepath.Join(c.DataDir, "server-pki"), c.Domain); e != nil {
		t.Fatal(e)
	}
	ca, e := os.ReadFile(filepath.Join(c.DataDir, "server-pki/ca.pem"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(c.DataDir, "ca.pem"), ca, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(c.DataDir, "client-ca.pem"), authority.CAPEM(), 0600); e != nil {
		t.Fatal(e)
	}
	vpn := &testEngine{authority: authority}
	return New(c, db, key, testAuth{}, vpn, false), vpn
}
func req(a *App, method, path, cookie, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Origin", a.C.Origin)
	r.Header.Set("X-CSRF-Token", secure.CSRF(a.Key, cookie, cookie))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func create(t *testing.T, a *App) store.Device {
	t.Helper()
	w := req(a, "POST", "/api/devices", "alice", `{"name":"我的电脑","platform":"windows"}`)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var d store.Device
	if e := json.Unmarshal(w.Body.Bytes(), &d); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestOwnershipAndNoSecretLeak(t *testing.T) {
	a, _ := app(t)
	d := create(t, a)
	if !d.Applied {
		t.Fatal("not applied")
	}
	w := req(a, "GET", "/api/devices", "bob", "")
	if strings.Contains(w.Body.String(), d.ID) {
		t.Fatal("another user can list device")
	}
	for _, action := range []string{"revoke", "export"} {
		w = req(a, "POST", "/api/devices/"+d.ID+"/"+action, "bob", "{}")
		if w.Code != 404 {
			t.Fatalf("cross-user %s allowed: %d", action, w.Code)
		}
	}
	w = req(a, "GET", "/api/devices", "alice", "")
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "password") {
		t.Fatal("secret exposed")
	}
}
func TestAuthenticationAndCSRF(t *testing.T) {
	a, _ := app(t)
	for _, cookie := range []string{"", "invalid"} {
		w := req(a, "GET", "/api/me", cookie, "")
		if w.Code != 401 {
			t.Fatal("unauthenticated request accepted")
		}
	}
	r := httptest.NewRequest("POST", "/api/devices", strings.NewReader(`{"name":"x","platform":"ios"}`))
	r.Header.Set("Cookie", "alice")
	r.Header.Set("Origin", a.C.Origin)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	r.Header.Set("X-CSRF-Token", secure.CSRF(a.Key, "alice", "alice"))
	r.Header.Set("Origin", "https://evil.test")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin request accepted")
	}
}
func TestRevokePersistsUntilBackendRecovers(t *testing.T) {
	a, vpn := app(t)
	d := create(t, a)
	vpn.down = true
	w := req(a, "POST", "/api/devices/"+d.ID+"/revoke", "alice", "{}")
	if w.Code != 202 {
		t.Fatalf("expected pending revocation: %d", w.Code)
	}
	stored, _ := a.DB.Get("alice", d.ID)
	if stored.State != "revoking" || stored.Applied {
		t.Fatal("revocation acknowledged too early")
	}
	w = req(a, "POST", "/api/devices/"+d.ID+"/export", "alice", "{}")
	if w.Code != 409 {
		t.Fatal("revoking credential exported")
	}
	vpn.down = false
	a.sync(context.Background())
	stored, _ = a.DB.Get("alice", d.ID)
	if stored.State != "revoked" || len(stored.PrivateKey) != 0 {
		t.Fatal("recovery failed to finish revocation")
	}
	for _, d := range vpn.devices {
		if d.Active {
			t.Fatal("revoked credential was reloaded")
		}
	}
}
func TestQuotaAndCredentialExpiry(t *testing.T) {
	a, _ := app(t)
	a.C.MaxDevices = 1
	d := create(t, a)
	w := req(a, "POST", "/api/devices", "alice", `{"name":"extra","platform":"ios"}`)
	if w.Code != 409 {
		t.Fatal("quota bypassed")
	}
	a.DB.DB.Exec("UPDATE devices SET expires=? WHERE id=?", time.Now().Unix()-1, d.ID)
	a.sync(context.Background())
	stored, _ := a.DB.Get("alice", d.ID)
	if stored.State != "revoked" {
		t.Fatal("expired credential remained active")
	}
}
func TestOneTimeDownloadAndRevokeInvalidation(t *testing.T) {
	a, _ := app(t)
	d := create(t, a)
	dir := filepath.Join(t.TempDir(), "pki")
	if e := pki.Init(dir, a.C.Domain); e != nil {
		t.Fatal(e)
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	os.WriteFile(filepath.Join(a.C.DataDir, "ca.pem"), ca, 0600)
	issue := func() string {
		w := req(a, "POST", "/api/devices/"+d.ID+"/export", "alice", "{}")
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var out map[string]string
		json.Unmarshal(w.Body.Bytes(), &out)
		return out["ticket"]
	}
	ticket := issue()
	w := req(a, "GET", "/api/download?ticket="+ticket, "bob", "")
	if w.Code != 403 {
		t.Fatal("another user downloaded profile")
	}
	ticket = issue()
	w = req(a, "GET", "/api/download?ticket="+ticket, "alice", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatal("download failed")
	}
	w = req(a, "GET", "/api/download?ticket="+ticket, "alice", "")
	if w.Code != 403 {
		t.Fatal("ticket replay accepted")
	}
	ticket = issue()
	req(a, "POST", "/api/devices/"+d.ID+"/revoke", "alice", "{}")
	w = req(a, "GET", "/api/download?ticket="+ticket, "alice", "")
	if w.Code != 409 {
		t.Fatal("revoked ticket remained usable")
	}
}

func TestStaticShellDoesNotExposeAuthenticatedData(t *testing.T) {
	a, _ := app(t)
	device := create(t, a)
	w := req(a, "GET", "/", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<html") {
		t.Fatal("login bootstrap shell unavailable")
	}
	for _, private := range []string{device.ID, a.C.Domain, "Alice"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("private data in public bootstrap shell")
		}
	}
	for _, endpoint := range []string{"/api/me", "/api/devices", "/api/download?ticket=fake"} {
		if got := req(a, "GET", endpoint, "", ""); got.Code != 401 {
			t.Fatal("bootstrap access bypassed API authentication")
		}
	}
}

func TestOnlineDeviceStatusRemainsOwnerScoped(t *testing.T) {
	a, vpn := app(t)
	alice := create(t, a)
	w := req(a, "POST", "/api/devices", "bob", `{"name":"Bob phone","platform":"ios"}`)
	if w.Code != 201 {
		t.Fatal("Bob creation failed")
	}
	var bob store.Device
	json.Unmarshal(w.Body.Bytes(), &bob)
	vpn.online = map[string]bool{alice.ID: true, bob.ID: true}
	for _, tc := range []struct{ user, own, other string }{{"alice", alice.ID, bob.ID}, {"bob", bob.ID, alice.ID}} {
		w = req(a, "GET", "/api/devices", tc.user, "")
		var result struct {
			Devices []store.Device `json:"devices"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid list")
		}
		if len(result.Devices) != 1 || result.Devices[0].ID != tc.own || !result.Devices[0].Online || strings.Contains(w.Body.String(), tc.other) {
			t.Fatal("online state crossed owners or was lost")
		}
	}
}
