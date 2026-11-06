package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"synovpn/internal/store"
)

func TestAndroidEnrollmentReturnsItsBoundProfile(t *testing.T) {
	a, _ := app(t)
	w := req(a, "POST", "/api/devices", "alice", `{"name":"android phone","platform":"android"}`)
	if w.Code != 201 {
		t.Fatal("android creation failed")
	}
	var d store.Device
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	token := grant(t, a, d.ID)
	w = claim(a, token, a.C.Origin)
	if w.Code != 200 {
		t.Fatal("android claim failed")
	}
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range z.File {
		if f.Name == "certificate.json" {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var metadata struct {
				DeviceID string `json:"device_id"`
			}
			if err = json.NewDecoder(r).Decode(&metadata); err != nil || metadata.DeviceID != d.ID {
				t.Fatal("grant released the wrong device")
			}
			return
		}
	}
	t.Fatal("android profile metadata missing")
}

func phone(t *testing.T, a *App) store.Device {
	t.Helper()
	w := req(a, "POST", "/api/devices", "alice", `{"name":"test phone","platform":"ios"}`)
	if w.Code != 201 {
		t.Fatalf("phone creation: %d", w.Code)
	}
	var d store.Device
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func grant(t *testing.T, a *App, id string) string {
	t.Helper()
	w := req(a, "POST", "/api/devices/"+id+"/enroll", "alice", "{}")
	if w.Code != 201 {
		t.Fatalf("enrollment: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		URL, QR string
		Expires int64
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result.URL)
	if err != nil || u.Scheme != "https" || u.Host != "nas.example.test:5001" || u.RawQuery != "" {
		t.Fatal("untrusted or query-bearing enrollment URL")
	}
	token := strings.TrimPrefix(u.Fragment, "enroll=")
	if len(token) != 43 || result.Expires <= time.Now().Unix() || result.Expires > time.Now().Add(enrollmentLifetime+time.Second).Unix() {
		t.Fatal("invalid token or lifetime")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.QR, "data:image/png;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(raw))
	if err != nil || image.Bounds().Dx() != 280 {
		t.Fatal("invalid QR image")
	}
	if strings.Contains(req(a, "GET", "/api/devices", "alice", "").Body.String(), token) {
		t.Fatal("enrollment token leaked in device listing")
	}
	return token
}

func claim(a *App, token, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/enroll/claim", strings.NewReader(url.Values{"claim": []string{token}}.Encode()))
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestPhoneEnrollmentIsScopedAndSingleUse(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	for _, owner := range []string{"", "bob"} {
		if w := req(a, "POST", "/api/devices/"+d.ID+"/enroll", owner, "{}"); w.Code == 201 {
			t.Fatal("other user created enrollment")
		}
	}
	desktop := create(t, a)
	if req(a, "POST", "/api/devices/"+desktop.ID+"/enroll", "alice", "{}").Code != 409 {
		t.Fatal("desktop profile offered as phone installation")
	}
	token := grant(t, a, d.ID)
	if claim(a, token, "https://untrusted.test").Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	w := claim(a, token, a.C.Origin)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "apple-aspen-config") || !strings.Contains(w.Body.String(), "com.apple.vpn.managed") {
		t.Fatalf("phone profile: %d", w.Code)
	}
	if claim(a, token, a.C.Origin).Code != 403 {
		t.Fatal("grant reused")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private profile cacheable")
	}
}

func TestEnrollmentExpiryReplacementCancelAndRestart(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	expired := grant(t, a, d.ID)
	key := sha256.Sum256([]byte(expired))
	g := a.enrollments[key]
	g.Expires = time.Now().Add(-time.Second)
	a.enrollments[key] = g
	if claim(a, expired, a.C.Origin).Code != 403 {
		t.Fatal("expired grant accepted")
	}
	old := grant(t, a, d.ID)
	fresh := grant(t, a, d.ID)
	if claim(a, old, a.C.Origin).Code != 403 {
		t.Fatal("replaced QR still valid")
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/enroll-cancel", "bob", "{}").Code != 404 {
		t.Fatal("cross-user cancel accepted")
	}
	if req(a, "POST", "/api/devices/"+d.ID+"/enroll-cancel", "alice", "{}").Code != 200 {
		t.Fatal("cancel failed")
	}
	if claim(a, fresh, a.C.Origin).Code != 403 {
		t.Fatal("canceled grant accepted")
	}
	if got, err := a.DB.Get("alice", d.ID); err != nil || got.State != "active" {
		t.Fatal("canceling QR revoked the device")
	}
	token := grant(t, a, d.ID)
	restarted := New(a.C, a.DB, a.Key, a.Auth, a.Engine, false)
	if claim(restarted, token, a.C.Origin).Code != 403 {
		t.Fatal("grant survived server restart")
	}
}

func TestEnrollmentRevocationAndConcurrentClaim(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	token := grant(t, a, d.ID)
	if req(a, "POST", "/api/devices/"+d.ID+"/revoke", "alice", "{}").Code != 200 {
		t.Fatal("revoke failed")
	}
	if claim(a, token, a.C.Origin).Code == 200 {
		t.Fatal("revoked device profile released")
	}
	d = phone(t, a)
	token = grant(t, a, d.ID)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- claim(a, token, a.C.Origin).Code }()
	}
	wg.Wait()
	close(codes)
	successes := 0
	failures := 0
	for code := range codes {
		if code == 200 {
			successes++
		} else if code == 403 {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatal("concurrent claim was not exactly once")
	}
}

func TestEnrollmentIssueStillRequiresCSRF(t *testing.T) {
	a, _ := app(t)
	d := phone(t, a)
	r := httptest.NewRequest("POST", "/api/devices/"+d.ID+"/enroll", strings.NewReader("{}"))
	r.Header.Set("Cookie", "alice")
	r.Header.Set("Origin", a.C.Origin)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("enrollment creation bypassed CSRF")
	}
	for _, body := range []string{"claim=bad", "claim=one&claim=two", "claim=" + strings.Repeat("a", 2048)} {
		r = httptest.NewRequest("POST", "/api/enroll/claim", strings.NewReader(body))
		r.Header.Set("Origin", a.C.Origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("malformed claim accepted")
		}
	}
}

// Native form downloads require a non-opaque same-origin Origin header.
func TestEnrollmentPagePreservesSameOriginFormOrigin(t *testing.T) {
	a, _ := app(t)
	w := req(a, "GET", "/", "", "")
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("native form Origin would be suppressed")
	}
}
