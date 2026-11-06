package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"synovpn/internal/auth"
	"synovpn/internal/store"
	"testing"
)

func portalReq(a *App, method, path, host, origin, csrf, cookie, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	env, _ := json.Marshal(map[string]string{"HTTP_HOST": host, "HTTPS": "on"})
	r.Header.Set(auth.CGIHeader, base64.RawURLEncoding.EncodeToString(env))
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func TestLANPortalDeviceLifecycleAndLANQR(t *testing.T) {
	a, _ := app(t)
	host := "192.168.10.10:5001"
	origin := "https://" + host
	w := portalReq(a, "GET", "/api/me", host, "", "", "alice", "")
	var me struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(w.Body.Bytes(), &me) != nil || me.CSRF == "" {
		t.Fatal("missing LAN CSRF")
	}
	w = portalReq(a, "POST", "/api/devices", host, origin, me.CSRF, "alice", `{"name":"LAN phone","platform":"ios"}`)
	if w.Code != 201 {
		t.Fatalf("LAN create: %d %s", w.Code, w.Body.String())
	}
	var d store.Device
	json.Unmarshal(w.Body.Bytes(), &d)
	for _, action := range []string{"export", "enroll", "enroll-cancel", "revoke"} {
		w = portalReq(a, "POST", "/api/devices/"+d.ID+"/"+action, host, origin, me.CSRF, "alice", "{}")
		if w.Code != 200 && w.Code != 201 {
			t.Fatalf("LAN %s: %d %s", action, w.Code, w.Body.String())
		}
		if action == "enroll" {
			var result struct {
				URL string `json:"url"`
			}
			json.Unmarshal(w.Body.Bytes(), &result)
			if !strings.HasPrefix(result.URL, origin+"/") {
				t.Fatal("LAN enrollment did not use its portal origin")
			}
		}
	}
}
func TestLANPortalRejectsCrossOriginMissingCSRFAndHostChanges(t *testing.T) {
	a, _ := app(t)
	host := "192.168.10.10:5001"
	origin := "https://" + host
	w := portalReq(a, "GET", "/api/me", host, "", "", "alice", "")
	var me struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &me)
	for _, tc := range []struct{ host, origin, csrf, cookie string }{
		{host, "https://evil.test", me.CSRF, "alice"},
		{host, origin, "", "alice"},
		{"192.168.10.11:5001", "https://192.168.10.11:5001", me.CSRF, "alice"},
		{host, origin, me.CSRF, "bob"},
		{host, origin, me.CSRF, ""},
	} {
		w = portalReq(a, "POST", "/api/devices", tc.host, tc.origin, tc.csrf, tc.cookie, `{"name":"x","platform":"ios"}`)
		if w.Code != 401 && w.Code != 403 {
			t.Fatalf("invalid portal accepted: %d", w.Code)
		}
	}
}
