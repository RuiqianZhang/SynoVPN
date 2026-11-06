package auth

import (
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"os/user"
	"testing"
)

func TestBrowserUsernameIsNeverAnIdentity(t *testing.T) {
	a := DSM{Path: "/does-not-exist", Groups: []string{"users"}}
	r := httptest.NewRequest("GET", "https://nas.test/?username=admin", nil)
	r.Header.Set("X-DSM-User", "admin")
	r.Header.Set("X-Forwarded-User", "admin")
	if _, e := a.Authenticate(r); e == nil {
		t.Fatal("spoofed browser identity accepted")
	}
	r.Header.Set(CGIHeader, base64.RawURLEncoding.EncodeToString([]byte(`{"username":"admin","HTTP_COOKIE":""}`)))
	if _, e := a.Authenticate(r); e == nil {
		t.Fatal("CGI envelope username accepted")
	}
}

func TestDSMSessionTokenIsPassedOnlyToNativeHelper(t *testing.T) {
	for _, env := range []map[string]string{
		{"HTTP_X_SYNO_TOKEN": "session-token", "QUERY_STRING": "route=%2Fapi%2Fme", "REQUEST_METHOD": "POST"},
		{"QUERY_STRING": "SynoToken=session-token&route=%2Fapi%2Fme"},
	} {
		if err := normalizeEnvironment(env); err != nil {
			t.Fatal(err)
		}
		if env["HTTP_X_SYNO_TOKEN"] != "session-token" || env["QUERY_STRING"] != "SynoToken=session-token" || env["REQUEST_METHOD"] != "GET" {
			t.Fatal("native helper did not receive consistent session metadata")
		}
	}
	for _, env := range []map[string]string{
		{},
		{"HTTP_X_SYNO_TOKEN": "one", "QUERY_STRING": "SynoToken=two"},
		{"QUERY_STRING": "SynoToken=one&SynoToken=two"},
		{"HTTP_X_SYNO_TOKEN": "bad\nvalue"},
	} {
		if normalizeEnvironment(env) == nil {
			t.Fatal("invalid or ambiguous session token accepted")
		}
	}
}

func TestRequestOriginComesOnlyFromCGIBridge(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"HTTP_HOST":"192.168.10.10:5001","HTTPS":"on"}`, "https://192.168.10.10:5001"},
		{`{"HTTP_HOST":"NAS.TEST:443","HTTPS":"1"}`, "https://nas.test"},
		{`{"HTTP_HOST":"[::1]:443","HTTPS":"on"}`, "https://[::1]"},
		{`{"HTTP_HOST":"192.168.10.10:5000"}`, "http://192.168.10.10:5000"},
		{`{"HTTP_HOST":"evil.test/path","HTTPS":"on"}`, ""},
		{`{"HTTP_HOST":"user@nas.test","HTTPS":"on"}`, ""},
		{`{"HTTP_HOST":"nas.test?x=1","HTTPS":"on"}`, ""},
		{`{}`, ""},
	} {
		r := httptest.NewRequest("GET", "https://untrusted.test", nil)
		r.Header.Set("X-Forwarded-Host", "spoofed.test")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set(CGIHeader, base64.RawURLEncoding.EncodeToString([]byte(tc.raw)))
		if got := RequestOrigin(r); got != tc.want {
			t.Fatalf("origin %q != %q", got, tc.want)
		}
	}
}

func TestAdministratorRoleUsesLocalGroupMembership(t *testing.T) {
	lookup := func(name string) (*user.Group, error) {
		if name != "administrators" {
			t.Fatal("wrong group")
		}
		return &user.Group{Name: name, Gid: "101"}, nil
	}
	if !inGroup([]string{"100", "101"}, "administrators", lookup) {
		t.Fatal("admin membership missed")
	}
	if inGroup([]string{"100", "0"}, "administrators", lookup) {
		t.Fatal("other group granted admin")
	}
	if inGroup([]string{"101"}, "administrators", func(string) (*user.Group, error) { return nil, errors.New("lookup failed") }) {
		t.Fatal("lookup failure granted admin")
	}
}
