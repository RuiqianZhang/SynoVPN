package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtectedAgentRejectsMissingWrongAndRemoteTokens(t *testing.T) {
	token := bytes.Repeat([]byte{0x7b}, 32)
	h, err := ProtectedAgent(&Demo{}, token, Trust{ServerCA: []byte("public-server-ca"), ClientCA: []byte("public-client-ca")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		remote, auth string
		want         int
	}{
		{"127.0.0.1:3210", "", 401},
		{"127.0.0.1:3210", "Bearer " + hex.EncodeToString(bytes.Repeat([]byte{0x7c}, 32)), 401},
		{"192.168.10.2:3210", "Bearer " + hex.EncodeToString(token), 401},
		{"127.0.0.1:3210", "Bearer " + hex.EncodeToString(token), 200},
	} {
		r := httptest.NewRequest("GET", "/trust", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("remote=%s status=%d want=%d", tc.remote, w.Code, tc.want)
		}
		if bytes.Contains(w.Body.Bytes(), []byte(hex.EncodeToString(token))) {
			t.Fatal("token leaked in response")
		}
	}
}

func TestLoopbackClientAuthenticatedTrustAndStatus(t *testing.T) {
	token := bytes.Repeat([]byte{0x5d}, 32)
	trust := Trust{ServerCA: []byte("server-ca"), ClientCA: []byte("client-ca")}
	handler, err := ProtectedAgent(&Demo{}, token, trust)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:18447")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	defer server.Close()
	go server.Serve(listener)
	client, err := NewLoopbackClient("127.0.0.1:18447", token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Trust(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ServerCA, trust.ServerCA) || !bytes.Equal(got.ClientCA, trust.ClientCA) {
		t.Fatal("trust mismatch")
	}
	if _, err = client.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad, _ := NewLoopbackClient("127.0.0.1:18447", bytes.Repeat([]byte{0x1a}, 32))
	if _, err = bad.Status(context.Background()); err == nil {
		t.Fatal("wrong token reached engine")
	}
}

func TestLoopbackClientRefusesExternalEndpoints(t *testing.T) {
	for _, address := range []string{"0.0.0.0:18447", "192.168.10.10:18447", "localhost:18447", "127.0.0.1:80"} {
		if _, err := NewLoopbackClient(address, make([]byte, 32)); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	if _, err := NewLoopbackClient("127.0.0.1:18447", make([]byte, 31)); err == nil {
		t.Fatal("accepted short token")
	}
}
