package engine

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

type Trust struct {
	ServerCA []byte `json:"server_ca"`
	ClientCA []byte `json:"client_ca"`
}

type tokenTransport struct {
	inner http.RoundTripper
	token string
}

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.inner.RoundTrip(r)
}

// Requests can only reach the fixed loopback endpoint, without a proxy or redirect.
func NewLoopbackClient(address string, token []byte) (*Client, error) {
	if address != "127.0.0.1:18447" || len(token) != 32 {
		return nil, errors.New("invalid engine endpoint or token")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", address)
	}}
	return &Client{HTTP: &http.Client{Transport: tokenTransport{transport, hex.EncodeToString(token)}, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Trust(ctx context.Context) (Trust, error) {
	var trust Trust
	r, e := http.NewRequestWithContext(ctx, "GET", "http://agent/trust", nil)
	if e != nil {
		return trust, e
	}
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return trust, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return trust, errors.New("engine trust unavailable")
	}
	e = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 32768)).Decode(&trust)
	if e == nil && (len(trust.ServerCA) == 0 || len(trust.ClientCA) == 0) {
		e = errors.New("empty engine trust")
	}
	return trust, e
}

// The token is shared only with the native package account, never with CGI/http.
func ProtectedAgent(e Engine, token []byte, trust Trust) (http.Handler, error) {
	if len(token) != 32 {
		return nil, errors.New("invalid engine token")
	}
	expected := "Bearer " + hex.EncodeToString(token)
	agent := AgentHandler(e)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/trust" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(trust)
			return
		}
		agent.ServeHTTP(w, r)
	}), nil
}
