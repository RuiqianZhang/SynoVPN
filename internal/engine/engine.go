package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"synovpn/internal/pki"
	"time"
)

type Device struct {
	ID          string `json:"id"`
	Certificate []byte `json:"certificate,omitempty"`
	Active      bool   `json:"active"`
	Expires     int64  `json:"expires"`
}
type Status struct {
	Ready   bool            `json:"ready"`
	Online  map[string]bool `json:"online"`
	Error   string          `json:"error,omitempty"`
	Applied map[string]bool `json:"applied,omitempty"`
}
type Engine interface {
	Issue(context.Context, pki.IssueRequest) (pki.Issued, error)
	Revoke(context.Context, string) (Status, error)
	Sync(context.Context, []Device) (Status, error)
	Status(context.Context) (Status, error)
}

var IDPattern = pki.IDPattern

func Validate(ds []Device) error {
	if len(ds) > 4096 {
		return errors.New("too many devices")
	}
	seen := map[string]bool{}
	for _, d := range ds {
		if !IDPattern.MatchString(d.ID) || seen[d.ID] {
			return errors.New("invalid or duplicate device identity")
		}
		seen[d.ID] = true
		if d.Active && (len(d.Certificate) == 0 || len(d.Certificate) > 8192 || d.Expires <= time.Now().Unix() || d.Expires > time.Now().Add(366*24*time.Hour).Unix()) {
			return errors.New("invalid device credential")
		}
	}
	return nil
}
func Identity(id string) string { return pki.Identity(id) }
func DeviceID(identity string) string {
	return pki.DeviceID(identity)
}

type Client struct{ HTTP *http.Client }

func NewClient(path string) *Client {
	return &Client{&http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, Timeout: 25 * time.Second}}
}
func (c *Client) request(ctx context.Context, method, path string, input any) (Status, error) {
	var s Status
	b, e := json.Marshal(input)
	if e != nil {
		return s, e
	}
	r, e := http.NewRequestWithContext(ctx, method, "http://agent"+path, strings.NewReader(string(b)))
	if e != nil {
		return s, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return s, e
	}
	defer resp.Body.Close()
	if e = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&s); e != nil {
		return s, e
	}
	if resp.StatusCode != 200 {
		return s, errors.New("VPN agent unavailable")
	}
	if !s.Ready {
		return s, errors.New("VPN engine is not ready")
	}
	return s, nil
}
func (c *Client) Revoke(ctx context.Context, id string) (Status, error) {
	return c.request(ctx, "POST", "/revoke", map[string]string{"id": id})
}
func (c *Client) Sync(ctx context.Context, ds []Device) (Status, error) {
	return c.request(ctx, "POST", "/sync", ds)
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	return c.request(ctx, "GET", "/status", nil)
}
func (c *Client) Issue(ctx context.Context, input pki.IssueRequest) (pki.Issued, error) {
	var result pki.Issued
	b, e := json.Marshal(input)
	if e != nil {
		return result, e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", "http://agent/issue", strings.NewReader(string(b)))
	if e != nil {
		return result, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return result, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, errors.New("certificate issuance failed")
	}
	e = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16384)).Decode(&result)
	return result, e
}

// Demo is deliberately isolated from the production command and never opens IKE ports.
type Demo struct {
	Authority *pki.Authority
	mu        sync.Mutex
	devices   map[string]bool
}

func (d *Demo) Issue(ctx context.Context, r pki.IssueRequest) (pki.Issued, error) {
	return d.Authority.Issue(r)
}
func (d *Demo) Revoke(ctx context.Context, id string) (Status, error) {
	if e := d.Authority.RevokeIDs([]string{id}); e != nil {
		return Status{}, e
	}
	return Status{Ready: true, Online: map[string]bool{}, Applied: map[string]bool{id: true}}, nil
}

func (d *Demo) Sync(ctx context.Context, ds []Device) (Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.devices = map[string]bool{}
	active := []pki.ActiveCertificate{}
	for _, v := range ds {
		if v.Active {
			active = append(active, pki.ActiveCertificate{ID: v.ID, Certificate: v.Certificate, Expires: v.Expires})
		}
	}
	if _, e := d.Authority.Reconcile(active); e != nil {
		return Status{}, e
	}
	applied := map[string]bool{}
	for _, v := range ds {
		applied[v.ID] = true
	}
	return Status{Ready: true, Online: map[string]bool{}, Applied: applied}, nil
}
func (d *Demo) Status(ctx context.Context) (Status, error) {
	return Status{Ready: true, Online: map[string]bool{}}, nil
}
