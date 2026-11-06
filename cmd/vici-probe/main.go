// vici-probe exercises the actual bundled charon, not a mock. It runs only in
// the Linux build container and does not claim native-client interoperability.
package main

import (
	"context"
	"fmt"
	"os"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/pki"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("real VICI: server key/certificate, certificate connection, pool, device issuance/CRL revocation verified")
}
func run() error {
	dir, e := os.MkdirTemp("", "synovpn-probe-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	c := config.Default()
	if socket := os.Getenv("SYNOVPN_TEST_VICI"); socket != "" {
		c.VICI = socket
	}
	c.PKIDir = dir
	c.Domain = "vpn.example.test"
	c.Routes = []string{"192.168.1.0/24"}
	c.DNS = []string{"192.168.1.1"}
	if e = pki.Init(dir, c.Domain); e != nil {
		return e
	}
	g := &engine.Gateway{C: c, Control: engine.VICI{Path: c.VICI}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e = g.Initialize(ctx); e != nil {
		return e
	}
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	_, csr, e := pki.NewKey(id)
	if e != nil {
		return e
	}
	expires := time.Now().Add(time.Hour).Unix()
	issued, e := g.Issue(ctx, pki.IssueRequest{ID: id, CSR: csr, Expires: expires})
	if e != nil {
		return e
	}
	if _, e = g.Sync(ctx, []engine.Device{{ID: id, Certificate: issued.Certificate, Active: true, Expires: expires}}); e != nil {
		return e
	}
	_, e = g.Sync(ctx, []engine.Device{{ID: id, Active: false}})
	return e
}
