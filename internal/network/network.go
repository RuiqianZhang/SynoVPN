package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"time"
)

func iptablesPath() string {
	if os.Getenv("SYNOVPN_ENGINE_CONTAINER") == "1" {
		return "/usr/sbin/iptables-legacy"
	}
	return "/sbin/iptables"
}

func Preflight(c config.Config) error {
	if _, e := os.Stat(iptablesPath()); e != nil {
		return errors.New("required iptables executable is unavailable")
	}
	for _, p := range []int{500, 4500} {
		s, e := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
		if e != nil {
			return fmt.Errorf("UDP %d already in use; stop the conflicting VPN service", p)
		}
		s.Close()
	}
	b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil {
		return e
	}
	if string(bytes.TrimSpace(b)) != "1" {
		if !c.EnableForwarding {
			return errors.New("IPv4 forwarding is disabled; administrator must allow enable_forwarding or enable it explicitly")
		}
		if e = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); e != nil {
			return e
		}
	}
	return nil
}

type Firewall struct {
	Config  config.Config
	Devices []engine.Device
}

func command(table string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	a := append([]string{"-w", "5", "-t", table}, args...)
	out, e := exec.CommandContext(ctx, iptablesPath(), a...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("iptables operation failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
func (f Firewall) Start() error {
	// Only package-owned chains and exact jump rules are touched. Traffic from
	// the VPN pool is accepted only with this package's IPsec reqid policy.
	f.Stop()
	for _, v := range []struct{ t, n string }{{"filter", "SVPN_INPUT"}, {"filter", "SVPN_FORWARD"}, {"nat", "SVPN_NAT"}} {
		if e := command(v.t, "-N", v.n); e != nil {
			return e
		}
	}
	rules := f.rules()
	for _, r := range rules {
		if e := command(r.t, r.a...); e != nil {
			return e
		}
	}
	for _, r := range []struct{ t, b, c string }{{"filter", "INPUT", "SVPN_INPUT"}, {"filter", "FORWARD", "SVPN_FORWARD"}, {"nat", "POSTROUTING", "SVPN_NAT"}} {
		if e := command(r.t, "-I", r.b, "1", "-j", r.c); e != nil {
			return e
		}
	}
	return nil
}
func (f Firewall) Stop() {
	for _, r := range []struct{ t, b, c string }{{"filter", "INPUT", "SVPN_INPUT"}, {"filter", "FORWARD", "SVPN_FORWARD"}, {"nat", "POSTROUTING", "SVPN_NAT"}} {
		command(r.t, "-D", r.b, "-j", r.c)
		command(r.t, "-F", r.c)
		command(r.t, "-X", r.c)
	}
}

func (f Firewall) rules() []struct {
	t string
	a []string
} {
	if f.Devices != nil {
		return f.deviceRules()
	}
	rules := []struct {
		t string
		a []string
	}{{"filter", []string{"-A", "SVPN_INPUT", "-m", "policy", "--dir", "in", "--pol", "none", "-p", "udp", "-m", "multiport", "--dports", "500,4500", "-j", "ACCEPT"}}}
	for _, route := range f.Config.TrafficRoutes() {
		for _, chain := range []string{"SVPN_INPUT", "SVPN_FORWARD"} {
			rules = append(rules, struct {
				t string
				a []string
			}{"filter", []string{"-A", chain, "-s", f.Config.Pool, "-d", route, "-m", "policy", "--dir", "in", "--pol", "ipsec", "--proto", "esp", "--mode", "tunnel", "--reqid", engine.ReqID, "-j", "ACCEPT"}})
		}
		rules = append(rules, struct {
			t string
			a []string
		}{"filter", []string{"-A", "SVPN_FORWARD", "-s", route, "-d", f.Config.Pool, "-m", "policy", "--dir", "out", "--pol", "ipsec", "--proto", "esp", "--mode", "tunnel", "--reqid", engine.ReqID, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}, struct {
			t string
			a []string
		}{"nat", []string{"-A", "SVPN_NAT", "-s", f.Config.Pool, "-d", route, "-m", "policy", "--dir", "out", "--pol", "none", "-j", "MASQUERADE"}})
	}
	for _, chain := range []string{"SVPN_INPUT", "SVPN_FORWARD"} {
		rules = append(rules, struct {
			t string
			a []string
		}{"filter", []string{"-A", chain, "-s", f.Config.Pool, "-j", "DROP"}})
	}
	rules = append(rules, struct {
		t string
		a []string
	}{"filter", []string{"-A", "SVPN_FORWARD", "-d", f.Config.Pool, "-j", "DROP"}})
	return rules
}

// Each table is replaced atomically without flushing unrelated DSM rules.
// Filter is installed first: removed destinations are blocked before NAT changes.
func (f Firewall) Update() error {
	for _, table := range []string{"filter", "nat"} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cmd := exec.CommandContext(ctx, iptablesPath()+"-restore", "--noflush", "-w", "5")
		cmd.Stdin = strings.NewReader(f.restoreRules(table))
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("iptables policy update failed: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}
func (f Firewall) restoreRules(table string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n", table)
	if table == "filter" {
		b.WriteString(":SVPN_INPUT - [0:0]\n:SVPN_FORWARD - [0:0]\n-F SVPN_INPUT\n-F SVPN_FORWARD\n")
	} else {
		b.WriteString(":SVPN_NAT - [0:0]\n-F SVPN_NAT\n")
	}
	for _, r := range f.rules() {
		if r.t == table {
			b.WriteString(strings.Join(r.a, " "))
			b.WriteByte('\n')
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}
