package network

import (
	"synovpn/internal/engine"
)

func (f Firewall) deviceRules() []struct {
	t string
	a []string
} {
	rules := []struct {
		t string
		a []string
	}{{"filter", []string{"-A", "SVPN_INPUT", "-m", "policy", "--dir", "in", "--pol", "none", "-p", "udp", "-m", "multiport", "--dports", "500,4500", "-j", "ACCEPT"}}}
	nat := map[string]bool{}
	for _, device := range f.Devices {
		reqid := engine.DeviceReqID(device.ID)
		for _, route := range device.Routes {
			for _, chain := range []string{"SVPN_INPUT", "SVPN_FORWARD"} {
				rules = append(rules, struct {
					t string
					a []string
				}{"filter", []string{"-A", chain, "-s", f.Config.Pool, "-d", route, "-m", "policy", "--dir", "in", "--pol", "ipsec", "--proto", "esp", "--mode", "tunnel", "--reqid", reqid, "-j", "ACCEPT"}})
			}
			rules = append(rules, struct {
				t string
				a []string
			}{"filter", []string{"-A", "SVPN_FORWARD", "-s", route, "-d", f.Config.Pool, "-m", "policy", "--dir", "out", "--pol", "ipsec", "--proto", "esp", "--mode", "tunnel", "--reqid", reqid, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}})
			if !nat[route] {
				nat[route] = true
				rules = append(rules, struct {
					t string
					a []string
				}{"nat", []string{"-A", "SVPN_NAT", "-s", f.Config.Pool, "-d", route, "-m", "policy", "--dir", "out", "--pol", "none", "-j", "MASQUERADE"}})
			}
		}
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
