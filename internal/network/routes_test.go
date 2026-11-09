package network

import (
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"testing"
)

func TestPublicPolicyRestrictsForwardingAndNATToListedHosts(t *testing.T) {
	c := config.Default()
	c.Routes = []string{"192.168.1.0/24"}
	c.PublicRoutes = []string{"8.8.8.8/32"}
	f := Firewall{Config: c}
	filter, nat := f.restoreRules("filter"), f.restoreRules("nat")
	for _, host := range c.TrafficRoutes() {
		if !strings.Contains(filter, "-s "+c.Pool+" -d "+host+" -m policy --dir in --pol ipsec") || !strings.Contains(nat, "-s "+c.Pool+" -d "+host+" -m policy --dir out --pol none -j MASQUERADE") {
			t.Fatalf("missing protected route %s", host)
		}
	}
	if !strings.Contains(filter, "-s "+c.Pool+" -j DROP") || !strings.Contains(filter, "--ctstate ESTABLISHED,RELATED") {
		t.Fatal("missing isolation or return path")
	}
	for _, script := range []string{filter, nat} {
		if strings.Contains(script, "0.0.0.0/0") || strings.Contains(script, "-F FORWARD") || strings.Contains(script, "-F POSTROUTING") {
			t.Fatal("changed unrelated policy")
		}
	}
	c.PublicRoutes = nil
	if strings.Contains((Firewall{Config: c}).restoreRules("filter"), "8.8.8.8") {
		t.Fatal("removed destination still allowed")
	}
}

func TestPerDeviceFirewallDoesNotShareAnotherUsersPermission(t *testing.T) {
	c := config.Default()
	c.Routes = []string{"192.168.1.0/24"}
	alice := engine.Device{ID: "aaaaaaaaaaaaaaaaaaaaaa", Routes: []string{"192.168.1.10/32", "8.8.8.0/24"}}
	bob := engine.Device{ID: "bbbbbbbbbbbbbbbbbbbbbb", Routes: []string{"192.168.1.20/32"}}
	script := (Firewall{Config: c, Devices: []engine.Device{alice, bob}}).restoreRules("filter")
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, "-j ACCEPT") || strings.Contains(line, "--dports") {
			continue
		}
		if strings.Contains(line, "8.8.8.0/24") && !strings.Contains(line, "--reqid "+engine.DeviceReqID(alice.ID)+" ") {
			t.Fatal("public permission not identity-bound")
		}
		if strings.Contains(line, "192.168.1.20/32") && !strings.Contains(line, "--reqid "+engine.DeviceReqID(bob.ID)+" ") {
			t.Fatal("private permission not identity-bound")
		}
		if strings.Contains(line, "--reqid "+engine.ReqID+" ") || strings.Contains(line, "192.168.1.0/24") {
			t.Fatal("default subnet bypasses user policy")
		}
	}
	empty := (Firewall{Config: c, Devices: []engine.Device{}}).restoreRules("filter")
	if strings.Contains(empty, "--reqid") {
		t.Fatal("startup accepts peers before policy reconciliation")
	}
}

func TestHandshakeAllowRuleCannotBypassAUsersNASRestrictions(t *testing.T) {
	script := (Firewall{Config: config.Default(), Devices: []engine.Device{}}).restoreRules("filter")
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "--dports 500,4500") && !strings.Contains(line, "-m policy --dir in --pol none") {
			t.Fatal("decrypted inner packets bypass ACL through the IKE exception")
		}
	}
}
