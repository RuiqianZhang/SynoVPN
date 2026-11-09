package config

import (
	"fmt"
	"slices"
	"testing"
)

func TestPublicRoutesAcceptCIDRAndNoCountCap(t *testing.T) {
	got, err := NormalizePublicRoutes([]string{"8.8.8.8", "1.1.1.1/32", " 8.8.8.8 "})
	if err != nil || !slices.Equal(got, []string{"1.1.1.1/32", "8.8.8.8/32"}) {
		t.Fatalf("normalization: %v %v", got, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::ffff:8.8.8.8", "2001:4860:4860::8888", "vpn.example.com", "8.8.8.8;reboot", ""} {
		if _, err := NormalizePublicRoutes([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	many := []string{}
	for i := 1; i <= 200; i++ {
		many = append(many, fmt.Sprintf("8.8.%d.1", i))
	}
	if got, err := NormalizePublicRoutes(many); err != nil || len(got) != 200 {
		t.Fatal("unexpected rule count limit", err)
	}
	if got, err := NormalizePublicRoutes([]string{"8.8.8.27/24", "8.8.8.8"}); err != nil || !slices.Equal(got, []string{"8.8.8.0/24"}) {
		t.Fatal("CIDR normalization", got, err)
	}
	c := Config{Routes: []string{"192.168.1.0/24"}, PublicRoutes: got}
	if !slices.Equal(c.TrafficRoutes(), []string{"192.168.1.0/24", "1.1.1.1/32", "8.8.8.8/32"}) {
		t.Fatal("private routes lost")
	}
}

func TestUserAccessRulesNormalizePrivateAndPublicCIDR(t *testing.T) {
	got, err := NormalizeAccessRoutes([]string{"192.168.1.20", "192.168.1.55/24", "8.8.8.7/24", "8.8.8.8", "10.20.30.40/16"})
	if err != nil || !slices.Equal(got, []string{"10.20.0.0/16", "192.168.1.0/24", "8.8.8.0/24"}) {
		t.Fatal(got, err)
	}
	if empty, err := NormalizeAccessRoutes([]string{}); err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("deny-all policy not explicit")
	}
	for _, value := range []string{"0.0.0.0/0", "127.0.0.1", "169.254.1.0/24", "224.0.0.0/4", "::/0", "host.example"} {
		if _, err := NormalizeAccessRoutes([]string{value}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
