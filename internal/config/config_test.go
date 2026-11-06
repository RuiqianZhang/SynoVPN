package config

import "testing"

func TestRejectUnsafeGatewayConfiguration(t *testing.T) {
	base := Default()
	base.Domain = "vpn.example.test"
	base.Origin = "https://nas.example.test:5001"
	base.Routes = []string{"192.168.1.0/24"}
	base.DNS = []string{"192.168.1.1"}
	if e := base.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Domain = "vpn.example.test\nload = malicious" }, func(c *Config) { c.Origin = "http://nas.test" }, func(c *Config) { c.Routes = []string{"0.0.0.0/0"} }, func(c *Config) { c.Routes = []string{c.Pool} }, func(c *Config) { c.Pool = "8.8.8.0/24" }, func(c *Config) { c.DNS = []string{"1.1.1.1;cmd"} }} {
		c := base
		change(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe administrator config accepted")
		}
	}
}
