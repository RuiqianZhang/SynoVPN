package config

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

const Package = "SynoVPN"
const Base = "/var/packages/" + Package

// Config is administrator-owned. A web request can never select a command,
// socket path, filesystem path, network range or VPN server identity.
type Config struct {
	Domain           string   `json:"domain"`
	Origin           string   `json:"origin"`
	Pool             string   `json:"pool"`
	Routes           []string `json:"routes"`
	DNS              []string `json:"dns"`
	AllowedGroups    []string `json:"allowed_groups"`
	MaxDevices       int      `json:"max_devices"`
	DeviceDays       int      `json:"device_days"`
	DataDir          string   `json:"data_dir"`
	RunDir           string   `json:"run_dir"`
	PKIDir           string   `json:"pki_dir"`
	AuthCGI          string   `json:"auth_cgi"`
	VICI             string   `json:"vici"`
	ServiceUser      string   `json:"service_user"`
	EnableForwarding bool     `json:"enable_forwarding"`
	EngineAddress    string   `json:"engine_address,omitempty"`
}

func Default() Config {
	return Config{Pool: "10.77.0.0/24", MaxDevices: 5, DeviceDays: 90,
		AllowedGroups: []string{"users"}, DataDir: Base + "/var/web", RunDir: Base + "/var/run", PKIDir: Base + "/var/pki",
		AuthCGI: "/usr/syno/synoman/webman/modules/authenticate.cgi", VICI: Base + "/var/run/charon.vici", ServiceUser: Package}
}

var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func (c Config) Validate() error {
	if c.EngineAddress != "" && c.EngineAddress != "127.0.0.1:18447" {
		return errors.New("engine must use the fixed loopback endpoint")
	}
	if !domainPattern.MatchString(c.Domain) || !strings.Contains(c.Domain, ".") || net.ParseIP(c.Domain) != nil || strings.Contains(c.Domain, "..") {
		return errors.New("domain must be a DNS name")
	}
	u, e := url.Parse(c.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("origin must be the exact HTTPS DSM origin, without a path")
	}
	p, e := netip.ParsePrefix(c.Pool)
	if e != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 || p != p.Masked() || !p.Addr().IsPrivate() {
		return errors.New("pool must be an aligned private IPv4 /16 through /29")
	}
	if len(c.Routes) == 0 || len(c.Routes) > 16 {
		return errors.New("one to sixteen internal routes required")
	}
	for _, s := range c.Routes {
		r, e := netip.ParsePrefix(s)
		if e != nil || !r.Addr().Is4() || !r.Addr().IsPrivate() || r != r.Masked() || r.Overlaps(p) || r.Bits() < 8 {
			return errors.New("routes must be aligned private IPv4 subnets outside the VPN pool")
		}
	}
	if len(c.DNS) == 0 || len(c.DNS) > 3 {
		return errors.New("one to three DNS addresses required")
	}
	for _, s := range c.DNS {
		a, e := netip.ParseAddr(s)
		if e != nil || !a.Is4() {
			return errors.New("DNS must contain IPv4 addresses")
		}
	}
	if c.MaxDevices < 1 || c.MaxDevices > 50 || c.DeviceDays < 1 || c.DeviceDays > 365 {
		return errors.New("invalid device quota or lifetime")
	}
	if len(c.AllowedGroups) == 0 {
		return errors.New("at least one DSM group must be explicitly allowed")
	}
	for _, s := range []string{c.DataDir, c.RunDir, c.PKIDir, c.AuthCGI, c.VICI} {
		if !path.IsAbs(s) || strings.ContainsAny(s, "\r\n\x00") {
			return errors.New("paths must be absolute")
		}
	}
	if c.ServiceUser != Package {
		return errors.New("unexpected service account")
	}
	return nil
}

func Read(path string) (Config, error) {
	c := Default()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	return c, c.Validate()
}
