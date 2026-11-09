package config

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

var specialRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}

// No product limit on rule count. CIDRs are masked, deduplicated and covered
// prefixes removed in at most 32 ancestor lookups per IPv4 prefix.
func NormalizeAccessRoutes(values []string) ([]string, error) {
	prefixes := map[netip.Prefix]bool{}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		var p netip.Prefix
		if ip, e := netip.ParseAddr(raw); e == nil && ip.Is4() {
			p = netip.PrefixFrom(ip, 32)
		} else {
			var err error
			p, err = netip.ParsePrefix(raw)
			if err != nil || !p.Addr().Is4() {
				return nil, errors.New("请填写 IPv4 地址或 CIDR 网段，不支持域名或 IPv6")
			}
		}
		p = p.Masked()
		for _, special := range specialRoutes {
			if p.Overlaps(special) {
				return nil, errors.New("规则不能包含默认路由、回环、链路本地、组播或保留地址")
			}
		}
		prefixes[p] = true
	}
	out := []string{}
	for p := range prefixes {
		covered := false
		for bits := 0; bits < p.Bits(); bits++ {
			if prefixes[netip.PrefixFrom(p.Addr(), bits).Masked()] {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p.String())
		}
	}
	sort.Strings(out)
	return out, nil
}
func NormalizePublicRoutes(values []string) ([]string, error) {
	routes, err := NormalizeAccessRoutes(values)
	if err != nil {
		return nil, err
	}
	for _, raw := range routes {
		p := netip.MustParsePrefix(raw)
		for _, private := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"} {
			if p.Overlaps(netip.MustParsePrefix(private)) {
				return nil, errors.New("全局公网规则不能包含私有或保留地址；请在用户访问规则中设置内网")
			}
		}
	}
	return routes, nil
}
func (c Config) TrafficRoutes() []string {
	return append(append([]string{}, c.Routes...), c.PublicRoutes...)
}
