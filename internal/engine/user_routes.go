package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/strongswan/govici/vici"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/pki"
)

func DeviceReqID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return strconv.FormatUint(uint64(binary.BigEndian.Uint32(sum[:4])&0x7fffffff)+100000, 10)
}
func deviceConnection(id, suffix string) string { return Connection + "-" + id + suffix }
func sessionMessage(m *vici.Message) (*vici.Message, bool) {
	for _, key := range m.Keys() {
		if key == Connection || strings.HasPrefix(key, Connection+"-") {
			if sa, ok := m.Get(key).(*vici.Message); ok {
				return sa, true
			}
		}
	}
	return nil, false
}
func cloneMessage(m *vici.Message) *vici.Message {
	out := vici.NewMessage()
	for _, key := range m.Keys() {
		value := m.Get(key)
		if nested, ok := value.(*vici.Message); ok {
			value = cloneMessage(nested)
		}
		if list, ok := value.([]string); ok {
			value = append([]string{}, list...)
		}
		_ = out.Set(key, value)
	}
	return out
}
func (g *Gateway) deviceConfig(d Device, suffix, identity string) *vici.Message {
	conn := cloneMessage(g.conn.Get(Connection).(*vici.Message))
	remote := conn.Get("remote").(*vici.Message)
	_ = remote.Set("id", identity)
	child := conn.Get("children").(*vici.Message).Get("synovpn-net").(*vici.Message)
	_ = child.Set("local_ts", d.Routes)
	_ = child.Set("reqid", DeviceReqID(d.ID))
	return message(map[string]any{deviceConnection(d.ID, suffix): conn})
}
func (g *Gateway) syncDeviceRoutes(ctx context.Context, ds []Device) error {
	fail := func(err error) error {
		g.ready = false
		if g.OnRouteFailure != nil {
			g.OnRouteFailure(err)
		}
		return err
	}
	desired := map[string][]string{}
	devices := []Device{}
	reqids := map[string]string{}
	for _, d := range ds {
		if !d.Active || d.Pending {
			continue
		}
		routes, err := config.NormalizeAccessRoutes(d.Routes)
		if err != nil {
			return fail(err)
		}
		if d.Routes == nil {
			return fail(errors.New("device access policy is required"))
		}
		pool, err := netip.ParsePrefix(g.C.Pool)
		if err != nil {
			return fail(err)
		}
		for _, route := range routes {
			if netip.MustParsePrefix(route).Overlaps(pool) {
				return fail(errors.New("access policy overlaps VPN pool"))
			}
		}
		reqid := DeviceReqID(d.ID)
		if previous, ok := reqids[reqid]; ok && previous != d.ID {
			return fail(errors.New("device IPsec policy identifier collision"))
		}
		reqids[reqid] = d.ID
		d.Routes = routes
		desired[d.ID] = routes
		devices = append(devices, d)
	}
	if g.devicePolicies != nil && policyEqual(g.devicePolicies, desired) {
		return nil
	}

	// Replace packet authorization before changing accepted peer configurations.
	if err := g.ApplyDeviceFirewall(g.C, devices); err != nil {
		return fail(err)
	}
	changed := map[string]bool{}
	for id, old := range g.devicePolicies {
		if now, ok := desired[id]; !ok || !slices.Equal(old, now) {
			changed[id] = true
		}
	}
	for _, d := range devices {
		old, exists := g.devicePolicies[d.ID]
		if exists && slices.Equal(old, d.Routes) {
			continue
		}
		changed[d.ID] = true
		if len(d.Routes) == 0 {
			continue
		}
		for _, variant := range []struct{ suffix, id string }{{"-dns", pki.DNSIdentity(d.ID)}, {"-dn", "CN=" + pki.Identity(d.ID)}} {
			if _, err := g.Control.Call(ctx, "load-conn", g.deviceConfig(d, variant.suffix, variant.id)); err != nil {
				return fail(err)
			}
		}
	}
	for id := range changed {
		if _, exists := g.devicePolicies[id]; !exists {
			continue
		}
		if routes, ok := desired[id]; ok && len(routes) > 0 {
			continue
		}
		for _, suffix := range []string{"-dns", "-dn"} {
			if len(g.devicePolicies[id]) > 0 {
				if _, err := g.Control.Call(ctx, "unload-conn", message(map[string]any{"name": deviceConnection(id, suffix)})); err != nil {
					return fail(err)
				}
			}
		}
	}
	// The old wildcard configuration must never remain available after an upgrade.
	if g.enabled && g.devicePolicies == nil {
		if _, err := g.Control.Call(ctx, "unload-conn", message(map[string]any{"name": Connection})); err != nil {
			return fail(err)
		}
	}
	sas, err := g.Control.SAs(ctx)
	if err != nil {
		return fail(err)
	}
	for _, outer := range sas {
		sa, ok := sessionMessage(outer)
		if !ok {
			continue
		}
		id := saDevice(sa)
		if !changed[id] {
			continue
		}
		unique := value(sa, "uniqueid")
		if _, err = strconv.ParseUint(unique, 10, 64); err != nil {
			return fail(err)
		}
		_, terminateErr := g.Control.Call(ctx, "terminate", message(map[string]any{"ike-id": unique, "force": "yes", "timeout": "1000"}))
		remaining, err := g.Control.SAs(ctx)
		if err != nil {
			return fail(err)
		}
		for _, m := range remaining {
			if current, ok := sessionMessage(m); ok && value(current, "uniqueid") == unique {
				if terminateErr != nil {
					return fail(terminateErr)
				}
				return fail(errors.New("old access policy session remains active"))
			}
		}
	}
	g.devicePolicies = desired
	g.enabled = true
	return nil
}
func policyEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for id, routes := range a {
		other, ok := b[id]
		if !ok || !slices.Equal(routes, other) {
			return false
		}
	}
	return true
}
