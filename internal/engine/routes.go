package engine

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/strongswan/govici/vici"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/secure"
)

type RouteManager interface {
	SetPublicRoutes(context.Context, []string) error
}

func (c *Client) SetPublicRoutes(ctx context.Context, routes []string) error {
	b, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", "http://agent/public-routes", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("公网出口规则尚未应用，请确认引擎已升级并就绪")
	}
	return nil
}
func (d *Demo) SetPublicRoutes(ctx context.Context, routes []string) error {
	_, err := config.NormalizePublicRoutes(routes)
	return err
}

// Failures after changing kernel policy stop the engine;
// no partial policy is acknowledged, and the durable old policy is restored on restart.
func (g *Gateway) SetPublicRoutes(ctx context.Context, routes []string) error {
	normalized, err := config.NormalizePublicRoutes(routes)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready {
		return errors.New("gateway not ready")
	}
	if g.ApplyDeviceFirewall != nil {
		return nil
	}
	if slices.Equal(normalized, g.C.PublicRoutes) {
		return nil
	}
	if g.ApplyRouteFirewall == nil {
		return errors.New("routing updates unavailable")
	}
	next := g.C
	next.PublicRoutes = normalized
	fail := func(err error) error {
		g.ready = false
		if g.OnRouteFailure != nil {
			g.OnRouteFailure(err)
		}
		return err
	}
	if err = g.ApplyRouteFirewall(next); err != nil {
		return fail(err)
	}
	conn := g.conn.Get(Connection).(*vici.Message)
	children := conn.Get("children").(*vici.Message)
	child := children.Get("synovpn-net").(*vici.Message)
	if err = child.Set("local_ts", next.TrafficRoutes()); err != nil {
		return fail(err)
	}
	if g.enabled {
		if _, err = g.Control.Call(ctx, "load-conn", g.conn); err != nil {
			return fail(err)
		}
		// Existing CHILD SAs retain old selectors. Terminate only real IDs:
		// strongSwan rejects a named terminate when there are no matching SAs.
		ids, err := g.routeSessions(ctx)
		if err != nil {
			return fail(err)
		}
		for _, id := range ids {
			_, terminateErr := g.Control.Call(ctx, "terminate", message(map[string]any{"ike-id": id, "timeout": "5000", "force": "yes"}))
			remaining, checkErr := g.routeSessions(ctx)
			if checkErr != nil {
				return fail(checkErr)
			}
			if slices.Contains(remaining, id) {
				if terminateErr != nil {
					return fail(terminateErr)
				}
				return fail(errors.New("old routing session remains active"))
			}
			// A peer may have disconnected between enumeration and termination.
		}
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return fail(err)
	}
	if err = secure.Atomic(filepath.Join(g.C.PKIDir, "public-routes.json"), raw, 0600); err != nil {
		return fail(err)
	}
	g.C = next
	return nil
}

func (g *Gateway) routeSessions(ctx context.Context) ([]string, error) {
	sas, err := g.Control.SAs(ctx)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, outer := range sas {
		if sa, ok := outer.Get(Connection).(*vici.Message); ok {
			id := value(sa, "uniqueid")
			if id == "" {
				return nil, errors.New("session has no unique ID")
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}
