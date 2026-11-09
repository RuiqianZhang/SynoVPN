package web

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"synovpn/internal/auth"
	"synovpn/internal/config"
	"synovpn/internal/store"
)

func (a *App) effectiveRoutes(owner string) []string {
	routes, custom, err := a.DB.UserRoutes(owner)
	if err != nil {
		return []string{}
	}
	if custom {
		return routes
	}
	return a.C.TrafficRoutes()
}
func (a *App) policyUsers(ctx context.Context) ([]store.PolicyUser, error) {
	if directory, ok := a.Auth.(auth.UserDirectory); ok {
		users, err := directory.Users(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if err = a.DB.RememberUser(u.ID, u.Name); err != nil {
				return nil, err
			}
		}
	}
	users, err := a.DB.PolicyUsers()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Name == "" {
			users[i].Name = ownerName(users[i].Owner)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}
func (a *App) adminPolicyUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "不支持的操作")
		return
	}
	users, err := a.policyUsers(r.Context())
	if err != nil {
		fail(w, 503, "读取 DSM 用户失败")
		return
	}
	reply(w, 200, map[string]any{"users": users})
}
func (a *App) adminUserRoutes(w http.ResponseWriter, r *http.Request, u auth.User) {
	owner := r.URL.Query().Get("owner")
	var input struct {
		Owner   string    `json:"owner"`
		Routes  *[]string `json:"routes"`
		Inherit bool      `json:"inherit"`
	}
	if r.Method == "POST" {
		if decode(r, &input) != nil {
			fail(w, 400, "请提交用户和访问规则")
			return
		}
		owner = input.Owner
	} else if r.Method != "GET" {
		fail(w, 405, "不支持的操作")
		return
	}
	users, err := a.policyUsers(r.Context())
	if err != nil {
		fail(w, 503, "读取 DSM 用户失败")
		return
	}
	known := false
	for _, candidate := range users {
		if candidate.Owner == owner {
			known = true
			break
		}
	}
	if !known {
		fail(w, 404, "DSM 用户不存在")
		return
	}
	if r.Method == "POST" {
		if input.Routes == nil && !input.Inherit {
			fail(w, 400, "请提供访问规则；空列表表示禁止访问")
			return
		}
		routes := []string{}
		if !input.Inherit {
			routes, err = config.NormalizeAccessRoutes(*input.Routes)
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
		}
		pool := netip.MustParsePrefix(a.C.Pool)
		for _, raw := range routes {
			if netip.MustParsePrefix(raw).Overlaps(pool) {
				fail(w, 400, "访问规则不能与 VPN 地址池重叠")
				return
			}
		}
		if err = a.DB.SetUserRoutes(u.ID, owner, routes, input.Inherit); err != nil {
			fail(w, 500, "保存用户访问规则失败")
			return
		}
		// Existing download grants must not retain a superseded policy.
		for token, grant := range a.enrollments {
			if grant.Owner == owner {
				delete(a.enrollments, token)
			}
		}
		for token, grant := range a.tickets {
			if grant.Owner == owner {
				delete(a.tickets, token)
			}
		}
		a.sync(r.Context())
	}
	routes, custom, err := a.DB.UserRoutes(owner)
	if err != nil {
		fail(w, 500, "读取用户访问规则失败")
		return
	}
	if !custom {
		routes = a.C.TrafficRoutes()
	}
	status := 200
	if r.Method == "POST" && !a.last.Ready {
		status = 202
	}
	reply(w, status, map[string]any{"owner": owner, "routes": routes, "inherit": !custom, "applied": a.last.Ready, "error": a.last.Error})
}
