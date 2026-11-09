package web

import (
	"context"
	"net/http"
	"synovpn/internal/auth"
	"synovpn/internal/config"
	"synovpn/internal/engine"
)

func (a *App) applyPublicRoutes(ctx context.Context) {
	routes, err := a.DB.PublicRoutes()
	if err != nil {
		a.routeError = "读取公网出口规则失败"
		return
	}
	a.C.PublicRoutes = routes
	manager, ok := a.Engine.(engine.RouteManager)
	if !ok {
		if len(routes) > 0 {
			a.routeError = "引擎尚不支持公网出口规则，请升级引擎"
		} else {
			a.routeError = ""
		}
		return
	}
	if err = manager.SetPublicRoutes(ctx, routes); err != nil {
		a.routeError = "公网出口规则等待引擎应用，系统将自动重试"
		return
	}
	a.routeError = ""
}
func (a *App) adminPublicRoutes(w http.ResponseWriter, r *http.Request, u auth.User) {
	switch r.Method {
	case http.MethodPost:
		var input struct {
			Routes *[]string `json:"routes"`
		}
		if decode(r, &input) != nil || input.Routes == nil {
			fail(w, 400, "请提交公网 IPv4 列表")
			return
		}
		routes, err := config.NormalizePublicRoutes(*input.Routes)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if _, ok := a.Engine.(engine.RouteManager); !ok {
			fail(w, 503, "引擎尚不支持公网出口规则，请升级引擎")
			return
		}
		if err = a.DB.SetPublicRoutes(u.ID, routes); err != nil {
			fail(w, 500, "保存公网出口规则失败")
			return
		}
		a.sync(r.Context())
	case http.MethodGet:
	default:
		fail(w, 405, "不支持的操作")
		return
	}
	routes, err := a.DB.PublicRoutes()
	if err != nil {
		fail(w, 500, "读取公网出口规则失败")
		return
	}
	status := 200
	if r.Method == http.MethodPost && (a.routeError != "" || !a.last.Ready) {
		status = 202
	}
	reply(w, status, map[string]any{"routes": routes, "applied": a.routeError == "" && a.last.Ready, "error": a.routeError})
}
