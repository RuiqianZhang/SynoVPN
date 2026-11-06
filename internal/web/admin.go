package web

import (
	"errors"
	"net/http"
	"strings"
	"synovpn/internal/auth"
	"synovpn/internal/engine"
	"synovpn/internal/store"
)

type adminDevice struct {
	store.Device
	OwnerName string `json:"owner"`
}

func ownerName(owner string) string {
	parts := strings.SplitN(owner, ":", 3)
	if len(parts) == 3 && parts[0] == "dsm" {
		return parts[2]
	}
	if owner == "demo:1000" {
		return "演示用户"
	}
	return owner
}
func (a *App) admin(w http.ResponseWriter, r *http.Request, u auth.User) {
	if r.Method == "GET" && r.URL.Path == "/api/admin/devices" {
		a.adminList(w, r)
		return
	}
	const prefix = "/api/admin/devices/"
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, prefix) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if len(parts) == 2 && engine.IDPattern.MatchString(parts[0]) && (parts[1] == "revoke" || parts[1] == "delete") {
			if parts[1] == "delete" {
				a.deleteRecord(w, r, u, parts[0], true)
			} else {
				a.adminRevoke(w, r, u, parts[0])
			}
			return
		}
	}
	fail(w, 404, "管理操作不存在")
}
func (a *App) adminList(w http.ResponseWriter, r *http.Request) {
	status, err := a.Engine.Status(r.Context())
	if err != nil {
		status = engine.Status{Error: "VPN 服务暂不可用，连接状态未知"}
	}
	devices, err := a.DB.AllMetadata()
	if err != nil {
		fail(w, 500, "读取设备失败")
		return
	}
	out := make([]adminDevice, 0, len(devices))
	for _, d := range devices {
		d.Online = status.Ready && status.Online[d.ID]
		out = append(out, adminDevice{d, ownerName(d.Owner)})
	}
	reply(w, 200, map[string]any{"devices": out, "gateway": status.Ready, "gateway_error": status.Error})
}
func (a *App) adminRevoke(w http.ResponseWriter, r *http.Request, u auth.User, id string) {
	owner, err := a.DB.AdminRevoke(u.ID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, 404, "设备不存在")
		} else {
			fail(w, 500, "保存管理员解绑请求失败")
		}
		return
	}
	a.clearEnrollments(owner, id)
	for token, ticket := range a.tickets {
		if ticket.Device == id {
			delete(a.tickets, token)
		}
	}
	a.sync(r.Context())
	d, err := a.DB.Metadata(id)
	if err != nil {
		fail(w, 500, "读取设备失败")
		return
	}
	code := 200
	if d.State != "revoked" {
		code = 202
	}
	reply(w, code, adminDevice{d, ownerName(d.Owner)})
}

func (a *App) deleteRecord(w http.ResponseWriter, r *http.Request, u auth.User, id string, admin bool) {
	owner := u.ID
	if admin {
		d, err := a.DB.Metadata(id)
		if err != nil {
			fail(w, 404, "设备不存在")
			return
		}
		owner = d.Owner
	}
	err := a.DB.Archive(owner, id, u.ID, admin)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			fail(w, 404, "设备不存在")
		case errors.Is(err, store.ErrNotRevoked):
			fail(w, 409, "请先解绑，等待证书撤销完成后再删除记录")
		default:
			fail(w, 500, "删除记录失败")
		}
		return
	}
	a.clearEnrollments(owner, id)
	for token, t := range a.tickets {
		if t.Device == id {
			delete(a.tickets, token)
		}
	}
	reply(w, 200, map[string]bool{"deleted": true})
}
