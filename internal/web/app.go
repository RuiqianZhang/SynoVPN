package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"synovpn/internal/auth"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/pki"
	"synovpn/internal/profile"
	"synovpn/internal/secure"
	"synovpn/internal/store"
)

type ticket struct {
	Owner, Device, Session string
	Expires                time.Time
}
type App struct {
	mu          sync.Mutex
	C           config.Config
	DB          *store.Store
	Key         []byte
	Auth        auth.Authenticator
	Engine      engine.Engine
	Demo        bool
	tickets     map[string]ticket
	enrollments map[[32]byte]enrollment
	last        engine.Status
}

func New(c config.Config, db *store.Store, key []byte, a auth.Authenticator, e engine.Engine, demo bool) *App {
	return &App{C: c, DB: db, Key: key, Auth: a, Engine: e, Demo: demo, tickets: map[string]ticket{}, enrollments: map[[32]byte]enrollment{}, last: engine.Status{Online: map[string]bool{}}}
}
func (a *App) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		if r.URL.Path == "/api/enroll/claim" {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.claimEnrollment(w, r)
			return
		}
		// This is a static shell containing no user or gateway data. Every API
		// request below independently validates the live DSM session.
		if r.Method == "GET" && r.URL.Path == "/" {
			a.page(w)
			return
		}
		u, e := a.Auth.Authenticate(r)
		if e != nil {
			fail(w, 401, e.Error())
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			fail(w, 405, "不支持的操作")
			return
		}
		if r.Method == "POST" {
			if !a.samePortalOrigin(r) || !secure.Equal(r.Header.Get("X-CSRF-Token"), a.portalCSRF(r, u.ID)) {
				fail(w, 403, "页面会话已改变，请刷新后重试")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/admin/"):
			if !u.Admin {
				fail(w, 403, "仅 DSM 管理员可以访问设备管理")
				return
			}
			a.admin(w, r, u)
		case r.Method == "GET" && r.URL.Path == "/":
			a.page(w)
		case r.Method == "GET" && r.URL.Path == "/api/me":
			reply(w, 200, map[string]any{"user": u.Name, "is_admin": u.Admin, "csrf": a.portalCSRF(r, u.ID), "domain": a.C.Domain, "routes": a.C.Routes, "max_devices": a.C.MaxDevices, "device_days": a.C.DeviceDays, "demo": a.Demo, "authentication": "certificate"})
		case r.Method == "GET" && r.URL.Path == "/api/devices":
			a.list(w, r, u)
		case r.Method == "POST" && r.URL.Path == "/api/devices":
			a.create(w, r, u)
		case r.Method == "GET" && r.URL.Path == "/api/download":
			a.download(w, r, u)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/devices/"):
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/")
			if len(parts) != 2 || !engine.IDPattern.MatchString(parts[0]) {
				fail(w, 404, "设备不存在")
				return
			}
			switch parts[1] {
			case "enroll":
				a.enroll(w, r, u, parts[0])
			case "enroll-cancel":
				a.cancelEnrollment(w, r, u, parts[0])
			case "revoke":
				a.revoke(w, r, u, parts[0])
			case "export":
				a.export(w, r, u, parts[0])
			default:
				fail(w, 404, "页面不存在")
			}
		default:
			fail(w, 404, "页面不存在")
		}
	})
}
func (a *App) list(w http.ResponseWriter, r *http.Request, u auth.User) {
	s, e := a.Engine.Status(r.Context())
	if e != nil {
		s = engine.Status{Ready: false, Online: map[string]bool{}, Error: "VPN 服务暂不可用，连接状态未知"}
	}
	ds, e := a.DB.List(u.ID)
	if e != nil {
		fail(w, 500, "读取设备失败")
		return
	}
	for i := range ds {
		ds[i].Online = s.Ready && s.Online[ds[i].ID]
	}
	reply(w, 200, map[string]any{"devices": ds, "gateway": s.Ready, "gateway_error": s.Error})
}
func (a *App) create(w http.ResponseWriter, r *http.Request, u auth.User) {
	var input struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "请填写设备信息")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if utf8.RuneCountInString(input.Name) < 1 || utf8.RuneCountInString(input.Name) > 48 || strings.ContainsAny(input.Name, "\x00\r\n") {
		fail(w, 400, "设备名称需为 1–48 个字符")
		return
	}
	switch input.Platform {
	case "windows", "macos", "ios", "android":
	default:
		fail(w, 400, "请选择设备系统")
		return
	}
	owned, err := a.DB.List(u.ID)
	if err != nil {
		fail(w, 500, "读取设备配额失败")
		return
	}
	count := 0
	for _, v := range owned {
		if v.State != "revoked" {
			count++
		}
	}
	if count >= a.C.MaxDevices {
		fail(w, 409, "已达到设备数量上限，请先解绑旧设备")
		return
	}
	id := secure.Random(16)
	keyDER, _, e := pki.NewKey(id)
	if e != nil {
		fail(w, 500, "生成设备密钥失败")
		return
	}
	encrypted, e := secure.Seal(a.Key, string(keyDER), id)
	if e != nil {
		fail(w, 500, "生成凭据失败")
		return
	}
	now := time.Now()
	d := store.Device{ID: id, Owner: u.ID, Name: input.Name, Platform: input.Platform, Created: now.Unix(), Expires: now.Add(time.Duration(a.C.DeviceDays) * 24 * time.Hour).Unix(), PrivateKey: encrypted, State: "active"}
	e = a.DB.Create(d, a.C.MaxDevices)
	if errors.Is(e, store.ErrQuota) {
		fail(w, 409, "已达到设备数量上限，请先解绑旧设备")
		return
	}
	if e != nil {
		fail(w, 500, "保存设备失败")
		return
	}
	a.sync(r.Context())
	d, e = a.DB.Get(u.ID, id)
	if e != nil {
		fail(w, 500, "读取设备失败")
		return
	}
	reply(w, 201, d)
}
func (a *App) revoke(w http.ResponseWriter, r *http.Request, u auth.User, id string) {
	if e := a.DB.Revoke(u.ID, id); e != nil {
		if errors.Is(e, store.ErrNotFound) {
			fail(w, 404, "设备不存在")
		} else {
			fail(w, 500, "保存解绑请求失败")
		}
		return
	}
	a.clearEnrollments(u.ID, id)
	a.sync(r.Context())
	d, e := a.DB.Get(u.ID, id)
	if e != nil {
		fail(w, 500, "读取设备失败")
		return
	}
	code := 200
	if d.State != "revoked" {
		code = 202
	}
	reply(w, code, d)
}
func (a *App) export(w http.ResponseWriter, r *http.Request, u auth.User, id string) {
	a.sync(r.Context())
	d, e := a.DB.Get(u.ID, id)
	if e != nil {
		fail(w, 404, "设备不存在")
		return
	}
	if d.State != "active" || d.Expires <= time.Now().Unix() {
		fail(w, 409, "设备已解绑或已到期")
		return
	}
	if !d.Applied || !a.last.Ready {
		fail(w, 503, "VPN 配置尚未生效，请稍后重试")
		return
	}
	for k, v := range a.tickets {
		if time.Now().After(v.Expires) {
			delete(a.tickets, k)
		}
	}
	if len(a.tickets) >= 1024 {
		fail(w, 429, "下载请求过多，请稍后重试")
		return
	}
	token := secure.Random(32)
	a.tickets[token] = ticket{u.ID, id, session(r), time.Now().Add(time.Minute)}
	if e = a.DB.Audit(u.ID, "export-request", id); e != nil {
		delete(a.tickets, token)
		fail(w, 500, "记录下载失败")
		return
	}
	reply(w, 200, map[string]string{"ticket": token})
}
func (a *App) download(w http.ResponseWriter, r *http.Request, u auth.User) {
	token := r.URL.Query().Get("ticket")
	t, ok := a.tickets[token]
	delete(a.tickets, token)
	if !ok || t.Owner != u.ID || t.Session != session(r) || time.Now().After(t.Expires) {
		fail(w, 403, "下载链接已失效，请重新下载")
		return
	}
	f, code, e := a.deviceProfile(u.ID, t.Device)
	if e != nil {
		fail(w, code, e.Error())
		return
	}
	if e = a.DB.Audit(u.ID, "download", t.Device); e != nil {
		fail(w, 500, "记录下载失败")
		return
	}
	writeProfile(w, f)
}

func (a *App) deviceProfile(owner, id string) (profile.File, int, error) {
	d, e := a.DB.Get(owner, id)
	if e != nil || d.State != "active" || !d.Applied || d.Expires <= time.Now().Unix() {
		return profile.File{}, 409, errors.New("设备配置已失效")
	}
	key, e := secure.Open(a.Key, d.PrivateKey, d.ID)
	if e != nil {
		return profile.File{}, 500, errors.New("读取设备凭据失败")
	}
	ca, e := os.ReadFile(filepath.Join(a.C.DataDir, "ca.pem"))
	if e != nil {
		return profile.File{}, 503, errors.New("服务器证书尚未就绪")
	}
	clientCA, e := os.ReadFile(filepath.Join(a.C.DataDir, "client-ca.pem"))
	if e != nil {
		return profile.File{}, 503, errors.New("客户端签发证书尚未就绪")
	}
	f, e := profile.Generate(a.C, d, []byte(key), ca, clientCA)
	if e != nil {
		return profile.File{}, 500, errors.New("生成设备配置失败")
	}
	return f, 200, nil
}

func writeProfile(w http.ResponseWriter, f profile.File) {
	w.Header().Set("Content-Type", f.Type)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, f.Name))
	w.Write(f.Data)
}
func (a *App) sync(ctx context.Context) {
	if e := a.DB.Expire(); e != nil {
		a.last = engine.Status{}
		return
	}
	all, e := a.DB.List("")
	if e != nil {
		a.last = engine.Status{}
		return
	}
	// Revocation runs before new issuance, so a broken pending request can never
	// block another user's device from being revoked.
	for _, d := range all {
		if d.State == "revoking" {
			s, err := a.Engine.Revoke(ctx, d.ID)
			if err == nil && s.Applied[d.ID] {
				a.DB.FinishRevoke(d.ID)
			} else {
				a.DB.Mark(d.ID, false, "证书撤销处理中，系统将自动重试")
			}
		}
	}
	all, e = a.DB.List("")
	if e != nil {
		a.last = engine.Status{}
		return
	}
	ds := []engine.Device{}
	for _, d := range all {
		if d.State == "revoked" {
			continue
		}
		v := engine.Device{ID: d.ID, Active: d.State == "active", Expires: d.Expires}
		if v.Active {
			if len(d.Certificate) == 0 {
				key, err := secure.Open(a.Key, d.PrivateKey, d.ID)
				if err != nil {
					a.DB.Mark(d.ID, false, "设备密钥无法读取")
					a.last = engine.Status{}
					return
				}
				csr, err := pki.CSR(d.ID, []byte(key))
				if err != nil {
					a.DB.Mark(d.ID, false, "设备密钥无效")
					a.last = engine.Status{}
					return
				}
				issued, err := a.Engine.Issue(ctx, pki.IssueRequest{ID: d.ID, CSR: csr, Expires: d.Expires})
				if err != nil {
					a.DB.Mark(d.ID, false, "等待证书签发，系统将自动重试")
					a.last = engine.Status{}
					return
				}
				if issued.Expires != d.Expires {
					a.DB.Mark(d.ID, false, "证书有效期不匹配")
					a.last = engine.Status{}
					return
				}
				if err = a.DB.SetCertificate(d.ID, issued.Certificate, issued.Serial); err != nil {
					a.last = engine.Status{}
					return
				}
				d.Certificate = issued.Certificate
			}
			v.Certificate = d.Certificate
		}
		ds = append(ds, v)
	}
	s, e := a.Engine.Sync(ctx, ds)
	a.last = s
	for _, d := range all {
		if d.State == "revoked" {
			continue
		}
		if e != nil {
			a.DB.Mark(d.ID, false, "VPN 服务暂不可用，系统将自动重试")
			continue
		}
		if !s.Applied[d.ID] {
			a.DB.Mark(d.ID, false, "等待 VPN 服务确认")
			continue
		}
		if d.State == "revoking" {
			a.DB.FinishRevoke(d.ID)
		} else {
			a.DB.Mark(d.ID, true, "")
		}
	}
}
func (a *App) Reconcile(ctx context.Context) {
	run := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		a.sync(c)
	}
	run()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func session(r *http.Request) string {
	s := sha256.Sum256([]byte(r.Header.Get("Cookie")))
	return hex.EncodeToString(s[:])
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}

// The public origin remains fixed for QR links. Authenticated DSM management may
// also use the exact origin served by the native CGI bridge (e.g. a LAN IP).
func (a *App) samePortalOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin != "" && (origin == a.C.Origin || origin == auth.RequestOrigin(r))
}
func (a *App) portalCSRF(r *http.Request, user string) string {
	origin := auth.RequestOrigin(r)
	session := r.Header.Get("Cookie")
	if origin != "" && origin != a.C.Origin {
		session += "\nOrigin=" + origin
	}
	return secure.CSRF(a.Key, user, session)
}
