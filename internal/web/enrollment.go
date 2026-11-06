package web

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"mime"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"synovpn/internal/auth"
	"synovpn/internal/secure"
)

const enrollmentLifetime = 5 * time.Minute

// A phone receives a short-lived capability for exactly one existing device.
// Only its digest is retained. Restart, cancellation and revocation invalidate it.
type enrollment struct {
	Owner, Device string
	Expires       time.Time
}

func (a *App) clearEnrollments(owner, device string) {
	for key, grant := range a.enrollments {
		if time.Now().After(grant.Expires) || (grant.Owner == owner && grant.Device == device) {
			delete(a.enrollments, key)
		}
	}
}

func (a *App) enroll(w http.ResponseWriter, r *http.Request, u auth.User, id string) {
	a.sync(r.Context())
	d, err := a.DB.Get(u.ID, id)
	if err != nil {
		fail(w, 404, "设备不存在")
		return
	}
	if d.State != "active" || d.Expires <= time.Now().Unix() {
		fail(w, 409, "设备已解绑或已到期")
		return
	}
	if d.Platform != "ios" && d.Platform != "android" {
		fail(w, 409, "请先创建 iPhone / iPad 或 Android 设备配置")
		return
	}
	if !d.Applied || !a.last.Ready {
		fail(w, 503, "VPN 配置尚未生效，请稍后重试")
		return
	}
	a.clearEnrollments(u.ID, id)
	if len(a.enrollments) >= 1024 {
		fail(w, 429, "领取请求过多，请稍后重试")
		return
	}
	token := secure.Random(32)
	path := "/webman/3rdparty/SynoVPN/app.cgi"
	if a.Demo {
		path = "/"
	}
	link := a.C.Origin + path + "#enroll=" + token
	png, err := qrcode.Encode(link, qrcode.Medium, 280)
	if err != nil {
		fail(w, 500, "生成二维码失败")
		return
	}
	if err = a.DB.Audit(u.ID, "enroll-request", id); err != nil {
		fail(w, 500, "记录领取请求失败")
		return
	}
	expires := time.Now().Add(enrollmentLifetime)
	a.enrollments[sha256.Sum256([]byte(token))] = enrollment{u.ID, id, expires}
	reply(w, 201, map[string]any{"qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "url": link, "expires": expires.Unix()})
}

func (a *App) cancelEnrollment(w http.ResponseWriter, r *http.Request, u auth.User, id string) {
	if _, err := a.DB.Get(u.ID, id); err != nil {
		fail(w, 404, "设备不存在")
		return
	}
	if err := a.DB.Audit(u.ID, "enroll-cancel", id); err != nil {
		fail(w, 500, "记录取消失败")
		return
	}
	a.clearEnrollments(u.ID, id)
	reply(w, 200, map[string]bool{"canceled": true})
}

func enrollmentError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SynoVPN 配置领取</title><h1>暂时无法领取配置</h1><p>%s</p><p>请回到已登录 DSM 的电脑，重新生成此设备的二维码。</p></html>`, html.EscapeString(message))
}

func (a *App) claimEnrollment(w http.ResponseWriter, r *http.Request) {
	// The bearer capability authorizes just this download, never account access.
	if r.Method != "POST" {
		enrollmentError(w, 405, "请扫描二维码后点击领取按钮。")
		return
	}
	if r.Header.Get("Origin") != a.C.Origin {
		enrollmentError(w, 403, "领取页面来源不符，请重新扫码。")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		enrollmentError(w, 415, "领取请求格式不正确。")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err = r.ParseForm(); err != nil || len(r.PostForm["claim"]) != 1 {
		enrollmentError(w, 400, "领取请求无效。")
		return
	}
	token := r.PostForm.Get("claim")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || len(token) != 43 || strings.TrimSpace(token) != token {
		enrollmentError(w, 403, "二维码已失效。")
		return
	}
	key := sha256.Sum256([]byte(token))
	grant, ok := a.enrollments[key]
	// Consume before reading the private key, under the request-wide mutex.
	delete(a.enrollments, key)
	if !ok || !time.Now().Before(grant.Expires) {
		enrollmentError(w, 403, "二维码已过期、已领取或已作废。")
		return
	}
	f, code, err := a.deviceProfile(grant.Owner, grant.Device)
	if err != nil {
		enrollmentError(w, code, err.Error())
		return
	}
	if err = a.DB.Audit(grant.Owner, "phone-download", grant.Device); err != nil {
		enrollmentError(w, 500, "记录领取失败，请重新生成二维码。")
		return
	}
	writeProfile(w, f)
}
