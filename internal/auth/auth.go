package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

const CGIHeader = "X-Synovpn-Cgi-Environment"

var EnvKeys = []string{"HTTP_COOKIE", "REMOTE_ADDR", "REMOTE_PORT", "SERVER_ADDR", "SERVER_PORT", "SERVER_NAME", "SERVER_PROTOCOL", "REQUEST_METHOD", "REQUEST_URI", "QUERY_STRING", "SCRIPT_NAME", "HTTPS", "HTTP_HOST", "HTTP_X_SYNO_TOKEN"}

type User struct {
	ID    string `json:"-"`
	Name  string `json:"name"`
	Admin bool   `json:"is_admin"`
}
type Authenticator interface {
	Authenticate(*http.Request) (User, error)
}

func rejected(stage string, cause error) (User, error) {
	// Never log cookies, tokens, helper output or account names.
	if cause != nil {
		log.Printf("DSM authentication failed: stage=%s cause=%v", stage, cause)
	} else {
		log.Printf("DSM authentication failed: stage=%s", stage)
	}
	return User{}, ErrLogin
}

func normalizeEnvironment(env map[string]string) error {
	q, err := url.ParseQuery(env["QUERY_STRING"])
	if err != nil || len(q["SynoToken"]) > 1 {
		return ErrLogin
	}
	header, query := env["HTTP_X_SYNO_TOKEN"], q.Get("SynoToken")
	if header != "" && query != "" && header != query {
		return ErrLogin
	}
	token := header
	if token == "" {
		token = query
	}
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		return ErrLogin
	}
	env["HTTP_X_SYNO_TOKEN"] = token
	env["QUERY_STRING"] = url.Values{"SynoToken": []string{token}}.Encode()
	env["REQUEST_METHOD"] = "GET"
	return nil
}

type DSM struct {
	Path   string
	Groups []string
}

var ErrLogin = errors.New("请先登录 DSM，再从套件中心或主菜单打开 SynoVPN")

func (a DSM) Authenticate(r *http.Request) (User, error) {
	raw, e := base64.RawURLEncoding.DecodeString(r.Header.Get(CGIHeader))
	if e != nil || len(raw) > 32768 {
		return rejected("invalid_bridge_encoding", nil)
	}
	var env map[string]string
	if json.Unmarshal(raw, &env) != nil {
		return rejected("invalid_bridge_json", nil)
	}
	if env["HTTP_COOKIE"] == "" {
		return rejected("missing_cookie", nil)
	}
	if env["REMOTE_ADDR"] == "" {
		return rejected("missing_client_address", nil)
	}
	if normalizeEnvironment(env) != nil {
		return rejected("missing_or_conflicting_session_token", nil)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Path)
	cmd.Env = []string{"PATH=/usr/syno/bin:/usr/syno/sbin:/usr/bin:/usr/sbin:/bin:/sbin", "LANG=C", "GATEWAY_INTERFACE=CGI/1.1", "CONTENT_LENGTH=0"}
	for _, k := range EnvKeys {
		if v, ok := env[k]; ok {
			if strings.ContainsRune(v, 0) {
				return User{}, ErrLogin
			}
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	// No HTTP username, account query parameter or browser storage value is trusted.
	out, e := cmd.Output()
	if e != nil {
		return rejected("helper_execution", e)
	}
	if len(out) > 256 {
		return rejected("helper_output_length", nil)
	}
	name := strings.TrimSpace(string(out))
	if name == "" || name == "guest" || strings.ContainsAny(name, "\r\n\x00") {
		return rejected("helper_empty_or_invalid_identity", nil)
	}
	u, e := user.Lookup(name)
	if e != nil {
		return rejected("local_account_lookup", nil)
	}
	gids, e := u.GroupIds()
	if e != nil {
		return rejected("local_group_lookup", nil)
	}
	allowed := false
	for _, g := range a.Groups {
		entry, e := user.LookupGroup(g)
		if e != nil {
			continue
		}
		for _, gid := range gids {
			if gid == entry.Gid {
				allowed = true
			}
		}
	}
	if !allowed {
		return User{}, errors.New("当前 DSM 用户不在允许使用 VPN 的用户组中")
	}
	return User{ID: "dsm:" + u.Uid + ":" + u.Username, Name: u.Username, Admin: inGroup(gids, "administrators", user.LookupGroup)}, nil
}

type Demo struct{}

func (Demo) Authenticate(r *http.Request) (User, error) {
	return User{ID: "demo:1000", Name: "演示用户", Admin: true}, nil
}

// RequestOrigin uses only metadata captured by our native CGI bridge. Incoming
// copies of CGIHeader and forwarded-host/proto headers are stripped by bridge().
// The caller must authenticate the DSM session before using this for mutations.
func RequestOrigin(r *http.Request) string {
	raw, err := base64.RawURLEncoding.DecodeString(r.Header.Get(CGIHeader))
	if err != nil || len(raw) > 32768 {
		return ""
	}
	var env map[string]string
	if json.Unmarshal(raw, &env) != nil {
		return ""
	}
	host := env["HTTP_HOST"]
	if host == "" || strings.ContainsAny(host, "/\\?#@\r\n\x00 ") {
		return ""
	}
	scheme := "http"
	if env["HTTPS"] == "on" || env["HTTPS"] == "1" {
		scheme = "https"
	}
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" {
		return ""
	}
	// Browsers omit default ports from Origin.
	if (scheme == "http" && u.Port() == "80") || (scheme == "https" && u.Port() == "443") {
		host = u.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return scheme + "://" + strings.ToLower(host)
}

// Role membership is resolved on every authenticated request, never from a
// browser flag, username spelling, or a cached portal session.
func inGroup(gids []string, name string, lookup func(string) (*user.Group, error)) bool {
	group, err := lookup(name)
	if err != nil || group == nil || group.Gid == "" {
		return false
	}
	for _, gid := range gids {
		if gid == group.Gid {
			return true
		}
	}
	return false
}
