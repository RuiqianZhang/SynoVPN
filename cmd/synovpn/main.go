package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"synovpn/internal/auth"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/pki"
	"synovpn/internal/secure"
	"synovpn/internal/store"
	appweb "synovpn/internal/web"
)

func main() {
	if len(os.Args) == 1 && os.Getenv("GATEWAY_INTERFACE") != "" {
		if e := bridge(); e != nil {
			fmt.Print("Status: 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\nSynoVPN 服务尚未启动，请联系管理员。")
			os.Exit(1)
		}
		return
	}
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: synovpn init|run|web|demo")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch os.Args[1] {
	case "init":
		return initialize(os.Args[2:])
	case "run":
		f := flag.NewFlagSet("run", flag.ContinueOnError)
		path := f.String("config", config.Base+"/etc/config.json", "administrator configuration")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := config.Read(*path)
		if e != nil {
			return e
		}
		return supervise(ctx, c, *path)
	case "engine":
		return runContainerEngine(ctx, os.Args[2:])
	case "web":
		f := flag.NewFlagSet("web", flag.ContinueOnError)
		path := f.String("config", config.Base+"/etc/config.json", "configuration")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := config.Read(*path)
		if e != nil {
			return e
		}
		return serve(ctx, c, false, "")
	case "demo":
		f := flag.NewFlagSet("demo", flag.ContinueOnError)
		dir := f.String("data", "var/demo", "demo data")
		addr := f.String("listen", "127.0.0.1:8787", "loopback only")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		host, _, e := net.SplitHostPort(*addr)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("demo must bind to a literal loopback address")
		}
		absolute, e := filepath.Abs(*dir)
		if e != nil {
			return e
		}
		c := config.Default()
		c.Domain = "vpn.demo.invalid"
		c.Origin = "http://" + *addr
		c.DataDir = absolute
		c.PKIDir = filepath.Join(absolute, "pki")
		c.Routes = []string{"192.168.10.0/24"}
		c.DNS = []string{"192.168.10.1"}
		if e = os.MkdirAll(c.DataDir, 0700); e != nil {
			return e
		}
		if _, e = os.Stat(filepath.Join(c.DataDir, "ca.pem")); os.IsNotExist(e) {
			temp := filepath.Join(c.DataDir, "pki")
			if e = pki.Init(temp, c.Domain); e != nil {
				return e
			}
			b, e := os.ReadFile(filepath.Join(temp, "ca.pem"))
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(c.DataDir, "ca.pem"), b, 0600); e != nil {
				return e
			}
		}
		log.Printf("Demo only (no VPN): %s", c.Origin)
		return serve(ctx, c, true, *addr)
	default:
		return errors.New("unknown command")
	}
}

func initialize(args []string) error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	path := f.String("config", config.Base+"/etc/config.json", "configuration output")
	domain := f.String("domain", "", "public VPN DNS name")
	origin := f.String("origin", "", "exact HTTPS DSM origin")
	routes := f.String("routes", "", "comma-separated allowed IPv4 CIDRs")
	dns := f.String("dns", "", "comma-separated DNS IPv4 addresses")
	groups := f.String("groups", "users", "allowed DSM groups")
	pool := f.String("pool", "10.77.0.0/24", "VPN pool")
	forward := f.Bool("enable-forwarding", false, "allow enabling shared IPv4 forwarding (not restored on stop)")
	frontend := f.Bool("frontend-only", false, "initialize the unprivileged DSM portal")
	if e := f.Parse(args); e != nil {
		return e
	}
	if !*frontend && os.Geteuid() != 0 {
		return errors.New("init must be run by root on DSM")
	}
	if _, e := os.Stat(*path); e == nil {
		return errors.New("configuration exists; refusing to replace it")
	}
	c := config.Default()
	c.Domain = *domain
	c.Origin = strings.TrimSuffix(*origin, "/")
	c.Routes = split(*routes)
	c.DNS = split(*dns)
	c.AllowedGroups = split(*groups)
	c.Pool = *pool
	c.EnableForwarding = *forward
	if *frontend {
		c.EngineAddress = "127.0.0.1:18447"
	}
	if e := c.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(*path), 0755); e != nil {
		return e
	}
	if *frontend {
		if e := os.MkdirAll(config.Base+"/var", 0755); e != nil {
			return e
		}
		if _, e := secure.Key(config.Base + "/etc/engine.token"); e != nil {
			return e
		}
	} else {
		if e := pki.Init(c.PKIDir, c.Domain); e != nil {
			return e
		}
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return secure.Atomic(*path, b, 0644)
}
func split(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if x := strings.TrimSpace(v); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func serve(ctx context.Context, c config.Config, demo bool, addr string) error {
	if !demo && os.Geteuid() == 0 {
		return errors.New("web service must run as the package account, never root")
	}
	if e := os.MkdirAll(c.DataDir, 0700); e != nil {
		return e
	}
	db, e := store.Open(c.DataDir)
	if e != nil {
		return e
	}
	defer db.DB.Close()
	key, e := secure.Key(filepath.Join(c.DataDir, "key"))
	if e != nil {
		return e
	}
	var authenticator auth.Authenticator = auth.DSM{Path: c.AuthCGI, Groups: c.AllowedGroups}
	var vpn engine.Engine = engine.NewClient(filepath.Join(c.RunDir, "agent.sock"))
	if !demo && c.EngineAddress != "" {
		token, err := os.ReadFile(config.Base + "/etc/engine.token")
		if err != nil {
			return err
		}
		client, err := engine.NewLoopbackClient(c.EngineAddress, token)
		if err != nil {
			return err
		}
		var trust engine.Trust
		deadline := time.Now().Add(90 * time.Second)
		for {
			trust, err = client.Trust(ctx)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("container engine unavailable; inspect Container Manager logs")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		if err = secure.Atomic(filepath.Join(c.DataDir, "ca.pem"), trust.ServerCA, 0600); err != nil {
			return err
		}
		if err = secure.Atomic(filepath.Join(c.DataDir, "client-ca.pem"), trust.ClientCA, 0600); err != nil {
			return err
		}
		vpn = client
	}
	if demo {
		authenticator = auth.Demo{}
		authority, err := pki.OpenAuthority(c.PKIDir)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(c.DataDir, "client-ca.pem"), authority.CAPEM(), 0600); err != nil {
			return err
		}
		vpn = &engine.Demo{Authority: authority}
	}
	a := appweb.New(c, db, key, authenticator, vpn, demo)
	go a.Reconcile(ctx)
	var listener net.Listener
	if demo {
		listener, e = net.Listen("tcp", addr)
	} else {
		path := filepath.Join(c.RunDir, "web/web.sock")
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			return e
		}
		os.Remove(path)
		listener, e = net.Listen("unix", path)
		if e == nil {
			e = webSocketPermission(path)
		}
	}
	if e != nil {
		return e
	}
	defer listener.Close()
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32768}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	e = srv.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}

func bridge() error {
	// CGI inherits the real DSM request environment. Client-provided identity
	// headers are stripped. The daemon independently calls authenticate.cgi.
	env := map[string]string{}
	for _, k := range auth.EnvKeys {
		env[k] = os.Getenv(k)
	}
	raw, e := json.Marshal(env)
	if e != nil {
		return e
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", config.Base+"/var/run/web/web.sock")
	}}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(p *httputil.ProxyRequest) {
		route := p.In.URL.Query().Get("route")
		if route == "" {
			route = "/"
		}
		if !strings.HasPrefix(route, "/api/") && route != "/" {
			route = "/missing"
		}
		p.SetURL(&url.URL{Scheme: "http", Host: "synovpn"})
		p.Out.URL.Path = route
		p.Out.Header.Del(auth.CGIHeader)
		p.Out.Header.Set(auth.CGIHeader, base64.RawURLEncoding.EncodeToString(raw))
		p.Out.Header.Del("X-Forwarded-For")
		p.Out.Header.Del("X-Forwarded-Host")
		p.Out.Header.Del("X-Forwarded-Proto")
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":"SynoVPN 服务未启动，请联系管理员"}`)
	}}
	return cgi.Serve(proxy)
}
