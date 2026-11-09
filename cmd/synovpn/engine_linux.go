//go:build linux

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/network"
	"synovpn/internal/pki"
	"synovpn/internal/secure"
	"syscall"
	"time"
)

const engineHome = "/var/lib/synovpn-engine"

// Bootstrap inputs are read-only. Private state lives in a named volume, never
// in a writable NAS bind mount. Configuration and token are pinned at first boot.
func runContainerEngine(parent context.Context, args []string) error {
	f := flag.NewFlagSet("engine", flag.ContinueOnError)
	source := f.String("config", "/bootstrap/config.json", "bootstrap config")
	tokenFile := f.String("token-file", "/bootstrap/engine.token", "bootstrap token")
	if err := f.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || os.Getenv("SYNOVPN_ENGINE_CONTAINER") != "1" {
		return fmt.Errorf("engine requires root inside managed container: uid=%d marker=%q", os.Geteuid(), os.Getenv("SYNOVPN_ENGINE_CONTAINER"))
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if err := os.MkdirAll(engineHome, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(engineHome+"/engine.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("engine already running")
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	if len(token) != 32 {
		return errors.New("invalid bootstrap token")
	}
	pinnedToken := engineHome + "/engine.token"
	existing, err := os.ReadFile(pinnedToken)
	if err == nil {
		if subtle.ConstantTimeCompare(token, existing) != 1 {
			return errors.New("bootstrap token changed; explicit administrator recovery required")
		}
	} else if os.IsNotExist(err) {
		if _, err = os.Stat(engineHome + "/pki/client-ca.pem"); err == nil {
			return errors.New("authority exists without token; refusing reset")
		}
		if err = secure.Atomic(pinnedToken, token, 0600); err != nil {
			return err
		}
	} else {
		return err
	}
	pinnedConfig := engineHome + "/config.json"
	c, err := config.Read(pinnedConfig)
	if os.IsNotExist(err) {
		c, err = config.Read(*source)
		if err != nil {
			return err
		}
		if c.EngineAddress != "127.0.0.1:18447" {
			return errors.New("invalid frontend configuration")
		}
		c.PKIDir = engineHome + "/pki"
		c.RunDir = engineHome + "/run"
		c.DataDir = engineHome + "/unused"
		c.VICI = c.RunDir + "/charon.vici"
		b, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		if err = secure.Atomic(pinnedConfig, b, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if c.PKIDir != engineHome+"/pki" || c.RunDir != engineHome+"/run" || c.VICI != engineHome+"/run/charon.vici" {
		return errors.New("invalid pinned paths")
	}
	for _, path := range []string{c.RunDir, config.Base + "/var/run"} {
		if err = os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	if _, err = os.Stat(filepath.Join(c.PKIDir, "ca.pem")); os.IsNotExist(err) {
		if err = pki.Init(c.PKIDir, c.Domain); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	authority, err := pki.OpenAuthority(c.PKIDir)
	if err != nil {
		return err
	}
	if raw, e := os.ReadFile(filepath.Join(c.PKIDir, "public-routes.json")); e == nil {
		if e = json.Unmarshal(raw, &c.PublicRoutes); e != nil {
			return e
		}
		c.PublicRoutes, e = config.NormalizePublicRoutes(c.PublicRoutes)
		if e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if err = network.Preflight(c); err != nil {
		return err
	}
	charonConfig := engineHome + "/strongswan.conf"
	if err = writeCharonConfig(charonConfig, c); err != nil {
		return err
	}
	charon := exec.Command("/opt/synovpn/charon")
	charon.Env = []string{"PATH=/sbin:/usr/sbin:/usr/bin:/bin", "STRONGSWAN_CONF=" + charonConfig}
	charon.Stdout = os.Stdout
	charon.Stderr = os.Stderr
	charon.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = charon.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- charon.Wait() }()
	daemonExited := false
	var cleanupFirewall func()
	defer func() {
		// Let charon remove its kernel SAs before removing package firewall rules.
		if !daemonExited {
			charon.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				charon.Process.Kill()
				<-done
			}
		}
		if cleanupFirewall != nil {
			cleanupFirewall()
		}
	}()
	control := engine.VICI{Path: c.VICI}
	ready := false
	for i := 0; i < 100; i++ {
		test, stop := context.WithTimeout(ctx, time.Second)
		_, err = control.Call(test, "version", nil)
		stop()
		if err == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return errors.New("charon VICI startup failed")
	}
	if err = os.Chmod(c.VICI, 0600); err != nil {
		return err
	}
	routeFailure := make(chan error, 1)
	gateway := &engine.Gateway{C: c, Control: control, Authority: authority,
		ApplyRouteFirewall: func(next config.Config) error { return (network.Firewall{Config: next}).Update() },
		ApplyDeviceFirewall: func(next config.Config, devices []engine.Device) error {
			return (network.Firewall{Config: next, Devices: devices}).Update()
		},
		OnRouteFailure: func(e error) {
			select {
			case routeFailure <- e:
			default:
			}
		},
	}
	initCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	err = gateway.Initialize(initCtx)
	stop()
	if err != nil {
		return err
	}
	firewall := network.Firewall{Config: c, Devices: []engine.Device{}}
	if err = firewall.Start(); err != nil {
		firewall.Stop()
		return err
	}
	cleanupFirewall = firewall.Stop
	ca, err := os.ReadFile(filepath.Join(c.PKIDir, "ca.pem"))
	if err != nil {
		return err
	}
	handler, err := engine.ProtectedAgent(gateway, token, engine.Trust{ServerCA: ca, ClientCA: authority.CAPEM()})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:18447")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 25 * time.Second, MaxHeaderBytes: 4096}
	defer server.Close()
	failure := make(chan error, 2)
	go func() { failure <- server.Serve(listener) }()
	go gateway.Maintain(ctx, func(e error) { failure <- e })
	select {
	case <-ctx.Done():
		return nil
	case err = <-done:
		daemonExited = true
		if err == nil {
			err = errors.New("charon stopped unexpectedly")
		}
		return err
	case err = <-failure:
		return err
	case err = <-routeFailure:
		return err
	}
}
