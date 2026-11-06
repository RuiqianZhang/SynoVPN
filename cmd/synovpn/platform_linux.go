//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"synovpn/internal/config"
	"synovpn/internal/engine"
	"synovpn/internal/network"
	"synovpn/internal/pki"
	"synovpn/internal/secure"
	"syscall"
	"time"
)

func webSocketPermission(path string) error {
	if os.Geteuid() != 0 {
		// CGI runs as DSM http, while authentication remains in the native web
		// process. No engine token or private CA is reachable through this socket.
		return os.Chmod(path, 0666)
	}
	g, e := user.LookupGroup("http")
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(g.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown(path, -1, gid); e != nil {
		return e
	}
	return os.Chmod(path, 0660)
}
func supervise(parent context.Context, c config.Config, configPath string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if os.Geteuid() != 0 {
		return errors.New("package supervisor requires root")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	info, e := os.Stat(configPath)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("configuration must be root-owned and not group/world writable")
	}
	u, e := user.Lookup(c.ServiceUser)
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 {
		return errors.New("package user must not be root")
	}
	httpGroup, e := user.LookupGroup("http")
	if e != nil {
		return e
	}
	httpGID, _ := strconv.Atoi(httpGroup.Gid)
	for _, d := range []string{c.DataDir, c.RunDir} {
		if e = os.MkdirAll(d, 0755); e != nil {
			return e
		}
	}
	if e = os.Chown(c.DataDir, uid, gid); e != nil {
		return e
	}
	if e = os.Chmod(c.DataDir, 0700); e != nil {
		return e
	}
	// Root sockets must not be replaceable by the web account. Only the web
	// listener subdirectory is writable by that account.
	if e = os.Chown(c.RunDir, 0, 0); e != nil {
		return e
	}
	if e = os.Chmod(c.RunDir, 0755); e != nil {
		return e
	}
	webDir := filepath.Join(c.RunDir, "web")
	if e = os.MkdirAll(webDir, 0750); e != nil {
		return e
	}
	if e = os.Chown(webDir, uid, httpGID); e != nil {
		return e
	}
	if e = os.Chmod(webDir, 0750); e != nil {
		return e
	}
	authority, e := pki.OpenAuthority(c.PKIDir)
	if e != nil {
		return e
	}
	clientCAPath := filepath.Join(c.DataDir, "client-ca.pem")
	if e = secure.AtomicOwned(clientCAPath, authority.CAPEM(), 0600, uid, gid); e != nil {
		return e
	}
	ca, e := os.ReadFile(filepath.Join(c.PKIDir, "ca.pem"))
	if e != nil {
		return e
	}
	caPath := filepath.Join(c.DataDir, "ca.pem")
	if e = secure.AtomicOwned(caPath, ca, 0600, uid, gid); e != nil {
		return e
	}
	pidLock, e := os.OpenFile(filepath.Join(c.RunDir, "supervisor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer pidLock.Close()
	if e = syscall.Flock(int(pidLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("supervisor already running")
	}
	if e = network.Preflight(c); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	charonPath := filepath.Join(config.Base, "target/runtime/charon")
	if _, e = os.Stat(charonPath); e != nil {
		return errors.New("bundled strongSwan runtime missing; build the SPK with tools/build.py")
	}
	strongConfig := filepath.Join(config.Base, "etc/strongswan.conf")
	if e = writeCharonConfig(strongConfig, c); e != nil {
		return e
	}
	charon := exec.CommandContext(ctx, charonPath)
	charon.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STRONGSWAN_CONF=" + strongConfig}
	charon.Stdout = os.Stdout
	charon.Stderr = os.Stderr
	charon.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if e = charon.Start(); e != nil {
		return e
	}
	defer func() { charon.Process.Kill(); charon.Wait() }()
	control := engine.VICI{Path: c.VICI}
	var ready bool
	for i := 0; i < 100; i++ {
		cc, stop := context.WithTimeout(ctx, time.Second)
		_, e = control.Call(cc, "version", nil)
		stop()
		if e == nil {
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
		return errors.New("strongSwan failed to expose VICI; inspect package logs")
	}
	if e = os.Chmod(c.VICI, 0600); e != nil {
		return e
	}
	gateway := &engine.Gateway{C: c, Control: control, Authority: authority}
	cc, stop := context.WithTimeout(ctx, 10*time.Second)
	e = gateway.Initialize(cc)
	stop()
	if e != nil {
		return e
	}
	firewall := network.Firewall{Config: c}
	if e = firewall.Start(); e != nil {
		firewall.Stop()
		return e
	}
	defer firewall.Stop()
	sock := filepath.Join(c.RunDir, "agent.sock")
	os.Remove(sock)
	listener, e := net.Listen("unix", sock)
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chown(sock, uid, gid); e != nil {
		return e
	}
	if e = os.Chmod(sock, 0600); e != nil {
		return e
	}
	agent := &http.Server{Handler: engine.AgentHandler(gateway), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 25 * time.Second, MaxHeaderBytes: 4096}
	defer agent.Close()
	failure := make(chan error, 3)
	go func() { failure <- agent.Serve(listener) }()
	go gateway.Maintain(ctx, func(e error) { failure <- e })
	web := exec.CommandContext(ctx, exe, "web", "--config", configPath)
	web.Env = []string{"PATH=/usr/syno/bin:/usr/bin:/bin", "HOME=" + c.DataDir}
	web.Stdout = os.Stdout
	web.Stderr = os.Stderr
	web.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid), uint32(httpGID)}}, Pdeathsig: syscall.SIGKILL}
	if e = web.Start(); e != nil {
		return e
	}
	defer web.Process.Kill()
	go func() { failure <- web.Wait() }()
	// If charon exits unexpectedly, VICI maintenance fails within a bounded time.
	select {
	case <-ctx.Done():
		return nil
	case e = <-failure:
		if e == nil {
			e = errors.New("a package component stopped unexpectedly")
		}
		cancel()
		return e
	}
}
func writeCharonConfig(path string, c config.Config) error {
	v := fmt.Sprintf(`charon {
 threads = 16
 load_modular = no
 load = random nonce openssl sha1 sha2 aes hmac x509 revocation constraints pubkey pkcs1 pkcs8 pem kernel-netlink socket-default vici
 pid_file = %s/charon.pid
 plugins {
  vici { socket = unix://%s }
  kernel-netlink { install_routes = yes }
 }
 filelog {
  stderr { default = 1 }
 }
}
`, c.RunDir, c.VICI)
	return os.WriteFile(path, []byte(v), 0600)
}
