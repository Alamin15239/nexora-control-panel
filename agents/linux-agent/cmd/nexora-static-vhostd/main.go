//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/staticvhost"
)

const (
	socketPath = "/run/nexora-static-vhost/vhost.sock"
	configDir = "/etc/nginx/conf.d"
	publisherUser = "nexora-runtime"
)

func main() {
	flag.Parse()
	if os.Geteuid() != 0 {
		fatal("nexora-static-vhostd must run as root")
	}
	publisher, err := user.Lookup(publisherUser)
	if err != nil { fatal("cannot resolve publisher account: %v", err) }
	uid, err := strconv.ParseUint(publisher.Uid, 10, 32)
	if err != nil { fatal("invalid publisher UID: %v", err) }
	trust, err := staticvhost.LoadRootBrokerTrust()
	if err != nil {
		fatal("deployment-envelope trust configuration is unavailable: %v", err)
	}
	if err := os.MkdirAll("/run/nexora-static-vhost", 0750); err != nil {
		fatal("create broker runtime directory: %v", err)
	}
	runtimeInfo, err := os.Lstat("/run/nexora-static-vhost")
	if err != nil {
		fatal("inspect broker runtime directory: %v", err)
	}
	runtimeStat, ok := runtimeInfo.Sys().(*syscall.Stat_t)
	if !ok || !runtimeInfo.IsDir() || runtimeInfo.Mode()&os.ModeSymlink != 0 ||
		runtimeStat.Uid != 0 || runtimeStat.Gid != uint32(syscall.Getegid()) || runtimeInfo.Mode().Perm()&0022 != 0 {
		fatal("broker runtime directory is not a trusted root-owned directory")
	}
	if err := os.Chmod("/run/nexora-static-vhost", 0750); err != nil {
		fatal("set broker runtime directory mode: %v", err)
	}
	listener, err := listenSocket(socketPath)
	if err != nil { fatal("configure broker socket: %v", err) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := staticvhost.Serve(ctx, listener, uint32(uid), configDir, trust); err != nil {
		fatal("static vhost broker stopped: %v", err)
	}
}

func listenSocket(path string) (*net.UnixListener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("socket path already exists; refusing to replace it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name:path, Net:"unix"})
	if err != nil { return nil, err }
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket mode: %w", err)
	}
	return listener, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
