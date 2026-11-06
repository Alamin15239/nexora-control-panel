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

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/provisionipc"
)

const (
	socketPath = "/run/nexora/provision.sock"
	helperPath = "/usr/local/libexec/nexora-provision"
	agentUser  = "nexora-agent"
)

func main() {
	flag.Parse()
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "nexora-provisiond must run as root")
		os.Exit(1)
	}
	agent, err := user.Lookup(agentUser)
	if err != nil {
		fatal("cannot resolve agent account: %v", err)
	}
	uid, err := strconv.ParseUint(agent.Uid, 10, 32)
	if err != nil {
		fatal("invalid agent UID: %v", err)
	}
	gid, err := strconv.ParseUint(agent.Gid, 10, 32)
	if err != nil {
		fatal("invalid agent GID: %v", err)
	}
	if err := validateHelper(helperPath); err != nil {
		fatal("unsafe provisioning helper: %v", err)
	}
	if err := os.MkdirAll("/run/nexora", 0755); err != nil {
		fatal("create runtime directory: %v", err)
	}
	if err := os.Chown("/run/nexora", 0, int(gid)); err != nil {
		fatal("set runtime directory ownership: %v", err)
	}
	if err := os.Chmod("/run/nexora", 0750); err != nil {
		fatal("set runtime directory mode: %v", err)
	}
	listener, err := listenProvisionSocket(socketPath, 0, int(gid))
	if err != nil {
		fatal("configure provisioning socket: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := provisionipc.Server{AllowedUID: uint32(uid), HelperPath: helperPath}
	if err := server.Serve(ctx, listener); err != nil {
		fatal("provisioning IPC server stopped: %v", err)
	}
}

func listenProvisionSocket(path string, ownerUID, ownerGID int) (*net.UnixListener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("socket path already exists; refusing to replace it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on provisioning socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chown(path, ownerUID, ownerGID); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket ownership: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return listener, nil
}

func validateHelper(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("helper must be a regular file, not a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("helper must be owned by root")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("helper must not be group- or world-writable")
	}
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
