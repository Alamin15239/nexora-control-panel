//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestListenSocketSetsRootBoundaryPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhost.sock")
	listener, err := listenSocket(path, os.Getgid())
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	info, err := os.Lstat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode()&os.ModeSocket == 0 { t.Fatalf("path is not a socket: %v", info.Mode()) }
	if got := info.Mode().Perm(); got != 0660 { t.Fatalf("socket mode = %04o, want 0660", got) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("socket stat lacks ownership metadata") }
	if stat.Uid != 0 || stat.Gid != uint32(os.Getgid()) {
		t.Fatalf("socket owner = %d:%d, want 0:%d", stat.Uid, stat.Gid, os.Getgid())
	}
}

func TestListenSocketRefusesExistingRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhost.sock")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil { t.Fatal(err) }
	if listener, err := listenSocket(path, os.Getgid()); err == nil {
		if listener != nil { _ = listener.Close() }
		t.Fatal("replaced an existing regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "preserve" { t.Fatalf("existing file changed: %q", data) }
}

func TestListenSocketRefusesExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "vhost.sock")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, path); err != nil { t.Fatal(err) }
	if listener, err := listenSocket(path, os.Getgid()); err == nil {
		if listener != nil { _ = listener.Close() }
		t.Fatal("replaced an existing symlink")
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("symlink changed: %q, %v", got, err)
	}
}

func TestListenSocketRefusesExistingUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhost.sock")
	original, err := net.ListenUnix("unix", &net.UnixAddr{Name:path, Net:"unix"})
	if err != nil { t.Fatal(err) }
	defer original.Close()
	if listener, err := listenSocket(path, os.Getgid()); err == nil {
		if listener != nil { _ = listener.Close() }
		t.Fatal("replaced an existing Unix socket")
	}
}
