//go:build linux

package staticvhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
)

var managedConfigName = regexp.MustCompile(`^nexora-static-[a-f0-9]{32}\.conf$`)

// CommandRunner is the narrow system boundary used by the installer.
type CommandRunner interface {
	Run(name string, args ...string) error
}

type execRunner struct{}
func (execRunner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Install atomically installs one renderer-produced vhost, validates the full
// Nginx configuration, then reloads Nginx. On failure it restores the previous
// file (or removes the new file) and makes a best-effort validation/reload of
// the restored configuration.
// InstallBinding is the only supported installation API. It accepts a validated
// domain/account binding and renders the vhost locally; callers cannot supply
// arbitrary Nginx directives or a filesystem filename.
func InstallBinding(configDir string, binding Binding, ownerUID uint32, runner CommandRunner) error {
	filename, err := ConfigName(binding.DomainID)
	if err != nil {
		return err
	}
	content, err := Render(binding)
	if err != nil {
		return err
	}
	return install(configDir, filename, content, ownerUID, runner)
}

func install(configDir, filename, content string, ownerUID uint32, runner CommandRunner) error {
	if runner == nil { return errors.New("Nginx command runner is required") }
	if uint32(os.Geteuid()) != ownerUID { return errors.New("installer effective UID does not match config ownership") }
	if !managedConfigName.MatchString(filename) { return errors.New("invalid managed Nginx config filename") }
	if len(content) == 0 || len(content) > 64<<10 || content[:min(len(content), len("# Managed by Nexora. Do not edit.\n"))] != "# Managed by Nexora. Do not edit.\n" {
		return errors.New("configuration is not a bounded Nexora-rendered vhost")
	}
	info, err := os.Lstat(configDir)
	if err != nil { return fmt.Errorf("inspect Nginx config directory: %w", err) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != ownerUID || info.Mode().Perm()&0022 != 0 {
		return errors.New("Nginx config directory failed ownership or permission checks")
	}
	unlock, err := acquireInstallLock(configDir, filename, ownerUID)
	if err != nil { return err }
	defer unlock()

	target := filepath.Join(configDir, filename)
	var previous []byte
	hadPrevious := false
	oldInfo, err := os.Lstat(target)
	if err == nil {
		oldStat, valid := oldInfo.Sys().(*syscall.Stat_t)
		if !valid || !oldInfo.Mode().IsRegular() || oldInfo.Mode()&os.ModeSymlink != 0 ||
			oldStat.Uid != ownerUID || oldInfo.Mode().Perm()&0022 != 0 || oldInfo.Size() > 64<<10 {
			return errors.New("existing managed Nginx config is not a trusted bounded regular file")
		}
		fd, openErr := syscall.Open(target, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return fmt.Errorf("open previous Nginx config safely: %w", openErr)
		}
		oldFile := os.NewFile(uintptr(fd), target)
		openedInfo, statErr := oldFile.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(oldInfo, openedInfo) ||
			openedInfo.Mode().Perm()&0022 != 0 || openedInfo.Size() > 64<<10 {
			_ = oldFile.Close()
			return errors.New("existing managed Nginx config changed during verification")
		}
		previous, err = io.ReadAll(io.LimitReader(oldFile, (64<<10)+1))
		closeErr := oldFile.Close()
		if err != nil || closeErr != nil || len(previous) > 64<<10 {
			return errors.New("existing managed Nginx config could not be read safely")
		}
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect previous Nginx config: %w", err)
	}

	restore := func() error {
		if hadPrevious {
			return atomicWrite(configDir, filename, previous, ownerUID)
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) { return err }
		return syncDirectory(configDir)
	}
	if err := atomicWrite(configDir, filename, []byte(content), ownerUID); err != nil { return err }
	if err := runner.Run("/usr/sbin/nginx", "-t"); err != nil {
		restoreErr := restore()
		if restoreErr != nil { return fmt.Errorf("Nginx validation failed: %v; restoring previous config failed: %w", err, restoreErr) }
		return fmt.Errorf("Nginx configuration validation failed; previous config restored: %w", err)
	}
	if err := runner.Run("/usr/bin/systemctl", "reload", "nginx"); err != nil {
		restoreErr := restore()
		if restoreErr != nil {
			return fmt.Errorf("Nginx reload failed: %v; restoring previous config failed: %w", err, restoreErr)
		}
		_ = runner.Run("/usr/sbin/nginx", "-t")
		_ = runner.Run("/usr/bin/systemctl", "reload", "nginx")
		return fmt.Errorf("Nginx reload failed; previous config restored: %w", err)
	}
	return nil
}

func acquireInstallLock(dir, filename string, ownerUID uint32) (func(), error) {
	path := filepath.Join(dir, "."+filename+".lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil { return nil, fmt.Errorf("open Nginx install lock: %w", err) }
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect Nginx install lock: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != ownerUID || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("Nginx install lock failed ownership or permission checks")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil { file.Close(); return nil, fmt.Errorf("lock Nginx install: %w", err) }
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}

func atomicWrite(dir, filename string, data []byte, ownerUID uint32) error {
	tmp, err := os.CreateTemp(dir, ".nexora-static-*.tmp")
	if err != nil { return fmt.Errorf("create staged Nginx config: %w", err) }
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0644); err != nil { tmp.Close(); return err }
	if _, err := tmp.Write(data); err != nil { tmp.Close(); return err }
	if err := tmp.Sync(); err != nil { tmp.Close(); return err }
	if err := tmp.Close(); err != nil { return err }
	if err := os.Rename(tmpPath, filepath.Join(dir, filename)); err != nil { return fmt.Errorf("atomically publish Nginx config: %w", err) }
	return syncDirectory(dir)
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil { return err }
	defer dir.Close()
	return dir.Sync()
}

// InstallAsRoot is the production entry point. The caller must authenticate
// the IPC peer and resolve binding from a root-owned account/domain registry.
// It deliberately accepts no raw Nginx text or caller-selected filename.
func InstallAsRoot(configDir string, binding Binding) error {
	if os.Geteuid() != 0 {
		return errors.New("static vhost installation requires root")
	}
	return InstallBinding(configDir, binding, 0, execRunner{})
}
