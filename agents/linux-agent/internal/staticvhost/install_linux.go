//go:build linux

package staticvhost

import (
	"errors"
	"fmt"
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
func Install(configDir, filename, content string, ownerUID uint32, runner CommandRunner) error {
	if runner == nil { return errors.New("Nginx command runner is required") }
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
	target := filepath.Join(configDir, filename)
	var previous []byte
	hadPrevious := false
	oldInfo, err := os.Lstat(target)
	if err == nil {
		oldStat, valid := oldInfo.Sys().(*syscall.Stat_t)
		if !valid || !oldInfo.Mode().IsRegular() || oldInfo.Mode()&os.ModeSymlink != 0 || oldStat.Uid != ownerUID {
			return errors.New("existing managed Nginx config is not a trusted regular file")
		}
		previous, err = os.ReadFile(target)
		if err != nil { return fmt.Errorf("read previous Nginx config: %w", err) }
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
		restore()
		return fmt.Errorf("Nginx configuration validation failed: %w", err)
	}
	if err := runner.Run("/usr/bin/systemctl", "reload", "nginx"); err != nil {
		restoreErr := restore()
		_ = runner.Run("/usr/sbin/nginx", "-t")
		_ = runner.Run("/usr/bin/systemctl", "reload", "nginx")
		if restoreErr != nil { return fmt.Errorf("Nginx reload failed: %v; restoring previous config failed: %w", err, restoreErr) }
		return fmt.Errorf("Nginx reload failed; previous config restored: %w", err)
	}
	return nil
}

func atomicWrite(dir, filename string, data []byte, ownerUID uint32) error {
	tmp, err := os.CreateTemp(dir, ".nexora-static-*.tmp")
	if err != nil { return fmt.Errorf("create staged Nginx config: %w", err) }
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0644); err != nil { tmp.Close(); return err }
	if err := tmp.Chown(int(ownerUID), 0); err != nil { tmp.Close(); return err }
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

// InstallAsRoot is the production entry point; callers must separately
// authenticate the IPC peer and resolve the binding from the root-owned registry.
func InstallAsRoot(configDir, filename, content string) error {
	if os.Geteuid() != 0 { return errors.New("static vhost installation requires root") }
	return Install(configDir, filename, content, 0, execRunner{})
}
