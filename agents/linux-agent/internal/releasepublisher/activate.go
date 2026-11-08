// Package releasepublisher atomically activates immutable, pre-staged releases.
// It never executes customer code. Callers must ensure baseDir and its parents
// are operator-owned and not writable by untrusted local users.
package releasepublisher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateBase(baseDir string) error {
	if !filepath.IsAbs(baseDir) {
		return errors.New("release base directory must be absolute")
	}
	info, err := os.Lstat(baseDir)
	if err != nil {
		return fmt.Errorf("inspect release base directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("release base directory must be a real, non-group/world-writable directory")
	}
	return nil
}

func validateName(name string) error {
	if !releaseIDPattern.MatchString(name) || name == "." || name == ".." {
		return errors.New("release identifier is invalid")
	}
	return nil
}

// Publish moves a private staging directory into the immutable releases
// directory, then atomically switches the active symlink. Staging and releases
// must be on the same filesystem. Existing release identifiers are never
// overwritten. If activation fails, the immutable release remains stored but inactive.
func Publish(baseDir, stagingID, releaseID string) error {
	if err := validateBase(baseDir); err != nil { return err }
	if err := validateName(stagingID); err != nil { return fmt.Errorf("invalid staging identifier: %w", err) }
	if err := validateName(releaseID); err != nil { return err }

	stagingRoot := filepath.Join(baseDir, "staging")
	releasesRoot := filepath.Join(baseDir, "releases")
	if err := validateChildDirectory(stagingRoot); err != nil { return err }
	if err := validateChildDirectory(releasesRoot); err != nil { return err }

	stage := filepath.Join(stagingRoot, stagingID)
	stageInfo, err := os.Lstat(stage)
	if err != nil { return fmt.Errorf("inspect staging release: %w", err) }
	if !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 || stageInfo.Mode().Perm()&0022 != 0 {
		return errors.New("staging release must be a private, real directory")
	}
	target := filepath.Join(releasesRoot, releaseID)
	if _, err := os.Lstat(target); err == nil {
		return errors.New("release identifier already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect release destination: %w", err)
	}
	if err := os.Rename(stage, target); err != nil {
		return fmt.Errorf("move staged release into immutable store: %w", err)
	}
	if err := syncDirectory(releasesRoot); err != nil {
		return fmt.Errorf("sync release store: %w", err)
	}
	if err := Activate(baseDir, releaseID); err != nil {
		return fmt.Errorf("release stored but activation failed: %w", err)
	}
	return nil
}

// Activate atomically changes baseDir/current to point at an existing release.
// All activations are serialized with an advisory lock so a rollback compare-and-switch
// cannot race another deployment activation.
func Activate(baseDir, releaseID string) error {
	if err := validateBase(baseDir); err != nil { return err }
	if err := validateName(releaseID); err != nil { return err }
	unlock, err := acquireActivationLock(baseDir)
	if err != nil { return err }
	defer unlock()
	return activateLocked(baseDir, releaseID)
}

// Rollback switches from failedReleaseID to previousReleaseID only if the failed
// release is still active. A retry after a successful rollback is idempotent;
// a newer deployment or unexpected active target is never overwritten.
func Rollback(baseDir, failedReleaseID, previousReleaseID string) error {
	if err := validateBase(baseDir); err != nil { return err }
	if err := validateName(failedReleaseID); err != nil { return fmt.Errorf("invalid failed release: %w", err) }
	if err := validateName(previousReleaseID); err != nil { return fmt.Errorf("invalid previous release: %w", err) }
	if failedReleaseID == previousReleaseID {
		return errors.New("failed and previous release identifiers must differ")
	}
	unlock, err := acquireActivationLock(baseDir)
	if err != nil { return err }
	defer unlock()

	if err := validateReleaseDirectory(baseDir, previousReleaseID); err != nil {
		return fmt.Errorf("previous rollback target is not safe: %w", err)
	}
	active := filepath.Join(baseDir, "current")
	currentTarget, err := os.Readlink(active)
	if err != nil {
		return fmt.Errorf("read active release before rollback: %w", err)
	}
	previousTarget := filepath.Join("releases", previousReleaseID)
	if currentTarget == previousTarget {
		return nil
	}
	failedTarget := filepath.Join("releases", failedReleaseID)
	if currentTarget != failedTarget {
		return errors.New("refusing stale rollback because the failed release is no longer active")
	}
	return activateLocked(baseDir, previousReleaseID)
}

func acquireActivationLock(baseDir string) (func(), error) {
	lockPath := filepath.Join(baseDir, ".activation.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("activation lock must be a private regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect activation lock: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil { return nil, fmt.Errorf("open activation lock: %w", err) }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("activation lock is not a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock release activation: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func activateLocked(baseDir, releaseID string) error {
	if err := validateBase(baseDir); err != nil { return err }
	if err := validateName(releaseID); err != nil { return err }
	releasesRoot := filepath.Join(baseDir, "releases")
	if err := validateChildDirectory(releasesRoot); err != nil { return err }
	if err := validateReleaseDirectory(baseDir, releaseID); err != nil { return err }

	active := filepath.Join(baseDir, "current")
	if currentInfo, statErr := os.Lstat(active); statErr == nil {
		if currentInfo.Mode()&os.ModeSymlink == 0 {
			return errors.New("active release path exists and is not a symlink")
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect active release link: %w", statErr)
	}

	tmp := filepath.Join(baseDir, ".current-"+releaseID)
	if _, err := os.Lstat(tmp); err == nil {
		return errors.New("temporary activation path already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect temporary activation path: %w", err)
	}
	if err := os.Symlink(filepath.Join("releases", releaseID), tmp); err != nil {
		return fmt.Errorf("create temporary active link: %w", err)
	}
	if err := os.Rename(tmp, active); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomically switch active release: %w", err)
	}
	if err := syncDirectory(baseDir); err != nil {
		return fmt.Errorf("sync active release directory: %w", err)
	}
	return nil
}

func validateReleaseDirectory(baseDir, releaseID string) error {
	releasePath := filepath.Join(baseDir, "releases", releaseID)
	info, err := os.Lstat(releasePath)
	if err != nil { return fmt.Errorf("inspect target release: %w", err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("target release must be a real directory not writable by group or others")
	}
	return nil
}

func validateChildDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil { return fmt.Errorf("inspect managed directory %q: %w", filepath.Base(path), err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("managed directory %q must be real and not group/world writable", filepath.Base(path))
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil { return err }
	defer dir.Close()
	return dir.Sync()
}

// IsReleaseID reports whether value is a valid opaque release identifier.
func IsReleaseID(value string) bool {
	return releaseIDPattern.MatchString(value) && !strings.Contains(value, string(filepath.Separator))
}
