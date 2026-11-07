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
// It is also the rollback primitive: pass the previously active release ID.
func Activate(baseDir, releaseID string) error {
	if err := validateBase(baseDir); err != nil { return err }
	if err := validateName(releaseID); err != nil { return err }
	releasesRoot := filepath.Join(baseDir, "releases")
	if err := validateChildDirectory(releasesRoot); err != nil { return err }
	releasePath := filepath.Join(releasesRoot, releaseID)
	info, err := os.Lstat(releasePath)
	if err != nil { return fmt.Errorf("inspect target release: %w", err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("target release must be a real directory not writable by group or others")
	}

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
