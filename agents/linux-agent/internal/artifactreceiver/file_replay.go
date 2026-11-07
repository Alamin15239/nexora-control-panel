package artifactreceiver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var replayIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// FileReplayGuard persists consumed envelope identifiers using exclusive file
// creation. Its directory must be pre-created, private, and operator-owned.
type FileReplayGuard struct {
	Directory string
}

func (g FileReplayGuard) Consume(ctx context.Context, jti string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !replayIDPattern.MatchString(jti) || expiresAt.IsZero() {
		return errors.New("invalid deployment replay identifier or expiry")
	}
	if !filepath.IsAbs(g.Directory) {
		return errors.New("replay guard directory must be absolute")
	}
	info, err := os.Lstat(g.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("replay guard directory must be a real private directory")
	}
	path := filepath.Join(g.Directory, jti+".used")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("deployment authorization has already been consumed")
		}
		return fmt.Errorf("create deployment replay record: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("secure deployment replay record: %w", err)
	}
	if _, err := file.WriteString(strconv.FormatInt(expiresAt.UTC().Unix(), 10)+"\n"); err != nil {
		return fmt.Errorf("write deployment replay record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync deployment replay record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close deployment replay record: %w", err)
	}
	directory, err := os.Open(g.Directory)
	if err != nil { return fmt.Errorf("open replay guard directory: %w", err) }
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil { return fmt.Errorf("sync replay guard directory: %w", syncErr) }
	if closeErr != nil { return fmt.Errorf("close replay guard directory: %w", closeErr) }
	keep = true
	return nil
}

// PruneExpired removes only expired, regular replay records. It should be called
// periodically by the trusted node service, never from an untrusted workload.
func (g FileReplayGuard) PruneExpired(ctx context.Context, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if now.IsZero() || !filepath.IsAbs(g.Directory) {
		return 0, errors.New("replay pruning requires an absolute directory and explicit time")
	}
	info, err := os.Lstat(g.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return 0, errors.New("replay guard directory must be a real private directory")
	}
	entries, err := os.ReadDir(g.Directory)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".used") || !replayIDPattern.MatchString(strings.TrimSuffix(name, ".used")) {
			continue
		}
		path := filepath.Join(g.Directory, name)
		fileInfo, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) { continue }
			return removed, err
		}
		if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0077 != 0 {
			return removed, fmt.Errorf("replay record %q is not a private regular file", name)
		}
		data, err := os.ReadFile(path)
		if err != nil { return removed, err }
		expires, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil { return removed, fmt.Errorf("replay record %q is malformed", name) }
		if expires > now.Unix() { continue }
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
