package artifactreceiver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileReplayGuardPersistsAndRejectsDuplicateJTI(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(directory, 0700); err != nil { t.Fatal(err) }
	guard := FileReplayGuard{Directory: directory}
	expires := time.Date(2026, 11, 7, 10, 5, 0, 0, time.UTC)
	if err := guard.Consume(context.Background(), "0123456789abcdef0123456789abcdef", expires); err != nil {
		t.Fatal(err)
	}
	if err := guard.Consume(context.Background(), "0123456789abcdef0123456789abcdef", expires); err == nil {
		t.Fatal("expected duplicate JTI rejection")
	}
	info, err := os.Stat(filepath.Join(directory, "0123456789abcdef0123456789abcdef.used"))
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("replay record permissions: %o", info.Mode().Perm()) }
}

func TestFileReplayGuardPrunesOnlyExpiredRecords(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(directory, 0700); err != nil { t.Fatal(err) }
	guard := FileReplayGuard{Directory: directory}
	expiredID := "11111111111111111111111111111111"
	activeID := "22222222222222222222222222222222"
	if err := guard.Consume(context.Background(), expiredID, time.Unix(100, 0)); err != nil { t.Fatal(err) }
	if err := guard.Consume(context.Background(), activeID, time.Unix(300, 0)); err != nil { t.Fatal(err) }
	removed, err := guard.PruneExpired(context.Background(), time.Unix(200, 0))
	if err != nil { t.Fatal(err) }
	if removed != 1 { t.Fatalf("expected one expired record removed, got %d", removed) }
	if _, err := os.Stat(filepath.Join(directory, expiredID+".used")); !os.IsNotExist(err) {
		t.Fatal("expired replay record was not removed")
	}
	if _, err := os.Stat(filepath.Join(directory, activeID+".used")); err != nil {
		t.Fatal("active replay record was removed")
	}
}

func TestFileReplayGuardRejectsUnsafeDirectoryAndIdentifier(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(directory, 0755); err != nil { t.Fatal(err) }
	guard := FileReplayGuard{Directory: directory}
	if err := guard.Consume(context.Background(), "0123456789abcdef0123456789abcdef", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("expected non-private replay directory rejection")
	}
	if err := os.Chmod(directory, 0700); err != nil { t.Fatal(err) }
	if err := guard.Consume(context.Background(), "../outside", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("expected invalid JTI rejection")
	}
}
