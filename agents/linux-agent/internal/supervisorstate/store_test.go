package supervisorstate

import (
	"os"
	"fmt"
	"sync"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
	store, err := Open(filepath.Join(dir, "runtime.json"))
	if err != nil { t.Fatal(err) }
	return store, dir
}

func sample() WorkloadState {
	return WorkloadState{
		WorkloadID: "workload-001",
		ReleaseID: "release-001",
		ContainerID: "0123456789abcdef0123456789abcdef",
		State: "running",
	}
}

func TestStoreUpsertLoadAndDelete(t *testing.T) {
	store, dir := newStore(t)
	if err := store.Upsert(sample()); err != nil { t.Fatal(err) }
	items, err := store.Load()
	if err != nil { t.Fatal(err) }
	if len(items) != 1 || items[0].WorkloadID != "workload-001" || items[0].State != "running" {
		t.Fatalf("unexpected state snapshot: %+v", items)
	}
	info, err := os.Stat(filepath.Join(dir, "runtime.json"))
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("state file mode = %o, want 600", info.Mode().Perm()) }
	if err := store.Delete("workload-001"); err != nil { t.Fatal(err) }
	items, err = store.Load()
	if err != nil { t.Fatal(err) }
	if len(items) != 0 { t.Fatalf("expected empty state after delete: %+v", items) }
}

func TestStoreRejectsInvalidStateAndIdentifiers(t *testing.T) {
	store, _ := newStore(t)
	item := sample()
	item.ContainerID = "../../etc/passwd"
	if err := store.Upsert(item); err == nil { t.Fatal("invalid container ID accepted") }
	item = sample()
	item.State = "unknown"
	if err := store.Upsert(item); err == nil { t.Fatal("unknown state accepted") }
	if err := store.Delete("../escape"); err == nil { t.Fatal("invalid workload ID accepted") }
}

func TestOpenRejectsUnsafeDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	if err := os.Chmod(dir, 0755); err != nil { t.Fatal(err) }
	if _, err := Open(filepath.Join(dir, "runtime.json")); err == nil {
		t.Fatal("group/world-accessible state directory accepted")
	}
}

func TestOpenRejectsSymlinkStateFile(t *testing.T) {
	store, dir := newStore(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, filepath.Join(dir, "runtime.json")); err != nil { t.Fatal(err) }
	if _, err := store.Load(); err == nil { t.Fatal("symlink state file accepted") }
}

func TestOpenRejectsMalformedOrUnknownJSON(t *testing.T) {
	_, dir := newStore(t)
	path := filepath.Join(dir, "runtime.json")
	for _, raw := range []string{
		`{"version":99,"workloads":{}}`,
		`{"version":1,"workloads":{},"unexpected":"value"}`,
		`{"version":1,"workloads":{}} { }`,
	} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil { t.Fatal(err) }
		if _, err := Open(path); err == nil { t.Fatalf("invalid state accepted: %s", raw) }
	}
}

func TestStateFileDoesNotPersistSecretFields(t *testing.T) {
	store, dir := newStore(t)
	if err := store.Upsert(sample()); err != nil { t.Fatal(err) }
	raw, err := os.ReadFile(filepath.Join(dir, "runtime.json"))
	if err != nil { t.Fatal(err) }
	for _, forbidden := range []string{"password", "secret", "environment", "command"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("runtime state unexpectedly contains forbidden field %q", forbidden)
		}
	}
}

func TestConcurrentUpsertsRemainConsistent(t *testing.T) {
	store, _ := newStore(t)
	const count = 24
	var wg sync.WaitGroup
	errors := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			item := WorkloadState{
				WorkloadID: fmt.Sprintf("workload-%03d", index),
				ReleaseID: fmt.Sprintf("release-%03d", index),
				ContainerID: fmt.Sprintf("%032x", index+1),
				State: "running",
			}
			if err := store.Upsert(item); err != nil { errors <- err }
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors { t.Error(err) }
	items, err := store.Load()
	if err != nil { t.Fatal(err) }
	if len(items) != count { t.Fatalf("persisted %d workloads, want %d", len(items), count) }
}

func TestGetReturnsOnlyRequestedWorkload(t *testing.T) {
	store, _ := newStore(t)
	if err := store.Upsert(sample()); err != nil { t.Fatal(err) }
	got, ok, err := store.Get("workload-001")
	if err != nil { t.Fatal(err) }
	if !ok || got.ReleaseID != "release-001" { t.Fatalf("unexpected lookup: %+v, found=%v", got, ok) }
	_, ok, err = store.Get("workload-002")
	if err != nil { t.Fatal(err) }
	if ok { t.Fatal("unexpected workload found") }
	if _, _, err := store.Get("../invalid"); err == nil { t.Fatal("invalid workload ID accepted") }
}

func TestUpsertManyIsAtomicAndRejectsDuplicateIDs(t *testing.T) {
	store, _ := newStore(t)
	first := sample()
	second := sample()
	second.WorkloadID = "workload-002"
	second.ReleaseID = "release-002"
	second.ContainerID = "abcdef0123456789abcdef0123456789"
	if err := store.UpsertMany([]WorkloadState{first, second}); err != nil { t.Fatal(err) }
	items, err := store.Load()
	if err != nil { t.Fatal(err) }
	if len(items) != 2 { t.Fatalf("persisted %d workloads, want 2", len(items)) }

	invalid := second
	invalid.WorkloadID = "workload-003"
	invalid.ContainerID = "bad"
	if err := store.UpsertMany([]WorkloadState{first, invalid}); err == nil {
		t.Fatal("invalid batch was accepted")
	}
	duplicate := second
	duplicate.WorkloadID = first.WorkloadID
	if err := store.UpsertMany([]WorkloadState{first, duplicate}); err == nil {
		t.Fatal("duplicate workload ID was accepted")
	}
	items, err = store.Load()
	if err != nil { t.Fatal(err) }
	if len(items) != 2 { t.Fatalf("failed batch partially changed state: %+v", items) }
}

func TestUpsertManyEmptyBatchDoesNotCreateStateFile(t *testing.T) {
	store, dir := newStore(t)
	if err := store.UpsertMany(nil); err != nil { t.Fatal(err) }
	if _, err := os.Lstat(filepath.Join(dir, "runtime.json")); !os.IsNotExist(err) {
		t.Fatalf("empty batch unexpectedly created state file: %v", err)
	}
}
