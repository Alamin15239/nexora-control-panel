package supervisorstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
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
