package runtimesecrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSecretManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
	if err := os.Chmod(root, 0700); err != nil { t.Fatal(err) }
	manager, err := Open(root)
	if err != nil { t.Fatal(err) }
	return manager, root
}

func TestMaterializeCreatesOwnerOnlyImmutableSecretFiles(t *testing.T) {
	manager, _ := newSecretManager(t)
	secrets := map[string][]byte{"DATABASE_URL": []byte("postgres://user:password@db/app"), "API_TOKEN": []byte("token-value")}
	path, err := manager.Materialize("workload-123", "bundle-001", secrets)
	if err != nil { t.Fatal(err) }
	if err := manager.Validate("workload-123", "bundle-001", path); err != nil { t.Fatal(err) }
	dir, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if dir.Mode().Perm() != 0700 { t.Fatalf("secret directory mode = %o", dir.Mode().Perm()) }
	for name, expected := range secrets {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil { t.Fatal(err) }
		if info.Mode().Perm() != 0400 { t.Fatalf("secret file %s mode = %o", name, info.Mode().Perm()) }
		actual, err := os.ReadFile(filepath.Join(path, name))
		if err != nil { t.Fatal(err) }
		if string(actual) != string(expected) { t.Fatalf("secret file %s contents differ", name) }
	}
	if _, err := manager.Materialize("workload-123", "bundle-001", secrets); err == nil {
		t.Fatal("existing secret bundle was overwritten")
	}
}

func TestMaterializeRejectsInvalidNamesAndOversizedValues(t *testing.T) {
	manager, _ := newSecretManager(t)
	cases := []map[string][]byte{
		{"lowercase": []byte("value")},
		{"BAD-NAME": []byte("value")},
		{"EMPTY": []byte{}},
		{"TOO_LARGE": []byte(strings.Repeat("x", maxSecretValueBytes+1))},
	}
	for _, secrets := range cases {
		if _, err := manager.Materialize("workload-123", "bundle-001", secrets); err == nil {
			t.Fatal("invalid secret bundle was accepted")
		}
	}
}

func TestValidateRejectsSymlinkAndUnsafeSecretFiles(t *testing.T) {
	manager, root := newSecretManager(t)
	path, err := manager.Materialize("workload-123", "bundle-001", map[string][]byte{"TOKEN": []byte("secret")})
	if err != nil { t.Fatal(err) }
	if err := os.Chmod(filepath.Join(path, "TOKEN"), 0600); err != nil { t.Fatal(err) }
	if err := manager.Validate("workload-123", "bundle-001", path); err == nil { t.Fatal("group-readable secret file accepted") }

	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0400); err != nil { t.Fatal(err) }
	if err := os.Remove(filepath.Join(path, "TOKEN")); err != nil { t.Fatal(err) }
	if err := os.Symlink(outside, filepath.Join(path, "TOKEN")); err != nil { t.Fatal(err) }
	if err := manager.Validate("workload-123", "bundle-001", path); err == nil { t.Fatal("symlink secret file accepted") }
}

func TestMaterializeRejectsInvalidIDsAndBundleSize(t *testing.T) {
	manager, _ := newSecretManager(t)
	if _, err := manager.Materialize("../escape", "bundle-001", map[string][]byte{"TOKEN": []byte("x")}); err == nil {
		t.Fatal("path traversal workload ID accepted")
	}
	if _, err := manager.Materialize("workload-123", "../escape", map[string][]byte{"TOKEN": []byte("x")}); err == nil {
		t.Fatal("path traversal bundle ID accepted")
	}
	large := map[string][]byte{}
	for i := 0; i < maxSecretCount; i++ { large[string(rune('A'+i))] = []byte(strings.Repeat("x", 5000)) }
	if _, err := manager.Materialize("workload-123", "bundle-002", large); err == nil {
		t.Fatal("oversized aggregate secret bundle accepted")
	}
}
