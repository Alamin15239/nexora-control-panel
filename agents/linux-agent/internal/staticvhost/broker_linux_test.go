//go:build linux

package staticvhost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRegistryFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil { t.Fatal(err) }
	if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
	return path
}

func TestLoadRootRegistryRejectsNonCanonicalPaths(t *testing.T) {
	for _, path := range []string{"", "relative/domains.json", "/etc/../etc/domains.json", "/etc//domains.json"} {
		if _, err := LoadRootRegistry(path); err == nil {
			t.Fatalf("accepted non-canonical registry path %q", path)
		}
	}
}

func TestLoadRootRegistryRequiresRootOwnedFile(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root ownership check requires root") }
	path := writeRegistryFixture(t, `{"version":1,"domains":[{"DomainID":"domain_123","Hostname":"example.test","HostingAccountID":"account_123"}]}`)
	got, err := LoadRootRegistry(path)
	if err != nil { t.Fatal(err) }
	if binding, ok := got["domain_123"]; !ok || binding.Hostname != "example.test" {
		t.Fatalf("unexpected registry binding: %#v", got)
	}
}

func TestLoadRootRegistryRejectsDuplicateDomainIDs(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root ownership check requires root") }
	body := `{"version":1,"domains":[
		{"DomainID":"domain_123","Hostname":"one.example.test","HostingAccountID":"account_123"},
		{"DomainID":"domain_123","Hostname":"two.example.test","HostingAccountID":"account_123"}
	]}`
	_, err := LoadRootRegistry(writeRegistryFixture(t, body))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-domain rejection, got %v", err)
	}
}

func TestLoadRootRegistryRejectsUnknownJSONFields(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root ownership check requires root") }
	body := `{"version":1,"domains":[{"DomainID":"domain_123","Hostname":"example.test","HostingAccountID":"account_123","documentRoot":"/tmp"}]}`
	if _, err := LoadRootRegistry(writeRegistryFixture(t, body)); err == nil {
		t.Fatal("accepted untrusted documentRoot field")
	}
}

func TestLoadRootRegistryRejectsInvalidBinding(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root ownership check requires root") }
	body := `{"version":1,"domains":[{"DomainID":"domain_123","Hostname":"example.test; include /etc/passwd;","HostingAccountID":"account_123"}]}`
	if _, err := LoadRootRegistry(writeRegistryFixture(t, body)); err == nil {
		t.Fatal("accepted Nginx directive injection in registry hostname")
	}
}

func TestLoadRootRegistryRejectsGroupWritableDirectory(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root ownership check requires root") }
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"domains":[]}`), 0600); err != nil { t.Fatal(err) }
	if err := os.Chmod(dir, 0770); err != nil { t.Fatal(err) }
	if _, err := LoadRootRegistry(path); err == nil {
		t.Fatal("accepted group-writable registry directory")
	}
}
