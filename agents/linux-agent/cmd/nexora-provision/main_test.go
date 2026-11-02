package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUsernamePattern(t *testing.T) {
	valid := []string{"web001", "client_01", "abc"}
	for _, value := range valid {
		if !usernamePattern.MatchString(value) { t.Errorf("expected %q to be accepted", value) }
	}
	invalid := []string{"ab", "1client", "Client01", "client-name", "client.name", "client;id", "sixteen_char_name"}
	for _, value := range invalid {
		if usernamePattern.MatchString(value) { t.Errorf("expected %q to be rejected", value) }
	}
}

func TestDomainPattern(t *testing.T) {
	valid := []string{"example.com", "sub.example.co.uk", "nxoratest01.test", "a1.example-domain.com"}
	for _, value := range valid {
		if !domainPattern.MatchString(value) { t.Errorf("expected domain %q to be accepted", value) }
	}
	invalid := []string{"", "localhost", "-bad.example.com", "bad-.example.com", "bad..example.com", "bad;domain.com", "example.com/path", "example .com", "example.com\n"}
	for _, value := range invalid {
		if domainPattern.MatchString(value) { t.Errorf("expected domain %q to be rejected", value) }
	}
}

func TestDocumentRootPattern(t *testing.T) {
	valid := []string{"/home/client01/public_html", "/home/client_01/public_html/example.com"}
	for _, value := range valid {
		if !validDocumentRoot(value) { t.Errorf("expected document root %q to be accepted", value) }
	}
	invalid := []string{"/home/client01/public_html;include", "/home/client01/public_html with spaces", "/home/client01/../other", "/tmp/site", "/home/client01/.ssh", "/home/client01/public_html/.private", "/home/client01/public_html\\n"}
	for _, value := range invalid {
		if validDocumentRoot(value) { t.Errorf("expected document root %q to be rejected", value) }
	}
}

func TestSafeManagedPathRejectsTraversalAndSymlinks(t *testing.T) {
 root := t.TempDir()
 if err := os.Mkdir(filepath.Join(root, "assets"), 0750); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root, "assets", "site.css"), []byte("body{}"), 0640); err != nil { t.Fatal(err) }
 if _, info, err := safeManagedPath(root, "assets/site.css", false); err != nil || info == nil || !info.Mode().IsRegular() {
  t.Fatalf("expected a regular file, got info=%v err=%v", info, err)
 }
 for _, value := range []string{"../etc/passwd", "/etc/passwd", "assets/../../etc/passwd", "assets\\\\site.css"} {
  if _, _, err := safeManagedPath(root, value, false); err == nil {
   t.Errorf("expected unsafe path %q to be rejected", value)
  }
 }
 if err := os.Symlink("/etc/passwd", filepath.Join(root, "assets", "escape")); err != nil { t.Fatal(err) }
 if _, _, err := safeManagedPath(root, "assets/escape", false); err == nil {
  t.Fatal("expected symbolic link to be rejected")
 }
}

func TestManagedParentPath(t *testing.T) {
 if got := managedParentPath("index.html"); got != "" { t.Fatalf("root-level parent = %q, want empty", got) }
 if got := managedParentPath("assets/site.css"); got != "assets" { t.Fatalf("nested parent = %q, want assets", got) }
}

func TestUpgradeLegacyDefaultIndexOnlyReplacesKnownPlaceholder(t *testing.T) {
	root := t.TempDir()
	index := filepath.Join(root, "index.html")
	if err := os.WriteFile(index, []byte(legacyDefaultIndexHTML), 0640); err != nil { t.Fatal(err) }
	if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(index)
	if err != nil { t.Fatal(err) }
	if string(got) != defaultIndexHTML { t.Fatalf("legacy placeholder was not upgraded: %q", string(got)) }

	custom := []byte("<h1>Customer website</h1>")
	if err := os.WriteFile(index, custom, 0640); err != nil { t.Fatal(err) }
	if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err != nil { t.Fatal(err) }
	got, err = os.ReadFile(index)
	if err != nil { t.Fatal(err) }
	if string(got) != string(custom) { t.Fatalf("customer index was modified: %q", string(got)) }
}

func TestUpgradeLegacyDefaultIndexDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "customer.html")
	if err := os.WriteFile(target, []byte(legacyDefaultIndexHTML), 0640); err != nil { t.Fatal(err) }
	index := filepath.Join(root, "index.html")
	if err := os.Symlink(target, index); err != nil { t.Fatal(err) }
	if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected symlink index.html to be rejected")
	}
	got, err := os.ReadFile(target)
	if err != nil { t.Fatal(err) }
	if string(got) != legacyDefaultIndexHTML { t.Fatal("symlink target was modified") }
}

func TestOpenDirectoryChainRejectsSymlinkComponents(t *testing.T) {
 root := t.TempDir()
 real := filepath.Join(root, "real")
 if err := os.Mkdir(real, 0750); err != nil { t.Fatal(err) }
 if err := os.Symlink(real, filepath.Join(root, "linked")); err != nil { t.Fatal(err) }
 fd, err := openDirectoryChain(root, "real")
 if err != nil { t.Fatalf("expected real directory to open: %v", err) }
 _ = syscall.Close(fd)
 if fd, err := openDirectoryChain(root, "linked"); err == nil {
  _ = syscall.Close(fd)
  t.Fatal("expected symlink directory component to be rejected")
 }
}
