package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRuntimeConfig(t *testing.T, cfg Config, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.json")
	raw, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, raw, mode); err != nil { t.Fatal(err) }
	if err := os.Chmod(path, mode); err != nil { t.Fatal(err) }
	return path
}

func validRuntimeConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(private)), 0600); err != nil { t.Fatal(err) }
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil { t.Fatal(err) }
	return Config{
		ControlPlaneURL: "https://api.nexoraedge.digital",
		NodeIdentity: "runtime-node-a",
		PrivateKeyFile: keyPath,
		StateFile: filepath.Join(stateDir, "runtime.json"),
		AllowedRegistries: []string{"registry.nexoraedge.digital"},
		PollIntervalSeconds: 30,
	}
}

func TestLoadConfigAcceptsSecureRuntimeConfig(t *testing.T) {
	cfg := validRuntimeConfig(t)
	loaded, err := loadConfig(writeRuntimeConfig(t, cfg, 0600))
	if err != nil { t.Fatal(err) }
	if loaded.NodeIdentity != cfg.NodeIdentity { t.Fatalf("unexpected node identity %q", loaded.NodeIdentity) }
}

func TestLoadConfigRejectsInsecureConfigPermissions(t *testing.T) {
	cfg := validRuntimeConfig(t)
	if _, err := loadConfig(writeRuntimeConfig(t, cfg, 0644)); err == nil {
		t.Fatal("world-readable runtime config accepted")
	}
}

func TestLoadConfigRejectsHTTPAndInvalidPollInterval(t *testing.T) {
	cfg := validRuntimeConfig(t)
	cfg.ControlPlaneURL = "http://api.example.test"
	if _, err := loadConfig(writeRuntimeConfig(t, cfg, 0600)); err == nil { t.Fatal("HTTP control plane accepted") }
	cfg = validRuntimeConfig(t)
	cfg.PollIntervalSeconds = 2
	if _, err := loadConfig(writeRuntimeConfig(t, cfg, 0600)); err == nil { t.Fatal("too-frequent polling accepted") }
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	cfg := validRuntimeConfig(t)
	raw, _ := json.Marshal(cfg)
	raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"secret":"unexpected"}`)
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
	if _, err := loadConfig(path); err == nil { t.Fatal("unknown config field accepted") }
}

func TestLoadPrivateKeyRequiresOwnerOnlyValidEd25519Key(t *testing.T) {
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(private)), 0600); err != nil { t.Fatal(err) }
	if _, err := loadPrivateKey(path); err != nil { t.Fatal(err) }
	if err := os.Chmod(path, 0644); err != nil { t.Fatal(err) }
	if _, err := loadPrivateKey(path); err == nil { t.Fatal("world-readable private key accepted") }
	if err := os.Chmod(path, 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil { t.Fatal(err) }
	if _, err := loadPrivateKey(path); err == nil { t.Fatal("invalid Ed25519 key accepted") }
}

func TestLoadPrivateKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 128)), 0600); err != nil { t.Fatal(err) }
	link := filepath.Join(dir, "key")
	if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
	if _, err := loadPrivateKey(link); err == nil { t.Fatal("symlink key file accepted") }
}

func TestLoadConfigRejectsTrailingJSON(t *testing.T) {
	cfg := validRuntimeConfig(t)
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, append(raw, []byte(" {}")...), 0600); err != nil { t.Fatal(err) }
	if _, err := loadConfig(path); err == nil { t.Fatal("trailing JSON value accepted") }
}
