package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, cfg Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	raw, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
	return path
}

func validConfig() Config {
	return Config{
		NodeID: "node-123",
		Secret: strings.Repeat("a", 64),
		ControlPlane: "https://control.example",
		ServerID: "server-123",
	}
}

func TestLoadConfigAcceptsValidHTTPSConfig(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, validConfig()))
	if err != nil { t.Fatalf("expected valid config, got %v", err) }
	if cfg.NodeID != "node-123" { t.Fatalf("unexpected node ID %q", cfg.NodeID) }
}

func TestLoadConfigRejectsHTTPControlPlane(t *testing.T) {
	cfg := validConfig()
	cfg.ControlPlane = "http://control.example"
	if _, err := loadConfig(writeConfig(t, cfg)); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestLoadConfigRejectsMissingNodeID(t *testing.T) {
	cfg := validConfig()
	cfg.NodeID = ""
	if _, err := loadConfig(writeConfig(t, cfg)); err == nil || !strings.Contains(err.Error(), "node_id") {
		t.Fatalf("expected node ID validation error, got %v", err)
	}
}

func TestLoadConfigRejectsInvalidSecret(t *testing.T) {
	cfg := validConfig()
	cfg.Secret = "not-a-secret"
	if _, err := loadConfig(writeConfig(t, cfg)); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected secret validation error, got %v", err)
	}
}

func TestLoadConfigRejectsURLCredentials(t *testing.T) {
	cfg := validConfig()
	cfg.ControlPlane = "https://user:pass@control.example"
	if _, err := loadConfig(writeConfig(t, cfg)); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected embedded credential URL rejection, got %v", err)
	}
}

func TestAPIBaseRequiresHTTPS(t *testing.T) {
	if _, err := apiBase("http://control.example"); err == nil {
		t.Fatal("expected HTTP API URL to be rejected")
	}
	base, err := apiBase("https://control.example/")
	if err != nil { t.Fatal(err) }
	if base != "https://control.example" { t.Fatalf("unexpected normalized URL %q", base) }
}

func TestRandomHexStringUsesExpectedLength(t *testing.T) {
	value := randomHexString(16)
	if len(value) != 32 { t.Fatalf("expected 32 hex characters, got %d", len(value)) }
	if _, err := json.Marshal(value); err != nil { t.Fatal(err) }
}
