package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsHTTPControlPlane(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"node_id":"node-1","control_plane_url":"http://control.example","ca_cert_file":"ca.pem","client_cert_file":"client.pem","client_key_file":"client.key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := validate(path)
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestValidateRejectsMissingNodeID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"control_plane_url":"https://control.example","ca_cert_file":"ca.pem","client_cert_file":"client.pem","client_key_file":"client.key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := validate(path)
	if err == nil || !strings.Contains(err.Error(), "node_id is required") {
		t.Fatalf("expected node ID validation error, got %v", err)
	}
}
