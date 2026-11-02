package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAgentConfig(t *testing.T, dir, caPath, certPath, keyPath, controlPlane string) string {
	t.Helper()
	path := filepath.Join(dir, "agent.json")
	body := `{"node_id":"node-1","control_plane_url":"` + controlPlane + `","ca_cert_file":"` + caPath + `","client_cert_file":"` + certPath + `","client_key_file":"` + keyPath + `"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateRejectsHTTPControlPlane(t *testing.T) {
	dir := t.TempDir()
	path := writeAgentConfig(t, dir, "ca.pem", "client.pem", "client.key", "http://control.example")
	err := validate(path)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
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

func TestValidateRejectsHTTPSURLWithCredentials(t *testing.T) {
	dir := t.TempDir()
	path := writeAgentConfig(t, dir, "ca.pem", "client.pem", "client.key", "https://user:pass@control.example")
	err := validate(path)
	if err == nil || !strings.Contains(err.Error(), "without embedded credentials") {
		t.Fatalf("expected embedded credentials validation error, got %v", err)
	}
}

func TestValidateRejectsUntrustedClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	caTemplate := &x509.Certificate{SerialNumber: bigIntForTest(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil { t.Fatal(err) }

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	otherCATemplate := &x509.Certificate{SerialNumber: bigIntForTest(3), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	otherCADER, err := x509.CreateCertificate(rand.Reader, otherCATemplate, otherCATemplate, otherPub, otherPriv)
	if err != nil { t.Fatal(err) }
	otherCACert, err := x509.ParseCertificate(otherCADER)
	if err != nil { t.Fatal(err) }
	clientTemplate := &x509.Certificate{SerialNumber: bigIntForTest(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, otherCACert, otherPub, otherPriv)
	if err != nil { t.Fatal(err) }
	keyDER, err := x509.MarshalPKCS8PrivateKey(otherPriv)
	if err != nil { t.Fatal(err) }

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:caDER}), 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:clientDER}), 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER}), 0600); err != nil { t.Fatal(err) }
	path := writeAgentConfig(t, dir, caPath, certPath, keyPath, "https://control.example")
	if err := validate(path); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("expected untrusted client certificate error, got %v", err)
	}
}

func bigIntForTest(v int64) *big.Int { return big.NewInt(v) }
