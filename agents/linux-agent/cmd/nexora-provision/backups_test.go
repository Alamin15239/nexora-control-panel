package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBackupDigestAcceptsMatchingArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.tar.gz")
	data := []byte("nexora backup integrity fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if err := verifyBackupDigest(path, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("expected matching digest to pass, got %v", err)
	}
}

func TestVerifyBackupDigestRejectsMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(path, []byte("tampered archive"), 0600); err != nil {
		t.Fatal(err)
	}
	expected := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := verifyBackupDigest(path, expected); err == nil {
		t.Fatal("expected mismatched archive digest to be rejected")
	}
}

func TestVerifyBackupDigestRejectsInvalidExpectedDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(path, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupDigest(path, "not-a-sha256"); err == nil {
		t.Fatal("expected malformed expected digest to be rejected")
	}
}
