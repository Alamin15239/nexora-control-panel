package main

import (
	"archive/tar"
	"compress/gzip"
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

func writeBackupArchiveFixture(t *testing.T, headers []tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	writer := tar.NewWriter(gz)
	for _, header := range headers {
		headerCopy := header
		if err := writer.WriteHeader(&headerCopy); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateBackupArchiveAcceptsExpectedRoots(t *testing.T) {
	path := writeBackupArchiveFixture(t, []tar.Header{
		{Name: "public_html/", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "public_html/index.html", Typeflag: tar.TypeReg, Mode: 0600, Size: 1},
		{Name: "databases/", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "databases/example.sql", Typeflag: tar.TypeReg, Mode: 0600, Size: 1},
	})
	if err := validateBackupArchive(path); err != nil {
		t.Fatalf("expected valid archive, got %v", err)
	}
}

func TestValidateBackupArchiveRejectsTraversal(t *testing.T) {
	path := writeBackupArchiveFixture(t, []tar.Header{
		{Name: "public_html", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "databases", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "public_html/../../etc/passwd", Typeflag: tar.TypeReg, Mode: 0600, Size: 1},
	})
	if err := validateBackupArchive(path); err == nil {
		t.Fatal("expected path traversal member to be rejected")
	}
}

func TestValidateBackupArchiveRejectsBackslashAndLinks(t *testing.T) {
	for _, header := range []tar.Header{
		{Name: "public_html\\escape", Typeflag: tar.TypeReg, Mode: 0600, Size: 1},
		{Name: "public_html/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0777},
	} {
		path := writeBackupArchiveFixture(t, []tar.Header{
			{Name: "public_html", Typeflag: tar.TypeDir, Mode: 0700},
			{Name: "databases", Typeflag: tar.TypeDir, Mode: 0700},
			header,
		})
		if err := validateBackupArchive(path); err == nil {
			t.Fatalf("expected unsafe member %q to be rejected", header.Name)
		}
	}
}

func TestValidateBackupArchiveRequiresBothRootsAndRejectsDuplicates(t *testing.T) {
	missingRoot := writeBackupArchiveFixture(t, []tar.Header{
		{Name: "public_html", Typeflag: tar.TypeDir, Mode: 0700},
	})
	if err := validateBackupArchive(missingRoot); err == nil {
		t.Fatal("expected archive missing databases root to be rejected")
	}
	duplicate := writeBackupArchiveFixture(t, []tar.Header{
		{Name: "public_html", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "public_html", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "databases", Typeflag: tar.TypeDir, Mode: 0700},
	})
	if err := validateBackupArchive(duplicate); err == nil {
		t.Fatal("expected duplicate archive member to be rejected")
	}
}

func TestValidateBackupArchiveRejectsCorruptGzipTrailer(t *testing.T) {
	path := writeBackupArchiveFixture(t, []tar.Header{
		{Name: "public_html/", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "databases/", Typeflag: tar.TypeDir, Mode: 0700},
	})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 {
		t.Fatal("gzip fixture unexpectedly short")
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupArchive(path); err == nil {
		t.Fatal("expected corrupt gzip trailer to be rejected")
	}
}
