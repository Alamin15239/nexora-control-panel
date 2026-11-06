package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func runSecureFMTest(t *testing.T, root, operation, path, newPath, content string) (any, error) {
	t.Helper()

	input := request{
		FileOperation: operation,
		Path:          path,
		NewPath:       newPath,
	}
	if content != "" {
		input.ContentBase64 = base64.StdEncoding.EncodeToString([]byte(content))
	}

	var result any
	quarantinePath := filepath.Join(t.TempDir(), "quarantine")
	if err := os.Mkdir(quarantinePath, 0700); err != nil {
		t.Fatal(err)
	}

	quarantineFD, err := syscall.Open(
		quarantinePath,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(quarantineFD)

	err = secureFileManagerOperation(input, root, quarantineFD, func(value any) error {
		result = value
		return nil
	})
	return result, err
}

func TestSecureFileManagerWriteReadAndOverwrite(t *testing.T) {
	root := t.TempDir()

	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "index.html", "", "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "index.html", "", "replacement"); err != nil {
		t.Fatalf("overwrite failed: %v", err)
	}

	result, err := runSecureFMTest(t, root, "READ_FILE", "index.html", "", "")
	if err != nil {
		t.Fatal(err)
	}

	payload := result.(map[string]any)
	decoded, err := base64.StdEncoding.DecodeString(payload["contentBase64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "replacement" {
		t.Fatalf("unexpected file content: %q", decoded)
	}
}

func TestSecureFileManagerDirectoryAndListing(t *testing.T) {
	root := t.TempDir()

	if _, err := runSecureFMTest(t, root, "CREATE_DIRECTORY", "assets", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "assets/site.css", "", "body{}"); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("/etc/passwd", filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "named-pipe"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := runSecureFMTest(t, root, "LIST_FILES", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	entries := result.(map[string]any)["entries"].([]managedFileEntry)
	foundDir, foundLink, foundFIFO := false, false, false
	for _, entry := range entries {
		switch entry.Name {
		case "assets":
			foundDir = entry.IsDir
		case "outside-link":
			foundLink = true
		case "named-pipe":
			foundFIFO = true
		}
	}
	if !foundDir || foundLink || foundFIFO {
		t.Fatalf("unexpected listing: %+v", entries)
	}
}

func TestSecureFileManagerRejectsTraversalAndSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(outsideFile, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "READ_FILE", "../keep.txt", "", ""); err == nil {
		t.Fatal("path traversal was accepted")
	}

	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "linked/keep.txt", "", "changed"); err == nil {
		t.Fatal("symlink parent was accepted")
	}

	data, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("outside file was modified: %q", data)
	}
}

func TestSecureFileManagerRenameNoReplace(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "RENAME_PATH", "source.txt", "target.txt", ""); err == nil {
		t.Fatal("rename unexpectedly replaced an existing destination")
	}

	data, err := os.ReadFile(filepath.Join(root, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "target" {
		t.Fatalf("destination was overwritten: %q", data)
	}

	if _, err := runSecureFMTest(t, root, "RENAME_PATH", "source.txt", "renamed.txt", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestSecureFileManagerRecursiveDeleteAndSymlinkSafety(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "nested", "child"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "child", "data.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nested", "outside-link")); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "DELETE_PATH", "nested", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "nested")); !os.IsNotExist(err) {
		t.Fatalf("directory still exists: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(data) != "safe" {
		t.Fatalf("symlink target was affected: data=%q err=%v", data, err)
	}
}

func TestSecureFileManagerRejectsOversizedReadAndWrite(t *testing.T) {
	root := t.TempDir()
	large := make([]byte, maxManagedFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "large.txt"), large, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "READ_FILE", "large.txt", "", ""); err == nil {
		t.Fatal("oversized file was readable")
	}
	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "new.txt", "", string(large)); err == nil {
		t.Fatal("oversized content was accepted")
	}
}

func TestSecureFileManagerDeleteSymlinkDoesNotDeleteTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "important.txt")

	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "DELETE_PATH", "link.txt", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("symlink still exists: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep" {
		t.Fatalf("symlink target was changed: %q, %v", data, err)
	}
}

func TestSecureFileManagerRejectsFinalSymlinkWrite(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}

	if _, err := runSecureFMTest(t, root, "WRITE_FILE", "link.txt", "", "changed"); err == nil {
		t.Fatal("write through final symlink was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("symlink target was modified: %q, %v", data, err)
	}
}

func TestSecureFileManagerListingCapsAcceptedEntries(t *testing.T) {
	root := t.TempDir()

	if err := os.Symlink("/etc/passwd", filepath.Join(root, "000-link")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1005; i++ {
		name := filepath.Join(root, fmt.Sprintf("file-%04d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	result, err := runSecureFMTest(t, root, "LIST_FILES", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	entries := result.(map[string]any)["entries"].([]managedFileEntry)
	if len(entries) != 1000 {
		t.Fatalf("expected 1000 accepted entries, got %d", len(entries))
	}
}
