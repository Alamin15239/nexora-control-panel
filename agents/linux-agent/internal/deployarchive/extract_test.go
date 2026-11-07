package deployarchive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractGzipTarWritesOnlyRegularFilesIntoPrivateStage(t *testing.T) {
	archive := makeArchive(t,
		testEntry{name: "./", kind: tar.TypeDir},
		testEntry{name: "assets/", kind: tar.TypeDir},
		testEntry{name: "index.html", kind: tar.TypeReg, body: "<h1>Nexora</h1>"},
		testEntry{name: "assets/site.css", kind: tar.TypeReg, body: "body{}"},
	)
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
	result, err := ExtractGzipTar(bytes.NewReader(archive), stage, Limits{})
	if err != nil { t.Fatal(err) }
	if result.Files != 2 || result.Bytes != int64(len("<h1>Nexora</h1>")+len("body{}")) {
		t.Fatalf("unexpected extraction result: %+v", result)
	}
	content, err := os.ReadFile(filepath.Join(stage, "index.html"))
	if err != nil { t.Fatal(err) }
	if string(content) != "<h1>Nexora</h1>" { t.Fatalf("unexpected file content %q", content) }
	info, err := os.Stat(filepath.Join(stage, "index.html"))
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("archive permissions were not normalized: %o", info.Mode().Perm()) }
}

func TestExtractGzipTarRejectsUnsafeOrNonEmptyDestinations(t *testing.T) {
	archive := makeArchive(t, testEntry{name: "index.html", kind: tar.TypeReg, body: "safe"})
	t.Run("non-empty", func(t *testing.T) {
		stage := filepath.Join(t.TempDir(), "stage")
		if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(stage, "existing"), []byte("keep"), 0600); err != nil { t.Fatal(err) }
		if _, err := ExtractGzipTar(bytes.NewReader(archive), stage, Limits{}); err == nil { t.Fatal("non-empty stage was accepted") }
	})
	t.Run("symlink", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0700); err != nil { t.Fatal(err) }
		stage := filepath.Join(parent, "stage-link")
		if err := os.Symlink(real, stage); err != nil { t.Fatal(err) }
		if _, err := ExtractGzipTar(bytes.NewReader(archive), stage, Limits{}); err == nil { t.Fatal("symlink stage was accepted") }
	})
	t.Run("group-writable", func(t *testing.T) {
		stage := filepath.Join(t.TempDir(), "stage")
		if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
		if err := os.Chmod(stage, 0770); err != nil { t.Fatal(err) }
		if _, err := ExtractGzipTar(bytes.NewReader(archive), stage, Limits{}); err == nil { t.Fatal("group-writable stage was accepted") }
	})
}
