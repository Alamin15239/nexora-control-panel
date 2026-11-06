package deployarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

type testEntry struct { name string; kind byte; body string }

func makeArchive(t *testing.T, entries ...testEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0644, Typeflag: entry.kind, Size: int64(len(entry.body))}
		if entry.kind == tar.TypeDir { header.Size = 0 }
		if err := tw.WriteHeader(header); err != nil { t.Fatal(err) }
		if entry.kind == tar.TypeReg || entry.kind == tar.TypeRegA {
			if _, err := tw.Write([]byte(entry.body)); err != nil { t.Fatal(err) }
		}
	}
	if err := tw.Close(); err != nil { t.Fatal(err) }
	if err := gz.Close(); err != nil { t.Fatal(err) }
	return output.Bytes()
}

func TestValidateGzipTarAcceptsStaticSite(t *testing.T) {
	archive := makeArchive(t,
		testEntry{name: "./", kind: tar.TypeDir},
		testEntry{name: "./assets/", kind: tar.TypeDir},
		testEntry{name: "./index.html", kind: tar.TypeReg, body: "<h1>Nexora</h1>"},
		testEntry{name: "assets/site.css", kind: tar.TypeReg, body: "body{}"},
	)
	result, err := ValidateGzipTar(bytes.NewReader(archive), Limits{})
	if err != nil { t.Fatal(err) }
	if result.Files != 2 || result.Bytes != int64(len("<h1>Nexora</h1>")+len("body{}")) {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}

func TestValidateGzipTarRejectsUnsafeEntryTypes(t *testing.T) {
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeFifo, tar.TypeChar, tar.TypeBlock, tar.TypeGNUSparse} {
		t.Run(string(rune(kind)), func(t *testing.T) {
			archive := makeArchive(t, testEntry{name: "bad", kind: kind})
			if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{}); err == nil {
				t.Fatalf("entry type %d was accepted", kind)
			}
		})
	}
}

func TestValidateGzipTarRejectsTraversalAndAbsolutePaths(t *testing.T) {
	for _, name := range []string{"../outside", "nested/../../outside", "/etc/passwd", "C:\\Windows\\system.ini", "nested\\file.txt"} {
		t.Run(name, func(t *testing.T) {
			archive := makeArchive(t, testEntry{name: name, kind: tar.TypeReg, body: "x"})
			if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{}); err == nil {
				t.Fatalf("unsafe path %q was accepted", name)
			}
		})
	}
}

func TestValidateGzipTarRejectsDuplicatesAndFileDirectoryCollisions(t *testing.T) {
	cases := [][]testEntry{
		{{name: "index.html", kind: tar.TypeReg, body: "a"}, {name: "./index.html", kind: tar.TypeReg, body: "b"}},
		{{name: "assets", kind: tar.TypeReg, body: "a"}, {name: "assets/site.css", kind: tar.TypeReg, body: "b"}},
		{{name: "assets/site.css", kind: tar.TypeReg, body: "a"}, {name: "assets", kind: tar.TypeReg, body: "b"}},
	}
	for i, entries := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			archive := makeArchive(t, entries...)
			if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{}); err == nil {
				t.Fatal("duplicate or conflicting paths were accepted")
			}
		})
	}
}

func TestValidateGzipTarEnforcesEntryAndExpandedSizeLimits(t *testing.T) {
	archive := makeArchive(t,
		testEntry{name: "one", kind: tar.TypeReg, body: "12345"},
		testEntry{name: "two", kind: tar.TypeReg, body: "67890"},
	)
	if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{MaxEntries: 1}); err == nil { t.Fatal("entry count limit was not enforced") }
	if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{MaxTotalBytes: 9}); err == nil { t.Fatal("expanded size limit was not enforced") }
	if _, err := ValidateGzipTar(bytes.NewReader(archive), Limits{MaxFileBytes: 4}); err == nil { t.Fatal("per-file size limit was not enforced") }
}
