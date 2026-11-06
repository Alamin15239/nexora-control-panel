//go:build linux

package provisionipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startTestServer(t *testing.T, allowedUID uint32, helper string) (string, context.CancelFunc) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "provision.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{AllowedUID: allowedUID, HelperPath: helper}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("IPC server did not stop")
		}
	})
	return socketPath, cancel
}

func TestServerClientRoundTrip(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid, "/usr/bin/cat")
	request := []byte(`{"operation":"DATABASE_USAGE"}`)
	result, err := Run(context.Background(), socketPath, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("helper exit code = %d, stderr = %q", result.ExitCode, result.Stderr)
	}
	if string(result.Stdout) != string(request) {
		t.Fatalf("stdout = %q, want %q", result.Stdout, request)
	}
}

func TestServerRejectsWrongPeerUID(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid+1, "/usr/bin/cat")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Run(ctx, socketPath, []byte("request")); err == nil {
		t.Fatal("expected unauthorized peer to be disconnected")
	}
}

func TestServerRejectsTrailingRequestData(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid, "/usr/bin/cat")
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, []byte("request"), MaxRequestBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("unexpected")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var response [1]byte
	if n, err := conn.Read(response[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF for trailing bytes, read=%d err=%v", n, err)
	}
}

func TestResultExitCodeIsPreserved(t *testing.T) {
	result := Result{ExitCode: 23, Stdout: []byte("out"), Stderr: []byte("err")}
	payload, err := marshalResult(result)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalResult(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 23 || string(got.Stdout) != "out" || string(got.Stderr) != "err" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}
