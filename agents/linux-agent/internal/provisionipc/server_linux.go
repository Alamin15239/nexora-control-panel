//go:build linux

package provisionipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	maxConcurrentRequests = 4
	requestReadTimeout    = 10 * time.Second
	helperTimeout         = 2 * time.Minute
	// JSON encodes []byte as base64. Keeping the combined raw streams below
	// half the frame budget leaves ample room for base64 expansion and JSON.
	maxCapturedStreamBytes = MaxResponseBytes / 4
)

type Server struct {
	AllowedUID uint32
	HelperPath string
}

type cappedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	if credential == nil {
		return 0, errors.New("peer credentials unavailable")
	}
	return credential.Uid, nil
}

// Serve accepts one bounded request per Unix connection. The privileged helper
// is always executed as a separate child because FILE_MANAGER irreversibly
// changes its process root and credentials.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if s.HelperPath == "" || listener == nil {
		return errors.New("provisioning server is not configured")
	}
	slots := make(chan struct{}, maxConcurrentRequests)
	var workers sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				workers.Wait()
				return nil
			}
			continue
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func(c *net.UnixConn) {
				defer workers.Done()
				defer func() { <-slots }()
				defer c.Close()
				s.handle(ctx, c)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handle(parent context.Context, conn *net.UnixConn) {
	_ = conn.SetReadDeadline(time.Now().Add(requestReadTimeout))
	uid, err := peerUID(conn)
	if err != nil || uid != s.AllowedUID {
		return
	}
	request, err := readFrame(conn, MaxRequestBytes)
	if err != nil {
		return
	}
	if err := conn.SetDeadline(time.Now().Add(helperTimeout + 5*time.Second)); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(parent, helperTimeout)
	defer cancel()

	// Keep the client write side open while the helper runs. EOF means the
	// client disconnected; any additional byte means it violated the
	// one-request protocol. Either condition cancels and reaps the helper.
	disconnected := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		var extra [1]byte
		n, readErr := conn.Read(extra[:])
		if n > 0 || errors.Is(readErr, io.EOF) {
			close(disconnected)
			cancel()
		}
	}()

	command := exec.CommandContext(ctx, s.HelperPath)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdin = bytesReader(request)
	stdout := &cappedBuffer{limit: maxCapturedStreamBytes}
	stderr := &cappedBuffer{limit: maxCapturedStreamBytes}
	command.Stdout = stdout
	command.Stderr = stderr

	exitCode := 0
	if err := command.Run(); err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() != nil && len(stderr.data) == 0 {
			stderr.data = []byte("provisioning request timed out or was cancelled")
		}
	}

	// Stop the connection watcher without affecting the write side used for
	// the response. A read timeout here is expected after the helper exits.
	_ = conn.SetReadDeadline(time.Now())
	select {
	case <-watcherDone:
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-disconnected:
		return
	default:
	}

	result := Result{ExitCode: exitCode, Stdout: stdout.data, Stderr: stderr.data, OutputTruncated: stdout.truncated || stderr.truncated}
	payload, err := json.Marshal(result)
	if err != nil || len(payload) > MaxResponseBytes {
		payload, _ = json.Marshal(Result{ExitCode: 1, Stderr: []byte("provisioner response exceeded the IPC size limit")})
	}
	_ = writeFrame(conn, payload, MaxResponseBytes)
}

type byteReader struct {
	data []byte
}

func bytesReader(data []byte) io.Reader {
	return &byteReader{data: data}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
