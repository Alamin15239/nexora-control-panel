//go:build linux

package provisionipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	maxConcurrentRequests = 4
	helperTimeout         = 2 * time.Minute
)

type Server struct {
	AllowedUID uint32
	HelperPath string
}

type cappedBuffer struct {
	data  []byte
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		return 0, errors.New("provisioner output limit exceeded")
	}
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		return remaining, errors.New("provisioner output limit exceeded")
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
	_ = conn.SetDeadline(time.Now().Add(helperTimeout + 5*time.Second))
	uid, err := peerUID(conn)
	if err != nil || uid != s.AllowedUID {
		return
	}
	request, err := readFrame(conn, MaxRequestBytes)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, helperTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, s.HelperPath)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdin = bytesReader(request)
	stdout := &cappedBuffer{limit: MaxResponseBytes / 2}
	stderr := &cappedBuffer{limit: MaxResponseBytes / 2}
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
			stderr.data = []byte("provisioning request timed out")
		}
	}
	result := Result{ExitCode: exitCode, Stdout: stdout.data, Stderr: stderr.data}
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

var _ = fmt.Sprintf
