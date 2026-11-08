//go:build linux

package staticvhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"sync"
	"time"
)

const (
	maxBrokerRequest = 4096
	brokerTimeout = 10 * time.Second
)

type registryFile struct {
	Version int       `json:"version"`
	Domains []Binding `json:"domains"`
}

type brokerRequest struct {
	DomainID string `json:"domainId"`
}

type brokerResponse struct {
	OK bool `json:"ok"`
	Error string `json:"error,omitempty"`
}

// LoadRootRegistry accepts only a root-owned, non-writable regular file.
// The registry is the authority for hostname/account mapping; callers supply
// only a domain ID and can never choose a hostname, account, path or Nginx text.
func LoadRootRegistry(path string) (map[string]Binding, error) {
	if path == "" || !filepathIsCleanAbsolute(path) {
		return nil, errors.New("registry path must be absolute and clean")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("inspect static domain registry directory: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentStat.Uid != 0 || parentInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("static domain registry directory must be root-owned and non-writable by group or others")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open static domain registry: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat static domain registry: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 ||
		info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("static domain registry must be a bounded root-owned non-writable regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("read static domain registry safely")
	}
	var doc registryFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode static domain registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("static domain registry contains trailing data")
	}
	if doc.Version != 1 || len(doc.Domains) > 100000 {
		return nil, errors.New("unsupported or oversized static domain registry")
	}
	result := make(map[string]Binding, len(doc.Domains))
	for _, binding := range doc.Domains {
		if _, err := Render(binding); err != nil {
			return nil, fmt.Errorf("invalid registry binding %q: %w", binding.DomainID, err)
		}
		if _, exists := result[binding.DomainID]; exists {
			return nil, fmt.Errorf("duplicate static domain ID %q", binding.DomainID)
		}
		result[binding.DomainID] = binding
	}
	return result, nil
}

func filepathIsCleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// Serve handles one bounded request per Unix connection and authorizes the
// peer using kernel SO_PEERCRED before consulting the trusted registry.
func Serve(ctx context.Context, listener *net.UnixListener, allowedUID uint32, registryPath, configDir string) error {
	if listener == nil || registryPath == "" || configDir != "/etc/nginx/conf.d" {
		return errors.New("static vhost broker configuration is invalid")
	}
	slots := make(chan struct{}, 4)
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	var workers sync.WaitGroup
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				workers.Wait()
				return nil
			}
			workers.Wait()
			return fmt.Errorf("accept static vhost request: %w", err)
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func(c *net.UnixConn) {
				defer workers.Done()
				defer func(){ <-slots }()
				handleBrokerRequest(ctx, c, allowedUID, registryPath, configDir)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func handleBrokerRequest(ctx context.Context, conn *net.UnixConn, allowedUID uint32, registryPath, configDir string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(brokerTimeout))
	raw, err := conn.SyscallConn()
	if err != nil { return }
	var credential *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil || credential.Uid != allowedUID {
		return
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil { return }
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxBrokerRequest { return }
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil { return }
	var request brokerRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeBrokerResponse(conn, brokerResponse{Error:"invalid request"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || request.DomainID == "" {
		writeBrokerResponse(conn, brokerResponse{Error:"invalid request"})
		return
	}
	select { case <-ctx.Done(): return; default: }
	registry, err := LoadRootRegistry(registryPath)
	if err != nil {
		writeBrokerResponse(conn, brokerResponse{Error:"trusted domain registry unavailable"})
		return
	}
	binding, ok := registry[request.DomainID]
	if !ok {
		writeBrokerResponse(conn, brokerResponse{Error:"domain is not registered for static hosting"})
		return
	}
	if err := InstallAsRoot(configDir, binding); err != nil {
		writeBrokerResponse(conn, brokerResponse{Error:"Nginx vhost installation failed"})
		return
	}
	writeBrokerResponse(conn, brokerResponse{OK:true})
}

func writeBrokerResponse(w io.Writer, response brokerResponse) {
	payload, err := json.Marshal(response)
	if err != nil || len(payload) > 1024 { return }
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	_ = writeBrokerFrame(w, header[:], payload)
}

// RequestInstall asks the privileged broker to install the vhost for a domain
// already present in the root-owned registry. It never transmits Nginx text.
func RequestInstall(ctx context.Context, socketPath, domainID string) error {
	if domainID == "" || len(domainID) > 128 { return errors.New("invalid domain ID") }
	if socketPath == "" { socketPath = "/run/nexora-static-vhost/vhost.sock" }
	conn, err := (&net.Dialer{Timeout: 3*time.Second}).DialContext(ctx, "unix", socketPath)
	if err != nil { return fmt.Errorf("connect to static vhost broker: %w", err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(brokerTimeout))
	payload, err := json.Marshal(brokerRequest{DomainID:domainID})
	if err != nil { return err }
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeBrokerFrame(conn, header[:], payload); err != nil { return err }
	if _, err := io.ReadFull(conn, header[:]); err != nil { return fmt.Errorf("read static vhost broker response: %w", err) }
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 1024 { return errors.New("invalid static vhost broker response") }
	responseBytes := make([]byte, size)
	if _, err := io.ReadFull(conn, responseBytes); err != nil { return err }
	var response brokerResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil { return err }
	if !response.OK {
		if response.Error == "" { response.Error = "broker rejected request" }
		return errors.New(response.Error)
	}
	return nil
}

func writeBrokerFrame(w io.Writer, header, payload []byte) error {
	for _, part := range [][]byte{header, payload} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil { return err }
			if n == 0 { return io.ErrShortWrite }
			part = part[n:]
		}
	}
	return nil
}
