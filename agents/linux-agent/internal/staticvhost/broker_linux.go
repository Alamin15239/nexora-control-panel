//go:build linux

package staticvhost

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"sync"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
)

const (
	maxBrokerRequest = 9 << 10
	brokerTimeout = 2 * time.Minute
	brokerTrustPath = "/etc/nexora-static-vhost/trust.json"
	brokerPublicKeyPath = "/etc/nexora-static-vhost/deployment-envelope-public.pem"
)

type brokerTrustFile struct {
	Issuer string `json:"issuer"`
	Audience string `json:"audience"`
	KeyID string `json:"keyId"`
}

type BrokerTrust struct {
	Issuer string
	Audience string
	KeyID string
	PublicKey *rsa.PublicKey
}

type brokerRequest struct {
	DeploymentEnvelope string `json:"deploymentEnvelope"`
}

type brokerResponse struct {
	OK bool `json:"ok"`
	Error string `json:"error,omitempty"`
}

// LoadRootBrokerTrust loads the pinned deployment-envelope trust configuration
// and public key. Both files and their parent directory must be root-owned and
// non-writable by group or others. Key paths are fixed by the broker.
func LoadRootBrokerTrust() (BrokerTrust, error) {
	var trust BrokerTrust
	dirInfo, err := os.Lstat(filepath.Dir(brokerTrustPath))
	if err != nil { return trust, fmt.Errorf("inspect broker trust directory: %w", err) }
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirStat.Uid != 0 || dirInfo.Mode().Perm()&0022 != 0 {
		return trust, errors.New("broker trust directory must be root-owned and non-writable by group or others")
	}
	configBytes, err := readRootOwnedFile(brokerTrustPath, 4096)
	if err != nil { return trust, fmt.Errorf("read broker trust config: %w", err) }
	var doc brokerTrustFile
	decoder := json.NewDecoder(bytes.NewReader(configBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil { return trust, fmt.Errorf("decode broker trust config: %w", err) }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF { return trust, errors.New("broker trust config contains trailing data") }
	if doc.Issuer == "" || len(doc.Issuer) > 256 || doc.Audience == "" || len(doc.Audience) > 256 ||
		len(doc.KeyID) < 1 || len(doc.KeyID) > 64 {
		return trust, errors.New("broker trust config has invalid issuer, audience or key ID")
	}
	keyBytes, err := readRootOwnedFile(brokerPublicKeyPath, 16<<10)
	if err != nil { return trust, fmt.Errorf("read pinned deployment public key: %w", err) }
	block, _ := pem.Decode(keyBytes)
	if block == nil { return trust, errors.New("pinned deployment public key is not PEM encoded") }
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if key, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
			parsed = key
		} else {
			return trust, errors.New("unable to parse pinned deployment public key")
		}
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N == nil || publicKey.N.BitLen() < 2048 || publicKey.E < 3 {
		return trust, errors.New("pinned deployment public key must be RSA-2048 or stronger")
	}
	return BrokerTrust{Issuer:doc.Issuer, Audience:doc.Audience, KeyID:doc.KeyID, PublicKey:publicKey}, nil
}

func readRootOwnedFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil { return nil, err }
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil { return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 ||
		info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("file must be bounded, regular, root-owned and not group/world writable")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit { return nil, errors.New("file exceeds its size limit") }
	return data, nil
}

// Serve accepts only the enrolled publisher UID. The signed deployment envelope
// itself supplies the domain/account binding; no mutable domain registry is used.
func Serve(ctx context.Context, listener *net.UnixListener, allowedUID uint32, configDir string, trust BrokerTrust) error {
	if listener == nil || configDir != "/etc/nginx/conf.d" ||
		trust.Issuer == "" || trust.Audience == "" || trust.KeyID == "" || trust.PublicKey == nil {
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
			if ctx.Err() != nil { workers.Wait(); return nil }
			workers.Wait()
			return fmt.Errorf("accept static vhost request: %w", err)
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func(c *net.UnixConn) {
				defer workers.Done()
				defer func(){ <-slots }()
				handleBrokerRequest(ctx, c, allowedUID, configDir, trust)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func handleBrokerRequest(ctx context.Context, conn *net.UnixConn, allowedUID uint32, configDir string, trust BrokerTrust) {
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
	if err := decoder.Decode(&trailing); err != io.EOF || request.DeploymentEnvelope == "" {
		writeBrokerResponse(conn, brokerResponse{Error:"invalid request"})
		return
	}
	select { case <-ctx.Done(): return; default: }
	claims, err := deployenvelope.VerifySigned(
		request.DeploymentEnvelope,
		map[string]*rsa.PublicKey{trust.KeyID: trust.PublicKey},
		trust.Issuer, trust.Audience, time.Now().UTC(),
	)
	if err != nil {
		writeBrokerResponse(conn, brokerResponse{Error:"deployment authorization is invalid or expired"})
		return
	}
	binding := Binding{
		DomainID: claims.DomainID,
		Hostname: claims.Hostname,
		HostingAccountID: claims.HostingAccountID,
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

// RequestInstall sends only a signed deployment envelope. The root broker
// independently verifies the signature and derives the domain/account binding.
func RequestInstall(ctx context.Context, socketPath, signedEnvelope string) error {
	if signedEnvelope == "" || len(signedEnvelope) > 8<<10 {
		return errors.New("deployment envelope is empty or oversized")
	}
	if socketPath == "" { socketPath = "/run/nexora-static-vhost/vhost.sock" }
	conn, err := (&net.Dialer{Timeout: 3*time.Second}).DialContext(ctx, "unix", socketPath)
	if err != nil { return fmt.Errorf("connect to static vhost broker: %w", err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(brokerTimeout))
	payload, err := json.Marshal(brokerRequest{DeploymentEnvelope:signedEnvelope})
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
