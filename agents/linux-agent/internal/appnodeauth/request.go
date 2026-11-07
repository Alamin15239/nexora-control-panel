// Package appnodeauth creates and verifies Ed25519 proofs for application-node API requests.
package appnodeauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	nodeIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$`)
	noncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	methodPattern = regexp.MustCompile(`^[A-Z]{3,10}$`)
)

type Proof struct {
	Timestamp string
	Nonce string
	Signature string
}

// CanonicalMessage binds a proof to node identity, method, path, timestamp,
// nonce, and the exact request body digest. The API must use the same version.
func CanonicalMessage(nodeIdentity, timestamp, nonce, method, path string, body []byte) ([]byte, error) {
	if !nodeIdentityPattern.MatchString(nodeIdentity) {
		return nil, errors.New("invalid application node identity")
	}
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil || len(timestamp) != 10 {
		return nil, errors.New("invalid request timestamp")
	}
	if !noncePattern.MatchString(nonce) {
		return nil, errors.New("invalid request nonce")
	}
	if !methodPattern.MatchString(method) || method != strings.ToUpper(method) {
		return nil, errors.New("invalid HTTP method")
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return nil, errors.New("request path must be an absolute path without query or fragment")
	}
	digest := sha256.Sum256(body)
	message := fmt.Sprintf("NEXORA-APPLICATION-NODE-V1\n%s\n%s\n%s\n%s\n%s\n%s",
		nodeIdentity, timestamp, nonce, method, path, hex.EncodeToString(digest[:]))
	return []byte(message), nil
}

// Sign creates a timestamped request proof using a fresh cryptographic nonce.
func Sign(privateKey ed25519.PrivateKey, nodeIdentity, method, path string, body []byte, now time.Time) (Proof, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Proof{}, errors.New("invalid Ed25519 private key")
	}
	if now.IsZero() {
		return Proof{}, errors.New("request timestamp must be supplied")
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Proof{}, fmt.Errorf("generate request nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	message, err := CanonicalMessage(nodeIdentity, timestamp, nonce, method, path, body)
	if err != nil {
		return Proof{}, err
	}
	signature := ed25519.Sign(privateKey, message)
	return Proof{Timestamp: timestamp, Nonce: nonce, Signature: hex.EncodeToString(signature)}, nil
}

// Verify validates a proof and enforces the same five-minute request window as the API.
func Verify(publicKey ed25519.PublicKey, nodeIdentity, method, path string, body []byte, proof Proof, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	issuedAt, err := strconv.ParseInt(proof.Timestamp, 10, 64)
	if err != nil || len(proof.Timestamp) != 10 || now.IsZero() || abs(now.Unix()-issuedAt) > 300 {
		return errors.New("request timestamp is invalid or outside the permitted window")
	}
	signature, err := hex.DecodeString(proof.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature encoding")
	}
	message, err := CanonicalMessage(nodeIdentity, proof.Timestamp, proof.Nonce, method, path, body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("application-node request signature verification failed")
	}
	return nil
}

func (p Proof) Apply(request *http.Request, nodeIdentity string) error {
	if request == nil {
		return errors.New("HTTP request is required")
	}
	if !nodeIdentityPattern.MatchString(nodeIdentity) {
		return errors.New("invalid application node identity")
	}
	if p.Timestamp == "" || !noncePattern.MatchString(p.Nonce) || len(p.Signature) != ed25519.SignatureSize*2 {
		return errors.New("incomplete application-node request proof")
	}
	request.Header.Set("X-Nexora-Node-Identity", nodeIdentity)
	request.Header.Set("X-Nexora-Node-Timestamp", p.Timestamp)
	request.Header.Set("X-Nexora-Node-Nonce", p.Nonce)
	request.Header.Set("X-Nexora-Node-Signature", p.Signature)
	return nil
}

func abs(value int64) int64 {
	if value < 0 { return -value }
	return value
}
