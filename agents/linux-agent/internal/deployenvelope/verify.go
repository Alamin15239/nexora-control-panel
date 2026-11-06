// Package deployenvelope verifies short-lived deployment authorization tokens.
// It is intentionally independent of the IPC and filesystem layers.
package deployenvelope

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	maxTokenBytes = 8 << 10
	maxArtifactBytes = 100 << 20
	maxLifetime = 5 * time.Minute
	clockSkew = 30 * time.Second
)

var (
	kidPattern = regexp.MustCompile("^[A-Za-z0-9._-]{1,64}$")
	idPattern = regexp.MustCompile("^[A-Za-z0-9_-]{1,128}$")
	hex32Pattern = regexp.MustCompile("^[a-f0-9]{32}$")
	digestPattern = regexp.MustCompile("^[a-f0-9]{64}$")
	commitPattern = regexp.MustCompile("^[a-f0-9]{40}$")
	repositoryIDPattern = regexp.MustCompile("^[1-9][0-9]{0,19}$")
)

type Expected struct {
	Issuer string
	Audience string
	OrganizationID string
	ProjectID string
	DeploymentID string
	HostingAccountID string
	RepositoryID string
	CommitSHA string
}

type Claims struct {
	Issuer string `json:"iss"`
	Audience string `json:"aud"`
	OrganizationID string `json:"organization_id"`
	ProjectID string `json:"project_id"`
	DeploymentID string `json:"deployment_id"`
	HostingAccountID string `json:"hosting_account_id"`
	RepositoryID string `json:"repository_id"`
	CommitSHA string `json:"commit_sha"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactBytes int64 `json:"artifact_bytes"`
	JWTID string `json:"jti"`
	IssuedAt int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

type header struct {
	Algorithm string `json:"alg"`
	Type string `json:"typ"`
	KeyID string `json:"kid"`
}

// Verify validates an RS256 JWS using an explicitly pinned key ring and binds
// every deployment identity field to the caller's expected values. Replay
// prevention is deliberately left to the receiver's durable single-use store.
func Verify(token string, keys map[string]*rsa.PublicKey, expected Expected, now time.Time) (Claims, error) {
	var zero Claims
	if len(token) == 0 || len(token) > maxTokenBytes {
		return zero, errors.New("deployment envelope has an invalid size")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, errors.New("deployment envelope is not a compact JWS")
	}
	var h header
	if err := decodeStrictJSONSegment(parts[0], &h); err != nil {
		return zero, fmt.Errorf("invalid JWS header: %w", err)
	}
	if h.Algorithm != "RS256" || h.Type != "JWT" || !kidPattern.MatchString(h.KeyID) {
		return zero, errors.New("unsupported JWS header")
	}
	key := keys[h.KeyID]
	if key == nil || key.N.BitLen() < 2048 || key.E < 3 {
		return zero, errors.New("deployment signing key is not trusted")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != key.Size() {
		return zero, errors.New("invalid JWS signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return zero, errors.New("deployment envelope signature verification failed")
	}

	var claims Claims
	if err := decodeStrictJSONSegment(parts[1], &claims); err != nil {
		return zero, fmt.Errorf("invalid deployment claims: %w", err)
	}
	if expected.Issuer == "" || expected.Audience == "" {
		return zero, errors.New("expected issuer and audience must be configured")
	}
	if claims.Issuer != expected.Issuer || claims.Audience != expected.Audience ||
		claims.OrganizationID != expected.OrganizationID ||
		claims.ProjectID != expected.ProjectID ||
		claims.DeploymentID != expected.DeploymentID ||
		claims.HostingAccountID != expected.HostingAccountID ||
		claims.RepositoryID != expected.RepositoryID ||
		claims.CommitSHA != expected.CommitSHA {
		return zero, errors.New("deployment envelope identity does not match the requested deployment")
	}
	if !idPattern.MatchString(claims.OrganizationID) ||
		!idPattern.MatchString(claims.ProjectID) ||
		!idPattern.MatchString(claims.DeploymentID) ||
		!idPattern.MatchString(claims.HostingAccountID) ||
		!repositoryIDPattern.MatchString(claims.RepositoryID) ||
		!commitPattern.MatchString(claims.CommitSHA) ||
		!digestPattern.MatchString(claims.ArtifactSHA256) ||
		!hex32Pattern.MatchString(claims.JWTID) {
		return zero, errors.New("deployment envelope contains malformed identifiers")
	}
	if claims.ArtifactBytes < 1 || claims.ArtifactBytes > maxArtifactBytes {
		return zero, errors.New("deployment artifact size is outside the permitted range")
	}
	nowUnix := now.Unix()
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.IssuedAt > nowUnix+int64(clockSkew.Seconds()) ||
		claims.ExpiresAt <= nowUnix ||
		time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > maxLifetime {
		return zero, errors.New("deployment envelope is expired or has an invalid lifetime")
	}
	return claims, nil
}

func decodeStrictJSONSegment(segment string, target any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return errors.New("invalid base64url JSON segment")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

// DigestHex returns the canonical lowercase SHA-256 representation.
func DigestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
