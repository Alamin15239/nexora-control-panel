package deployenvelope

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testExpected() Expected {
	return Expected{
		Issuer: "https://api.nexoraedge.digital",
		Audience: "nexora-linux-deployment-receiver",
		OrganizationID: "org_123",
		ProjectID: "project_123",
		DeploymentID: "deployment_123",
		HostingAccountID: "account_123",
		RepositoryID: "123456789",
		CommitSHA: strings.Repeat("a", 40),
	}
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, claims Claims) string {
	t.Helper()
	headerJSON, err := json.Marshal(header{Algorithm: "RS256", Type: "JWT", KeyID: "test-key-1"})
	if err != nil { t.Fatal(err) }
	claimsJSON, err := json.Marshal(claims)
	if err != nil { t.Fatal(err) }
	encode := base64.RawURLEncoding.EncodeToString
	unsigned := encode(headerJSON) + "." + encode(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil { t.Fatal(err) }
	return unsigned + "." + encode(signature)
}

func validClaims(expected Expected, now time.Time) Claims {
	return Claims{
		Issuer: expected.Issuer, Audience: expected.Audience,
		OrganizationID: expected.OrganizationID, ProjectID: expected.ProjectID,
		DeploymentID: expected.DeploymentID, HostingAccountID: expected.HostingAccountID,
		RepositoryID: expected.RepositoryID, CommitSHA: expected.CommitSHA,
		ArtifactSHA256: strings.Repeat("b", 64), ArtifactBytes: 1024,
		JWTID: strings.Repeat("c", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(4*time.Minute).Unix(),
	}
}

func TestVerifyAcceptsBoundShortLivedEnvelope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Unix(1_800_000_000, 0)
	expected := testExpected()
	token := signTestToken(t, key, validClaims(expected, now))
	claims, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &key.PublicKey}, expected, now)
	if err != nil { t.Fatalf("Verify() error = %v", err) }
	if claims.ArtifactBytes != 1024 || claims.ArtifactSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("unexpected verified claims: %+v", claims)
	}
}

func TestVerifyRejectsIdentityMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)
	expected := testExpected()
	claims := validClaims(expected, now)
	claims.HostingAccountID = "different-account"
	token := signTestToken(t, key, claims)
	if _, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &key.PublicKey}, expected, now); err == nil {
		t.Fatal("Verify() accepted an envelope for another hosting account")
	}
}

func TestVerifyRejectsExpiredAndLongLivedEnvelope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)
	expected := testExpected()
	for name, mutate := range map[string]func(*Claims){
		"expired": func(c *Claims) { c.ExpiresAt = now.Unix() },
		"long-lived": func(c *Claims) { c.ExpiresAt = c.IssuedAt + 301 },
		"future-issued": func(c *Claims) { c.IssuedAt = now.Unix() + 31 },
	} {
		t.Run(name, func(t *testing.T) {
			claims := validClaims(expected, now)
			mutate(&claims)
			token := signTestToken(t, key, claims)
			if _, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &key.PublicKey}, expected, now); err == nil {
				t.Fatal("Verify() accepted invalid time claims")
			}
		})
	}
}

func TestVerifyRejectsUntrustedKeyAndOversizedArtifact(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)
	expected := testExpected()
	claims := validClaims(expected, now)
	token := signTestToken(t, key, claims)
	if _, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &other.PublicKey}, expected, now); err == nil {
		t.Fatal("Verify() accepted an untrusted signing key")
	}
	claims.ArtifactBytes = maxArtifactBytes + 1
	token = signTestToken(t, key, claims)
	if _, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &key.PublicKey}, expected, now); err == nil {
		t.Fatal("Verify() accepted an oversized artifact")
	}
}

func TestVerifyRejectsUnknownClaimsAndMalformedToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)
	expected := testExpected()
	claims := validClaims(expected, now)
	raw, _ := json.Marshal(claims)
	raw = append(raw[:len(raw)-1], []byte(", \"untrusted\": true}")...)
	headerJSON, _ := json.Marshal(header{Algorithm: "RS256", Type: "JWT", KeyID: "test-key-1"})
	encode := base64.RawURLEncoding.EncodeToString
	unsigned := encode(headerJSON) + "." + encode(raw)
	digest := sha256.Sum256([]byte(unsigned))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	token := unsigned + "." + encode(signature)
	if _, err := Verify(token, map[string]*rsa.PublicKey{"test-key-1": &key.PublicKey}, expected, now); err == nil {
		t.Fatal("Verify() accepted an unknown claim")
	}
	if _, err := Verify("not.a.valid.token", nil, expected, now); err == nil {
		t.Fatal("Verify() accepted malformed token")
	}
}
