package appnodeauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignAndVerifyBindsEveryRequestField(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	body := []byte("{\"deploymentId\":\"release-a\"}")
	proof, err := Sign(privateKey, "runtime-a", "POST", "/internal/v1/application-nodes/artifact", body, now)
	if err != nil { t.Fatal(err) }
	if err := Verify(publicKey, "runtime-a", "POST", "/internal/v1/application-nodes/artifact", body, proof, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, "runtime-b", "POST", "/internal/v1/application-nodes/artifact", body, proof, now); err == nil {
		t.Fatal("expected node identity mismatch")
	}
	if err := Verify(publicKey, "runtime-a", "GET", "/internal/v1/application-nodes/artifact", body, proof, now); err == nil {
		t.Fatal("expected method mismatch")
	}
	if err := Verify(publicKey, "runtime-a", "POST", "/internal/v1/application-nodes/other", body, proof, now); err == nil {
		t.Fatal("expected path mismatch")
	}
	if err := Verify(publicKey, "runtime-a", "POST", "/internal/v1/application-nodes/artifact", []byte("tampered"), proof, now); err == nil {
		t.Fatal("expected body mismatch")
	}
}

func TestVerifyRejectsExpiredProofAndInvalidPath(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	proof, err := Sign(privateKey, "runtime-a", "POST", "/artifact", nil, now.Add(-10*time.Minute))
	if err != nil { t.Fatal(err) }
	if err := Verify(publicKey, "runtime-a", "POST", "/artifact", nil, proof, now); err == nil {
		t.Fatal("expected stale request rejection")
	}
	if _, err := CanonicalMessage("runtime-a", proof.Timestamp, proof.Nonce, "POST", "/artifact?x=1", nil); err == nil {
		t.Fatal("expected query string rejection")
	}
}
