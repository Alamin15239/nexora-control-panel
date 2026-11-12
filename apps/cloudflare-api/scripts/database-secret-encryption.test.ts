import test from "node:test";
import assert from "node:assert/strict";
import {
  generateDatabasePassword,
  encryptDatabaseSecret,
  decryptDatabaseSecret,
} from "../src/index.ts";

// ---------------------------------------------------------------------------
// database-secret-encryption.test.ts
//
// Fix 5 — secure database password reset.
//
// These tests cover the cryptographic primitives that protect database
// credentials in transit and at rest:
//
//   * generateDatabasePassword produces 24-character random passwords with
//     the full charset coverage we promise. Two consecutive calls never
//     return the same value (no PRNG seeding regression).
//   * encryptDatabaseSecret + decryptDatabaseSecret round-trip arbitrary
//     JSON payloads without truncation or mutation.
//   * Each encryption produces a fresh 12-byte IV — IV reuse would let an
//     attacker recover plaintext via the GCM keystream-reuse attack, so we
//     assert two encryptions of the same plaintext yield different IVs and
//     different ciphertexts.
//   * Tampering with the ciphertext causes decryption to fail — AES-GCM
//     authenticates the ciphertext, so any modification is detected.
//   * A ciphertext encrypted under one key cannot be decrypted under
//     another key — this guards against cross-tenant confusion if a key
//     rotation misconfiguration ever lands two tenants on the same key.
//
// The endpoint-level anti-replay and one-time-reveal guarantees are
// enforced by the SQL UPDATE in /v1/databases/:id/users/:userId/secret
// (`UPDATE ... WHERE revealed_at IS NULL AND expires_at > ? RETURNING ...`).
// The atomicity of that UPDATE is a property of D1 itself, so it cannot
// be unit-tested without a real D1 binding — it is documented in the
// PROJECT_STATUS.md hand-off instead.
// ---------------------------------------------------------------------------

const testEnv = {
  DB: {} as never,
  DATABASE_SECRET_ENCRYPTION_KEY: "a".repeat(64),
} as unknown as Parameters<typeof encryptDatabaseSecret>[0];

const otherKeyEnv = {
  DB: {} as never,
  DATABASE_SECRET_ENCRYPTION_KEY: "b".repeat(64),
} as unknown as Parameters<typeof encryptDatabaseSecret>[0];

test("generateDatabasePassword returns a 24-character alphanumeric password", () => {
  const pw = generateDatabasePassword();
  assert.equal(pw.length, 24);
  assert.match(pw, /^[A-Za-z0-9]{24}$/);
});

test("generateDatabasePassword is non-deterministic across calls", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 32; i++) {
    seen.add(generateDatabasePassword());
  }
  // 32 draws from a 62-symbol alphabet should never collide in practice.
  // If they do, the CSPRNG is broken.
  assert.equal(seen.size, 32);
});

test("encryptDatabaseSecret + decryptDatabaseSecret round-trip the credential JSON", async () => {
  const payload = JSON.stringify({ username: "wp_user", password: generateDatabasePassword() });
  const encrypted = await encryptDatabaseSecret(testEnv, payload);
  const decrypted = await decryptDatabaseSecret(testEnv, encrypted.ciphertext, encrypted.iv);
  assert.equal(decrypted, payload);
});

test("each encryption uses a fresh IV (no IV reuse)", async () => {
  const payload = JSON.stringify({ username: "u", password: "p" });
  const a = await encryptDatabaseSecret(testEnv, payload);
  const b = await encryptDatabaseSecret(testEnv, payload);
  assert.notEqual(a.iv, b.iv, "IV must not repeat across encryptions of the same plaintext");
  assert.notEqual(a.ciphertext, b.ciphertext, "ciphertext must differ when IV differs");
});

test("tampering with ciphertext causes decryption to fail", async () => {
  const payload = JSON.stringify({ username: "u", password: "secret" });
  const encrypted = await encryptDatabaseSecret(testEnv, payload);

  // Flip the first byte of the ciphertext. AES-GCM authentication tag
  // should reject the modified ciphertext.
  const decode = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
  const ct = decode(encrypted.ciphertext);
  ct[0] ^= 0x01;
  const tamperedCiphertext = encode(ct);

  // WebCrypto rejects GCM-tag failures with an OperationError. We just
  // assert decryption throws — the specific error class is not contractual.
  await assert.rejects(decryptDatabaseSecret(testEnv, tamperedCiphertext, encrypted.iv));
});

test("a ciphertext encrypted under one key cannot be decrypted under another", async () => {
  const payload = JSON.stringify({ username: "u", password: "p" });
  const encrypted = await encryptDatabaseSecret(testEnv, payload);
  await assert.rejects(decryptDatabaseSecret(otherKeyEnv, encrypted.ciphertext, encrypted.iv));
});

test("decryptDatabaseSecret rejects ciphertext truncated below the GCM tag size", async () => {
  // A ciphertext shorter than the 16-byte GCM tag cannot authenticate.
  const tooShort = btoa(String.fromCharCode(1, 2, 3));
  await assert.rejects(
    decryptDatabaseSecret(testEnv, tooShort, btoa(String.fromCharCode(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))),
  );
});
