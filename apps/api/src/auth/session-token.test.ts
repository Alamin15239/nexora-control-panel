import assert from "node:assert/strict";
import test from "node:test";
import { signSessionToken, verifySessionToken } from "./session-token";

const secret = "test-only-session-secret-with-at-least-32-bytes";
const identity = { sub: "user-1", organizationId: "org-1", role: "OWNER" as const };

test("signs and verifies an organization-scoped session", () => {
  const token = signSessionToken(identity, secret, 1_800_000_000, 900);
  const claims = verifySessionToken(token, secret, 1_800_000_001);
  assert.ok(claims);
  assert.deepEqual(
    { ...claims, jti: undefined },
    {
      ...identity,
      jti: undefined,
      iat: 1_800_000_000,
      exp: 1_800_000_900,
      iss: "nexora-api",
      aud: "nexora-web",
    },
  );
  assert.match(claims.jti, /^[0-9a-f-]{36}$/);
});

test("rejects expired, tampered and malformed tokens", () => {
  const token = signSessionToken(identity, secret, 1_800_000_000, 60);
  assert.equal(verifySessionToken(token, secret, 1_800_000_060), null);
  assert.equal(verifySessionToken(`${token.slice(0, -1)}x`, secret, 1_800_000_001), null);
  assert.equal(verifySessionToken("not-a-token", secret), null);
});

test("rejects weak secrets and excessive lifetimes", () => {
  assert.throws(() => signSessionToken(identity, "short", 100, 60));
  assert.throws(() => signSessionToken(identity, secret, 100, 3601));
  assert.equal(verifySessionToken("a.b.c", "short"), null);
});
