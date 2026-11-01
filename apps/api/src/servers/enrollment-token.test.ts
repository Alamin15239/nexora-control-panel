import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createEnrollmentToken,
  hashEnrollmentToken,
  verifyEnrollmentToken,
} from "./enrollment-token";

describe("server enrollment tokens", () => {
  it("creates unique high-entropy tokens and a storage hash", () => {
    const first = createEnrollmentToken();
    const second = createEnrollmentToken();
    assert.match(first.token, /^nxa_[A-Za-z0-9_-]{43}$/);
    assert.match(first.tokenHash, /^[a-f0-9]{64}$/);
    assert.notEqual(first.token, second.token);
    assert.notEqual(first.tokenHash, second.tokenHash);
    assert.notEqual(first.token, first.tokenHash);
  });

  it("verifies only the matching token", () => {
    const { token, tokenHash } = createEnrollmentToken();
    assert.equal(verifyEnrollmentToken(token, tokenHash), true);
    assert.equal(verifyEnrollmentToken("nxa_wrong", tokenHash), false);
  });

  it("rejects malformed input and malformed stored hashes", () => {
    assert.throws(() => hashEnrollmentToken("not-a-token"));
    assert.equal(verifyEnrollmentToken("not-a-token", "0".repeat(64)), false);
    assert.equal(verifyEnrollmentToken(createEnrollmentToken().token, "bad-hash"), false);
  });
});
