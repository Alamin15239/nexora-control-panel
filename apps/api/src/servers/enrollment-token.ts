import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_PREFIX = "nxa_";
const TOKEN_BYTES = 32;

/** Create a high-entropy enrollment secret. Store only hashEnrollmentToken(token). */
export function createEnrollmentToken(): { token: string; tokenHash: string } {
  const token = TOKEN_PREFIX + randomBytes(TOKEN_BYTES).toString("base64url");
  return { token, tokenHash: hashEnrollmentToken(token) };
}

/** Hashes a token for storage. Raw enrollment tokens must never be persisted or logged. */
export function hashEnrollmentToken(token: string): string {
  if (!/^nxa_[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error("Invalid enrollment token format");
  }
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Constant-time comparison of a presented token with a stored SHA-256 hex digest. */
export function verifyEnrollmentToken(token: string, expectedHash: string): boolean {
  let actualHash: string;
  try {
    actualHash = hashEnrollmentToken(token);
  } catch {
    return false;
  }
  if (!/^[a-f0-9]{64}$/i.test(expectedHash)) return false;
  const actual = Buffer.from(actualHash, "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return timingSafeEqual(actual, expected);
}
