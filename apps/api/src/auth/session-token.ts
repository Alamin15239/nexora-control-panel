import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export interface SessionClaims {
  sub: string;
  jti: string;
  organizationId: string;
  role: "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

const ISSUER = "nexora-api";
const AUDIENCE = "nexora-web";
const MAX_TOKEN_LENGTH = 4096;

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signature(input: string, secret: string): Buffer {
  return createHmac("sha256", secret).update(input).digest();
}

export function signSessionToken(
  input: Omit<SessionClaims, "iat" | "exp" | "iss" | "aud" | "jti">,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1000),
  lifetimeSeconds = 15 * 60,
): string {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 bytes");
  }
  if (!input.sub || !input.organizationId || !input.role) {
    throw new Error("Session subject, organization and role are required");
  }
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 3600) {
    throw new Error("Session lifetime must be between 1 and 3600 seconds");
  }

  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({
    ...input,
    jti: randomUUID(),
    iat: nowSeconds,
    exp: nowSeconds + lifetimeSeconds,
    iss: ISSUER,
    aud: AUDIENCE,
  } satisfies SessionClaims);
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${signature(signingInput, secret).toString("base64url")}`;
}

export function verifySessionToken(
  token: string,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): SessionClaims | null {
  if (Buffer.byteLength(secret, "utf8") < 32 || token.length > MAX_TOKEN_LENGTH) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  try {
    const [headerPart, payloadPart, signaturePart] = parts;
    const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8")) as Record<string, unknown>;
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;

    const expected = signature(`${headerPart}.${payloadPart}`, secret);
    const supplied = Buffer.from(signaturePart, "base64url");
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;

    const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as SessionClaims;
    if (
      typeof claims.sub !== "string" || !claims.sub ||
      typeof claims.jti !== "string" || !claims.jti ||
      typeof claims.organizationId !== "string" || !claims.organizationId ||
      !["OWNER", "ADMIN", "BILLING", "SUPPORT", "MEMBER"].includes(claims.role) ||
      !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
      claims.iat > nowSeconds + 60 || claims.exp <= nowSeconds ||
      claims.exp <= claims.iat || claims.exp - claims.iat > 3600 ||
      claims.iss !== ISSUER || claims.aud !== AUDIENCE
    ) return null;

    return claims;
  } catch {
    return null;
  }
}
