import { Hono } from "hono";
import { ensureSaasDnsRecord } from "./cloudflare-dns";
import { createDnsRecord, deleteDnsRecord, listDnsRecords, updateDnsRecord } from "./dns-records";
import { pruneFailedDeploymentArtifacts } from "./artifact-retention";
import { isRuntimeAssignmentAdmitted } from "./runtime-admission";

type Bindings = {
  DB: D1Database;
  ALLOW_PUBLIC_REGISTRATION?: string;
  CLOUDFLARE_API_TOKEN?: string;
  CLOUDFLARE_DNS_API_TOKEN?: string;
  CLOUDFLARE_ZONE_NAME?: string;
  CLOUDFLARE_ZONE_ID?: string;
  CLOUDFLARE_SAAS_TARGET?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  DATABASE_SECRET_ENCRYPTION_KEY?: string;
  GITHUB_APP_CLIENT_ID?: string;
  GITHUB_APP_CLIENT_SECRET?: string;
  GITHUB_OAUTH_CALLBACK_URL?: string;
  GITHUB_TOKEN_ENCRYPTION_KEY?: string;
  DEPLOY_ENV_ENCRYPTION_KEY?: string;
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  GITHUB_APP_SLUG?: string;
  GITHUB_OIDC_AUDIENCE?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_PRIVATE_KEY?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_KEY_ID?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_ISSUER?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_AUDIENCE?: string;
  ARTIFACTS?: R2Bucket;
  DASHBOARD_URL?: string;
  APPLICATION_NODE_OPERATOR_TOKEN?: string;
  MFA_ENCRYPTION_KEY?: string;
  PAYMENT_WEBHOOK_SECRET?: string;
  EMAIL_PROVIDER?: string;
  EMAIL_PROVIDER_API_URL?: string;
  EMAIL_PROVIDER_API_TOKEN?: string;
  EMAIL_MAIL_HOST?: string;
};

type Role = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";
type PlatformRole = "PLATFORM_OWNER" | "PLATFORM_ADMIN";

const app = new Hono<{ Bindings: Bindings }>();
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const PASSWORD_ITERATIONS = 100_000;
// MFA challenge hardening constants.
// MFA_CHALLENGE_TTL_MS: how long a login challenge remains valid once issued.
//   10 minutes is long enough for a user to switch to their authenticator app
//   and type the 6-digit code, but short enough that a leaked challengeId
//   cannot be brute-forced (combined with the 5-attempt cap below).
// MAX_MFA_FAILED_ATTEMPTS: per-challenge attempt cap. After this many invalid
//   code submissions the challenge is locked and the user must restart login.
//   A 6-digit TOTP has 1,000,000 possible values; capping attempts at 5 makes
//   the per-challenge success probability of brute force 5e-6, which is
//   negligible.
const MFA_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const MAX_MFA_FAILED_ATTEMPTS = 5;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function randomHex(length: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(length)));
}

export function generateDatabasePassword(): string {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let password = "";
  for (let i = 0; i < 24; i++) {
    password += charset[bytes[i] % charset.length];
  }
  return password;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return hex(new Uint8Array(digest));
}


function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function utf8Base64Url(value: string): string {
  return base64UrlEncode(new TextEncoder().encode(value));
}

function decodePKCS8PEM(pem: string): Uint8Array {
  const normalized = pem.trim();
  const match = /^-----BEGIN PRIVATE KEY-----([\s\S]+)-----END PRIVATE KEY-----$/.exec(normalized);
  if (!match) throw new Error("Deployment signing key must be an unencrypted PKCS#8 PEM private key");
  const base64 = match[1].replace(/\s/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

type DeploymentEnvelopeInput = {
  organizationId: string;
  projectId: string;
  deploymentId: string;
  hostingAccountId: string;
  domainId: string;
  hostname: string;
  repositoryId: string;
  commitSha: string;
  artifactSha256: string;
  artifactBytes: number;
};

async function signDeploymentEnvelope(env: Bindings, input: DeploymentEnvelopeInput): Promise<string> {
  const privateKeyPEM = env.GITHUB_DEPLOYMENT_ENVELOPE_PRIVATE_KEY;
  const keyId = env.GITHUB_DEPLOYMENT_ENVELOPE_KEY_ID ?? "";
  const issuer = env.GITHUB_DEPLOYMENT_ENVELOPE_ISSUER ?? "";
  const audience = env.GITHUB_DEPLOYMENT_ENVELOPE_AUDIENCE ?? "";
  if (!privateKeyPEM || !/^[A-Za-z0-9._-]{1,64}$/.test(keyId) || !issuer || !audience) {
    throw new Error("Deployment envelope signing is not configured");
  }
  if (!/^[a-f0-9]{40}$/.test(input.commitSha) ||
      !/^[a-f0-9]{64}$/.test(input.artifactSha256) ||
      !Number.isSafeInteger(input.artifactBytes) || input.artifactBytes < 1 || input.artifactBytes > 100 * 1024 * 1024) {
    throw new Error("Deployment envelope artifact claims are invalid");
  }
  for (const value of [input.organizationId, input.projectId, input.deploymentId, input.hostingAccountId, input.domainId]) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new Error("Deployment envelope identity is invalid");
  }
  if (input.hostname !== input.hostname.toLowerCase() || input.hostname.length > 253 ||
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(input.hostname)) {
    throw new Error("Deployment envelope hostname is invalid");
  }
  if (!/^[1-9][0-9]{0,19}$/.test(input.repositoryId)) throw new Error("Deployment repository ID is invalid");

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer,
    aud: audience,
    organization_id: input.organizationId,
    project_id: input.projectId,
    deployment_id: input.deploymentId,
    hosting_account_id: input.hostingAccountId,
    domain_id: input.domainId,
    hostname: input.hostname,
    repository_id: input.repositoryId,
    commit_sha: input.commitSha,
    artifact_sha256: input.artifactSha256,
    artifact_bytes: input.artifactBytes,
    jti: randomHex(16),
    iat: now,
    exp: now + 300,
  };
  const header = { alg: "RS256", typ: "JWT", kid: keyId };
  const signingInput = utf8Base64Url(JSON.stringify(header)) + "." + utf8Base64Url(JSON.stringify(claims));
  const key = await crypto.subtle.importKey(
    "pkcs8",
    decodePKCS8PEM(privateKeyPEM),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );
  return signingInput + "." + base64UrlEncode(new Uint8Array(signature));
}


function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return hex(new Uint8Array(signature));
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PASSWORD_ITERATIONS },
    key,
    256,
  );
  return `pbkdf2-sha256$${PASSWORD_ITERATIONS}$${hex(salt)}$${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  const [algorithm, iterationText, saltHex, expectedHex] = stored.split("$");
  const iterations = Number(iterationText);
  if (algorithm !== "pbkdf2-sha256" || !Number.isInteger(iterations) || iterations < 100_000 || iterations > 1_000_000 || !/^[a-f0-9]{32}$/.test(saltHex ?? "") || !/^[a-f0-9]{64}$/.test(expectedHex ?? "")) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  const actual = new Uint8Array(bits);
  let difference = 0;
  for (let i = 0; i < actual.length; i++) difference |= actual[i] ^ Number.parseInt(expectedHex.slice(i * 2, i * 2 + 2), 16);
  return difference === 0;
}

function databaseSecretKey(env: Bindings): Uint8Array {
  const value = env.DATABASE_SECRET_ENCRYPTION_KEY ?? "";
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error("Database credential encryption is not configured");
  return new Uint8Array(value.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
}
function base64(bytes: Uint8Array): string {
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary);
}
export async function encryptDatabaseSecret(env: Bindings, plaintext: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", databaseSecretKey(env), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: base64(iv), ciphertext: base64(new Uint8Array(ciphertext)) };
}
export async function decryptDatabaseSecret(env: Bindings, ciphertext: string, iv: string): Promise<string> {
  const decode = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", databaseSecretKey(env), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(iv) }, key, decode(ciphertext));
  return new TextDecoder().decode(plaintext);
}

// isUniqueConstraintError reports whether a D1/SQLite error is a UNIQUE
// constraint violation. D1 wraps the SQLite error in various shapes
// (message, cause.message), so we walk the chain looking for the
// constraint marker. Used to distinguish a legitimate exclusion conflict
// (another active backup already exists → 409) from unrelated database
// failures (→ 500, must not be swallowed).
export function isUniqueConstraintError(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current; depth++) {
    if (current instanceof Error) {
      if (/UNIQUE constraint failed/i.test(current.message)) return true;
      current = (current as Error & { cause?: unknown }).cause;
    } else if (typeof current === "string") {
      return /UNIQUE constraint failed/i.test(current);
    } else if (current && typeof current === "object" && "message" in current) {
      const message = String((current as { message: unknown }).message);
      if (/UNIQUE constraint failed/i.test(message)) return true;
      current = (current as { cause?: unknown }).cause;
    } else {
      return false;
    }
  }
  return false;
}

function normalizeEmail(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function validEmail(email: string): boolean {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function slugBase(value: string): string {
  return value.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 42) || "workspace";
}

async function issueSession(db: D1Database, userId: string, organizationId: string, role: Role) {
  const token = randomHex(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_SECONDS * 1000).toISOString();
  await db.prepare(
    "INSERT INTO auth_sessions (id, user_id, organization_id, token_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), userId, organizationId, crypto.randomUUID(), await sha256(token), expiresAt).run();

  return {
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: SESSION_SECONDS,
    organizationId,
    role,
  };
}

function decodeHex(value: string, expectedBytes: number): Uint8Array | null {
  if (value.length !== expectedBytes * 2 || !/^[a-f0-9]+$/i.test(value)) return null;
  const bytes = new Uint8Array(expectedBytes);
  for (let index = 0; index < expectedBytes; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function verifyNodeSignature(publicKeyHex: string, timestamp: string, nonce: string, rawBody: string, signatureHex: string) {
  if (!/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32,128}$/i.test(nonce)) return false;
  const issuedAt = Number(timestamp);
  if (!Number.isSafeInteger(issuedAt) || Math.abs(Math.floor(Date.now() / 1000) - issuedAt) > 300) return false;
  const publicKey = decodeHex(publicKeyHex, 32);
  const signature = decodeHex(signatureHex, 64);
  if (!publicKey || !signature) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    const message = new TextEncoder().encode(timestamp + "." + nonce + "." + rawBody);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

async function verifyApplicationNodeRequestSignature(
  publicKeyHex: string, nodeIdentity: string, timestamp: string, nonce: string,
  method: string, path: string, rawBody: string, signatureHex: string,
): Promise<boolean> {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      method !== method.toUpperCase() || !path.startsWith("/") || /[?#\r\n]/.test(path)) return false;
  const issuedAt = Number(timestamp);
  if (!Number.isSafeInteger(issuedAt) || Math.abs(Math.floor(Date.now() / 1000) - issuedAt) > 300) return false;
  const publicKey = decodeHex(publicKeyHex, 32);
  const signature = decodeHex(signatureHex, 64);
  if (!publicKey || !signature) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    const message = [
      "NEXORA-APPLICATION-NODE-V1", nodeIdentity, timestamp, nonce, method, path, await sha256(rawBody),
    ].join("\n");
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

async function nodeOperatorAuthorized(request: Request, env: Bindings): Promise<boolean> {
  const configured = env.APPLICATION_NODE_OPERATOR_TOKEN ?? "";
  const supplied = request.headers.get("authorization") ?? "";
  if (configured.length < 32 || !/^Bearer [A-Za-z0-9_-]{32,}$/.test(supplied)) return false;
  return constantTimeEqual(supplied.slice(7), configured);
}

async function bearerIdentity(request: Request, db: D1Database) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+([a-f0-9]{64})$/i.exec(authorization);
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  return db.prepare(
    `SELECT u.id, u.email, u.display_name AS displayName,
            o.id AS organizationId, o.name AS organizationName, o.slug AS organizationSlug,
            m.role, pm.role AS platformRole
     FROM auth_sessions s
     JOIN users u ON u.id = s.user_id
     JOIN memberships m ON m.user_id = u.id AND m.organization_id = s.organization_id
     JOIN organizations o ON o.id = s.organization_id
     LEFT JOIN platform_memberships pm ON pm.user_id = u.id AND pm.status = 'ACTIVE'
     WHERE s.token_hash = ? AND s.revoked_at IS NULL
       AND s.expires_at > ? AND u.status = 'ACTIVE' AND o.status = 'ACTIVE'
     LIMIT 1`,
  ).bind(tokenHash, new Date().toISOString()).first<{
    id: string; email: string; displayName: string | null;
    organizationId: string; organizationName: string; organizationSlug: string; role: Role; platformRole: PlatformRole | null;
  }>();
}

/**
 * Customer logins (MEMBER) are confined to the account-scoped cPanel API.
 * All WHM/control-plane routes are denied by default for customer identities.
 * Customer endpoints independently verify hosting_account_memberships, while
 * internal node endpoints use their own signed/operator authentication.
 */
app.use("/v1/*", async (c, next) => {
  const path = c.req.path;
  if (
    path === "/v1/health" ||
    path === "/v1/health/ready" ||
    path === "/v1/health/schema" ||
    path.startsWith("/v1/auth/") ||
    path.startsWith("/v1/customer/") ||
    path.startsWith("/v1/store/") ||
    path.startsWith("/v1/applications/") ||
    path.startsWith("/v1/internal/") ||
    path.startsWith("/v1/agent/") ||
    path === "/v1/audit-logs" ||
    path === "/v1/sessions" || path.startsWith("/v1/sessions/") ||
    path.startsWith("/v1/organizations/") ||
    // Subscriptions, invoices, and email hosting are managed by organization
    // OWNER/ADMIN as well as platform staff; each route enforces roles
    // internally (see the organization-administration and billing sections).
    path === "/v1/subscriptions" || path.startsWith("/v1/subscriptions/") ||
    path === "/v1/invoices" || path.startsWith("/v1/invoices/") ||
    path.startsWith("/v1/email/") ||
    // Payment-provider webhooks authenticate with an HMAC signature header,
    // not a session; the handler rejects unsigned or stale requests.
    path.startsWith("/v1/billing/webhooks/") ||
    path === "/v1/github/callback" ||
    path === "/v1/github/connection" || path === "/v1/github/connect" ||
    path === "/v1/github/repositories" || path === "/v1/github/projects" ||
    path.startsWith("/v1/github/deployments/") ||
    // Nexora Deploy project-scoped routes authenticate inside their handlers
    // (organization role or active hosting-account membership, mirroring
    // POST /v1/github/projects); they must not be gated to platform staff.
    /^\/v1\/github\/projects\/[0-9a-fA-F-]{36}\/env-vars(\/[0-9a-fA-F-]{36})?$/.test(path) ||
    path === "/v1/github/projects/detect-framework" ||
    // Nexora Deploy helper catalog (framework presets); handlers authenticate
    // with bearerIdentity and are safe for customer identities.
    path.startsWith("/v1/deploy/")
  ) {
    await next();
    return;
  }

  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!identity.platformRole) {
    return c.json({ message: "Customer accounts cannot access WHM administration." }, 403);
  }
  await next();
});

app.get("/v1/health", (c) =>
  c.json({ service: "nexora-api", status: "ok", runtime: "cloudflare-workers" }),
);

app.get("/v1/health/ready", async (c) => {
  try {
    await c.env.DB.prepare("SELECT 1").first();
    return c.json({ status: "ready", database: "connected" });
  } catch {
    return c.json({ status: "not_ready", database: "unavailable" }, 503);
  }
});

app.get("/v1/health/schema", async (c) => {
  const expected = ["users", "organizations", "memberships", "platform_memberships", "auth_sessions", "login_attempts", "servers", "hosting_plans", "hosting_accounts", "hosting_account_memberships", "domains", "hosting_databases", "hosting_database_users", "agent_credentials", "agent_nonces", "provisioning_jobs", "audit_logs", "server_service_checks", "server_incidents", "incident_notification_settings", "incident_notification_outbox", "hosting_backups", "github_connections", "github_oauth_states", "github_projects", "github_deployments", "github_deployment_upload_tokens", "application_runtime_profiles", "application_node_pools", "application_nodes", "application_project_settings", "application_releases", "application_release_events", "application_workloads", "application_usage_periods", "application_usage_events", "application_node_request_nonces", "application_node_signing_key_history", "application_rollback_acknowledgements", "payment_settings", "payment_orders", "application_env_vars", "application_deployment_aliases", "github_webhook_deliveries"];
  try {
    const rows = await c.env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (" + expected.map(() => "?").join(",") + ")",
    ).bind(...expected).all<{ name: string }>();
    const found = new Set((rows.results ?? []).map((row) => row.name));
    const missing = expected.filter((name) => !found.has(name));
    return c.json({ status: missing.length ? "incomplete" : "ready", tablesChecked: expected.length, missing }, missing.length ? 503 : 200);
  } catch {
    return c.json({ status: "unavailable", message: "Unable to inspect database schema" }, 503);
  }
});

app.post("/v1/auth/register", async (c) => {
  if (c.env.ALLOW_PUBLIC_REGISTRATION !== "true") {
    return c.json({ message: "Public registration is disabled. Ask the platform administrator for an invitation." }, 403);
  }

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const email = normalizeEmail(input.email);
  const name = typeof input.name === "string" ? input.name.trim() : "";
  const organizationName = typeof input.organizationName === "string" ? input.organizationName.trim() : "";
  const password = typeof input.password === "string" ? input.password : "";

  if (!validEmail(email)) return c.json({ message: "Enter a valid email address" }, 400);
  if (!name || name.length > 100 || !organizationName || organizationName.length > 120) {
    return c.json({ message: "Name and organization name are required" }, 400);
  }
  if (password.length < 12 || password.length > 128) {
    return c.json({ message: "Password must be between 12 and 128 characters" }, 400);
  }

  // Limit customer registration by source IP to reduce automated public sign-up abuse.
  const registrationIp = c.req.header("CF-Connecting-IP") ?? "unknown";
  const registrationBucket = await sha256("register|" + registrationIp);
  const registrationLimit = await c.env.DB.prepare(
    "SELECT attempts, window_start AS windowStart, blocked_until AS blockedUntil FROM login_attempts WHERE bucket_key = ?",
  ).bind(registrationBucket).first<{ attempts: number; windowStart: string; blockedUntil: string | null }>();
  const registrationNow = Date.now();
  if (registrationLimit?.blockedUntil && Date.parse(registrationLimit.blockedUntil) > registrationNow) {
    return c.json({ message: "Too many workspace registrations from this network. Try again later." }, 429);
  }
  const registrationWindowExpired = !registrationLimit || registrationNow - Date.parse(registrationLimit.windowStart) >= 60 * 60 * 1000;
  const registrationAttempts = registrationWindowExpired ? 1 : registrationLimit.attempts + 1;
  const registrationBlockedUntil = registrationAttempts >= 5
    ? new Date(registrationNow + 60 * 60 * 1000).toISOString()
    : null;
  await c.env.DB.prepare(
    `INSERT INTO login_attempts (id, bucket_key, attempts, window_start, blocked_until, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(bucket_key) DO UPDATE SET attempts = excluded.attempts,
     window_start = excluded.window_start, blocked_until = excluded.blocked_until, updated_at = excluded.updated_at`,
  ).bind(crypto.randomUUID(), registrationBucket, registrationAttempts,
    registrationWindowExpired ? new Date(registrationNow).toISOString() : registrationLimit.windowStart,
    registrationBlockedUntil, new Date(registrationNow).toISOString()).run();

  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const slug = `${slugBase(organizationName)}-${randomHex(4)}`;
  try {
    const passwordHash = await hashPassword(password);
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO users (id, email, password_hash, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
        .bind(userId, email, passwordHash, name),
      c.env.DB.prepare("INSERT INTO organizations (id, name, slug, status) VALUES (?, ?, ?, 'ACTIVE')")
        .bind(organizationId, organizationName, slug),
      c.env.DB.prepare("INSERT INTO memberships (id, user_id, organization_id, role) VALUES (?, ?, ?, 'OWNER')")
        .bind(membershipId, userId, organizationId),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.register', 'organization', ?)")
        .bind(crypto.randomUUID(), organizationId, userId, organizationId),
    ]);
    const session = await issueSession(c.env.DB, userId, organizationId, "OWNER");
    return c.json({
      user: { id: userId, email, displayName: name },
      organization: { id: organizationId, name: organizationName, slug },
      ...session,
    }, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: users\.email/i.test(message)) {
      return c.json({ message: "An account with this email already exists" }, 409);
    }
    return c.json({ message: "Unable to create the workspace" }, 500);
  }
});

app.post("/v1/auth/forgot-password", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "If the account exists, a password reset link will be sent." }); }

  const email = normalizeEmail(input.email);
  const generic = { message: "If the account exists, a password reset link will be sent." };
  if (!validEmail(email)) return c.json(generic);

  const user = await c.env.DB.prepare(
    "SELECT id, email, display_name AS displayName FROM users WHERE email = ? COLLATE NOCASE AND status = 'ACTIVE' LIMIT 1",
  ).bind(email).first<{ id: string; email: string; displayName: string | null }>();
  if (!user) return c.json(generic);

  const now = new Date();
  const nowIso = now.toISOString();
  const recent = await c.env.DB.prepare(
    "SELECT created_at AS createdAt FROM password_reset_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
  ).bind(user.id).first<{ createdAt: string }>();
  if (recent && now.getTime() - Date.parse(recent.createdAt) < 60_000) return c.json(generic);

  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000).toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL")
      .bind(nowIso, user.id),
    c.env.DB.prepare("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), user.id, tokenHash, expiresAt, nowIso),
  ]);

  if (!c.env.RESEND_API_KEY || !c.env.EMAIL_FROM) {
    console.error("Password reset requested but Resend is not configured on nexora-api");
    return c.json({ message: "Password recovery email is temporarily unavailable. Contact your platform administrator." }, 503);
  }

  const baseUrl = (c.env.DASHBOARD_URL || "https://web.nexoraedge.digital").replace(/\/$/, "");
  const resetUrl = baseUrl + "/reset-password?token=" + encodeURIComponent(token);
  const safeName = escapeEmailHtml(user.displayName || "there");
  const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#172033">
    <h2>Reset your Nexora password</h2><p>Hello ${safeName},</p>
    <p>We received a request to reset your Nexora Control password. Use the secure link below within 30 minutes.</p>
    <p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;text-decoration:none;border-radius:8px">Reset password</a></p>
    <p>If you did not request this, you can ignore this email. Your password will not change.</p>
    <p style="font-size:12px;color:#64748b">This link can only be used once and expires in 30 minutes.</p>
  </div>`;
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${c.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: c.env.EMAIL_FROM, to: [user.email], subject: "Reset your Nexora password", html }),
    });
    if (!response.ok) {
      const details = (await response.text()).slice(0, 500);
      console.error("Password reset email rejected:", response.status, details);
      return c.json({ message: "Password recovery email could not be sent. Please check the email service configuration and try again." }, 503);
    }
  } catch (error) {
    console.error("Password reset email delivery failed:", error);
    return c.json({ message: "Password recovery email could not be sent. Please try again later." }, 503);
  }

  return c.json(generic);
});

app.post("/v1/auth/reset-password", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid reset request" }, 400); }

  const token = typeof input.token === "string" ? input.token.trim() : "";
  const password = typeof input.password === "string" ? input.password : "";
  if (!/^[a-f0-9]{64}$/i.test(token)) return c.json({ message: "This reset link is invalid or has expired. Request a new one." }, 400);
  if (password.length < 12 || password.length > 128) {
    return c.json({ message: "Password must be between 12 and 128 characters" }, 400);
  }

  const tokenHash = await sha256(token);
  const now = new Date().toISOString();
  const reset = await c.env.DB.prepare(
    "SELECT id, user_id AS userId FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? LIMIT 1",
  ).bind(tokenHash, now).first<{ id: string; userId: string }>();
  if (!reset) return c.json({ message: "This reset link is invalid or has expired. Request a new one." }, 400);

  const claimed = await c.env.DB.prepare(
    "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
  ).bind(now, reset.id, now).run();
  if ((claimed.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "This reset link is invalid or has expired. Request a new one." }, 400);
  }

  const passwordHash = await hashPassword(password);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ? AND status = 'ACTIVE'").bind(passwordHash, reset.userId),
    c.env.DB.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, reset.userId),
    c.env.DB.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL").bind(now, reset.userId),
  ]);
  return c.json({ success: true, message: "Your password has been reset. Sign in with your new password." });
});

app.post("/v1/auth/login", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const email = normalizeEmail(input.email);
  const password = typeof input.password === "string" ? input.password : "";
  const organizationKey = typeof input.organizationId === "string" ? input.organizationId.trim() : "";
  if (!validEmail(email) || !password || !organizationKey) {
    return c.json({ message: "Email, password and organization ID are required" }, 400);
  }

  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  const bucketKey = await sha256(`${email}| ${ip}`);
  const limiter = await c.env.DB.prepare("SELECT attempts, window_start AS windowStart, blocked_until AS blockedUntil FROM login_attempts WHERE bucket_key = ?")
    .bind(bucketKey).first<{ attempts: number; windowStart: string; blockedUntil: string | null }>();
  const now = Date.now();
  if (limiter?.blockedUntil && Date.parse(limiter.blockedUntil) > now) {
    return c.json({ message: "Too many sign-in attempts. Try again later." }, 429);
  }

  const user = await c.env.DB.prepare(
    "SELECT id, email, password_hash AS passwordHash, display_name AS displayName, status FROM users WHERE email = ? COLLATE NOCASE LIMIT 1",
  ).bind(email).first<{ id: string; email: string; passwordHash: string | null; displayName: string | null; status: string }>();

  const membership = user?.status === "ACTIVE" ? await c.env.DB.prepare(
    `SELECT m.organization_id AS organizationId, m.role, pm.role AS platformRole
     FROM memberships m JOIN organizations o ON o.id = m.organization_id
     LEFT JOIN platform_memberships pm ON pm.user_id = m.user_id AND pm.status = 'ACTIVE'
     WHERE m.user_id = ? AND o.status = 'ACTIVE' AND (o.id = ? OR o.slug = ?) LIMIT 1`,
  ).bind(user.id, organizationKey, organizationKey).first<{ organizationId: string; role: Role; platformRole: PlatformRole | null }>() : null;

  const passwordValid = await verifyPassword(password, user?.passwordHash ?? null);
  if (!user || user.status !== "ACTIVE" || !membership || !passwordValid) {
    const expiredWindow = !limiter || now - Date.parse(limiter.windowStart) >= LOGIN_WINDOW_MS;
    const attempts = expiredWindow ? 1 : limiter.attempts + 1;
    const blockedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(now + LOGIN_WINDOW_MS).toISOString() : null;
    await c.env.DB.prepare(
      `INSERT INTO login_attempts (id, bucket_key, user_id, attempts, window_start, blocked_until, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(bucket_key) DO UPDATE SET user_id = excluded.user_id, attempts = excluded.attempts,
       window_start = excluded.window_start, blocked_until = excluded.blocked_until, updated_at = excluded.updated_at`,
    ).bind(crypto.randomUUID(), bucketKey, user?.id ?? null, attempts,
      expiredWindow ? new Date(now).toISOString() : limiter.windowStart, blockedUntil, new Date(now).toISOString()).run();
    return c.json({ message: "Invalid email, password or organization" }, 401);
  }

  await c.env.DB.prepare("DELETE FROM login_attempts WHERE bucket_key = ?").bind(bucketKey).run();
  const role = membership.role as Role;

  // MFA enforcement: if the user has an active TOTP factor (backup_codes IS
  // NOT NULL means enrollment has been completed and verified), do NOT issue
  // a session. Instead, create an mfa_challenges row and return its id so the
  // dashboard can collect the 6-digit code and submit it to /v1/auth/login/mfa.
  // The challenge row is the only authorization to complete MFA — the password
  // has already been verified at this point, so the challenge is bound to the
  // authenticated user_id + organization_id pair.
  //
  // A new challengeId is generated for every successful password login. This
  // means each MFA-protected sign-in gets exactly one challenge with its own
  // 5-attempt cap and 10-minute expiry. Replaying an old challengeId after a
  // fresh login is rejected because the old row is either consumed or expired.
  const mfaFactor = await c.env.DB.prepare(
    "SELECT id FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL LIMIT 1",
  ).bind(user.id).first<{ id: string }>();
  if (mfaFactor) {
    const challengeId = crypto.randomUUID();
    const expiresAt = new Date(now + MFA_CHALLENGE_TTL_MS).toISOString();
    await c.env.DB.prepare(
      "INSERT INTO mfa_challenges (id, user_id, organization_id, expires_at) VALUES (?, ?, ?, ?)",
    ).bind(challengeId, user.id, membership.organizationId, expiresAt).run();
    // Audit the challenge creation so failed-MFA incidents can be traced back
    // to the password-valid login attempt that started them. The actor is the
    // user whose password was just verified; no session has been issued yet.
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, source_ip) VALUES (?, ?, ?, 'auth.login_mfa_challenge', 'mfa_challenge', ?, ?)",
    ).bind(crypto.randomUUID(), membership.organizationId, user.id, challengeId, ip).run();
    return c.json({
      mfaRequired: true,
      challengeId,
      expiresAt,
      message: "Enter the 6-digit code from your authenticator app.",
    });
  }

  const customerAccess = await c.env.DB.prepare(
    "SELECT 1 AS active FROM hosting_account_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(user.id).first<{ active: number }>();
  const session = await issueSession(c.env.DB, user.id, membership.organizationId, role);
  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, source_ip) VALUES (?, ?, ?, 'auth.login', 'user', ?, ?)",
  ).bind(crypto.randomUUID(), membership.organizationId, user.id, user.id, ip).run();

  return c.json({
    user: { id: user.id, email: user.email, displayName: user.displayName },
    customerAccess: Boolean(customerAccess),
    platformRole: membership.platformRole,
    ...session,
  });
});

app.get("/v1/overview", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);

  const now = Date.now();
  const onlineCutoff = new Date(now - 3 * 60 * 1000).toISOString();
  try {
    const [servers, onlineServers, accounts, domains, plans, databases, schemaRows] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM servers WHERE organization_id = ?").bind(identity.organizationId).first<{ count: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM servers WHERE organization_id = ? AND status = 'ONLINE' AND last_heartbeat_at >= ?").bind(identity.organizationId, onlineCutoff).first<{ count: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM hosting_accounts WHERE organization_id = ? AND status != 'DELETED'").bind(identity.organizationId).first<{ count: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM domains d JOIN hosting_accounts h ON h.id = d.hosting_account_id WHERE h.organization_id = ?").bind(identity.organizationId).first<{ count: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM hosting_plans WHERE organization_id = ? AND active = 1").bind(identity.organizationId).first<{ count: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS count FROM hosting_databases WHERE organization_id = ?").bind(identity.organizationId).first<{ count: number }>(),
      c.env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users','organizations','memberships','auth_sessions','servers','hosting_plans','hosting_accounts','domains','hosting_databases','agent_credentials','server_telemetry','server_service_checks','server_incidents','hosting_backups')").all<{ name: string }>(),
    ]);
    const requiredTables = ["users", "organizations", "memberships", "auth_sessions", "servers", "hosting_plans", "hosting_accounts", "domains", "hosting_databases", "agent_credentials", "server_telemetry", "server_service_checks", "server_incidents", "hosting_backups"];
    const presentTables = new Set((schemaRows.results ?? []).map((row) => row.name));
    const schemaReady = requiredTables.every((name) => presentTables.has(name));
    return c.json({
      counts: {
        servers: servers?.count ?? 0,
        onlineServers: onlineServers?.count ?? 0,
        hostingAccounts: accounts?.count ?? 0,
        websites: domains?.count ?? 0,
        hostingPlans: plans?.count ?? 0,
        databases: databases?.count ?? 0,
      },
      checks: {
        api: true,
        database: true,
        schema: schemaReady,
        agent: (onlineServers?.count ?? 0) > 0,
        server: (onlineServers?.count ?? 0) > 0,
      },
      updatedAt: new Date(now).toISOString(),
    });
  } catch {
    return c.json({ message: "Unable to load infrastructure overview" }, 503);
  }
});

app.get("/v1/auth/me", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const customerAccess = await c.env.DB.prepare(
    "SELECT 1 AS active FROM hosting_account_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(identity.id).first<{ active: number }>();
  // Return mfaEnrolled so the dashboard security page can render the
  // correct status (Enabled / Not configured) without making a second
  // request. A factor is "enrolled" only when backup_codes IS NOT NULL,
  // i.e. the user has completed the verify step after enrollment. A pending
  // enrollment (factor exists but backup_codes IS NULL) does not count as
  // enrolled because it cannot gate login.
  const mfaFactor = await c.env.DB.prepare(
    "SELECT 1 AS active FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL LIMIT 1",
  ).bind(identity.id).first<{ active: number }>();
  return c.json({
    id: identity.id,
    email: identity.email,
    displayName: identity.displayName,
    organization: { id: identity.organizationId, name: identity.organizationName, slug: identity.organizationSlug },
    role: identity.role,
    platformRole: identity.platformRole,
    customerAccess: Boolean(customerAccess),
    mfaEnrolled: Boolean(mfaFactor),
  });
});

app.post("/v1/auth/logout", async (c) => {
  const authorization = c.req.header("authorization") ?? "";
  const match = /^Bearer\s+([a-f0-9]{64})$/i.exec(authorization);
  if (match) {
    await c.env.DB.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
      .bind(new Date().toISOString(), await sha256(match[1])).run();
  }
  return c.json({ success: true });
});

// Email verification
async function issueEmailVerificationToken(db: D1Database, userId: string): Promise<string> {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  await db.batch([
    db.prepare("UPDATE email_verification_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL").bind(new Date().toISOString(), userId),
    db.prepare("INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)").bind(crypto.randomUUID(), userId, tokenHash, expiresAt),
  ]);
  return token;
}

async function sendVerificationEmail(env: Bindings, userEmail: string, userDisplayName: string | null, token: string): Promise<boolean> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return false;
  const baseUrl = (env.DASHBOARD_URL || "https://web.nexoraedge.digital").replace(/\/$/, "");
  const verifyUrl = baseUrl + "/verify-email?token=" + encodeURIComponent(token);
  const safeName = escapeEmailHtml(userDisplayName || "there");
  const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#172033"><h2>Verify your Nexora email</h2><p>Hello ${safeName},</p><p>Confirm your email address to complete your Nexora Control registration.</p><p><a href="${verifyUrl}" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;text-decoration:none;border-radius:8px">Verify email</a></p><p style="font-size:12px;color:#64748b">This link expires in 24 hours.</p></div>`;
  try {
    const response = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.EMAIL_FROM, to: [userEmail], subject: "Verify your Nexora email", html }) });
    return response.ok;
  } catch { return false; }
}

app.post("/v1/auth/verify-email", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const token = typeof input.token === "string" ? input.token.trim() : "";
  if (!token || !/^[a-f0-9]{64}$/i.test(token)) return c.json({ message: "Invalid verification token" }, 400);
  const tokenHash = await sha256(token);
  const record = await c.env.DB.prepare("SELECT id, user_id AS userId, expires_at AS expiresAt, consumed_at AS consumedAt FROM email_verification_tokens WHERE token_hash = ? LIMIT 1").bind(tokenHash).first<{ id: string; userId: string; expiresAt: string; consumedAt: string | null }>();
  if (!record) return c.json({ message: "Verification token not found" }, 404);
  if (record.consumedAt) return c.json({ message: "Verification token has already been used" }, 409);
  if (Date.parse(record.expiresAt) < Date.now()) return c.json({ message: "Verification token has expired" }, 410);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE email_verification_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL").bind(new Date().toISOString(), record.id),
    c.env.DB.prepare("UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL").bind(new Date().toISOString(), record.userId),
  ]);
  return c.json({ success: true, message: "Email verified successfully." });
});

app.post("/v1/auth/resend-verification", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const user = await c.env.DB.prepare("SELECT id, email, display_name AS displayName, email_verified_at AS emailVerifiedAt FROM users WHERE id = ? LIMIT 1").bind(identity.id).first<{ id: string; email: string; displayName: string | null; emailVerifiedAt: string | null }>();
  if (!user) return c.json({ message: "User not found" }, 404);
  if (user.emailVerifiedAt) return c.json({ message: "Email is already verified" }, 409);
  const recent = await c.env.DB.prepare("SELECT created_at AS createdAt FROM email_verification_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1").bind(user.id).first<{ createdAt: string }>();
  if (recent && Date.now() - Date.parse(recent.createdAt) < 60_000) return c.json({ message: "Please wait a minute before requesting another verification email" }, 429);
  const token = await issueEmailVerificationToken(c.env.DB, user.id);
  const sent = await sendVerificationEmail(c.env, user.email, user.displayName, token);
  if (!sent) return c.json({ message: "Verification email could not be sent." }, 503);
  return c.json({ success: true, message: "Verification email sent." });
});

// Session management
app.get("/v1/sessions", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const rows = await c.env.DB.prepare("SELECT id, organization_id AS organizationId, created_at AS issuedAt, expires_at AS expiresAt, revoked_at AS revokedAt, user_agent AS userAgent, source_ip AS sourceIp FROM auth_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").bind(identity.id).all<{ id: string; organizationId: string; issuedAt: string; expiresAt: string; revokedAt: string | null; userAgent: string | null; sourceIp: string | null }>();
  const currentTokenHash = await sha256((c.req.header("authorization") ?? "").replace(/^Bearer\s+/i, ""));
  const currentSession = await c.env.DB.prepare("SELECT id FROM auth_sessions WHERE token_hash = ? LIMIT 1").bind(currentTokenHash).first<{ id: string }>();
  const sessions = (rows.results ?? []).map((row) => ({ id: row.id, organizationId: row.organizationId, issuedAt: row.issuedAt, expiresAt: row.expiresAt, revokedAt: row.revokedAt, userAgent: row.userAgent, sourceIp: row.sourceIp, current: currentSession?.id === row.id }));
  return c.json({ sessions });
});

app.delete("/v1/sessions/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const sessionId = c.req.param("id");
  const session = await c.env.DB.prepare("SELECT id, user_id AS userId FROM auth_sessions WHERE id = ? LIMIT 1").bind(sessionId).first<{ id: string; userId: string }>();
  if (!session) return c.json({ message: "Session not found" }, 404);
  if (session.userId !== identity.id) return c.json({ message: "You can only revoke your own sessions" }, 403);
  const currentTokenHash = await sha256((c.req.header("authorization") ?? "").replace(/^Bearer\s+/i, ""));
  const currentSession = await c.env.DB.prepare("SELECT id FROM auth_sessions WHERE token_hash = ? LIMIT 1").bind(currentTokenHash).first<{ id: string }>();
  if (currentSession?.id === sessionId) return c.json({ message: "Use the logout endpoint to end your current session" }, 409);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(new Date().toISOString(), sessionId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.session_revoked', 'auth_session', ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, sessionId),
  ]);
  return c.json({ success: true, message: "Session revoked" });
});

// TOTP MFA
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes: Uint8Array): string {
  let result = ""; let bits = 0; let value = 0;
  for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}
function generateTotpSecret(): string { const bytes = new Uint8Array(20); crypto.getRandomValues(bytes); return base32Encode(bytes); }
async function computeTotpCode(secret: string, timestamp: number): Promise<string> {
  const period = 30; const counter = Math.floor(timestamp / 1000 / period);
  const keyBytes: number[] = []; let bits = 0; let value = 0;
  for (const char of secret) { const idx = BASE32_ALPHABET.indexOf(char.toUpperCase()); if (idx < 0) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { keyBytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  const key = new Uint8Array(keyBytes); const counterBytes = new Uint8Array(8); let v = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = v & 0xff; v = Math.floor(v / 256); }
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, "0");
}
async function encryptTotpSecret(secret: string, env: Bindings): Promise<string> {
  const keyHex = env.MFA_ENCRYPTION_KEY ?? "";
  if (!keyHex || keyHex.length !== 64) throw new Error("MFA_ENCRYPTION_KEY must be a 32-byte hex string");
  const keyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) keyBytes[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(secret);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded));
  const combined = new Uint8Array(iv.length + ciphertext.length); combined.set(iv, 0); combined.set(ciphertext, iv.length);
  return btoa(String.fromCharCode(...combined));
}
async function decryptTotpSecret(encrypted: string, env: Bindings): Promise<string> {
  const keyHex = env.MFA_ENCRYPTION_KEY ?? "";
  if (!keyHex || keyHex.length !== 64) throw new Error("MFA_ENCRYPTION_KEY must be a 32-byte hex string");
  const keyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) keyBytes[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const combined = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12); const ciphertext = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

app.post("/v1/auth/mfa/enroll", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { input = {}; }
  const accountName = typeof input.accountName === "string" ? input.accountName.trim() : identity.email ?? "nexora-user";
  const secret = generateTotpSecret();
  const encryptedSecret = await encryptTotpSecret(secret, c.env).catch(() => null);
  if (!encryptedSecret) return c.json({ message: "MFA encryption key is not configured on the API" }, 503);
  await c.env.DB.prepare("INSERT INTO mfa_factors (id, user_id, kind, encrypted_secret) VALUES (?, ?, 'totp', ?) ON CONFLICT(user_id, kind) DO UPDATE SET encrypted_secret = excluded.encrypted_secret, backup_codes = NULL, enrolled_at = datetime('now')").bind(crypto.randomUUID(), identity.id, encryptedSecret).run();
  const otpauthUri = `otpauth://totp/Nexora:${encodeURIComponent(accountName)}?secret=${secret}&issuer=Nexora&algorithm=SHA1&digits=6&period=30`;
  return c.json({ otpauthUri, secret, message: "Scan the QR code with your authenticator app, then verify with a 6-digit code." });
});

app.post("/v1/auth/mfa/verify", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const code = typeof input.code === "string" ? input.code.trim() : "";
  if (!/^\d{6}$/.test(code)) return c.json({ message: "Enter a 6-digit code" }, 400);
  const factor = await c.env.DB.prepare("SELECT id, encrypted_secret AS encryptedSecret FROM mfa_factors WHERE user_id = ? AND kind = 'totp' LIMIT 1").bind(identity.id).first<{ id: string; encryptedSecret: string }>();
  if (!factor) return c.json({ message: "No pending MFA enrollment found" }, 404);
  const secret = await decryptTotpSecret(factor.encryptedSecret, c.env).catch(() => null);
  if (!secret) return c.json({ message: "Unable to decrypt MFA secret" }, 500);
  const expectedCode = await computeTotpCode(secret, Date.now());
  if (code !== expectedCode) return c.json({ message: "Invalid verification code" }, 401);
  await c.env.DB.prepare("UPDATE mfa_factors SET backup_codes = ? WHERE id = ?").bind(JSON.stringify({ activated: true, enrolledAt: new Date().toISOString() }), factor.id).run();
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.mfa_enrolled', 'mfa_factor', ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, factor.id).run();
  return c.json({ success: true, message: "MFA enabled." });
});

app.post("/v1/auth/mfa/disable", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const code = typeof input.code === "string" ? input.code.trim() : "";
  if (!/^\d{6}$/.test(code)) return c.json({ message: "Enter a 6-digit code to confirm MFA removal" }, 400);
  const factor = await c.env.DB.prepare("SELECT id, encrypted_secret AS encryptedSecret FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL LIMIT 1").bind(identity.id).first<{ id: string; encryptedSecret: string }>();
  if (!factor) return c.json({ message: "MFA is not enabled" }, 404);
  const secret = await decryptTotpSecret(factor.encryptedSecret, c.env).catch(() => null);
  if (!secret) return c.json({ message: "Unable to decrypt MFA secret" }, 500);
  const expectedCode = await computeTotpCode(secret, Date.now());
  if (code !== expectedCode) return c.json({ message: "Invalid verification code" }, 401);
  await c.env.DB.prepare("DELETE FROM mfa_factors WHERE id = ?").bind(factor.id).run();
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.mfa_disabled', 'mfa_factor', ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, factor.id).run();
  return c.json({ success: true, message: "MFA disabled." });
});

app.post("/v1/auth/login/mfa", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const challengeId = typeof input.challengeId === "string" ? input.challengeId.trim() : "";
  const code = typeof input.code === "string" ? input.code.trim() : "";
  if (!challengeId || !/^[a-f0-9-]{36}$/i.test(challengeId)) return c.json({ message: "Invalid challenge" }, 400);
  if (!/^\d{6}$/.test(code)) return c.json({ message: "Enter a 6-digit code" }, 400);
  const challenge = await c.env.DB.prepare(
    "SELECT id, user_id AS userId, organization_id AS organizationId, expires_at AS expiresAt, consumed_at AS consumedAt, failed_attempts AS failedAttempts, locked_at AS lockedAt FROM mfa_challenges WHERE id = ? LIMIT 1",
  ).bind(challengeId).first<{ id: string; userId: string; organizationId: string; expiresAt: string; consumedAt: string | null; failedAttempts: number; lockedAt: string | null }>();
  if (!challenge) return c.json({ message: "Challenge not found" }, 404);
  if (challenge.consumedAt) return c.json({ message: "Challenge already used" }, 409);
  if (challenge.lockedAt) return c.json({ message: "Too many invalid attempts. Please sign in again to receive a new challenge." }, 423);
  if (Date.parse(challenge.expiresAt) < Date.now()) return c.json({ message: "Challenge expired" }, 410);
  const factor = await c.env.DB.prepare(
    "SELECT id, encrypted_secret AS encryptedSecret, last_used_totp_period AS lastUsedTotpPeriod FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL LIMIT 1",
  ).bind(challenge.userId).first<{ id: string; encryptedSecret: string; lastUsedTotpPeriod: number | null }>();
  if (!factor) return c.json({ message: "MFA is not enabled for this account" }, 404);
  const secret = await decryptTotpSecret(factor.encryptedSecret, c.env).catch(() => null);
  if (!secret) return c.json({ message: "Unable to decrypt MFA secret" }, 500);

  // Fast replay rejection for the common sequential case. This read is only
  // an optimization; the conditional factor UPDATE below is the authoritative
  // atomic guard against parallel requests.
  const currentTotpPeriod = Math.floor(Date.now() / 1000 / 30);
  if (factor.lastUsedTotpPeriod !== null && currentTotpPeriod <= factor.lastUsedTotpPeriod) {
    return c.json({ message: "This code has already been used. Wait for your authenticator to refresh and try again." }, 409);
  }

  const expectedCode = await computeTotpCode(secret, Date.now());
  if (code !== expectedCode) {
    // Atomic failed-attempt accounting: increment the persisted counter in SQL,
    // rather than writing a value derived from a potentially stale SELECT.
    const now = new Date().toISOString();
    const failedUpdate = await c.env.DB.prepare(
      `UPDATE mfa_challenges
       SET failed_attempts = failed_attempts + 1,
           locked_at = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_at END
       WHERE id = ? AND consumed_at IS NULL AND locked_at IS NULL
         AND expires_at > ? AND failed_attempts < ?`,
    ).bind(MAX_MFA_FAILED_ATTEMPTS, now, challenge.id, now, MAX_MFA_FAILED_ATTEMPTS).run();
    if ((failedUpdate.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "Challenge changed or is no longer valid. Please sign in again." }, 409);
    }
    const updatedChallenge = await c.env.DB.prepare(
      "SELECT failed_attempts AS failedAttempts, locked_at AS lockedAt FROM mfa_challenges WHERE id = ? LIMIT 1",
    ).bind(challenge.id).first<{ failedAttempts: number; lockedAt: string | null }>();
    const locked = Boolean(updatedChallenge?.lockedAt);
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.login_mfa_failed', 'mfa_challenge', ?)",
    ).bind(crypto.randomUUID(), challenge.organizationId, challenge.userId, challenge.id).run();
    if (locked) {
      await c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.login_mfa_locked', 'mfa_challenge', ?)",
      ).bind(crypto.randomUUID(), challenge.organizationId, challenge.userId, challenge.id).run();
      return c.json({ message: "Too many invalid attempts. Please sign in again to receive a new challenge." }, 423);
    }
    return c.json({ message: "Invalid verification code" }, 401);
  }

  // Revalidate all authorization state immediately before session creation.
  // Memberships have no separate status column; the user and organization must
  // still be ACTIVE and the exact membership must still exist.
  const membership = await c.env.DB.prepare(
    `SELECT m.role, pm.role AS platformRole
     FROM memberships m
     JOIN users u ON u.id = m.user_id AND u.status = 'ACTIVE'
     JOIN organizations o ON o.id = m.organization_id AND o.status = 'ACTIVE'
     LEFT JOIN platform_memberships pm ON pm.user_id = m.user_id AND pm.status = 'ACTIVE'
     WHERE m.user_id = ? AND m.organization_id = ? LIMIT 1`,
  ).bind(challenge.userId, challenge.organizationId).first<{ role: Role; platformRole: PlatformRole | null }>();
  if (!membership) return c.json({ message: "User or organization is no longer active, or membership no longer exists" }, 403);

  const consumedAt = new Date().toISOString();
  const consumeResult = await c.env.DB.prepare(
    `UPDATE mfa_challenges SET consumed_at = ?
     WHERE id = ? AND user_id = ? AND organization_id = ?
       AND consumed_at IS NULL AND locked_at IS NULL AND expires_at > ?`,
  ).bind(consumedAt, challenge.id, challenge.userId, challenge.organizationId, consumedAt).run();
  if ((consumeResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Challenge already used or no longer valid" }, 409);
  }

  // This conditional write is the authoritative replay guard: concurrent
  // challenges cannot both advance one factor to the same TOTP counter.
  const factorClaim = await c.env.DB.prepare(
    `UPDATE mfa_factors SET last_used_totp_period = ?
     WHERE id = ? AND (last_used_totp_period IS NULL OR last_used_totp_period < ?)
       AND EXISTS (
         SELECT 1 FROM mfa_challenges
         WHERE id = ? AND user_id = ? AND organization_id = ? AND consumed_at = ?
       )`,
  ).bind(currentTotpPeriod, factor.id, currentTotpPeriod, challenge.id, challenge.userId, challenge.organizationId, consumedAt).run();
  if ((factorClaim.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "This authenticator code has already been used. Wait for a new code and sign in again." }, 409);
  }

  // Fresh authorization read immediately before session persistence.
  const sessionAuthorization = await c.env.DB.prepare(
    `SELECT m.role
     FROM memberships m
     JOIN users u ON u.id = m.user_id AND u.status = 'ACTIVE'
     JOIN organizations o ON o.id = m.organization_id AND o.status = 'ACTIVE'
     WHERE m.user_id = ? AND m.organization_id = ? LIMIT 1`,
  ).bind(challenge.userId, challenge.organizationId).first<{ role: Role }>();
  if (!sessionAuthorization) return c.json({ message: "User or organization is no longer active" }, 403);

  const session = await issueSession(c.env.DB, challenge.userId, challenge.organizationId, sessionAuthorization.role);
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.login_mfa', 'user', ?)").bind(crypto.randomUUID(), challenge.organizationId, challenge.userId, challenge.userId).run();
  const user = await c.env.DB.prepare("SELECT id, email, display_name AS displayName FROM users WHERE id = ? LIMIT 1").bind(challenge.userId).first<{ id: string; email: string; displayName: string | null }>();
  const customerAccess = await c.env.DB.prepare(
    "SELECT 1 AS active FROM hosting_account_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(challenge.userId).first<{ active: number }>();
  return c.json({
    user: { id: user?.id, email: user?.email, displayName: user?.displayName },
    customerAccess: Boolean(customerAccess),
    platformRole: membership.platformRole,
    ...session,
  });
});


type ServerRow = {
  id: string;
  hostname: string;
  primary_ip: string;
  region: string | null;
  agent_version: string | null;
  status: string;
  last_heartbeat_at: string | null;
  created_at: string;
};

function validIp(value: string): boolean {
  const ipv4 = value.split(".");
  if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return true;
  if (!value.includes(":")) return false;
  try { new URL(`http://[${value}]/`); return true; } catch { return false; }
}

function canManageServers(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function dnsErrorStatus(error: unknown): 400 | 502 {
  const message = error instanceof Error ? error.message : "";
  return /required|valid|supported|must be|cannot|only available|TTL|priority|identifier|subdomain|label/i.test(message) ? 400 : 502;
}

app.get("/v1/dns-records", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  try {
    const records = await listDnsRecords(c.env);
    return c.json({
      zone: c.env.CLOUDFLARE_ZONE_NAME ?? null,
      records,
      canManage: Boolean(identity.platformRole),
    });
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to load DNS records." }, 502);
  }
});

app.post("/v1/dns-records", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  try {
    const record = await createDnsRecord(c.env, input);
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'dns.record_created', 'dns_record', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, record.id,
      JSON.stringify({ type: record.type, name: record.name })).run();
    return c.json({ record }, 201);
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to create DNS record." }, dnsErrorStatus(error));
  }
});

app.patch("/v1/dns-records/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  try {
    const record = await updateDnsRecord(c.env, c.req.param("id"), input);
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'dns.record_updated', 'dns_record', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, record.id,
      JSON.stringify({ type: record.type, name: record.name })).run();
    return c.json({ record });
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to update DNS record." }, dnsErrorStatus(error));
  }
});

app.delete("/v1/dns-records/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const id = c.req.param("id");
  try {
    const records = await listDnsRecords(c.env);
    const existing = records.find((record) => record.id === id);
    if (!existing) return c.json({ message: "DNS record not found in the managed zone." }, 404);
    await deleteDnsRecord(c.env, id);
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'dns.record_deleted', 'dns_record', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id,
      JSON.stringify({ type: existing.type, name: existing.name })).run();
    return c.json({ deleted: true, id });
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to delete DNS record." }, dnsErrorStatus(error));
  }
});

app.get("/v1/servers", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT id, hostname, primary_ip, region, agent_version, status,
            last_heartbeat_at, created_at
     FROM servers WHERE organization_id = ? ORDER BY created_at DESC`,
  ).bind(identity.organizationId).all<ServerRow>();
  return c.json({ servers: result.results ?? [] });
});

app.get("/v1/servers/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const server = await c.env.DB.prepare(
    `SELECT id, hostname, primary_ip, region, agent_version, status,
            last_heartbeat_at, created_at
     FROM servers WHERE id = ? AND organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<ServerRow>();
  if (!server) return c.json({ message: "Server not found" }, 404);
  return c.json({ server });
});

type ServerTelemetryRow = {
  id: string;
  agent_version: string;
  cpu_usage_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  load_average_1m: number;
  collected_at: string;
  received_at: string;
};

app.get("/v1/servers/:id/telemetry", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);

  const serverId = c.req.param("id");
  const server = await c.env.DB.prepare(
    `SELECT id, hostname, primary_ip, region, agent_version, status,
            last_heartbeat_at, created_at
     FROM servers WHERE id = ? AND organization_id = ? LIMIT 1`,
  ).bind(serverId, identity.organizationId).first<ServerRow>();
  if (!server) return c.json({ message: "Server not found" }, 404);

  const result = await c.env.DB.prepare(
    `SELECT id, agent_version, cpu_usage_percent, memory_total_bytes,
            memory_used_bytes, disk_total_bytes, disk_used_bytes,
            load_average_1m, collected_at, received_at
     FROM server_telemetry
     WHERE server_id = ?
     ORDER BY collected_at DESC
     LIMIT 60`,
  ).bind(serverId).all<ServerTelemetryRow>();

  const samples = (result.results ?? []).reverse();
  return c.json({
    server,
    latest: samples.length ? samples[samples.length - 1] : null,
    samples,
  });
});

app.get("/v1/servers/:id/services", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);

  const serverId = c.req.param("id");
  const server = await c.env.DB.prepare(
    `SELECT id, hostname, primary_ip, region, agent_version, status,
            last_heartbeat_at, created_at
     FROM servers WHERE id = ? AND organization_id = ? LIMIT 1`,
  ).bind(serverId, identity.organizationId).first<ServerRow>();
  if (!server) return c.json({ message: "Server not found" }, 404);

  const result = await c.env.DB.prepare(
    `SELECT id, service_key, display_name, status, checked_at, received_at
     FROM server_service_checks
     WHERE server_id = ?
     ORDER BY checked_at DESC, received_at DESC
     LIMIT 120`,
  ).bind(serverId).all<{
    id: string;
    service_key: string;
    display_name: string;
    status: string;
    checked_at: string;
    received_at: string;
  }>();

  const samples = (result.results ?? []).reverse();
  const latestByService = new Map<string, typeof samples[number]>();
  for (const sample of [...samples].reverse()) {
    if (!latestByService.has(sample.service_key)) {
      latestByService.set(sample.service_key, sample);
    }
  }

  return c.json({
    server,
    services: [...latestByService.values()],
    samples,
  });
});

app.get("/v1/incidents", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);

  const status = c.req.query("status");
  if (status && !["OPEN", "ACKNOWLEDGED", "RESOLVED"].includes(status)) {
    return c.json({ message: "Invalid incident status filter" }, 400);
  }

  const result = await c.env.DB.prepare(
    `SELECT i.id, i.server_id AS serverId, s.hostname AS serverHostname,
            i.incident_type AS incidentType, i.incident_key AS incidentKey,
            i.severity, i.status, i.title, i.description,
            i.opened_at AS openedAt, i.updated_at AS updatedAt,
            i.last_observed_at AS lastObservedAt, i.resolved_at AS resolvedAt,
            i.acknowledged_at AS acknowledgedAt,
            i.acknowledged_by AS acknowledgedBy
     FROM server_incidents i
     JOIN servers s ON s.id = i.server_id AND s.organization_id = i.organization_id
     WHERE i.organization_id = ?
       AND (? IS NULL OR i.status = ?)
     ORDER BY
       CASE WHEN i.status = 'RESOLVED' THEN 1 ELSE 0 END,
       i.opened_at DESC
     LIMIT 100`,
  ).bind(identity.organizationId, status || null, status || null).all();

  return c.json({ incidents: result.results ?? [] });
});

app.post("/v1/incidents/:id/acknowledge", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) {
    return c.json({ message: "Administrator access required" }, 403);
  }

  const incidentId = c.req.param("id");
  const incident = await c.env.DB.prepare(
    "SELECT id, status FROM server_incidents WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(incidentId, identity.organizationId).first<{ id: string; status: string }>();

  if (!incident) return c.json({ message: "Incident not found" }, 404);
  if (incident.status === "RESOLVED") {
    return c.json({ message: "Resolved incidents cannot be acknowledged" }, 409);
  }

  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "UPDATE server_incidents SET status = 'ACKNOWLEDGED', acknowledged_at = COALESCE(acknowledged_at, ?), acknowledged_by = COALESCE(acknowledged_by, ?), updated_at = ? WHERE id = ? AND organization_id = ? AND resolved_at IS NULL",
  ).bind(now, identity.id, now, incidentId, identity.organizationId).run();

  return c.json({ acknowledged: true, incidentId });
});


app.get("/v1/notification-settings", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);

  const row = await c.env.DB.prepare(
    "SELECT enabled, recipients_json AS recipientsJson, updated_at AS updatedAt FROM incident_notification_settings WHERE organization_id = ? LIMIT 1",
  ).bind(identity.organizationId).first<{
    enabled: number; recipientsJson: string; updatedAt: string;
  }>();

  let recipients: string[] = [];
  try {
    const parsed: unknown = row ? JSON.parse(row.recipientsJson) : [];
    if (Array.isArray(parsed)) recipients = parsed.filter((value): value is string => typeof value === "string");
  } catch {
    recipients = [];
  }

  return c.json({
    enabled: row?.enabled === 1,
    recipients,
    updatedAt: row?.updatedAt ?? null,
    providerConfigured: Boolean(c.env.RESEND_API_KEY && c.env.EMAIL_FROM),
    sender: c.env.EMAIL_FROM ?? null,
    canManage: Boolean(identity.platformRole),
  });
});

app.post("/v1/notification-settings", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) {
    return c.json({ message: "Administrator access required" }, 403);
  }

  let input: { enabled?: unknown; recipients?: unknown };
  try {
    input = await c.req.json();
  } catch {
    return c.json({ message: "Invalid JSON request body" }, 400);
  }

  if (typeof input.enabled !== "boolean" || !Array.isArray(input.recipients)) {
    return c.json({ message: "Provide an enabled boolean and a recipients array" }, 400);
  }
  if (input.recipients.length > 10) {
    return c.json({ message: "A maximum of 10 notification recipients is allowed" }, 400);
  }

  const recipients = [...new Set(input.recipients.map((value) =>
    typeof value === "string" ? normalizeEmail(value) : "",
  ))];

  if (recipients.some((email) => !validEmail(email))) {
    return c.json({ message: "One or more recipient email addresses are invalid" }, 400);
  }
  if (input.enabled && recipients.length === 0) {
    return c.json({ message: "Add at least one recipient before enabling notifications" }, 400);
  }

  const now = new Date().toISOString();
  await c.env.DB.prepare(
    `INSERT INTO incident_notification_settings
       (organization_id, enabled, recipients_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(organization_id) DO UPDATE SET
       enabled = excluded.enabled,
       recipients_json = excluded.recipients_json,
       updated_at = excluded.updated_at`,
  ).bind(
    identity.organizationId,
    input.enabled ? 1 : 0,
    JSON.stringify(recipients),
    now,
    now,
  ).run();

  return c.json({
    saved: true,
    enabled: input.enabled,
    recipients,
    providerConfigured: Boolean(c.env.RESEND_API_KEY && c.env.EMAIL_FROM),
  });
});


app.post("/v1/notification-settings/test", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) {
    return c.json({ message: "Administrator access required" }, 403);
  }
  if (!c.env.RESEND_API_KEY || !c.env.EMAIL_FROM) {
    return c.json({ message: "Resend email delivery is not configured" }, 503);
  }

  const settings = await c.env.DB.prepare(
    `SELECT enabled, recipients_json AS recipientsJson
     FROM incident_notification_settings
     WHERE organization_id = ? LIMIT 1`,
  ).bind(identity.organizationId).first<{
    enabled: number;
    recipientsJson: string;
  }>();

  if (!settings || settings.enabled !== 1) {
    return c.json({ message: "Enable incident email notifications before sending a test" }, 400);
  }

  let recipients: unknown;
  try {
    recipients = JSON.parse(settings.recipientsJson);
  } catch {
    return c.json({ message: "Saved notification recipients are invalid" }, 400);
  }

  if (!Array.isArray(recipients) || recipients.length === 0 ||
      recipients.length > 10 ||
      recipients.some((email) => typeof email !== "string" || !validEmail(email))) {
    return c.json({ message: "Saved notification recipient list is invalid" }, 400);
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const cooldownBefore = new Date(now.getTime() - 60 * 1000).toISOString();

  const throttle = await c.env.DB.prepare(
    `UPDATE incident_notification_settings
     SET last_test_at = ?
     WHERE organization_id = ?
       AND (last_test_at IS NULL OR last_test_at <= ?)`,
  ).bind(nowIso, identity.organizationId, cooldownBefore).run();

  if ((throttle.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "A test email was sent recently. Please wait 60 seconds before trying again." }, 429);
  }

  const subject = "[Nexora] Test email — incident notifications";
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#172033">
      <h2>Nexora email delivery test</h2>
      <p>This is a test message from your Nexora Control Panel workspace.</p>
      <p>Your saved incident notification recipients and Resend delivery configuration are working well enough for Resend to accept this test message.</p>
      <p><strong>Sent at:</strong> ${escapeEmailHtml(nowIso)}</p>
      <hr/>
      <p style="font-size:12px;color:#64748b">Nexora Control Panel · Test message only — no server incident was created.</p>
    </div>`;

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${c.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: c.env.EMAIL_FROM,
        to: recipients,
        subject,
        html,
      }),
    });

    const responseText = (await response.text()).slice(0, 800);
    let providerResult: { id?: string; message?: string } = {};
    try {
      providerResult = JSON.parse(responseText);
    } catch {
      providerResult = {};
    }

    if (!response.ok) {
      console.error("Resend test email rejected:", response.status, responseText);
      return c.json({
        sent: false,
        message: `Resend rejected the test email (HTTP ${response.status}). Check the API Worker logs and Resend account.`,
      }, 502);
    }

    return c.json({
      sent: true,
      message: "Resend accepted the test email.",
      emailId: providerResult.id ?? null,
      recipientCount: recipients.length,
    });
  } catch (error) {
    console.error("Resend test email request failed:", error);
    return c.json({
      sent: false,
      message: "Unable to contact Resend. Check the API Worker logs.",
    }, 502);
  }
});

app.post("/v1/servers", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const hostname = typeof input.hostname === "string" ? input.hostname.trim().toLowerCase() : "";
  const primaryIp = typeof input.primaryIp === "string" ? input.primaryIp.trim() : "";
  const region = typeof input.region === "string" ? input.region.trim().slice(0, 80) : null;
  if (!hostname || hostname.length > 253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(hostname)) {
    return c.json({ message: "Enter a valid server hostname" }, 400);
  }
  if (!validIp(primaryIp)) return c.json({ message: "Enter a valid IPv4 or IPv6 address" }, 400);

  const id = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO servers (id, organization_id, hostname, primary_ip, region, status) VALUES (?, ?, ?, ?, ?, 'PENDING')",
      ).bind(id, identity.organizationId, hostname, primaryIp, region),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'server.create', 'server', ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
    ]);
    return c.json({ server: { id, hostname, primaryIp, region, status: "PENDING" } }, 201);
  } catch (error) {
    return c.json({ message: "Unable to register server. Check whether the hostname or address is already in use." }, 409);
  }
});

app.post("/v1/servers/:id/enrollment-token", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  const serverId = c.req.param("id");
  const server = await c.env.DB.prepare(
    "SELECT id FROM servers WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(serverId, identity.organizationId).first<{ id: string }>();
  if (!server) return c.json({ message: "Server not found" }, 404);

  const token = randomHex(32);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO agent_enrollments (id, organization_id, server_id, token_hash, expires_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(server_id) DO UPDATE SET organization_id = excluded.organization_id,
       token_hash = excluded.token_hash, expires_at = excluded.expires_at,
       consumed_at = NULL, created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
    ).bind(crypto.randomUUID(), identity.organizationId, serverId, await sha256(token), expiresAt),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'server.enrollment_token.issue', 'server', ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, serverId),
  ]);

  return c.json({
    serverId,
    enrollmentToken: token,
    expiresAt,
    oneTimeDisplay: true,
    message: "Copy this token now. It will not be shown again and expires in 15 minutes.",
  });
});



app.post("/v1/agent/enroll", async (c) => {
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const serverId = typeof input.serverId === "string" ? input.serverId.trim() : "";
  const token = typeof input.enrollmentToken === "string" ? input.enrollmentToken.trim().toLowerCase() : "";
  if (!serverId || !/^[a-f0-9]{64}$/.test(token)) return c.json({ message: "A valid server ID and enrollment token are required" }, 400);

  const tokenHash = await sha256(token);
  const enrollment = await c.env.DB.prepare(
    `SELECT e.id, e.organization_id AS organizationId, e.server_id AS serverId
     FROM agent_enrollments e JOIN servers s ON s.id = e.server_id
     WHERE e.server_id = ? AND e.token_hash = ? AND e.consumed_at IS NULL
       AND e.expires_at > ? AND s.organization_id = e.organization_id LIMIT 1`,
  ).bind(serverId, tokenHash, new Date().toISOString()).first<{ id: string; organizationId: string; serverId: string }>();
  if (!enrollment) return c.json({ message: "Enrollment token is invalid, expired, already used, or does not match this server" }, 401);

  const consumed = await c.env.DB.prepare(
    "UPDATE agent_enrollments SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?",
  ).bind(new Date().toISOString(), enrollment.id, new Date().toISOString()).run();
  if ((consumed.meta?.changes ?? 0) !== 1) return c.json({ message: "Enrollment token has already been consumed" }, 409);

  const nodeId = crypto.randomUUID();
  const secret = randomHex(32);
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM agent_credentials WHERE server_id = ?").bind(serverId),
      c.env.DB.prepare(
        "INSERT INTO agent_credentials (node_id, organization_id, server_id, secret_hash) VALUES (?, ?, ?, ?)",
      ).bind(nodeId, enrollment.organizationId, serverId, await sha256(secret)),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, 'server.agent_enrolled', 'server', ?, ?)",
      ).bind(crypto.randomUUID(), enrollment.organizationId, serverId, JSON.stringify({ nodeId })),
    ]);
  } catch {
    return c.json({ message: "Unable to issue node credentials" }, 500);
  }
  return c.json({ nodeId, serverId, secret, message: "Node enrolled. Store this secret securely; it is shown only once." }, 201);
});

app.get("/v1/agent/deployments/:deploymentId/artifact", async (c) => {
  if (!c.env.ARTIFACTS) return c.json({ message: "Private deployment artifact storage is unavailable." }, 503);

  const nodeId = c.req.header("X-Nexora-Node") ?? "";
  const timestamp = c.req.header("X-Nexora-Timestamp") ?? "";
  const nonce = c.req.header("X-Nexora-Nonce") ?? "";
  const signature = (c.req.header("X-Nexora-Signature") ?? "").toLowerCase();
  if (!nodeId || !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) {
    return c.json({ message: "Missing or invalid agent authentication headers." }, 401);
  }
  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() / 1000 - requestTime) > 300) {
    return c.json({ message: "Agent request timestamp is outside the allowed five-minute window." }, 401);
  }

  const credential = await c.env.DB.prepare(
    "SELECT ac.secret_hash AS secretHash, ac.server_id AS serverId, ac.organization_id AS organizationId FROM agent_credentials ac JOIN servers s ON s.id = ac.server_id AND s.organization_id = ac.organization_id WHERE ac.node_id = ? AND ac.revoked_at IS NULL LIMIT 1",
  ).bind(nodeId).first<{ secretHash: string; serverId: string; organizationId: string }>();
  if (!credential) return c.json({ message: "Agent identity is unknown or revoked." }, 401);

  const canonical = [timestamp, nonce, "GET", new URL(c.req.url).pathname, await sha256("")].join("\n");
  const proofExpected = await hmacSha256(credential.secretHash, canonical);
  if (!constantTimeEqual(proofExpected, signature)) {
    return c.json({ message: "Agent signature is invalid." }, 401);
  }
  try {
    await c.env.DB.prepare("INSERT INTO agent_nonces (node_id, nonce) VALUES (?, ?)").bind(nodeId, nonce).run();
  } catch {
    return c.json({ message: "Agent request nonce has already been used." }, 409);
  }

  const deployment = await c.env.DB.prepare(
    `SELECT d.id AS deploymentId, d.organization_id AS organizationId, d.project_id AS projectId,
            d.commit_sha AS commitSha, d.artifact_key AS artifactKey, d.artifact_bytes AS artifactBytes,
            d.artifact_sha256 AS artifactSha256, p.hosting_account_id AS hostingAccountId,
            dom.id AS domainId, lower(dom.name) AS hostname, p.github_repository_id AS repositoryId
     FROM github_deployments d
     JOIN github_projects p ON p.id = d.project_id AND p.organization_id = d.organization_id
     JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = d.organization_id AND h.status = 'ACTIVE'
     JOIN domains dom ON dom.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = h.id
                                  ORDER BY d2.is_primary DESC, d2.name ASC LIMIT 1)
     WHERE d.id = ? AND d.organization_id = ? AND h.server_id = ?
       AND d.status = 'building' AND d.artifact_key IS NOT NULL
       AND d.artifact_bytes IS NOT NULL AND d.artifact_sha256 IS NOT NULL
     LIMIT 1`,
  ).bind(c.req.param("deploymentId"), credential.organizationId, credential.serverId).first<{
    deploymentId: string;
    organizationId: string;
    projectId: string;
    commitSha: string;
    artifactKey: string;
    artifactBytes: number;
    artifactSha256: string;
    hostingAccountId: string;
    domainId: string;
    hostname: string;
    repositoryId: string;
  }>();
  if (!deployment) return c.json({ message: "No staged artifact is available for this server deployment." }, 404);
  if (!Number.isSafeInteger(deployment.artifactBytes) || deployment.artifactBytes < 1 ||
      deployment.artifactBytes > 100 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(deployment.artifactSha256)) {
    return c.json({ message: "Staged artifact metadata is invalid." }, 409);
  }

  const object = await c.env.ARTIFACTS.get(deployment.artifactKey);
  if (!object || object.size !== deployment.artifactBytes ||
      object.customMetadata?.organizationId !== deployment.organizationId ||
      object.customMetadata?.projectId !== deployment.projectId ||
      object.customMetadata?.deploymentId !== deployment.deploymentId ||
      object.customMetadata?.commitSha !== deployment.commitSha ||
      object.customMetadata?.artifactSha256 !== deployment.artifactSha256) {
    return c.json({ message: "Staged artifact integrity metadata does not match the deployment record." }, 409);
  }

  let envelope: string;
  try {
    envelope = await signDeploymentEnvelope(c.env, {
      organizationId: deployment.organizationId,
      projectId: deployment.projectId,
      deploymentId: deployment.deploymentId,
      hostingAccountId: deployment.hostingAccountId,
      domainId: deployment.domainId,
      hostname: deployment.hostname,
      repositoryId: deployment.repositoryId,
      commitSha: deployment.commitSha,
      artifactSha256: deployment.artifactSha256,
      artifactBytes: deployment.artifactBytes,
    });
  } catch (error) {
    console.error("Deployment envelope signing unavailable:", error instanceof Error ? error.message : "unknown error");
    return c.json({ message: "Deployment envelope signing is not configured." }, 503);
  }

  return new Response(object.body, {
    status: 200,
    headers: {
      "Content-Type": "application/gzip",
      "Content-Length": String(deployment.artifactBytes),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Nexora-Deployment-Envelope": envelope,
      "X-Nexora-Artifact-SHA256": deployment.artifactSha256,
    },
  });
});

app.post("/v1/agent/heartbeat", async (c) => {
  const nodeId = c.req.header("X-Nexora-Node") ?? "";
  const timestamp = c.req.header("X-Nexora-Timestamp") ?? "";
  const nonce = c.req.header("X-Nexora-Nonce") ?? "";
  const signature = (c.req.header("X-Nexora-Signature") ?? "").toLowerCase();
  if (!nodeId || !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) {
    return c.json({ message: "Missing or invalid agent authentication headers" }, 401);
  }
  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() / 1000 - requestTime) > 300) {
    return c.json({ message: "Agent request timestamp is outside the allowed five-minute window" }, 401);
  }

  const credential = await c.env.DB.prepare(
    "SELECT ac.secret_hash AS secretHash, ac.server_id AS serverId, ac.organization_id AS organizationId FROM agent_credentials ac JOIN servers s ON s.id = ac.server_id AND s.organization_id = ac.organization_id WHERE ac.node_id = ? AND ac.revoked_at IS NULL LIMIT 1",
  ).bind(nodeId).first<{ secretHash: string; serverId: string; organizationId: string }>();
  if (!credential) return c.json({ message: "Agent identity is unknown or revoked" }, 401);

  const rawBody = await c.req.text();
  if (rawBody.length > 16384) return c.json({ message: "Telemetry payload is too large" }, 413);
  let input: Record<string, unknown>;
  try { input = JSON.parse(rawBody) as Record<string, unknown>; }
  catch { return c.json({ message: "Invalid telemetry JSON" }, 400); }

  const agentVersion = typeof input.agentVersion === "string" ? input.agentVersion.slice(0, 40) : "";
  const cpu = Number(input.cpuUsagePercent);
  const memoryTotal = Number(input.memoryTotalBytes);
  const memoryUsed = Number(input.memoryUsedBytes);
  const diskTotal = Number(input.diskTotalBytes);
  const diskUsed = Number(input.diskUsedBytes);
  const load = Number(input.loadAverage1m);
  const collectedAt = typeof input.collectedAt === "string" ? input.collectedAt : "";
  if (!agentVersion || ![cpu, memoryTotal, memoryUsed, diskTotal, diskUsed, load].every(Number.isFinite) ||
      cpu < 0 || cpu > 100 || memoryTotal < 1 || memoryUsed < 0 || memoryUsed > memoryTotal ||
      diskTotal < 1 || diskUsed < 0 || diskUsed > diskTotal || load < 0 || load > 100000 ||
      !Number.isSafeInteger(memoryTotal) || !Number.isSafeInteger(memoryUsed) ||
      !Number.isSafeInteger(diskTotal) || !Number.isSafeInteger(diskUsed) ||
      !Number.isFinite(Date.parse(collectedAt)) || Math.abs(Date.now() - Date.parse(collectedAt)) > 10 * 60 * 1000) {
    return c.json({ message: "Telemetry fields are invalid or outside accepted limits" }, 400);
  }


    const serviceNames: Record<string, string> = {
      nginx: "Nginx",
      php_fpm: "PHP 8.5-FPM",
      mariadb: "MariaDB",
      ssh: "SSH",
      nexora_agent: "Nexora Agent",
      cloudflared: "Cloudflare Tunnel",
    };
    const allowedServiceStatuses = new Set([
      "ACTIVE", "INACTIVE", "FAILED", "NOT_INSTALLED", "UNKNOWN",
    ]);
    const serviceChecks: Array<{
      key: string;
      displayName: string;
      status: string;
      checkedAt: string;
    }> = [];

    // Backward compatibility: older agents may omit services.
    if (input.services !== undefined) {
      if (!Array.isArray(input.services) || input.services.length > 6) {
        return c.json({ message: "Service checks must be an array of at most six entries" }, 400);
      }

      const seenServiceKeys = new Set<string>();
      for (const item of input.services) {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          return c.json({ message: "Invalid service check entry" }, 400);
        }

        const check = item as Record<string, unknown>;
        const key = typeof check.key === "string" ? check.key : "";
        const status = typeof check.status === "string" ? check.status : "";
        const checkedAt = typeof check.checkedAt === "string" ? check.checkedAt : "";
        const checkedAtMs = Date.parse(checkedAt);

        if (
          !Object.prototype.hasOwnProperty.call(serviceNames, key) ||
          seenServiceKeys.has(key) ||
          !allowedServiceStatuses.has(status) ||
          !Number.isFinite(checkedAtMs) ||
          Math.abs(Date.now() - checkedAtMs) > 10 * 60 * 1000
        ) {
          return c.json({ message: "Service check fields are invalid or outside accepted limits" }, 400);
        }

        seenServiceKeys.add(key);
        serviceChecks.push({
          key,
          displayName: serviceNames[key],
          status,
          checkedAt: new Date(checkedAtMs).toISOString(),
        });
      }
    }

  type IncomingDatabaseUsage = {
    name: string;
    usedBytes: number;
    collectedAt: string;
  };
  const databaseUsage: IncomingDatabaseUsage[] = [];

  // Older agents may omit databaseUsage.
  if (input.databaseUsage !== undefined) {
    if (!Array.isArray(input.databaseUsage) || input.databaseUsage.length > 100) {
      return c.json({ message: "Database usage must be an array of at most 100 entries" }, 400);
    }

    const seenDatabaseNames = new Set<string>();
    for (const item of input.databaseUsage) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        return c.json({ message: "Invalid database usage entry" }, 400);
      }

      const measurement = item as Record<string, unknown>;
      const name = typeof measurement.name === "string" ? measurement.name : "";
      const usedBytes = measurement.usedBytes;
      const collectedAt = typeof measurement.collectedAt === "string" ? measurement.collectedAt : "";
      const collectedAtMs = Date.parse(collectedAt);

      if (
        !/^[a-z][a-z0-9_]{1,63}$/.test(name) ||
        seenDatabaseNames.has(name) ||
        typeof usedBytes !== "number" ||
        !Number.isSafeInteger(usedBytes) ||
        usedBytes < 0 ||
        !Number.isFinite(collectedAtMs) ||
        Math.abs(Date.now() - collectedAtMs) > 10 * 60 * 1000
      ) {
        return c.json({ message: "Database usage fields are invalid or outside accepted limits" }, 400);
      }

      seenDatabaseNames.add(name);
      databaseUsage.push({ name, usedBytes, collectedAt: new Date(collectedAtMs).toISOString() });
    }
  }

  const bodyHash = await sha256(rawBody);
  const path = new URL(c.req.url).pathname;
  const canonical = [timestamp, nonce, c.req.method.toUpperCase(), path, bodyHash].join("\n");
  // The agent derives the HMAC key as hex(SHA-256(secret)); only that hash is stored here.
  const proofExpected = await hmacSha256(credential.secretHash, canonical);
  if (!constantTimeEqual(proofExpected, signature)) {
    return c.json({ message: "Agent signature is invalid" }, 401);
  }

  try {
    await c.env.DB.prepare("INSERT INTO agent_nonces (node_id, nonce) VALUES (?, ?)").bind(nodeId, nonce).run();
  } catch {
    return c.json({ message: "Agent request nonce has already been used" }, 409);
  }
  const now = new Date().toISOString();

  const databaseUsageStatements: D1PreparedStatement[] = [];
  if (databaseUsage.length > 0) {
    const managedDatabases = await c.env.DB.prepare(
      `SELECT d.id, d.name
       FROM hosting_databases d
       JOIN hosting_accounts a ON a.id = d.hosting_account_id
       WHERE a.server_id = ? AND d.organization_id = ?
         AND a.status = 'ACTIVE' AND d.status = 'ACTIVE'`,
    ).bind(credential.serverId, credential.organizationId).all<{ id: string; name: string }>();

    const managedByName = new Map(
      (managedDatabases.results ?? []).map((database) => [database.name, database.id]),
    );

    for (const measurement of databaseUsage) {
      const databaseId = managedByName.get(measurement.name);
      if (!databaseId) continue;

      databaseUsageStatements.push(
        c.env.DB.prepare(
          `INSERT INTO database_usage
           (database_id, server_id, organization_id, used_bytes, collected_at, received_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(database_id) DO UPDATE SET
             server_id = excluded.server_id,
             organization_id = excluded.organization_id,
             used_bytes = excluded.used_bytes,
             collected_at = excluded.collected_at,
             received_at = excluded.received_at
           WHERE excluded.collected_at >= database_usage.collected_at`,
        ).bind(databaseId, credential.serverId, credential.organizationId,
          measurement.usedBytes, measurement.collectedAt, now),
      );
    }
  }

  const incidentStatements = serviceChecks.flatMap((check) => {
    const incidentKey = `service:${check.key}`;
    if (check.status === "INACTIVE" || check.status === "FAILED") {
      const severity = check.status === "FAILED" ? "CRITICAL" : "WARNING";
      const title = `${check.displayName} ${check.status.toLowerCase()}`;
      const description = `${check.displayName} reported ${check.status} by the authenticated server agent.`;

      return [
        c.env.DB.prepare(
          "UPDATE server_incidents SET updated_at = ?, last_observed_at = ?, severity = ?, title = ?, description = ? WHERE server_id = ? AND organization_id = ? AND incident_key = ? AND resolved_at IS NULL",
        ).bind(now, check.checkedAt, severity, title, description, credential.serverId, credential.organizationId, incidentKey),
        c.env.DB.prepare(
          "INSERT OR IGNORE INTO server_incidents (id, organization_id, server_id, incident_type, incident_key, severity, status, title, description, opened_at, updated_at, last_observed_at) SELECT ?, ?, ?, 'SERVICE', ?, ?, 'OPEN', ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM servers WHERE id = ? AND organization_id = ?)",
        ).bind(
          crypto.randomUUID(), credential.organizationId, credential.serverId,
          incidentKey, severity, title, description, now, now, check.checkedAt,
          credential.serverId, credential.organizationId,
        ),
        notificationOutboxStatement(
          c.env.DB, credential.organizationId, credential.serverId,
          incidentKey, "OPENED", now,
        ),
      ];
    }

    if (check.status === "ACTIVE") {
      return [
        c.env.DB.prepare(
          "UPDATE server_incidents SET status = 'RESOLVED', resolved_at = ?, updated_at = ?, last_observed_at = ? WHERE server_id = ? AND organization_id = ? AND incident_key = ? AND resolved_at IS NULL",
        ).bind(now, now, check.checkedAt, credential.serverId, credential.organizationId, incidentKey),
        notificationOutboxStatement(
          c.env.DB, credential.organizationId, credential.serverId,
          incidentKey, "RESOLVED", now,
        ),
      ];
    }

    return [];
  });

  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO server_telemetry (id, server_id, agent_version, cpu_usage_percent, memory_total_bytes, memory_used_bytes, disk_total_bytes, disk_used_bytes, load_average_1m, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(crypto.randomUUID(), credential.serverId, agentVersion, cpu, memoryTotal, memoryUsed, diskTotal, diskUsed, load, collectedAt),
    c.env.DB.prepare("UPDATE servers SET status = 'ONLINE', agent_version = ?, last_heartbeat_at = ?, updated_at = ? WHERE id = ?")
      .bind(agentVersion, now, now, credential.serverId),
    ...serviceChecks.map((check) =>
      c.env.DB.prepare(
        "INSERT INTO server_service_checks (id, server_id, service_key, display_name, status, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(crypto.randomUUID(), credential.serverId, check.key, check.displayName, check.status, check.checkedAt),
    ),
    ...databaseUsageStatements,
    c.env.DB.prepare("UPDATE agent_credentials SET last_seen_at = ? WHERE node_id = ?").bind(now, nodeId),
    ...incidentStatements,
    c.env.DB.prepare("UPDATE server_incidents SET status = 'RESOLVED', resolved_at = ?, updated_at = ?, last_observed_at = ? WHERE server_id = ? AND organization_id = ? AND incident_key = 'server-heartbeat' AND resolved_at IS NULL")
      .bind(now, now, now, credential.serverId, credential.organizationId),
    notificationOutboxStatement(
      c.env.DB, credential.organizationId, credential.serverId,
      "server-heartbeat", "RESOLVED", now,
    ),
    c.env.DB.prepare("DELETE FROM agent_nonces WHERE created_at < ?").bind(new Date(Date.now() - 10 * 60 * 1000).toISOString()),
  ]);
  return c.json({ accepted: true, receivedAt: now });
});



type StorePlanRow = { id: string; name: string; disk_limit_bytes: number; bandwidth_limit_bytes: number | null; website_limit: number; database_limit: number; mailbox_limit: number; price_sar_minor: number; billing_period: string };
async function platformOwnerOrganization(db: D1Database): Promise<string | null> {
  const row = await db.prepare(
    `SELECT m.organization_id AS organizationId
     FROM platform_memberships pm
     JOIN memberships m ON m.user_id = pm.user_id
     WHERE pm.role = 'PLATFORM_OWNER' AND pm.status = 'ACTIVE'
     ORDER BY pm.created_at ASC LIMIT 1`,
  ).first<{ organizationId: string }>();
  return row?.organizationId ?? null;
}
function platformAdmin(identity: { platformRole: PlatformRole | null }): boolean {
  return identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
}

app.get("/v1/store/plans", async (c) => {
  const ownerOrganizationId = await platformOwnerOrganization(c.env.DB);
  if (!ownerOrganizationId) return c.json({ plans: [] });
  const rows = await c.env.DB.prepare(
    `SELECT id,name,disk_limit_bytes,bandwidth_limit_bytes,website_limit,database_limit,mailbox_limit,
            price_sar_minor,billing_period
     FROM hosting_plans
     WHERE organization_id = ? AND active = 1 AND public_enabled = 1 AND price_sar_minor > 0
     ORDER BY price_sar_minor ASC,name COLLATE NOCASE`,
  ).bind(ownerOrganizationId).all<StorePlanRow>();
  return c.json({ plans: rows.results ?? [] });
});

app.get("/v1/store/payment-instructions", async (c) => {
  const ownerOrganizationId = await platformOwnerOrganization(c.env.DB);
  if (!ownerOrganizationId) return c.json({ configured: false, instructions: null });
  const settings = await c.env.DB.prepare(
    "SELECT bank_name,account_holder,iban,payment_instructions FROM payment_settings WHERE organization_id = ? LIMIT 1",
  ).bind(ownerOrganizationId).first<{ bank_name: string | null; account_holder: string | null; iban: string | null; payment_instructions: string | null }>();
  const configured = Boolean(settings?.bank_name && settings?.account_holder && settings?.iban);
  return c.json({ configured, instructions: configured ? settings : null });
});

app.get("/v1/store/orders", async (c) => {
  const identity = await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" },401);
  const rows = await c.env.DB.prepare(
    `SELECT id,order_reference,plan_name,amount_sar_minor,billing_period,desired_username,primary_domain,
            status,transfer_reference,receipt_content_type,receipt_size,review_note,created_at,updated_at
     FROM payment_orders WHERE organization_id = ? AND user_id = ? ORDER BY created_at DESC`,
  ).bind(identity.organizationId,identity.id).all();
  return c.json({ orders: rows.results ?? [] });
});

app.post("/v1/store/orders", async (c) => {
  const identity = await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" },401);
  let input: Record<string,unknown>;
  try { input = await c.req.json<Record<string,unknown>>(); } catch { return c.json({message:"Invalid JSON request"},400); }
  const planId = typeof input.planId === "string" ? input.planId : "";
  const username = typeof input.username === "string" ? input.username.trim().toLowerCase() : "";
  const domain = typeof input.primaryDomain === "string" ? input.primaryDomain.trim().toLowerCase() : "";
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(username)) return c.json({message:"Choose a username of 3–16 lowercase letters, numbers or underscores."},400);
  if (domain && !validDomain(domain)) return c.json({message:"Enter a valid domain name."},400);
  const ownerOrganizationId = await platformOwnerOrganization(c.env.DB);
  if (!ownerOrganizationId) return c.json({message:"The hosting catalogue is not configured."},503);
  const plan = await c.env.DB.prepare(
    "SELECT id,name,price_sar_minor,billing_period,website_limit FROM hosting_plans WHERE id = ? AND organization_id = ? AND active = 1 AND public_enabled = 1 LIMIT 1",
  ).bind(planId,ownerOrganizationId).first<{id:string;name:string;price_sar_minor:number|null;billing_period:string;website_limit:number}>();
  if (!plan || !plan.price_sar_minor || plan.price_sar_minor < 1) return c.json({message:"This hosting plan is not available for purchase."},404);
  if (domain && plan.website_limit < 1) return c.json({message:"This plan does not include a website slot."},409);
  const id=crypto.randomUUID(), reference="NX-"+randomHex(6).toUpperCase(), now=new Date().toISOString();
  await c.env.DB.prepare(
    `INSERT INTO payment_orders
     (id,organization_id,user_id,plan_id,order_reference,plan_name,amount_sar_minor,billing_period,desired_username,primary_domain,status,created_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,'AWAITING_PAYMENT',?,?)`,
  ).bind(id,identity.organizationId,identity.id,plan.id,reference,plan.name,plan.price_sar_minor,plan.billing_period,username,domain||null,now,now).run();
  return c.json({order:{id,order_reference:reference,plan_name:plan.name,amount_sar_minor:plan.price_sar_minor,billing_period:plan.billing_period,status:"AWAITING_PAYMENT"}},201);
});

app.post("/v1/store/orders/:id/receipt", async (c) => {
  const identity = await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!c.env.ARTIFACTS) return c.json({message:"Private receipt storage is unavailable."},503);
  let input: Record<string,unknown>;
  try { input=await c.req.json<Record<string,unknown>>(); } catch { return c.json({message:"Invalid JSON request"},400); }
  const transferReference=typeof input.transferReference==="string"?input.transferReference.trim().slice(0,100):"";
  const contentType=typeof input.contentType==="string"?input.contentType:"";
  const encoded=typeof input.fileBase64==="string"?input.fileBase64:"";
  if (!transferReference) return c.json({message:"Enter the bank transfer reference."},400);
  if (!["image/jpeg","image/png","application/pdf"].includes(contentType)) return c.json({message:"Upload a JPG, PNG or PDF receipt."},400);
  if (!encoded || encoded.length > 7_000_000) return c.json({message:"Receipt is empty or exceeds the 5 MB limit."},400);
  let bytes: Uint8Array;
  try { const binary=atob(encoded); bytes=Uint8Array.from(binary,ch=>ch.charCodeAt(0)); } catch { return c.json({message:"Receipt file is invalid."},400); }
  if (bytes.length < 1 || bytes.length > 5*1024*1024) return c.json({message:"Receipt must be 5 MB or smaller."},400);
  const order=await c.env.DB.prepare("SELECT id,status FROM payment_orders WHERE id=? AND organization_id=? AND user_id=? LIMIT 1")
    .bind(c.req.param("id"),identity.organizationId,identity.id).first<{id:string;status:string}>();
  if (!order) return c.json({message:"Order not found."},404);
  if (!["AWAITING_PAYMENT","REJECTED"].includes(order.status)) return c.json({message:"A receipt cannot be changed for this order status."},409);
  const key="payment-receipts/"+identity.organizationId+"/"+order.id+"/"+crypto.randomUUID();
  await c.env.ARTIFACTS.put(key,bytes,{httpMetadata:{contentType}});
  const now=new Date().toISOString();
  await c.env.DB.prepare(
    "UPDATE payment_orders SET receipt_key=?,receipt_content_type=?,receipt_size=?,transfer_reference=?,status='RECEIPT_SUBMITTED',updated_at=?,review_note=NULL WHERE id=? AND organization_id=? AND user_id=?",
  ).bind(key,contentType,bytes.length,transferReference,now,order.id,identity.organizationId,identity.id).run();
  return c.json({submitted:true,message:"Receipt submitted for Nexora review."});
});

app.get("/v1/platform/payment-settings", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  const row=await c.env.DB.prepare("SELECT bank_name,account_holder,iban,payment_instructions,updated_at FROM payment_settings WHERE organization_id=? LIMIT 1")
    .bind(identity.organizationId).first();
  return c.json({settings:row??{bank_name:"",account_holder:"",iban:"",payment_instructions:""}});
});

app.put("/v1/platform/payment-settings", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  let input:Record<string,unknown>;
  try { input=await c.req.json<Record<string,unknown>>(); } catch { return c.json({message:"Invalid JSON request"},400); }
  const bankName=typeof input.bankName==="string"?input.bankName.trim().slice(0,100):"";
  const holder=typeof input.accountHolder==="string"?input.accountHolder.trim().slice(0,120):"";
  const iban=typeof input.iban==="string"?input.iban.replace(/\\s/g,"").toUpperCase().slice(0,34):"";
  const instructions=typeof input.instructions==="string"?input.instructions.trim().slice(0,2000):"";
  if (iban && !/^[A-Z]{2}[0-9A-Z]{13,32}$/.test(iban)) return c.json({message:"Enter a valid IBAN or leave it blank until you are ready."},400);
  await c.env.DB.prepare(
    `INSERT INTO payment_settings (organization_id,bank_name,account_holder,iban,payment_instructions,updated_by,updated_at)
     VALUES (?,?,?,?,?,?,?) ON CONFLICT(organization_id) DO UPDATE SET bank_name=excluded.bank_name,
     account_holder=excluded.account_holder,iban=excluded.iban,payment_instructions=excluded.payment_instructions,
     updated_by=excluded.updated_by,updated_at=excluded.updated_at`,
  ).bind(identity.organizationId,bankName||null,holder||null,iban||null,instructions||null,identity.id,new Date().toISOString()).run();
  await c.env.DB.prepare("INSERT INTO audit_logs (id,organization_id,actor_user_id,action,resource_type,metadata) VALUES (?,?,?,'payment.settings_updated','payment_settings',?)")
    .bind(crypto.randomUUID(),identity.organizationId,identity.id,JSON.stringify({bankConfigured:Boolean(bankName&&holder&&iban)})).run();
  return c.json({saved:true});
});

app.get("/v1/platform/payment-orders", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  const rows=await c.env.DB.prepare(
    `SELECT po.id,po.order_reference,po.plan_name,po.amount_sar_minor,po.billing_period,po.desired_username,
            po.primary_domain,po.status,po.transfer_reference,po.receipt_content_type,po.receipt_size,
            po.review_note,po.created_at,po.updated_at,u.email,u.display_name AS customer_name,o.name AS organization_name
     FROM payment_orders po JOIN users u ON u.id=po.user_id JOIN organizations o ON o.id=po.organization_id
     ORDER BY po.created_at DESC LIMIT 200`,
  ).all();
  return c.json({orders:rows.results??[]});
});

app.get("/v1/platform/payment-orders/:id/receipt", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  const order=await c.env.DB.prepare("SELECT receipt_key,receipt_content_type FROM payment_orders WHERE id=? LIMIT 1")
    .bind(c.req.param("id")).first<{receipt_key:string|null;receipt_content_type:string|null}>();
  if (!order?.receipt_key || !c.env.ARTIFACTS) return c.json({message:"Receipt not found."},404);
  const object=await c.env.ARTIFACTS.get(order.receipt_key);
  if (!object) return c.json({message:"Receipt file is missing."},404);
  const bytes=new Uint8Array(await object.arrayBuffer());
  let binary=""; for(let i=0;i<bytes.length;i+=0x8000) binary+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
  return c.json({contentType:order.receipt_content_type,fileBase64:btoa(binary)});
});

app.post("/v1/platform/payment-orders/:id/review", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  let input:Record<string,unknown>;
  try { input=await c.req.json<Record<string,unknown>>(); } catch { return c.json({message:"Invalid JSON request"},400); }
  const decision=input.decision==="approve"?"APPROVED":input.decision==="reject"?"REJECTED":null;
  const note=typeof input.note==="string"?input.note.trim().slice(0,500):"";
  if (!decision) return c.json({message:"Choose approve or reject."},400);
  if (decision==="REJECTED"&&!note) return c.json({message:"A reason is required when rejecting a payment."},400);
  const order=await c.env.DB.prepare("SELECT id,organization_id,user_id,status FROM payment_orders WHERE id=? LIMIT 1")
    .bind(c.req.param("id")).first<{id:string;organization_id:string;user_id:string;status:string}>();
  if (!order) return c.json({message:"Order not found."},404);
  if (!["RECEIPT_SUBMITTED","UNDER_REVIEW"].includes(order.status)) return c.json({message:"Only submitted receipts can be reviewed."},409);
  const now=new Date().toISOString();
  const result=await c.env.DB.prepare(
    "UPDATE payment_orders SET status=?,reviewed_by=?,reviewed_at=?,review_note=?,updated_at=? WHERE id=? AND status IN ('RECEIPT_SUBMITTED','UNDER_REVIEW')",
  ).bind(decision,identity.id,now,note||null,now,order.id).run();
  if ((result.meta?.changes??0)!==1) return c.json({message:"This order was already reviewed. Refresh the list."},409);
  await c.env.DB.prepare("INSERT INTO audit_logs (id,organization_id,actor_user_id,action,resource_type,resource_id,metadata) VALUES (?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),identity.organizationId,identity.id,decision==="APPROVED"?"payment.order_approved":"payment.order_rejected","payment_order",order.id,JSON.stringify({customerOrganizationId:order.organization_id,note})).run();
  return c.json({reviewed:true,status:decision,message:decision==="APPROVED"?"Payment approved. Hosting provisioning must now be completed from the hosting-account workflow.":"Payment rejected. The customer can submit a corrected receipt."});
});

// ---------------------------------------------------------------------------
// Subscriptions, invoices, and billing operations.
//
// Design rules:
//   - No fabricated payment success. Invoices are marked PAID only by an
//     explicit admin renewal record (bank transfer with reference) or a
//     signature-verified provider webhook.
//   - Idempotency: invoice creation is keyed by payment_order_ref /
//     provider_ref / an explicit client idempotency key; webhook events are
//     deduplicated through billing_webhook_events; live-subscription
//     uniqueness is enforced by a partial UNIQUE index.
//   - Plan changes validate current resource usage against the target
//     plan's quotas; downgrades that would violate usage are rejected with
//     409 and a violation list instead of silently breaking accounts.
//   - Expiration is lazy (evaluated on read) plus a cron sweep so no
//     background job is required to observe EXPIRED state.
// ---------------------------------------------------------------------------

const BILLING_PERIOD_MONTHS: Record<string, number> = { monthly: 1, yearly: 12 };
const RETRYABLE_JOB_OPERATIONS = new Set([
  "ADD_DOMAIN", "REMOVE_DOMAIN", "CREATE_DATABASE", "CREATE_DATABASE_USER",
  "REVOKE_DATABASE_USER", "RESET_DATABASE_USER_PASSWORD", "UPDATE_PHP_POOL",
  "SUSPEND_HOSTING_ACCOUNT", "REACTIVATE_HOSTING_ACCOUNT",
  "CREATE_BACKUP", "DELETE_BACKUP",
]);

type SubscriptionRow = {
  id: string; organizationId: string; hostingAccountId: string | null;
  planId: string; status: string; billingPeriod: string; provider: string;
  amountSarMinor: number | null; currentPeriodStart: string | null;
  currentPeriodEnd: string | null; trialEnd: string | null;
  cancelAtPeriodEnd: number; cancelledAt: string | null; suspendedAt: string | null;
};

// expireDueSubscriptions transitions ACTIVE/TRIALING subscriptions whose
// current_period_end has passed to EXPIRED (or to CANCELLED when a
// cancellation was scheduled at period end) and records the events. Used by
// both the lazy read path and the cron sweep. Returns the number changed.
async function expireDueSubscriptions(db: D1Database): Promise<number> {
  const now = new Date().toISOString();
  const due = await db.prepare(
    `SELECT id, organization_id, status, cancel_at_period_end FROM subscriptions
     WHERE status IN ('TRIALING','ACTIVE')
       AND current_period_end IS NOT NULL AND current_period_end < ?`,
  ).bind(now).all<{ id: string; organization_id: string; status: string; cancel_at_period_end: number }>();
  const rows = due.results ?? [];
  let changed = 0;
  for (const row of rows) {
    const nextStatus = row.cancel_at_period_end === 1 ? "CANCELLED" : "EXPIRED";
    const result = await db.prepare(
      `UPDATE subscriptions SET status = ?, cancelled_at = CASE WHEN ? = 'CANCELLED' THEN ? ELSE cancelled_at END,
         updated_at = ? WHERE id = ? AND status IN ('TRIALING','ACTIVE')`,
    ).bind(nextStatus, nextStatus, now, now, row.id).run();
    if ((result.meta?.changes ?? 0) === 1) {
      changed += 1;
      await db.prepare(
        "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, metadata) VALUES (?, ?, ?, ?, ?)",
      ).bind(crypto.randomUUID(), row.id, row.organization_id, nextStatus === "CANCELLED" ? "cancelled" : "expired", JSON.stringify({ reason: "period_ended" })).run();
    }
  }
  return changed;
}

// appendSubscriptionEvent records an auditable subscription transition.
// (Retained as the single definition point for event metadata shapes.)
async function appendSubscriptionEvent(
  db: D1Database, subscriptionId: string, organizationId: string | null,
  eventType: string, actorUserId: string | null, metadata: Record<string, unknown>,
) {
  await db.prepare(
    "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), subscriptionId, organizationId, eventType, actorUserId, JSON.stringify(metadata)).run();
}
void appendSubscriptionEvent;

// nextInvoiceNumber allocates the next sequential invoice number for an
// organization through the counter table. UPDATE ... RETURNING performs an
// atomic increment; the first call seeds the counter at 0 via an idempotent
// INSERT so the first invoice number is 1. The UNIQUE invoice_number
// constraint is the final guard against a raced allocation.
async function nextInvoiceNumber(db: D1Database, organizationId: string): Promise<string> {
  let row = await db.prepare(
    `UPDATE invoice_counters SET last_number = last_number + 1 WHERE organization_id = ?
     RETURNING last_number`,
  ).bind(organizationId).first<{ last_number: number }>();
  if (!row) {
    await db.prepare(
      "INSERT INTO invoice_counters (organization_id, last_number) VALUES (?, 0) ON CONFLICT(organization_id) DO NOTHING",
    ).bind(organizationId).run();
    row = await db.prepare(
      `UPDATE invoice_counters SET last_number = last_number + 1 WHERE organization_id = ?
       RETURNING last_number`,
    ).bind(organizationId).first<{ last_number: number }>();
  }
  const value = row?.last_number ?? 1;
  return `INV-${new Date().getUTCFullYear()}-${String(value).padStart(6, "0")}`;
}

// Subscription inventory. Platform admins see every subscription; the org
// OWNER/ADMIN/BILLING see their own workspace's subscriptions.
app.get("/v1/subscriptions", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  await expireDueSubscriptions(c.env.DB).catch(() => 0);
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  const orgFilter = isPlatformAdmin ? c.req.query("organizationId") : identity.organizationId;
  const status = c.req.query("status");
  const conditions: string[] = [];
  const binds: (string)[] = [];
  if (!isPlatformAdmin) conditions.push("s.organization_id = ?");
  else if (orgFilter) conditions.push("s.organization_id = ?");
  if (orgFilter) binds.push(orgFilter);
  if (status && /^[A-Z_]{3,20}$/.test(status)) { conditions.push("s.status = ?"); binds.push(status); }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const result = await c.env.DB.prepare(
    `SELECT s.id, s.organization_id AS organizationId, o.name AS organizationName,
            s.hosting_account_id AS hostingAccountId, a.username AS accountUsername,
            a.primary_domain AS primaryDomain,
            s.plan_id AS planId, p.name AS planName,
            s.status, s.billing_period AS billingPeriod, s.provider,
            s.amount_sar_minor AS amountSarMinor,
            s.current_period_start AS currentPeriodStart, s.current_period_end AS currentPeriodEnd,
            s.trial_end AS trialEnd, s.cancel_at_period_end AS cancelAtPeriodEnd,
            s.cancelled_at AS cancelledAt, s.suspended_at AS suspendedAt,
            s.created_at AS createdAt,
            CASE WHEN s.status IN ('ACTIVE','TRIALING') AND s.current_period_end < datetime('now') THEN 1 ELSE 0 END AS periodOverdue
     FROM subscriptions s
     JOIN organizations o ON o.id = s.organization_id
     JOIN hosting_plans p ON p.id = s.plan_id
     LEFT JOIN hosting_accounts a ON a.id = s.hosting_account_id
     ${where} ORDER BY s.created_at DESC LIMIT 200`,
  ).bind(...binds).all();
  return c.json({ subscriptions: result.results ?? [] });
});

// Create a subscription for a hosting account. Platform admin only. The
// partial UNIQUE index rejects a second live subscription for the same
// account; period bounds and trial windows are validated server-side.
app.post("/v1/subscriptions", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const hostingAccountId = typeof input.hostingAccountId === "string" ? input.hostingAccountId : "";
  const planId = typeof input.planId === "string" ? input.planId : "";
  const billingPeriod = input.billingPeriod === "yearly" ? "yearly" : "monthly";
  const trialDays = input.trialDays === undefined ? 0 : Number(input.trialDays);
  const amountSarMinor = input.amountSarMinor == null || input.amountSarMinor === "" ? null : Number(input.amountSarMinor);
  if (!/^[0-9a-f-]{36}$/i.test(hostingAccountId)) return c.json({ message: "A valid hosting account is required." }, 400);
  if (!/^[0-9a-f-]{36}$/i.test(planId)) return c.json({ message: "A valid hosting plan is required." }, 400);
  if (!Number.isInteger(trialDays) || trialDays < 0 || trialDays > 90) return c.json({ message: "Trial days must be between 0 and 90." }, 400);
  if (amountSarMinor !== null && (!Number.isSafeInteger(amountSarMinor) || amountSarMinor < 0 || amountSarMinor > 100000000)) {
    return c.json({ message: "Amount must be between SAR 0.00 and SAR 1,000,000.00." }, 400);
  }
  const account = await c.env.DB.prepare(
    `SELECT a.id, a.organization_id AS organizationId, a.status, p.id AS planId
     FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.id = ? LIMIT 1`,
  ).bind(hostingAccountId).first<{ id: string; organizationId: string; status: string; planId: string }>();
  if (!account) return c.json({ message: "Hosting account not found." }, 404);
  if (account.status !== "ACTIVE") return c.json({ message: "Subscriptions can only be created for active hosting accounts." }, 409);
  const plan = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, active, price_sar_minor AS priceSarMinor, billing_period AS billingPeriod FROM hosting_plans WHERE id = ? LIMIT 1",
  ).bind(planId).first<{ id: string; organizationId: string; active: number; priceSarMinor: number | null; billingPeriod: string }>();
  if (!plan) return c.json({ message: "Hosting plan not found." }, 404);
  if (plan.organizationId !== account.organizationId) return c.json({ message: "The plan must belong to the same workspace as the hosting account." }, 400);
  if (!plan.active) return c.json({ message: "This plan is inactive. Activate it before subscribing." }, 409);
  const now = new Date();
  const nowIso = now.toISOString();
  const periodMonths = BILLING_PERIOD_MONTHS[billingPeriod];
  const periodEnd = addMonthsClamped(now, periodMonths);
  const trialEnd = trialDays > 0 ? new Date(now.getTime() + trialDays * 86400_000).toISOString() : null;
  const id = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO subscriptions
         (id, organization_id, hosting_account_id, plan_id, status, billing_period, provider, amount_sar_minor,
          current_period_start, current_period_end, trial_end)
         VALUES (?, ?, ?, ?, ?, ?, 'manual', ?, ?, ?, ?)`,
      ).bind(id, account.organizationId, account.id, planId, trialDays > 0 ? "TRIALING" : "ACTIVE", billingPeriod,
        amountSarMinor ?? plan.priceSarMinor, nowIso, periodEnd.toISOString(), trialEnd),
      c.env.DB.prepare(
        "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'created', ?, ?)",
      ).bind(crypto.randomUUID(), id, account.organizationId, identity.id,
        JSON.stringify({ hostingAccountId: account.id, planId, billingPeriod, trialDays })),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.created', 'subscription', ?, ?)",
      ).bind(crypto.randomUUID(), account.organizationId, identity.id, id, JSON.stringify({ hostingAccountId: account.id, planId })),
    ]);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return c.json({ message: "This hosting account already has a live subscription." }, 409);
    }
    return c.json({ message: "Unable to create the subscription." }, 500);
  }
  return c.json({ subscription: { id, status: trialDays > 0 ? "TRIALING" : "ACTIVE", currentPeriodEnd: periodEnd.toISOString(), trialEnd } }, 201);
});

// Record a renewal payment: extends the period, writes a PAID invoice, and
// appends audited events. Idempotent per idempotencyKey — replaying the same
// key returns the original invoice instead of double-charging the period.
app.post("/v1/subscriptions/:id/renew", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const idempotencyKey = typeof input.idempotencyKey === "string" && input.idempotencyKey.length <= 128 ? input.idempotencyKey : "";
  const transferReference = typeof input.transferReference === "string" ? input.transferReference.trim().slice(0, 120) : "";
  const amountSarMinor = input.amountSarMinor == null || input.amountSarMinor === "" ? null : Number(input.amountSarMinor);
  if (amountSarMinor !== null && (!Number.isSafeInteger(amountSarMinor) || amountSarMinor < 100 || amountSarMinor > 100000000)) {
    return c.json({ message: "Amount must be between SAR 1.00 and SAR 1,000,000.00." }, 400);
  }
  if (!idempotencyKey && !transferReference) {
    return c.json({ message: "Provide an idempotency key or a bank transfer reference so this payment is traceable and cannot be double-applied." }, 400);
  }
  const dedupeRef = idempotencyKey || `bank-transfer:${transferReference}`;
  const subscription = await c.env.DB.prepare(
    `SELECT id, organization_id AS organizationId, hosting_account_id AS hostingAccountId,
            plan_id AS planId, status, billing_period AS billingPeriod, amount_sar_minor AS amountSarMinor,
            current_period_end AS currentPeriodEnd
     FROM subscriptions WHERE id = ? LIMIT 1`,
  ).bind(c.req.param("id")).first<SubscriptionRow>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  if (!["ACTIVE", "TRIALING", "PAST_DUE", "SUSPENDED", "EXPIRED"].includes(subscription.status)) {
    return c.json({ message: "A cancelled subscription cannot be renewed. Create a new subscription instead." }, 409);
  }
  // Idempotency: an invoice already exists for this payment reference.
  const existingInvoice = await c.env.DB.prepare(
    "SELECT id, invoice_number AS invoiceNumber, status, paid_at AS paidAt FROM invoices WHERE payment_order_ref = ? LIMIT 1",
  ).bind(dedupeRef).first<{ id: string; invoiceNumber: string; status: string; paidAt: string | null }>();
  if (existingInvoice) {
    return c.json({ duplicate: true, invoice: existingInvoice, message: "This payment was already recorded." });
  }
  await expireDueSubscriptions(c.env.DB).catch(() => 0);
  const fresh = await c.env.DB.prepare(
    "SELECT status, current_period_end AS currentPeriodEnd, amount_sar_minor AS amountSarMinor, billing_period AS billingPeriod FROM subscriptions WHERE id = ? LIMIT 1",
  ).bind(subscription.id).first<{ status: string; currentPeriodEnd: string | null; amountSarMinor: number | null; billingPeriod: string }>();
  if (!fresh) return c.json({ message: "Subscription not found." }, 404);
  const now = new Date();
  const nowIso = now.toISOString();
  // Renewals stack on the existing period when it has not ended yet, and on
  // "now" when it has, so no paid time is lost or double-counted.
  const base = fresh.currentPeriodEnd && fresh.currentPeriodEnd > nowIso ? new Date(fresh.currentPeriodEnd) : now;
  const periodMonths = BILLING_PERIOD_MONTHS[fresh.billingPeriod] ?? 1;
  const newPeriodEnd = addMonthsClamped(base, periodMonths);
  const invoiceAmount = amountSarMinor ?? fresh.amountSarMinor;
  if (invoiceAmount === null) return c.json({ message: "Set an amount or configure a plan price before recording a renewal." }, 400);
  const invoiceNumber = await nextInvoiceNumber(c.env.DB, subscription.organizationId);
  const invoiceId = crypto.randomUUID();
  await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE subscriptions SET status = 'ACTIVE', current_period_start = ?, current_period_end = ?,
         suspended_at = NULL, updated_at = ? WHERE id = ? AND status IN ('ACTIVE','TRIALING','PAST_DUE','SUSPENDED','EXPIRED')`,
    ).bind(nowIso, newPeriodEnd.toISOString(), nowIso, subscription.id),
    c.env.DB.prepare(
      `INSERT INTO invoices
       (id, organization_id, subscription_id, hosting_account_id, invoice_number, amount_sar_minor,
        status, billing_period, period_start, period_end, due_date, paid_at, payment_method, payment_order_ref)
       VALUES (?, ?, ?, ?, ?, ?, 'PAID', ?, ?, ?, ?, ?, 'bank_transfer', ?)`,
    ).bind(invoiceId, subscription.organizationId, subscription.id, subscription.hostingAccountId,
      invoiceNumber, invoiceAmount, fresh.billingPeriod, nowIso, newPeriodEnd.toISOString(),
      newPeriodEnd.toISOString(), nowIso, dedupeRef),
    c.env.DB.prepare(
      "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'renewed', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id,
      JSON.stringify({ invoiceId, invoiceNumber, newPeriodEnd: newPeriodEnd.toISOString(), dedupeRef })),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.renewed', 'subscription', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id,
      JSON.stringify({ invoiceId, invoiceNumber, transferReference })),
  ]);
  return c.json({ invoice: { id: invoiceId, invoiceNumber, status: "PAID", paidAt: nowIso, amountSarMinor: invoiceAmount }, currentPeriodEnd: newPeriodEnd.toISOString() }, 201);
});

// Change the plan of a live subscription. Usage is validated against the
// target plan before the change; violations are returned, not applied.
app.post("/v1/subscriptions/:id/plan", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const planId = typeof input.planId === "string" ? input.planId : "";
  if (!/^[0-9a-f-]{36}$/i.test(planId)) return c.json({ message: "A valid hosting plan is required." }, 400);
  const subscription = await c.env.DB.prepare(
    `SELECT s.id, s.organization_id AS organizationId, s.hosting_account_id AS hostingAccountId, s.status, s.plan_id AS planId
     FROM subscriptions s WHERE s.id = ? LIMIT 1`,
  ).bind(c.req.param("id")).first<{ id: string; organizationId: string; hostingAccountId: string | null; status: string; planId: string }>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  if (!["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status)) {
    return c.json({ message: "Only a live subscription can change plan." }, 409);
  }
  if (subscription.planId === planId) return c.json({ success: true, message: "Subscription is already on that plan." });
  const targetPlan = await c.env.DB.prepare(
    `SELECT id, name, active, disk_limit_bytes AS diskLimitBytes, website_limit AS websiteLimit,
            database_limit AS databaseLimit, mailbox_limit AS mailboxLimit
     FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1`,
  ).bind(planId, subscription.organizationId).first<{ id: string; name: string; active: number; diskLimitBytes: number; websiteLimit: number; databaseLimit: number; mailboxLimit: number }>();
  if (!targetPlan) return c.json({ message: "Hosting plan not found in this workspace." }, 404);
  if (!targetPlan.active) return c.json({ message: "The target plan is inactive." }, 409);
  if (subscription.hostingAccountId) {
    const usage = await c.env.DB.prepare(
      `SELECT
         (SELECT COUNT(*) FROM domains d WHERE d.hosting_account_id = ? AND d.status != 'DELETED') AS domainCount,
         (SELECT COUNT(*) FROM hosting_databases db WHERE db.hosting_account_id = ? AND db.status != 'DELETED') AS databaseCount`,
    ).bind(subscription.hostingAccountId, subscription.hostingAccountId).first<{ domainCount: number; databaseCount: number }>();
    const violations: string[] = [];
    if (usage) {
      if (usage.domainCount > targetPlan.websiteLimit) violations.push(`Websites in use (${usage.domainCount}) exceed the target plan limit (${targetPlan.websiteLimit}).`);
      if (usage.databaseCount > targetPlan.databaseLimit) violations.push(`Databases in use (${usage.databaseCount}) exceed the target plan limit (${targetPlan.databaseLimit}).`);
    }
    if (violations.length > 0) {
      return c.json({ message: "Plan change rejected: current usage does not fit the target plan.", violations }, 409);
    }
  }
  const nowIso = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE subscriptions SET plan_id = ?, updated_at = ? WHERE id = ?").bind(planId, nowIso, subscription.id),
    c.env.DB.prepare(
      "UPDATE hosting_accounts SET plan_id = ?, updated_at = ? WHERE id = ? AND organization_id = ?",
    ).bind(planId, nowIso, subscription.hostingAccountId, subscription.organizationId),
    c.env.DB.prepare(
      "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'plan_changed', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id,
      JSON.stringify({ previousPlanId: subscription.planId, newPlanId: planId })),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.plan_changed', 'subscription', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id,
      JSON.stringify({ previousPlanId: subscription.planId, newPlanId: planId })),
  ]);
  return c.json({ success: true, planId, message: "Subscription plan changed." });
});

// Cancel a subscription. cancelAtPeriodEnd keeps service live until the
// period ends (the expiry sweep converts it to CANCELLED); immediate cancel
// ends it now. Subscription owners (org OWNER) and platform admins only.
app.post("/v1/subscriptions/:id/cancel", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { input = {}; }
  const immediate = input.immediate === true;
  const subscription = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, status FROM subscriptions WHERE id = ? LIMIT 1",
  ).bind(c.req.param("id")).first<{ id: string; organizationId: string; status: string }>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  if (!isPlatformAdmin) {
    const membership = await resolveOrgAccess(c.env.DB, identity.id, subscription.organizationId, null);
    if (membership.role !== "OWNER") return c.json({ message: "Organization owner or platform administrator access required." }, 403);
  }
  if (!["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status)) {
    return c.json({ message: "Only a live subscription can be cancelled." }, 409);
  }
  const nowIso = new Date().toISOString();
  if (immediate) {
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE subscriptions SET status = 'CANCELLED', cancel_at_period_end = 0, cancelled_at = ?, updated_at = ? WHERE id = ?").bind(nowIso, nowIso, subscription.id),
      c.env.DB.prepare(
        "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'cancelled', ?, ?)",
      ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id, JSON.stringify({ immediate: true })),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.cancelled', 'subscription', ?, ?)",
      ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id, JSON.stringify({ immediate: true })),
    ]);
    return c.json({ success: true, status: "CANCELLED", message: "Subscription cancelled immediately." });
  }
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE subscriptions SET cancel_at_period_end = 1, updated_at = ? WHERE id = ?").bind(nowIso, subscription.id),
    c.env.DB.prepare(
      "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'cancel_scheduled', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id, JSON.stringify({})),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.cancel_scheduled', 'subscription', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id, JSON.stringify({})),
  ]);
  return c.json({ success: true, cancelAtPeriodEnd: 1, message: "Cancellation scheduled for the end of the current period." });
});

// Suspend / reactivate. Platform admin only. Suspension is the manual
// counterpart of non-payment handling; reactivation restores service.
app.post("/v1/subscriptions/:id/suspend", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const subscription = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, status FROM subscriptions WHERE id = ? LIMIT 1",
  ).bind(c.req.param("id")).first<{ id: string; organizationId: string; status: string }>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  if (!["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status)) {
    return c.json({ message: "Only a live subscription can be suspended." }, 409);
  }
  const nowIso = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE subscriptions SET status = 'SUSPENDED', suspended_at = ?, updated_at = ? WHERE id = ? AND status IN ('ACTIVE','TRIALING','PAST_DUE')").bind(nowIso, nowIso, subscription.id),
    c.env.DB.prepare(
      "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'suspended', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id, JSON.stringify({})),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.suspended', 'subscription', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id, JSON.stringify({})),
  ]);
  return c.json({ success: true, status: "SUSPENDED" });
});

app.post("/v1/subscriptions/:id/reactivate", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const subscription = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, status, current_period_end AS currentPeriodEnd FROM subscriptions WHERE id = ? LIMIT 1",
  ).bind(c.req.param("id")).first<{ id: string; organizationId: string; status: string; currentPeriodEnd: string | null }>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  if (subscription.status !== "SUSPENDED") return c.json({ message: "Only a suspended subscription can be reactivated." }, 409);
  const nowIso = new Date().toISOString();
  const nextStatus = subscription.currentPeriodEnd && subscription.currentPeriodEnd > nowIso ? "ACTIVE" : "PAST_DUE";
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE subscriptions SET status = ?, suspended_at = NULL, updated_at = ? WHERE id = ? AND status = 'SUSPENDED'").bind(nextStatus, nowIso, subscription.id),
    c.env.DB.prepare(
      "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, actor_user_id, metadata) VALUES (?, ?, ?, 'reactivated', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.id, subscription.organizationId, identity.id, JSON.stringify({ nextStatus })),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'subscription.reactivated', 'subscription', ?, ?)",
    ).bind(crypto.randomUUID(), subscription.organizationId, identity.id, subscription.id, JSON.stringify({ nextStatus })),
  ]);
  return c.json({ success: true, status: nextStatus });
});

// Full subscription detail including the event history and invoices.
app.get("/v1/subscriptions/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const subscription = await c.env.DB.prepare(
    `SELECT s.id, s.organization_id AS organizationId, o.name AS organizationName,
            s.hosting_account_id AS hostingAccountId, a.username AS accountUsername,
            s.plan_id AS planId, p.name AS planName, s.status, s.billing_period AS billingPeriod,
            s.provider, s.amount_sar_minor AS amountSarMinor,
            s.current_period_start AS currentPeriodStart, s.current_period_end AS currentPeriodEnd,
            s.trial_end AS trialEnd, s.cancel_at_period_end AS cancelAtPeriodEnd,
            s.cancelled_at AS cancelledAt, s.suspended_at AS suspendedAt, s.created_at AS createdAt
     FROM subscriptions s
     JOIN organizations o ON o.id = s.organization_id
     JOIN hosting_plans p ON p.id = s.plan_id
     LEFT JOIN hosting_accounts a ON a.id = s.hosting_account_id
     WHERE s.id = ? LIMIT 1`,
  ).bind(c.req.param("id")).first<Record<string, unknown>>();
  if (!subscription) return c.json({ message: "Subscription not found." }, 404);
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  if (!isPlatformAdmin) {
    const membership = await resolveOrgAccess(c.env.DB, identity.id, String(subscription.organizationId), null);
    if (!membership.role) return c.json({ message: "Subscription not found." }, 404);
  }
  await expireDueSubscriptions(c.env.DB).catch(() => 0);
  const events = await c.env.DB.prepare(
    `SELECT e.id, e.event_type AS eventType, e.metadata, e.created_at AS createdAt, u.email AS actorEmail
     FROM subscription_events e LEFT JOIN users u ON u.id = e.actor_user_id
     WHERE e.subscription_id = ? ORDER BY e.created_at DESC LIMIT 100`,
  ).bind(subscription.id as string).all();
  const invoiceRows = await c.env.DB.prepare(
    `SELECT id, invoice_number AS invoiceNumber, amount_sar_minor AS amountSarMinor, status,
            billing_period AS billingPeriod, period_start AS periodStart, period_end AS periodEnd,
            paid_at AS paidAt, payment_method AS paymentMethod, created_at AS createdAt
     FROM invoices WHERE subscription_id = ? ORDER BY created_at DESC LIMIT 100`,
  ).bind(subscription.id as string).all();
  return c.json({ subscription, events: events.results ?? [], invoices: invoiceRows.results ?? [] });
});

// Invoice inventory. Platform admins see all invoices (optional org filter);
// org OWNER/ADMIN/BILLING see their own.
app.get("/v1/invoices", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  const orgFilter = isPlatformAdmin ? c.req.query("organizationId") : identity.organizationId;
  const conditions: string[] = [];
  const binds: string[] = [];
  if (orgFilter) { conditions.push("i.organization_id = ?"); binds.push(orgFilter); }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const result = await c.env.DB.prepare(
    `SELECT i.id, i.organization_id AS organizationId, o.name AS organizationName,
            i.subscription_id AS subscriptionId, i.invoice_number AS invoiceNumber,
            i.amount_sar_minor AS amountSarMinor, i.status, i.billing_period AS billingPeriod,
            i.period_start AS periodStart, i.period_end AS periodEnd, i.due_date AS dueDate,
            i.paid_at AS paidAt, i.payment_method AS paymentMethod, i.notes, i.created_at AS createdAt
     FROM invoices i JOIN organizations o ON o.id = i.organization_id
     ${where} ORDER BY i.created_at DESC LIMIT 200`,
  ).bind(...binds).all();
  return c.json({ invoices: result.results ?? [] });
});

// Mark an invoice PAID or VOID manually (platform admin). Auditable and
// idempotent: marking an already-PAID invoice PAID again is a no-op.
app.post("/v1/invoices/:id/settle", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const decision = input.status === "PAID" ? "PAID" : input.status === "VOID" ? "VOID" : null;
  const notes = typeof input.notes === "string" ? input.notes.trim().slice(0, 500) : "";
  if (!decision) return c.json({ message: "Status must be PAID or VOID." }, 400);
  const invoice = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, subscription_id AS subscriptionId, status FROM invoices WHERE id = ? LIMIT 1",
  ).bind(c.req.param("id")).first<{ id: string; organizationId: string; subscriptionId: string | null; status: string }>();
  if (!invoice) return c.json({ message: "Invoice not found." }, 404);
  if (invoice.status === decision) return c.json({ success: true, message: "Invoice already has that status." });
  const nowIso = new Date().toISOString();
  const statements = [
    c.env.DB.prepare(
      `UPDATE invoices SET status = ?, paid_at = ${decision === "PAID" ? "?" : "paid_at"}, notes = ?, updated_at = ? WHERE id = ? AND status != ?`,
    ).bind(...(decision === "PAID" ? [decision, nowIso, notes, nowIso, invoice.id, decision] as const : [decision, notes, nowIso, invoice.id, decision] as const)),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'invoice.settled', 'invoice', ?, ?)",
    ).bind(crypto.randomUUID(), invoice.organizationId, identity.id, invoice.id, JSON.stringify({ status: decision, notes })),
  ];
  await c.env.DB.batch(statements as unknown as Parameters<typeof c.env.DB.batch>[0]);
  return c.json({ success: true, status: decision });
});

// Payment-provider webhook receiver. Verifies an HMAC-SHA256 signature over
// the raw body (X-Nexora-Signature: t=<unix-seconds>,v1=<hex>), rejects
// stale timestamps (replay), deduplicates event IDs, and only then
// reconciles the referenced invoice. Requires PAYMENT_WEBHOOK_SECRET; when
// it is not configured the endpoint answers 503 instead of accepting
// unsigned events.
app.post("/v1/billing/webhooks/:provider", async (c) => {
  const provider = c.req.param("provider");
  if (!/^[a-z0-9_-]{2,32}$/.test(provider)) return c.json({ message: "Invalid provider." }, 400);
  const secret = c.env.PAYMENT_WEBHOOK_SECRET ?? "";
  if (secret.length < 32) {
    return c.json({ message: "Automated payment webhooks are not configured. Set the PAYMENT_WEBHOOK_SECRET Worker secret (32+ characters) to enable provider reconciliation." }, 503);
  }
  const rawBody = await c.req.text();
  const signatureHeader = c.req.header("x-nexora-signature") ?? "";
  const match = /^t=(\d{10}),v1=([a-f0-9]{64})$/.exec(signatureHeader);
  if (!match) return c.json({ message: "Missing or malformed signature header." }, 401);
  const timestamp = Number(match[1]);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300) {
    return c.json({ message: "Signature timestamp is outside the acceptance window." }, 401);
  }
  const expected = await hmacSha256(secret, `${match[1]}.${rawBody}`);
  if (!constantTimeEqual(expected, match[2])) {
    return c.json({ message: "Signature verification failed." }, 401);
  }
  let payload: { eventId?: unknown; invoiceRef?: unknown; outcome?: unknown };
  try { payload = JSON.parse(rawBody) as typeof payload; } catch { return c.json({ message: "Invalid JSON payload." }, 400); }
  const eventId = typeof payload.eventId === "string" && payload.eventId.length <= 128 ? payload.eventId : "";
  const invoiceRef = typeof payload.invoiceRef === "string" && payload.invoiceRef.length <= 128 ? payload.invoiceRef : "";
  const outcome = payload.outcome === "paid" ? "paid" : payload.outcome === "failed" ? "failed" : null;
  if (!eventId || !invoiceRef || !outcome) return c.json({ message: "Payload must include eventId, invoiceRef, and outcome." }, 400);
  // Deduplicate: the UNIQUE(provider, event_id) insert is the gate. A
  // duplicate insert (provider redelivery or replay) is acknowledged as a
  // duplicate instead of reprocessing the payment.
  const eventIdInsert = c.env.DB.prepare(
    `INSERT INTO billing_webhook_events (id, provider, event_id, payload_digest, received_at, processed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(crypto.randomUUID(), provider, eventId, await sha256(rawBody), new Date().toISOString(),
    outcome === "paid" ? null : new Date().toISOString());
  try {
    await eventIdInsert.run();
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return c.json({ duplicate: true, message: "Event already processed." });
    }
    return c.json({ message: "Unable to record the webhook event." }, 500);
  }
  if (outcome !== "paid") {
    return c.json({ received: true, processed: false, message: "Non-payment outcomes are recorded but require manual review." });
  }
  const invoice = await c.env.DB.prepare(
    `SELECT id, organization_id AS organizationId, subscription_id AS subscriptionId, status, amount_sar_minor AS amountSarMinor
     FROM invoices WHERE payment_order_ref = ? OR provider_ref = ? LIMIT 1`,
  ).bind(invoiceRef, invoiceRef).first<{ id: string; organizationId: string; subscriptionId: string | null; status: string; amountSarMinor: number }>();
  if (!invoice) {
    return c.json({ received: true, processed: false, message: "No invoice matches the provided reference. Record it for manual reconciliation." }, 202);
  }
  if (invoice.status === "PAID") {
    return c.json({ received: true, processed: true, duplicate: true, message: "Invoice was already paid." });
  }
  const nowIso = new Date().toISOString();
  const statements = [
    c.env.DB.prepare("UPDATE invoices SET status = 'PAID', paid_at = ?, payment_method = 'external', provider_ref = ?, updated_at = ? WHERE id = ? AND status = 'OPEN'")
      .bind(nowIso, invoiceRef, nowIso, invoice.id),
  ];
  if (invoice.subscriptionId) {
    const subscription = await c.env.DB.prepare(
      "SELECT id, billing_period AS billingPeriod, current_period_end AS currentPeriodEnd FROM subscriptions WHERE id = ? LIMIT 1",
    ).bind(invoice.subscriptionId).first<{ id: string; billingPeriod: string; currentPeriodEnd: string | null }>();
    if (subscription) {
      const base = subscription.currentPeriodEnd && subscription.currentPeriodEnd > nowIso ? new Date(subscription.currentPeriodEnd) : new Date();
      const newPeriodEnd = addMonthsClamped(base, BILLING_PERIOD_MONTHS[subscription.billingPeriod] ?? 1);
      statements.push(c.env.DB.prepare(
        `UPDATE subscriptions SET status = 'ACTIVE', current_period_start = ?, current_period_end = ?, suspended_at = NULL, updated_at = ?
         WHERE id = ? AND status IN ('ACTIVE','TRIALING','PAST_DUE','SUSPENDED','EXPIRED')`,
      ).bind(nowIso, newPeriodEnd.toISOString(), nowIso, subscription.id));
      statements.push(c.env.DB.prepare(
        "INSERT INTO subscription_events (id, subscription_id, organization_id, event_type, metadata) VALUES (?, ?, ?, 'renewed', ?)",
      ).bind(crypto.randomUUID(), subscription.id, invoice.organizationId, JSON.stringify({ via: "webhook", provider, eventId })));
    }
  }
  statements.push(c.env.DB.prepare("UPDATE billing_webhook_events SET processed_at = ? WHERE provider = ? AND event_id = ?")
    .bind(nowIso, provider, eventId));
  statements.push(c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, NULL, 'billing.webhook_invoice_paid', 'invoice', ?, ?)",
  ).bind(crypto.randomUUID(), invoice.organizationId, invoice.id, JSON.stringify({ provider, eventId })));
  await c.env.DB.batch(statements as unknown as Parameters<typeof c.env.DB.batch>[0]);
  return c.json({ received: true, processed: true });
});

// Provider configuration status. Surfaces exactly which secrets a live
// automated payment integration requires — never fakes success.
app.get("/v1/platform/billing/provider-status", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const webhookConfigured = (c.env.PAYMENT_WEBHOOK_SECRET ?? "").length >= 32;
  return c.json({
    provider: "external",
    automatedBillingEnabled: webhookConfigured,
    webhookEndpoint: "/v1/billing/webhooks/external",
    requirements: webhookConfigured ? [] : [
      "Set the PAYMENT_WEBHOOK_SECRET Worker secret (32+ characters).",
      "Configure the provider to POST {eventId, invoiceRef, outcome} with an X-Nexora-Signature: t=<seconds>,v1=<hmac-sha256> header.",
    ],
  });
});

// ---------------------------------------------------------------------------
// Email hosting module.
//
// IMPORTANT — what this module is and is not:
//   - OUTBOUND transactional email (password resets, verification,
//     incidents) is already sent through the Resend API elsewhere in the
//     Worker. That is NOT mailbox hosting.
//   - Mailbox hosting (IMAP/SMTP/POP3 with real mail storage) requires an
//     external mail server. This module manages the local inventory
//     (domains, mailboxes, quotas, forwards) and the DNS records the mail
//     server will need, and refuses — with 503 and exact configuration
//     requirements — to mark anything as provisioned until a mail
//     provider is configured and confirms provisioning.
//
// Provider abstraction: a provider is available when EMAIL_PROVIDER is set
// to a supported value AND its configuration is complete. 'none' (default)
// means inventory-only mode. The MailServerApiProvider is the first
// implementation: a generic authenticated REST bridge the operator can
// point at their own mailserver admin API (e.g. a Dovecot/Postfix admin
// service, mailcow, or a Stalwart instance) via EMAIL_PROVIDER_API_URL and
// EMAIL_PROVIDER_API_TOKEN.
// ---------------------------------------------------------------------------

type EmailProviderConfig = {
  kind: "none" | "mailserver-api";
  apiBaseUrl?: string;
  apiToken?: string;
  requirements: string[];
};

function resolveEmailProvider(env: Bindings): EmailProviderConfig {
  const kind = (env.EMAIL_PROVIDER ?? "none").trim().toLowerCase();
  if (kind === "none" || kind === "") {
    return {
      kind: "none",
      requirements: [
        "Set EMAIL_PROVIDER=mailserver-api to enable mailbox provisioning.",
        "Set EMAIL_PROVIDER_API_URL to the mail server admin API base URL.",
        "Set EMAIL_PROVIDER_API_TOKEN to the admin API token.",
        "Point the mail domain's MX, SPF, DKIM, and DMARC DNS records at the mail server.",
      ],
    };
  }
  if (kind === "mailserver-api") {
    const missing: string[] = [];
    const apiBaseUrl = env.EMAIL_PROVIDER_API_URL ?? "";
    const apiToken = env.EMAIL_PROVIDER_API_TOKEN ?? "";
    if (!/^https:\/\/[A-Za-z0-9._~:/-]+$/.test(apiBaseUrl)) missing.push("EMAIL_PROVIDER_API_URL must be an https:// base URL.");
    if (apiToken.length < 16) missing.push("EMAIL_PROVIDER_API_TOKEN must be set (16+ characters).");
    return { kind: "mailserver-api", apiBaseUrl, apiToken, requirements: missing };
  }
  return { kind: "none", requirements: [`Unsupported EMAIL_PROVIDER "${kind}". Supported: mailserver-api.`] };
}

async function emailProviderRequest(
  provider: EmailProviderConfig,
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body?: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; detail: string }> {
  if (provider.kind !== "mailserver-api" || !provider.apiBaseUrl || !provider.apiToken) {
    return { ok: false, status: 503, detail: "Mail provider is not configured." };
  }
  if (!path.startsWith("/") || /[?#]/.test(path)) return { ok: false, status: 400, detail: "Invalid provider path." };
  try {
    const response = await fetch(provider.apiBaseUrl.replace(/\/+$/, "") + path, {
      method,
      headers: {
        authorization: `Bearer ${provider.apiToken}`,
        accept: "application/json",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(12000),
    });
    return { ok: response.ok, status: response.status, detail: response.ok ? "" : `Mail provider returned HTTP ${response.status}.` };
  } catch (error) {
    return { ok: false, status: 502, detail: error instanceof Error ? `Mail provider request failed: ${error.message}` : "Mail provider request failed." };
  }
}

// Outbound notification email and hosted mailboxes are different services;
// this endpoint reports both honestly.
app.get("/v1/email/status", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const provider = resolveEmailProvider(c.env);
  return c.json({
    outboundNotification: {
      configured: Boolean(c.env.RESEND_API_KEY && c.env.EMAIL_FROM),
      purpose: "Transactional email only (password reset, verification, incident alerts).",
    },
    mailboxHosting: {
      provider: provider.kind,
      available: provider.kind === "mailserver-api" && provider.requirements.length === 0,
      purpose: "Hosted IMAP/SMTP mailboxes, quotas, and forwarding rules.",
      requirements: provider.requirements,
      dnsRecordsRequired: [
        { record: "MX", guidance: "Point the mail domain's MX record at the mail server host." },
        { record: "TXT/SPF", guidance: 'v=spf1 include:<mail-server-spf-domain> ~all — authorize the mail server to send for the domain.' },
        { record: "TXT/DKIM", guidance: "Publish the mail server's DKIM public key selector provided by the provider." },
        { record: "TXT/DMARC", guidance: "v=DMARC1; p=quarantine; rua=mailto:<dmarc-reports@your-domain> — start in quarantine and tighten after reviewing reports." },
      ],
    },
  });
});

// Email domain inventory for the caller's organization.
app.get("/v1/email/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT ed.id, ed.domain, ed.status, ed.provider_status AS providerStatus,
            ed.hosting_account_id AS hostingAccountId, ed.created_at AS createdAt,
            (SELECT COUNT(*) FROM email_mailboxes m WHERE m.email_domain_id = ed.id AND m.status != 'DELETED') AS mailboxCount,
            (SELECT COUNT(*) FROM email_forwards f WHERE f.email_domain_id = ed.id AND f.active = 1) AS forwardCount
     FROM email_domains ed WHERE ed.organization_id = ? AND ed.status != 'DELETED'
     ORDER BY ed.created_at DESC`,
  ).bind(identity.organizationId).all();
  return c.json({ domains: result.results ?? [] });
});

// Register an email domain for the organization. Optionally linked to a
// hosting account whose plan mailbox_limit caps mailbox counts. In
// inventory-only mode the domain is stored but stays provider_status
// 'not_provisioned' — the response says so explicitly.
app.post("/v1/email/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const domain = typeof input.domain === "string" ? input.domain.trim().toLowerCase() : "";
  const hostingAccountId = typeof input.hostingAccountId === "string" && /^[0-9a-f-]{36}$/i.test(input.hostingAccountId) ? input.hostingAccountId : null;
  if (!validDomain(domain)) return c.json({ message: "Enter a valid domain name, such as example.com." }, 400);
  if (hostingAccountId) {
    const account = await c.env.DB.prepare(
      "SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1",
    ).bind(hostingAccountId, identity.organizationId).first<{ id: string }>();
    if (!account) return c.json({ message: "Hosting account not found or not active." }, 404);
  }
  const provider = resolveEmailProvider(c.env);
  const providerAvailable = provider.kind === "mailserver-api" && provider.requirements.length === 0;
  const id = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO email_domains (id, organization_id, hosting_account_id, domain, status, provider_status)
         VALUES (?, ?, ?, ?, 'PENDING', 'not_provisioned')`,
      ).bind(id, identity.organizationId, hostingAccountId, domain),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_domain.registered', 'email_domain', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ domain, hostingAccountId })),
    ]);
  } catch (error) {
    if (isUniqueConstraintError(error)) return c.json({ message: "This email domain is already registered." }, 409);
    return c.json({ message: "Unable to register the email domain." }, 500);
  }
  return c.json({
    emailDomain: { id, domain, status: "PENDING", providerStatus: "not_provisioned" },
    provisioning: providerAvailable
      ? { available: true, message: "Mail provider configured. Provisioning will be attempted when the domain is activated." }
      : { available: false, message: "Mail provider is not configured. The domain is recorded as a plan but is NOT provisioned on any mail server.", requirements: provider.requirements },
  }, 201);
});

// Remove an email domain (soft delete) with its mailboxes and forwards.
app.delete("/v1/email/domains/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const emailDomain = await c.env.DB.prepare(
    "SELECT id, domain, status FROM email_domains WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; domain: string; status: string }>();
  if (!emailDomain) return c.json({ message: "Email domain not found." }, 404);
  if (emailDomain.status === "DELETED") return c.json({ message: "Email domain is already deleted." }, 409);
  const provider = resolveEmailProvider(c.env);
  if (provider.kind === "mailserver-api" && provider.requirements.length === 0) {
    const result = await emailProviderRequest(provider, "DELETE", `/domains/${encodeURIComponent(emailDomain.id)}`);
    if (!result.ok && result.status !== 404) {
      return c.json({ message: `The mail provider refused domain removal. ${result.detail}` }, 502);
    }
  }
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE email_domains SET status = 'DELETED', updated_at = datetime('now') WHERE id = ? AND status != 'DELETED'").bind(emailDomain.id),
    c.env.DB.prepare("UPDATE email_mailboxes SET status = 'DELETED', updated_at = datetime('now') WHERE email_domain_id = ? AND status != 'DELETED'").bind(emailDomain.id),
    c.env.DB.prepare("UPDATE email_forwards SET active = 0, updated_at = datetime('now') WHERE email_domain_id = ?").bind(emailDomain.id),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_domain.deleted', 'email_domain', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, emailDomain.id, JSON.stringify({ domain: emailDomain.domain })),
  ]);
  return c.json({ success: true, message: "Email domain removed from the inventory." });
});

// Mailbox inventory for one email domain.
app.get("/v1/email/domains/:id/mailboxes", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const emailDomain = await c.env.DB.prepare(
    "SELECT id, domain, hosting_account_id AS hostingAccountId FROM email_domains WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; domain: string; hostingAccountId: string | null }>();
  if (!emailDomain) return c.json({ message: "Email domain not found." }, 404);
  const result = await c.env.DB.prepare(
    `SELECT id, address, quota_mb AS quotaMb, status, provider_status AS providerStatus,
            password_set_at AS passwordSetAt, created_at AS createdAt
     FROM email_mailboxes WHERE email_domain_id = ? AND status != 'DELETED'
     ORDER BY created_at ASC`,
  ).bind(emailDomain.id).all();
  // Plan mailbox limit: when the domain is linked to a hosting account the
  // plan's mailbox_limit caps mailbox counts; otherwise a static safety cap.
  let mailboxLimit = 100;
  if (emailDomain.hostingAccountId) {
    const plan = await c.env.DB.prepare(
      `SELECT p.mailbox_limit FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id WHERE a.id = ? LIMIT 1`,
    ).bind(emailDomain.hostingAccountId).first<{ mailbox_limit: number }>();
    if (plan) mailboxLimit = plan.mailbox_limit;
  }
  return c.json({ mailboxes: result.results ?? [], mailboxLimit, domain: emailDomain.domain });
});

// Create a mailbox. Enforces the plan mailbox limit and honest
// provisioning: without a configured mail provider the mailbox stays
// 'not_provisioned' and the API response says exactly that.
app.post("/v1/email/domains/:id/mailboxes", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const emailDomain = await c.env.DB.prepare(
    "SELECT id, domain, hosting_account_id AS hostingAccountId, status FROM email_domains WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; domain: string; hostingAccountId: string | null; status: string }>();
  if (!emailDomain) return c.json({ message: "Email domain not found." }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const localPart = typeof input.localPart === "string" ? input.localPart.trim().toLowerCase() : "";
  const quotaMb = input.quotaMb === undefined ? 1024 : Number(input.quotaMb);
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(localPart) || localPart.startsWith(".") || localPart.includes("..")) {
    return c.json({ message: "Mailbox name must be 1-64 characters: lowercase letters, numbers, dots, dashes, or underscores." }, 400);
  }
  if (!Number.isInteger(quotaMb) || quotaMb < 128 || quotaMb > 51200) {
    return c.json({ message: "Mailbox quota must be between 128 and 51,200 MB." }, 400);
  }
  const address = `${localPart}@${emailDomain.domain}`;
  if (emailDomain.hostingAccountId) {
    const plan = await c.env.DB.prepare(
      `SELECT p.mailbox_limit,
              (SELECT COUNT(*) FROM email_mailboxes m
               JOIN email_domains ed ON ed.id = m.email_domain_id
               WHERE ed.hosting_account_id = ? AND m.status != 'DELETED') AS mailboxCount
       FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
       WHERE a.id = ? LIMIT 1`,
    ).bind(emailDomain.hostingAccountId, emailDomain.hostingAccountId).first<{ mailbox_limit: number; mailboxCount: number }>();
    if (plan && plan.mailboxCount >= plan.mailbox_limit) {
      return c.json({ message: `The hosting plan allows ${plan.mailbox_limit} mailbox(es) and the limit has been reached.` }, 409);
    }
  }
  const provider = resolveEmailProvider(c.env);
  const providerAvailable = provider.kind === "mailserver-api" && provider.requirements.length === 0;
  const id = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO email_mailboxes (id, organization_id, email_domain_id, address, quota_mb, status, provider_status)
       VALUES (?, ?, ?, ?, ?, 'PENDING', 'not_provisioned')`,
    ).bind(id, identity.organizationId, emailDomain.id, address, quotaMb).run();
  } catch (error) {
    if (isUniqueConstraintError(error)) return c.json({ message: "This mailbox address already exists." }, 409);
    return c.json({ message: "Unable to create the mailbox." }, 500);
  }
  if (providerAvailable) {
    const result = await emailProviderRequest(provider, "POST", "/mailboxes", { externalId: id, address, quotaMb });
    await c.env.DB.prepare(
      "UPDATE email_mailboxes SET provider_status = ?, updated_at = datetime('now') WHERE id = ?",
    ).bind(result.ok ? "provisioned" : "failed", id).run();
    if (!result.ok) {
      return c.json({ mailbox: { id, address, status: "PENDING", providerStatus: "failed" }, message: `Recorded locally but the mail provider rejected creation. ${result.detail}` }, 502);
    }
  }
  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_mailbox.created', 'email_mailbox', ?, ?)",
  ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ address, quotaMb, providerProvisioned: providerAvailable })).run();
  return c.json({
    mailbox: { id, address, status: "PENDING", providerStatus: providerAvailable ? "provisioned" : "not_provisioned", quotaMb },
    provisioning: providerAvailable
      ? { available: true, message: "Mailbox created on the mail server." }
      : { available: false, message: "Mail provider is not configured. The mailbox is a plan only — no IMAP/SMTP mailbox exists yet.", requirements: provider.requirements },
  }, 201);
});

// Update mailbox quota, suspend/unsuspend, or set a new mailbox password.
// Password changes require a configured provider — the control panel never
// stores mailbox passwords itself.
app.patch("/v1/email/mailboxes/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const mailbox = await c.env.DB.prepare(
    `SELECT m.id, m.address, m.status, m.provider_status AS providerStatus, ed.domain
     FROM email_mailboxes m JOIN email_domains ed ON ed.id = m.email_domain_id
     WHERE m.id = ? AND m.organization_id = ? AND m.status != 'DELETED' LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; address: string; status: string; providerStatus: string; domain: string }>();
  if (!mailbox) return c.json({ message: "Mailbox not found." }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const provider = resolveEmailProvider(c.env);
  const providerAvailable = provider.kind === "mailserver-api" && provider.requirements.length === 0;
  const updates: string[] = [];
  const binds: (string | number)[] = [];
  if (input.quotaMb !== undefined) {
    const quotaMb = Number(input.quotaMb);
    if (!Number.isInteger(quotaMb) || quotaMb < 128 || quotaMb > 51200) {
      return c.json({ message: "Mailbox quota must be between 128 and 51,200 MB." }, 400);
    }
    updates.push("quota_mb = ?"); binds.push(quotaMb);
    if (providerAvailable) {
      const result = await emailProviderRequest(provider, "PATCH", `/mailboxes/${encodeURIComponent(mailbox.id)}`, { quotaMb });
      if (!result.ok) return c.json({ message: `The mail provider refused the quota change. ${result.detail}` }, 502);
    }
  }
  if (input.status !== undefined) {
    const status = typeof input.status === "string" ? input.status : "";
    if (!["ACTIVE", "SUSPENDED"].includes(status)) return c.json({ message: "Mailbox status must be ACTIVE or SUSPENDED." }, 400);
    updates.push("status = ?"); binds.push(status);
    if (providerAvailable) {
      const result = await emailProviderRequest(provider, "PATCH", `/mailboxes/${encodeURIComponent(mailbox.id)}`, { status: status === "ACTIVE" ? "active" : "suspended" });
      if (!result.ok) return c.json({ message: `The mail provider refused the status change. ${result.detail}` }, 502);
    }
  }
  if (input.newPassword !== undefined) {
    if (!providerAvailable) {
      return c.json({ message: "Mailbox passwords are stored on the mail server, which is not configured. The control panel never stores mailbox passwords.", requirements: provider.requirements }, 503);
    }
    const newPassword = typeof input.newPassword === "string" ? input.newPassword : "";
    if (newPassword.length < 12 || newPassword.length > 128) {
      return c.json({ message: "The new mailbox password must be 12-128 characters." }, 400);
    }
    const result = await emailProviderRequest(provider, "POST", `/mailboxes/${encodeURIComponent(mailbox.id)}/password`, { password: newPassword });
    if (!result.ok) return c.json({ message: `The mail provider refused the password change. ${result.detail}` }, 502);
    updates.push("password_set_at = ?"); binds.push(new Date().toISOString());
  }
  if (updates.length === 0) return c.json({ message: "Nothing to update. Provide quotaMb, status, or newPassword." }, 400);
  updates.push("updated_at = datetime('now')");
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE email_mailboxes SET ${updates.join(", ")} WHERE id = ? AND organization_id = ?`).bind(...binds, mailbox.id, identity.organizationId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_mailbox.updated', 'email_mailbox', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, mailbox.id,
      JSON.stringify({ fields: Object.keys(input).filter((k) => k !== "newPassword"), passwordChanged: input.newPassword !== undefined })),
  ]);
  return c.json({ success: true, message: "Mailbox updated." });
});

// Delete a mailbox.
app.delete("/v1/email/mailboxes/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const mailbox = await c.env.DB.prepare(
    "SELECT id, address FROM email_mailboxes WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; address: string }>();
  if (!mailbox) return c.json({ message: "Mailbox not found." }, 404);
  const provider = resolveEmailProvider(c.env);
  if (provider.kind === "mailserver-api" && provider.requirements.length === 0) {
    const result = await emailProviderRequest(provider, "DELETE", `/mailboxes/${encodeURIComponent(mailbox.id)}`);
    if (!result.ok && result.status !== 404) {
      return c.json({ message: `The mail provider refused mailbox deletion. ${result.detail}` }, 502);
    }
  }
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE email_mailboxes SET status = 'DELETED', updated_at = datetime('now') WHERE id = ? AND status != 'DELETED'").bind(mailbox.id),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_mailbox.deleted', 'email_mailbox', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, mailbox.id, JSON.stringify({ address: mailbox.address })),
  ]);
  return c.json({ success: true, message: "Mailbox deleted." });
});

// Forwarding rules (also usable as simple aliases: source -> destination).
app.get("/v1/email/domains/:id/forwards", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const emailDomain = await c.env.DB.prepare(
    "SELECT id, domain FROM email_domains WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; domain: string }>();
  if (!emailDomain) return c.json({ message: "Email domain not found." }, 404);
  const result = await c.env.DB.prepare(
    `SELECT id, source, destination, active, provider_status AS providerStatus, created_at AS createdAt
     FROM email_forwards WHERE email_domain_id = ? ORDER BY created_at ASC`,
  ).bind(emailDomain.id).all();
  return c.json({ forwards: result.results ?? [], domain: emailDomain.domain });
});

app.post("/v1/email/domains/:id/forwards", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const emailDomain = await c.env.DB.prepare(
    "SELECT id, domain FROM email_domains WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; domain: string }>();
  if (!emailDomain) return c.json({ message: "Email domain not found." }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const localPart = typeof input.source === "string" ? input.source.trim().toLowerCase() : "";
  const destination = typeof input.destination === "string" ? input.destination.trim().toLowerCase() : "";
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(localPart)) return c.json({ message: "The source must be a local mailbox name on this domain." }, 400);
  if (!validEmail(destination)) return c.json({ message: "The destination must be a valid email address." }, 400);
  const source = `${localPart}@${emailDomain.domain}`;
  const provider = resolveEmailProvider(c.env);
  const providerAvailable = provider.kind === "mailserver-api" && provider.requirements.length === 0;
  const id = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO email_forwards (id, organization_id, email_domain_id, source, destination, active, provider_status)
       VALUES (?, ?, ?, ?, ?, 1, 'not_provisioned')`,
    ).bind(id, identity.organizationId, emailDomain.id, source, destination).run();
  } catch (error) {
    if (isUniqueConstraintError(error)) return c.json({ message: "This forwarding rule already exists." }, 409);
    return c.json({ message: "Unable to create the forwarding rule." }, 500);
  }
  if (providerAvailable) {
    const result = await emailProviderRequest(provider, "POST", "/forwards", { externalId: id, source, destination });
    await c.env.DB.prepare("UPDATE email_forwards SET provider_status = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(result.ok ? "provisioned" : "failed", id).run();
  }
  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_forward.created', 'email_forward', ?, ?)",
  ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ source, destination })).run();
  return c.json({
    forward: { id, source, destination, active: 1, providerStatus: providerAvailable ? "provisioned" : "not_provisioned" },
    provisioning: providerAvailable
      ? { available: true, message: "Forwarding rule created on the mail server." }
      : { available: false, message: "Mail provider is not configured. The rule is recorded but is NOT active on any mail server.", requirements: provider.requirements },
  }, 201);
});

app.delete("/v1/email/forwards/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const forward = await c.env.DB.prepare(
    "SELECT id, source, destination FROM email_forwards WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; source: string; destination: string }>();
  if (!forward) return c.json({ message: "Forwarding rule not found." }, 404);
  const provider = resolveEmailProvider(c.env);
  if (provider.kind === "mailserver-api" && provider.requirements.length === 0) {
    const result = await emailProviderRequest(provider, "DELETE", `/forwards/${encodeURIComponent(forward.id)}`);
    if (!result.ok && result.status !== 404) {
      return c.json({ message: `The mail provider refused forward removal. ${result.detail}` }, 502);
    }
  }
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM email_forwards WHERE id = ? AND organization_id = ?").bind(forward.id, identity.organizationId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'email_forward.deleted', 'email_forward', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, forward.id, JSON.stringify({ source: forward.source, destination: forward.destination })),
  ]);
  return c.json({ success: true, message: "Forwarding rule removed." });
});

// Mail delivery/service status. Reports what the control panel actually
// knows: provider configuration state and local inventory health. Live
// SMTP/IMAP probing requires the mail provider and is marked accordingly.
app.get("/v1/email/service-status", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const provider = resolveEmailProvider(c.env);
  const providerAvailable = provider.kind === "mailserver-api" && provider.requirements.length === 0;
  const inventory = await c.env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM email_domains WHERE organization_id = ? AND status NOT IN ('DELETED')) AS domains,
       (SELECT COUNT(*) FROM email_mailboxes m JOIN email_domains ed ON ed.id = m.email_domain_id
          WHERE ed.organization_id = ? AND m.status != 'DELETED') AS mailboxes,
       (SELECT COUNT(*) FROM email_forwards f JOIN email_domains ed ON ed.id = f.email_domain_id
          WHERE ed.organization_id = ? AND f.active = 1) AS forwards`,
  ).bind(identity.organizationId, identity.organizationId, identity.organizationId).first<{ domains: number; mailboxes: number; forwards: number }>();
  return c.json({
    mailboxHosting: {
      provider: provider.kind,
      available: providerAvailable,
      deliveryStatus: providerAvailable ? "unknown — the control panel does not probe SMTP/IMAP; check the provider's own status page." : "unavailable — no mail server is configured.",
      requirements: providerAvailable ? [] : provider.requirements,
    },
    outboundNotification: {
      configured: Boolean(c.env.RESEND_API_KEY && c.env.EMAIL_FROM),
    },
    inventory: inventory ?? { domains: 0, mailboxes: 0, forwards: 0 },
  });
});

type HostingPlanRow = {
  id: string; name: string; disk_limit_bytes: number; bandwidth_limit_bytes: number | null;
  website_limit: number; database_limit: number; mailbox_limit: number;
  app_cpu_millis: number; app_memory_mib: number; app_disk_mib: number; app_process_limit: number; app_build_minutes_month: number;
  active: number; created_at: string;
};

app.get("/v1/hosting-plans", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT id, name, disk_limit_bytes, bandwidth_limit_bytes, website_limit,
            database_limit, mailbox_limit, app_cpu_millis, app_memory_mib,
            app_disk_mib, app_process_limit, app_build_minutes_month, active, created_at, price_sar_minor, billing_period, public_enabled
     FROM hosting_plans WHERE organization_id = ? ORDER BY created_at DESC`,
  ).bind(identity.organizationId).all<HostingPlanRow>();
  return c.json({ plans: result.results ?? [] });
});

app.post("/v1/hosting-plans", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const name = typeof input.name === "string" ? input.name.trim() : "";
  const diskGb = Number(input.diskGb);
  const bandwidthGb = input.bandwidthGb === "" || input.bandwidthGb == null ? null : Number(input.bandwidthGb);
  const websiteLimit = Number(input.websiteLimit);
  const databaseLimit = Number(input.databaseLimit);
  const mailboxLimit = Number(input.mailboxLimit);
  const appCpuMillis = input.appCpuMillis === undefined ? 500 : Number(input.appCpuMillis);
  const appMemoryMiB = input.appMemoryMiB === undefined ? 512 : Number(input.appMemoryMiB);
  const appDiskMiB = input.appDiskMiB === undefined ? 2048 : Number(input.appDiskMiB);
  const appProcessLimit = input.appProcessLimit === undefined ? 128 : Number(input.appProcessLimit);
  const appBuildMinutesMonth = input.appBuildMinutesMonth === undefined ? 300 : Number(input.appBuildMinutesMonth);
  const priceSarMinor = input.priceSarMinor === "" || input.priceSarMinor == null ? null : Number(input.priceSarMinor);
  const billingPeriod = input.billingPeriod === "yearly" ? "yearly" : "monthly";
  const publicEnabled = input.publicEnabled === true ? 1 : 0;
  if (!name || name.length > 80) return c.json({ message: "Plan name is required (maximum 80 characters)" }, 400);
  if (priceSarMinor !== null && (!Number.isSafeInteger(priceSarMinor) || priceSarMinor < 100 || priceSarMinor > 100000000)) return c.json({ message: "Price must be at least SAR 1.00 and no more than SAR 1,000,000.00." }, 400);
  if (publicEnabled && priceSarMinor === null) return c.json({ message: "Set a price before publishing this plan." }, 400);
  if (!Number.isInteger(diskGb) || diskGb < 1 || diskGb > 100000) return c.json({ message: "Disk quota must be between 1 and 100,000 GB" }, 400);
  if (bandwidthGb !== null && (!Number.isInteger(bandwidthGb) || bandwidthGb < 1 || bandwidthGb > 1000000)) return c.json({ message: "Bandwidth must be blank or between 1 and 1,000,000 GB" }, 400);
  if (![websiteLimit, databaseLimit, mailboxLimit].every((v) => Number.isInteger(v) && v >= 0 && v <= 10000)) {
    return c.json({ message: "Resource limits must be whole numbers between 0 and 10,000" }, 400);
  }
  if (!Number.isInteger(appCpuMillis) || appCpuMillis < 100 || appCpuMillis > 8000 ||
      !Number.isInteger(appMemoryMiB) || appMemoryMiB < 128 || appMemoryMiB > 16384 ||
      !Number.isInteger(appDiskMiB) || appDiskMiB < 128 || appDiskMiB > 65536 ||
      !Number.isInteger(appProcessLimit) || appProcessLimit < 16 || appProcessLimit > 512 ||
      !Number.isInteger(appBuildMinutesMonth) || appBuildMinutesMonth < 0 || appBuildMinutesMonth > 100000) {
    return c.json({ message: "Application runtime quotas are outside the supported platform bounds." }, 400);
  }
  const id = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO hosting_plans
         (id, organization_id, name, disk_limit_bytes, bandwidth_limit_bytes, website_limit, database_limit, mailbox_limit,
          app_cpu_millis, app_memory_mib, app_disk_mib, app_process_limit, app_build_minutes_month, active,
          price_sar_minor, billing_period, public_enabled)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
      ).bind(id, identity.organizationId, name, diskGb * 1024 ** 3, bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
        websiteLimit, databaseLimit, mailboxLimit, appCpuMillis, appMemoryMiB, appDiskMiB, appProcessLimit, appBuildMinutesMonth, priceSarMinor, billingPeriod, publicEnabled),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'hosting_plan.create', 'hosting_plan', ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
    ]);
    return c.json({ plan: { id, name, disk_limit_bytes: diskGb * 1024 ** 3,
      bandwidth_limit_bytes: bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
      website_limit: websiteLimit, database_limit: databaseLimit, mailbox_limit: mailboxLimit,
      app_cpu_millis: appCpuMillis, app_memory_mib: appMemoryMiB, app_disk_mib: appDiskMiB,
      app_process_limit: appProcessLimit, app_build_minutes_month: appBuildMinutesMonth, active: 1, price_sar_minor: priceSarMinor, billing_period: billingPeriod, public_enabled: publicEnabled } }, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_plans.organization_id, hosting_plans.name/i.test(message)) {
      return c.json({ message: "A plan with this name already exists in your workspace" }, 409);
    }
    return c.json({ message: "Unable to create hosting plan" }, 500);
  }
});

app.put("/v1/hosting-plans/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const planId = c.req.param("id");
  const existing = await c.env.DB.prepare("SELECT id, organization_id, name FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1").bind(planId, identity.organizationId).first<{ id: string; organization_id: string; name: string }>();
  if (!existing) return c.json({ message: "Hosting plan not found." }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const diskGb = Number(input.diskGb);
  const bandwidthGb = input.bandwidthGb === "" || input.bandwidthGb == null ? null : Number(input.bandwidthGb);
  const websiteLimit = Number(input.websiteLimit);
  const databaseLimit = Number(input.databaseLimit);
  const mailboxLimit = Number(input.mailboxLimit);
  const appCpuMillis = input.appCpuMillis === undefined ? 500 : Number(input.appCpuMillis);
  const appMemoryMiB = input.appMemoryMiB === undefined ? 512 : Number(input.appMemoryMiB);
  const appDiskMiB = input.appDiskMiB === undefined ? 2048 : Number(input.appDiskMiB);
  const appProcessLimit = input.appProcessLimit === undefined ? 128 : Number(input.appProcessLimit);
  const appBuildMinutesMonth = input.appBuildMinutesMonth === undefined ? 300 : Number(input.appBuildMinutesMonth);
  const active = input.active === false ? 0 : 1;
  if (!Number.isInteger(diskGb) || diskGb < 1 || diskGb > 100000) return c.json({ message: "Disk quota must be between 1 and 100,000 GB" }, 400);
  if (bandwidthGb !== null && (!Number.isInteger(bandwidthGb) || bandwidthGb < 1 || bandwidthGb > 1000000)) return c.json({ message: "Bandwidth must be blank or between 1 and 1,000,000 GB" }, 400);
  if (![websiteLimit, databaseLimit, mailboxLimit].every((v) => Number.isInteger(v) && v >= 0 && v <= 10000)) return c.json({ message: "Resource limits must be whole numbers between 0 and 10,000" }, 400);
  if (!Number.isInteger(appCpuMillis) || appCpuMillis < 100 || appCpuMillis > 8000 || !Number.isInteger(appMemoryMiB) || appMemoryMiB < 128 || appMemoryMiB > 16384 || !Number.isInteger(appDiskMiB) || appDiskMiB < 128 || appDiskMiB > 65536 || !Number.isInteger(appProcessLimit) || appProcessLimit < 16 || appProcessLimit > 512 || !Number.isInteger(appBuildMinutesMonth) || appBuildMinutesMonth < 0 || appBuildMinutesMonth > 100000) return c.json({ message: "Application runtime quotas are outside the supported platform bounds." }, 400);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_plans SET disk_limit_bytes = ?, bandwidth_limit_bytes = ?, website_limit = ?, database_limit = ?, mailbox_limit = ?, app_cpu_millis = ?, app_memory_mib = ?, app_disk_mib = ?, app_process_limit = ?, app_build_minutes_month = ?, active = ?, updated_at = datetime('now') WHERE id = ? AND organization_id = ?").bind(diskGb * 1024 ** 3, bandwidthGb === null ? null : bandwidthGb * 1024 ** 3, websiteLimit, databaseLimit, mailboxLimit, appCpuMillis, appMemoryMiB, appDiskMiB, appProcessLimit, appBuildMinutesMonth, active, planId, identity.organizationId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_plan.updated', 'hosting_plan', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, planId, JSON.stringify({ name: existing.name, diskGb, websiteLimit, databaseLimit, mailboxLimit, active })),
  ]);
  return c.json({ success: true, planId, active, message: "Hosting plan updated." });
});

app.post("/v1/hosting-plans/:id/store-settings", async (c) => {
  const identity=await bearerIdentity(c.req.raw,c.env.DB);
  if (!identity) return c.json({message:"Not authenticated"},401);
  if (!platformAdmin(identity)) return c.json({message:"Platform administrator access required."},403);
  let input:Record<string,unknown>;
  try { input=await c.req.json<Record<string,unknown>>(); } catch { return c.json({message:"Invalid JSON request"},400); }
  const price=input.priceSarMinor===""||input.priceSarMinor==null?null:Number(input.priceSarMinor);
  const period=input.billingPeriod==="yearly"?"yearly":"monthly";
  const publish=input.publicEnabled===true?1:0;
  if (price!==null&&(!Number.isSafeInteger(price)||price<100||price>100000000)) return c.json({message:"Price must be between SAR 1.00 and SAR 1,000,000.00."},400);
  if (publish&&price===null) return c.json({message:"A price is required before publishing this plan."},400);
  const result=await c.env.DB.prepare("UPDATE hosting_plans SET price_sar_minor=?,billing_period=?,public_enabled=? WHERE id=? AND organization_id=?")
    .bind(price,period,publish,c.req.param("id"),identity.organizationId).run();
  if ((result.meta?.changes??0)!==1) return c.json({message:"Hosting plan not found."},404);
  await c.env.DB.prepare("INSERT INTO audit_logs (id,organization_id,actor_user_id,action,resource_type,resource_id,metadata) VALUES (?,?,?,'hosting_plan.store_settings_updated','hosting_plan',?,?)")
    .bind(crypto.randomUUID(),identity.organizationId,identity.id,c.req.param("id"),JSON.stringify({priceSarMinor:price,billingPeriod:period,publicEnabled:publish===1})).run();
  return c.json({saved:true});
});

app.post("/v1/hosting-plans/:id/website-limit", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const websiteLimit = Number(input.websiteLimit);
  if (!Number.isInteger(websiteLimit) || websiteLimit < 1 || websiteLimit > 10000) {
    return c.json({ message: "Website limit must be a whole number between 1 and 10,000." }, 400);
  }

  const planId = c.req.param("id");
  const plan = await c.env.DB.prepare(
    "SELECT id, name, website_limit FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(planId, identity.organizationId).first<{ id: string; name: string; website_limit: number }>();
  if (!plan) return c.json({ message: "Hosting plan not found in this workspace." }, 404);

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_plans SET website_limit = ?, updated_at = ? WHERE id = ? AND organization_id = ?")
      .bind(websiteLimit, new Date().toISOString(), planId, identity.organizationId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_plan.website_limit_updated', 'hosting_plan', ?, ?)")
      .bind(crypto.randomUUID(), identity.organizationId, identity.id, planId, JSON.stringify({ previous: plan.website_limit, current: websiteLimit })),
  ]);
  return c.json({ plan: { id: plan.id, name: plan.name, website_limit: websiteLimit } });
});

// Delete a hosting plan. Only unused plans can be deleted: a plan that is
// referenced by any hosting account or subscription is rejected with 409
// and a count of the references. Deactivate the plan instead to stop new
// signups while keeping existing accounts working.
app.delete("/v1/hosting-plans/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const planId = c.req.param("id");
  const plan = await c.env.DB.prepare(
    "SELECT id, name FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(planId, identity.organizationId).first<{ id: string; name: string }>();
  if (!plan) return c.json({ message: "Hosting plan not found in this workspace." }, 404);
  const accountCount = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM hosting_accounts WHERE plan_id = ?",
  ).bind(planId).first<{ count: number }>();
  if ((accountCount?.count ?? 0) > 0) {
    return c.json({ message: `This plan is used by ${accountCount?.count} hosting account(s) and cannot be deleted. Deactivate it instead.` }, 409);
  }
  const subscriptionCount = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM subscriptions WHERE plan_id = ?",
  ).bind(planId).first<{ count: number }>();
  if ((subscriptionCount?.count ?? 0) > 0) {
    return c.json({ message: `This plan is referenced by ${subscriptionCount?.count} subscription(s) and cannot be deleted.` }, 409);
  }
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM hosting_plans WHERE id = ? AND organization_id = ?").bind(planId, identity.organizationId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_plan.deleted', 'hosting_plan', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, planId, JSON.stringify({ name: plan.name })),
  ]);
  return c.json({ success: true, message: "Hosting plan deleted." });
});

// ---------------------------------------------------------------------------
// Provisioning job inspector (platform administration).
//
// Provides the operations inventory for queued/running/finished jobs with
// failure reasons, and a guarded retry for failed jobs whose operation is
// known-idempotent. Destructive or non-idempotent operations (restore,
// delete-database, file-manager) can NOT be retried from here — the
// operator must re-trigger them from the resource workflow, which
// re-validates current state.
// ---------------------------------------------------------------------------

app.get("/v1/provisioning-jobs", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const status = c.req.query("status");
  const operation = c.req.query("operation");
  const organizationId = c.req.query("organizationId");
  const conditions: string[] = [];
  const binds: string[] = [];
  if (status && /^[A-Z_]{3,20}$/.test(status)) { conditions.push("j.status = ?"); binds.push(status); }
  if (operation && /^[A-Z_]{3,40}$/.test(operation)) { conditions.push("j.operation = ?"); binds.push(operation); }
  if (organizationId && /^[0-9a-f-]{36}$/i.test(organizationId)) { conditions.push("a.organization_id = ?"); binds.push(organizationId); }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const result = await c.env.DB.prepare(
    `SELECT j.id, j.operation, j.status, j.attempts, j.requested_at AS requestedAt,
            j.started_at AS startedAt, j.finished_at AS finishedAt,
            j.error_code AS errorCode, j.error_message AS errorMessage,
            j.hosting_account_id AS hostingAccountId, a.username AS accountUsername,
            a.status AS accountStatus, a.organization_id AS organizationId, o.name AS organizationName,
            s.hostname AS serverHostname,
            CASE WHEN j.finished_at IS NULL AND j.requested_at < datetime('now', '-1 hour') AND j.status IN ('QUEUED','RUNNING') THEN 1 ELSE 0 END AS stalled
     FROM provisioning_jobs j
     JOIN hosting_accounts a ON a.id = j.hosting_account_id
     JOIN organizations o ON o.id = a.organization_id
     LEFT JOIN servers s ON s.id = a.server_id
     ${where} ORDER BY j.requested_at DESC LIMIT 200`,
  ).bind(...binds).all();
  return c.json({ jobs: result.results ?? [], retryableOperations: Array.from(RETRYABLE_JOB_OPERATIONS) });
});

app.get("/v1/provisioning-jobs/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const job = await c.env.DB.prepare(
    `SELECT j.id, j.operation, j.status, j.attempts, j.idempotency_key AS idempotencyKey,
            j.request_payload AS requestPayload, j.requested_at AS requestedAt,
            j.started_at AS startedAt, j.finished_at AS finishedAt,
            j.error_code AS errorCode, j.error_message AS errorMessage,
            j.hosting_account_id AS hostingAccountId, a.username AS accountUsername,
            a.organization_id AS organizationId, o.name AS organizationName,
            s.hostname AS serverHostname, s.status AS serverStatus, s.last_heartbeat_at AS serverLastHeartbeatAt
     FROM provisioning_jobs j
     JOIN hosting_accounts a ON a.id = j.hosting_account_id
     JOIN organizations o ON o.id = a.organization_id
     LEFT JOIN servers s ON s.id = a.server_id
     WHERE j.id = ? LIMIT 1`,
  ).bind(c.req.param("id")).first<Record<string, unknown>>();
  if (!job) return c.json({ message: "Provisioning job not found." }, 404);
  return c.json({
    job,
    retryable: RETRYABLE_JOB_OPERATIONS.has(String(job.operation)) && job.status === "FAILED",
  });
});

// Retry a failed job. Only known-idempotent operations are retryable; the
// previous FAILED job is preserved for audit and a fresh job is queued with
// a unique idempotency key suffix so the agent claim protocol cannot
// confuse the attempts.
app.post("/v1/provisioning-jobs/:id/retry", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!platformAdmin(identity)) return c.json({ message: "Platform administrator access required." }, 403);
  const job = await c.env.DB.prepare(
    `SELECT j.id, j.operation, j.status, j.attempts, j.request_payload AS requestPayload, j.idempotency_key AS idempotencyKey,
            j.hosting_account_id AS hostingAccountId, a.organization_id AS organizationId
     FROM provisioning_jobs j JOIN hosting_accounts a ON a.id = j.hosting_account_id
     WHERE j.id = ? LIMIT 1`,
  ).bind(c.req.param("id")).first<{ id: string; operation: string; status: string; attempts: number; requestPayload: string | null; idempotencyKey: string; hostingAccountId: string; organizationId: string }>();
  if (!job) return c.json({ message: "Provisioning job not found." }, 404);
  if (!RETRYABLE_JOB_OPERATIONS.has(job.operation)) {
    return c.json({ message: `The ${job.operation} operation cannot be retried from the inspector. Re-trigger it from the resource workflow so current state is re-validated.` }, 409);
  }
  if (job.status !== "FAILED") {
    return c.json({ message: "Only failed jobs can be retried." }, 409);
  }
  const activeJob = await c.env.DB.prepare(
    `SELECT id FROM provisioning_jobs
     WHERE hosting_account_id = ? AND idempotency_key = ? AND status IN ('QUEUED','RUNNING') LIMIT 1`,
  ).bind(job.hostingAccountId, job.idempotencyKey).first<{ id: string }>();
  if (activeJob) return c.json({ message: "A job with the same idempotency key is already queued or running." }, 409);
  const jobId = crypto.randomUUID();
  const retryKey = `${job.idempotencyKey}:retry-${job.attempts + 1}`;
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, attempts, request_payload)
       VALUES (?, ?, ?, 'QUEUED', ?, 0, ?)`,
    ).bind(jobId, job.hostingAccountId, job.operation, retryKey, job.requestPayload),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'provisioning_job.retried', 'provisioning_job', ?, ?)",
    ).bind(crypto.randomUUID(), job.organizationId, identity.id, job.id, JSON.stringify({ newJobId: jobId, operation: job.operation, attempt: job.attempts + 1 })),
  ]);
  return c.json({ success: true, jobId, idempotencyKey: retryKey, message: "Retry queued. The agent will claim it with the next poll." }, 201);
});


type HostingAccountRow = {
  id: string; username: string; primary_domain: string | null; status: string;
  created_at: string; server_id: string; server_hostname: string;
  plan_id: string; plan_name: string; job_status: string | null;
};

function validDomain(value: string): boolean {
  if (value.length > 253 || value.length < 3 || value.includes("..")) return false;
  return value.split(".").every((label) =>
    label.length >= 1 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label),
  ) && value.includes(".");
}

// Customer-facing account discovery is membership-scoped. Never accept an account ID
// from the browser as proof of access; the authenticated user is the scope.
app.get("/v1/customer/hosting-accounts", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT a.id, a.username, a.primary_domain, a.status, a.created_at,
            p.name AS plan_name, p.disk_limit_bytes, p.bandwidth_limit_bytes,
            p.website_limit, p.database_limit, p.mailbox_limit,
            m.role AS account_role
     FROM hosting_account_memberships m
     JOIN hosting_accounts a
       ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     JOIN hosting_plans p
       ON p.id = a.plan_id AND p.organization_id = a.organization_id
     WHERE m.user_id = ?
       AND m.status = 'ACTIVE' AND a.status = 'ACTIVE'
     ORDER BY a.created_at DESC`,
  ).bind(identity.id).all();
  return c.json({ accounts: result.results ?? [] });
});

// Customer account overview is available only to an active account member.
app.get("/v1/customer/hosting-accounts/:id/overview", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare(
    `SELECT a.id, a.username, a.primary_domain, a.status, a.created_at,
            p.name AS plan_name, p.disk_limit_bytes, p.bandwidth_limit_bytes,
            p.website_limit, p.database_limit, p.mailbox_limit,
            m.role AS account_role,
            (SELECT COUNT(*) FROM domains d
             WHERE d.hosting_account_id = a.id) AS websites,
            (SELECT COUNT(*) FROM hosting_databases d
             WHERE d.hosting_account_id = a.id AND d.status != 'DELETED') AS databases
     FROM hosting_account_memberships m
     JOIN hosting_accounts a
       ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     JOIN hosting_plans p
       ON p.id = a.plan_id AND p.organization_id = a.organization_id
     WHERE a.id = ? AND m.user_id = ?
       AND m.status = 'ACTIVE' AND a.status = 'ACTIVE'
     LIMIT 1`,
  ).bind(accountId, identity.id).first();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  return c.json({ account });
});

// Customer website inventory: only the active member's selected hosting account.
app.get("/v1/customer/hosting-accounts/:id/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ?
       AND m.status = 'ACTIVE' AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  const result = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.document_root, d.is_primary, d.created_at,
            (SELECT j.status FROM provisioning_jobs j
             WHERE j.idempotency_key = 'add-domain:' || d.id AND j.operation = 'ADD_DOMAIN'
             LIMIT 1) AS job_status
     FROM domains d
     WHERE d.hosting_account_id = ?
     ORDER BY d.is_primary DESC, d.created_at ASC`,
  ).bind(membership.id).all();
  return c.json({ domains: result.results ?? [] });
});

// Customer database inventory: metadata only; credentials and mutations are never returned here.
app.get("/v1/customer/hosting-accounts/:id/databases", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ?
       AND m.status = 'ACTIVE' AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  const result = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.engine, d.status, d.created_at,
            (SELECT COUNT(*) FROM hosting_database_users u
             WHERE u.database_id = d.id AND u.status = 'ACTIVE') AS active_users
     FROM hosting_databases d
     WHERE d.hosting_account_id = ? AND d.status != 'DELETED'
     ORDER BY d.created_at DESC`,
  ).bind(membership.id).all();
  return c.json({ databases: result.results ?? [] });
});

// ---------------------------------------------------------------------------
// Customer self-service mutations.
//
// Customers (hosting-account members) manage domains and databases on their
// own accounts. Every route resolves the account from the caller's ACTIVE
// hosting-account membership — never from an account ID the browser claims.
// Mutating roles:
//   - ACCOUNT_OWNER / ACCOUNT_ADMIN: domains and databases
//   - ACCOUNT_DEVELOPER: databases only (no domain changes)
//   - ACCOUNT_READONLY: read-only, no mutations
// Plan quotas (website_limit, database_limit) are enforced here in the API,
// not only in the dashboard.
// ---------------------------------------------------------------------------

function customerMutationAllowed(role: string, scope: "domain" | "database"): boolean {
  if (role === "ACCOUNT_OWNER" || role === "ACCOUNT_ADMIN") return true;
  if (scope === "database" && role === "ACCOUNT_DEVELOPER") return true;
  return false;
}

// Customer adds a domain to their own hosting account. Mirrors the WHM
// domain-add validation: plan website limit, domain syntax, document root
// confinement, unique domain names.
app.post("/v1/customer/hosting-accounts/:id/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT m.role, a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ? AND m.status = 'ACTIVE' AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ role: string; id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  if (!customerMutationAllowed(membership.role, "domain")) {
    return c.json({ message: "Your hosting account role cannot manage domains. Ask an account owner or admin." }, 403);
  }
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const name = typeof input.name === "string" ? input.name.trim().toLowerCase() : "";
  const plan = await c.env.DB.prepare(
    `SELECT p.website_limit,
            (SELECT COUNT(*) FROM domains d WHERE d.hosting_account_id = a.id) AS website_count,
            a.username
     FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.id = ? LIMIT 1`,
  ).bind(membership.id).first<{ website_limit: number; website_count: number; username: string }>();
  if (!plan) return c.json({ message: "Hosting account not found" }, 404);
  if (plan.website_count >= plan.website_limit) {
    return c.json({ message: "This hosting plan has reached its website limit." }, 409);
  }
  if (!validDomain(name)) return c.json({ message: "Enter a valid domain name, such as example.com." }, 400);
  const accountWebRoot = "/home/" + plan.username + "/public_html";
  const suppliedRoot = typeof input.documentRoot === "string" ? input.documentRoot.trim() : "";
  const root = suppliedRoot || accountWebRoot + "/" + name;
  if (!(root === accountWebRoot || root.startsWith(accountWebRoot + "/")) || root.includes("..") || root.length > 240 ||
      !/^\/home\/[a-z][a-z0-9_]{2,15}\/public_html(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/.test(root)) {
    return c.json({ message: "Document root must be inside this account's public_html directory and cannot contain hidden or unsafe path components." }, 400);
  }
  const id = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const statements = [
    c.env.DB.prepare("INSERT INTO domains (id, hosting_account_id, name, document_root, is_primary) VALUES (?, ?, ?, ?, 0)").bind(id, membership.id, name, root),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'ADD_DOMAIN', 'QUEUED', ?)").bind(jobId, membership.id, "add-domain:" + id),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.create_requested', 'domain', ?, ?)")
      .bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ hostingAccountId: membership.id, via: "customer-portal", name })),
  ];
  try { await c.env.DB.batch(statements); }
  catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: domains.name/i.test(message)) return c.json({ message: "This domain is already registered." }, 409);
    return c.json({ message: "Unable to save this domain." }, 500);
  }
  return c.json({ domain: { id, name, document_root: root, is_primary: 0 }, provisioningJob: { id: jobId, status: "QUEUED" }, message: "Domain saved. Server configuration is queued and awaits a connected Linux agent." }, 201);
});

// Customer removes a non-primary domain from their own hosting account.
// Primary domains are protected here exactly as in the WHM route.
app.delete("/v1/customer/hosting-accounts/:id/domains/:domainId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT m.role, a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ? AND m.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ role: string; id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  if (!customerMutationAllowed(membership.role, "domain")) {
    return c.json({ message: "Your hosting account role cannot manage domains. Ask an account owner or admin." }, 403);
  }
  const domainId = c.req.param("domainId");
  const domain = await c.env.DB.prepare(
    "SELECT d.id, d.name, d.is_primary AS isPrimary, d.status FROM domains d WHERE d.id = ? AND d.hosting_account_id = ? LIMIT 1",
  ).bind(domainId, membership.id).first<{ id: string; name: string; isPrimary: number; status: string }>();
  if (!domain) return c.json({ message: "Domain not found on this hosting account." }, 404);
  if (domain.status === "DELETED") return c.json({ message: "Domain is already deleted." }, 409);
  if (domain.isPrimary === 1) {
    return c.json({ message: "The primary domain cannot be removed. Set another domain as primary first." }, 409);
  }
  const jobId = crypto.randomUUID();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE domains SET status = 'DELETED', updated_at = datetime('now') WHERE id = ? AND status != 'DELETED'").bind(domainId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'REMOVE_DOMAIN', 'QUEUED', ?)").bind(jobId, membership.id, `remove-domain:${domainId}`),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.deleted', 'domain', ?, ?)")
      .bind(crypto.randomUUID(), identity.organizationId, identity.id, domainId, JSON.stringify({ name: domain.name, jobId, via: "customer-portal" })),
  ]);
  return c.json({ success: true, domainId, jobId, status: "DELETED", message: "Domain removal queued." });
});

// Customer creates a MariaDB database on their own hosting account. The
// username-prefixed database name, plan database limit, and username
// restrictions are enforced server-side.
app.post("/v1/customer/hosting-accounts/:id/databases", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT m.role, a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ? AND m.status = 'ACTIVE' AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ role: string; id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  if (!customerMutationAllowed(membership.role, "database")) {
    return c.json({ message: "Your hosting account role cannot create databases. Ask an account owner, admin, or developer." }, 403);
  }
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const requestedName = typeof input.name === "string" ? input.name.toLowerCase() : "";
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(requestedName)) {
    return c.json({ message: "Choose a database name using 2–31 lowercase letters, numbers, or underscores." }, 400);
  }
  const account = await c.env.DB.prepare(
    `SELECT a.username, p.database_limit AS databaseLimit
     FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.id = ? LIMIT 1`,
  ).bind(membership.id).first<{ username: string; databaseLimit: number }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(account.username)) {
    return c.json({ message: "The hosting account username is invalid." }, 409);
  }
  const databaseName = `${account.username}_${requestedName}`;
  if (!/^[a-z][a-z0-9_]{1,63}$/.test(databaseName) || databaseName.length > 64) {
    return c.json({ message: "The generated database name is invalid or too long." }, 400);
  }
  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM hosting_databases WHERE hosting_account_id = ? AND status != 'DELETED'",
  ).bind(membership.id).first<{ count: number }>();
  if ((count?.count ?? 0) >= account.databaseLimit) {
    return c.json({ message: "This hosting account has reached its database limit." }, 409);
  }
  const databaseId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();
  const payload = JSON.stringify({ databaseId, databaseName });
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO hosting_databases (id, organization_id, hosting_account_id, name, engine, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'MARIADB', 'PENDING', ?, ?)",
      ).bind(databaseId, identity.organizationId, membership.id, databaseName, now, now),
      c.env.DB.prepare(
        "INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'CREATE_DATABASE', 'QUEUED', ?, ?)",
      ).bind(jobId, membership.id, "create-database:" + databaseId, payload),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database.provisioning_queued', 'database', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, databaseId, JSON.stringify({ hostingAccountId: membership.id, jobId, via: "customer-portal" })),
    ]);
  } catch {
    return c.json({ message: "Unable to queue database provisioning. Refresh and try again." }, 409);
  }
  return c.json({ databaseId, jobId, status: "PENDING", name: databaseName, engine: "MARIADB", message: "Database creation has been queued for the connected Linux agent." }, 202);
});

// Customer deletes one of their own databases. The same guards as the WHM
// route apply: pending user operations block deletion, usernames are
// validated against the account prefix, and concurrent jobs are rejected.
app.delete("/v1/customer/hosting-accounts/:id/databases/:databaseId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const membership = await c.env.DB.prepare(
    `SELECT m.role, a.id FROM hosting_account_memberships m
     JOIN hosting_accounts a ON a.id = m.hosting_account_id AND a.organization_id = m.organization_id
     WHERE a.id = ? AND m.user_id = ? AND m.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.id).first<{ role: string; id: string }>();
  if (!membership) return c.json({ message: "Hosting account not found" }, 404);
  if (!customerMutationAllowed(membership.role, "database")) {
    return c.json({ message: "Your hosting account role cannot delete databases. Ask an account owner, admin, or developer." }, 403);
  }
  const database = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.status, a.username AS accountUsername
     FROM hosting_databases d
     JOIN hosting_accounts a ON a.id = d.hosting_account_id AND a.organization_id = d.organization_id
     WHERE d.id = ? AND d.hosting_account_id = ? AND d.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("databaseId"), membership.id, identity.organizationId)
    .first<{ id: string; name: string; status: string; accountUsername: string }>();
  if (!database) return c.json({ message: "Database not found on this hosting account." }, 404);
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(database.accountUsername) ||
      !/^[a-z][a-z0-9_]{1,63}$/.test(database.name) || database.name.length > 64 ||
      !database.name.startsWith(database.accountUsername + "_") ||
      database.name.length <= database.accountUsername.length + 1) {
    return c.json({ message: "The database name does not belong to its hosting account." }, 409);
  }
  if (database.status === "DELETED") return c.json({ message: "This database has already been deleted." }, 409);
  const existingDelete = await c.env.DB.prepare(
    "SELECT id, status FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'DELETE_DATABASE' AND json_extract(request_payload, '$.databaseName') = ? ORDER BY requested_at DESC LIMIT 1",
  ).bind(membership.id, database.name).first<{ id: string; status: string }>();
  if (database.status === "DELETING" && existingDelete && ["QUEUED", "RUNNING"].includes(existingDelete.status)) {
    return c.json({ databaseId: database.id, jobId: existingDelete.id, status: "DELETING", message: "Database deletion is already in progress." }, 202);
  }
  if (!["ACTIVE", "FAILED", "DELETING"].includes(database.status)) {
    return c.json({ message: "Only an active or failed database can be deleted." }, 409);
  }
  const usersResult = await c.env.DB.prepare(
    "SELECT username, status FROM hosting_database_users WHERE database_id = ? AND organization_id = ?",
  ).bind(database.id, identity.organizationId).all<{ username: string; status: string }>();
  const dbUsers = usersResult.results ?? [];
  if (dbUsers.some((u) => u.status === "PENDING" || u.status === "REVOKING")) {
    return c.json({ message: "Wait for pending user creation or revocation to finish before deleting this database." }, 409);
  }
  const prefix = database.accountUsername + "_";
  const databaseUserNames: string[] = [];
  for (const user of dbUsers) {
    if (user.status === "REVOKED") continue;
    if (!user.username.startsWith(prefix)) {
      return c.json({ message: "A stored database username does not belong to this hosting account. Deletion was blocked." }, 409);
    }
    const suffix = user.username.slice(prefix.length);
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(suffix) || user.username.length > 80) {
      return c.json({ message: "A stored database username is invalid. Deletion was blocked." }, 409);
    }
    databaseUserNames.push(user.username);
  }
  if (databaseUserNames.length > 100) return c.json({ message: "This database has too many users for a safe deletion request." }, 409);
  const activeJobs = await c.env.DB.prepare(
    `SELECT id FROM provisioning_jobs
     WHERE hosting_account_id = ? AND status IN ('QUEUED', 'RUNNING')
       AND operation IN ('CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER')
       AND json_extract(request_payload, '$.databaseName') = ? LIMIT 1`,
  ).bind(membership.id, database.name).first<{ id: string }>();
  if (activeJobs) return c.json({ message: "A database provisioning or user-management job is still running. Refresh after it finishes." }, 409);
  const jobId = crypto.randomUUID();
  const idempotencyKey = "delete-database:" + database.id + ":" + jobId;
  const now = new Date().toISOString();
  const payload = JSON.stringify({ databaseName: database.name, databaseUserNames });
  try {
    const results = await c.env.DB.batch([
      c.env.DB.prepare(
        `UPDATE hosting_databases SET status = 'DELETING', updated_at = ?
         WHERE id = ? AND organization_id = ? AND status IN ('ACTIVE', 'FAILED', 'DELETING')
           AND NOT EXISTS (SELECT 1 FROM hosting_database_users u
             WHERE u.database_id = hosting_databases.id AND u.status IN ('PENDING', 'REVOKING'))`,
      ).bind(now, database.id, identity.organizationId),
      c.env.DB.prepare(
        `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload)
         SELECT ?, ?, 'DELETE_DATABASE', 'QUEUED', ?, ?
         WHERE EXISTS (SELECT 1 FROM hosting_databases WHERE id = ? AND organization_id = ? AND status = 'DELETING')`,
      ).bind(jobId, membership.id, idempotencyKey, payload, database.id, identity.organizationId),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database.deletion_queued', 'database', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, database.id, JSON.stringify({ jobId, databaseName: database.name, userCount: databaseUserNames.length, via: "customer-portal" })),
    ]);
    if ((results[0]?.meta?.changes ?? 0) !== 1 || (results[1]?.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "Database state changed or another operation is in progress. Refresh and try again." }, 409);
    }
  } catch {
    return c.json({ message: "Unable to queue database deletion. Refresh and try again." }, 409);
  }
  return c.json({ databaseId: database.id, jobId, status: "DELETING", message: "Database deletion has been queued. The database will remain listed until the server confirms deletion." }, 202);
});

app.get("/v1/hosting-accounts/:id/memberships", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const account = await c.env.DB.prepare(
    "SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  const result = await c.env.DB.prepare(
    `SELECT m.id, m.user_id AS userId, u.email, u.display_name AS displayName,
            m.role, m.status, m.created_at AS createdAt
     FROM hosting_account_memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.hosting_account_id = ? AND m.organization_id = ?
     ORDER BY m.created_at ASC`,
  ).bind(account.id, identity.organizationId).all();
  return c.json({ memberships: result.results ?? [] });
});

app.post("/v1/hosting-accounts/:id/memberships", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
  const role = typeof input.role === "string" ? input.role : "ACCOUNT_READONLY";
  const allowedRoles = ["ACCOUNT_OWNER", "ACCOUNT_ADMIN", "ACCOUNT_DEVELOPER", "ACCOUNT_READONLY"];
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return c.json({ message: "Enter a valid customer email address." }, 400);
  if (!allowedRoles.includes(role)) return c.json({ message: "Select a valid hosting account role." }, 400);

  const account = await c.env.DB.prepare(
    "SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);

  const user = await c.env.DB.prepare(
    "SELECT id FROM users WHERE email = ? COLLATE NOCASE AND status = 'ACTIVE' LIMIT 1",
  ).bind(email).first<{ id: string }>();
  if (!user) return c.json({ message: "No active Nexora login exists for that email. Ask the customer to register first." }, 404);

  const now = new Date().toISOString();
  const membershipId = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO hosting_account_memberships
         (id, hosting_account_id, organization_id, user_id, role, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
         ON CONFLICT(hosting_account_id, user_id) DO UPDATE SET
           role = excluded.role, status = 'ACTIVE', updated_at = excluded.updated_at`,
      ).bind(membershipId, account.id, identity.organizationId, user.id, role, now, now),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.member_assigned', 'hosting_account', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, account.id, JSON.stringify({ userId: user.id, role })),
    ]);
    return c.json({ success: true, userId: user.id, role, message: "Hosting account access assigned." }, 201);
  } catch {
    return c.json({ message: "Unable to assign hosting account access." }, 409);
  }
});

app.delete("/v1/hosting-accounts/:id/memberships/:userId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const accountId = c.req.param("id");
  const userId = c.req.param("userId");
  const account = await c.env.DB.prepare(
    "SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1",
  ).bind(accountId, identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found." }, 404);
  const membership = await c.env.DB.prepare(
    "SELECT id FROM hosting_account_memberships WHERE hosting_account_id = ? AND organization_id = ? AND user_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(accountId, identity.organizationId, userId).first<{ id: string }>();
  if (!membership) return c.json({ message: "Active customer access was not found." }, 404);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_account_memberships SET status = 'REVOKED', updated_at = ? WHERE id = ?").bind(new Date().toISOString(), membership.id),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.member_revoked', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, accountId, JSON.stringify({ userId })),
  ]);
  return c.json({ success: true, message: "Customer access revoked for this hosting account." });
});

app.get("/v1/platform/customers", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  // Platform-wide customer data is restricted to the platform OWNER, not ordinary workspace admins.
  if (identity.platformRole !== "PLATFORM_OWNER" && identity.platformRole !== "PLATFORM_ADMIN") {
    return c.json({ message: "Platform administrator access required." }, 403);
  }

  const result = await c.env.DB.prepare(
    `SELECT u.id AS userId, u.email, u.display_name AS displayName,
            u.status AS userStatus, u.created_at AS registeredAt,
            o.id AS organizationId, o.name AS organizationName, o.slug AS organizationSlug,
            o.status AS organizationStatus, m.role AS organizationRole,
            (SELECT COUNT(*) FROM hosting_accounts h WHERE h.organization_id = o.id AND h.status != 'DELETED') AS hostingAccounts,
            (SELECT COUNT(*) FROM hosting_accounts h WHERE h.organization_id = o.id AND h.status = 'ACTIVE') AS activeHostingAccounts,
            (SELECT COUNT(*) FROM hosting_accounts h WHERE h.organization_id = o.id AND h.status = 'PENDING') AS pendingHostingAccounts
     FROM users u
     JOIN memberships m ON m.user_id = u.id
     JOIN organizations o ON o.id = m.organization_id
     ORDER BY u.created_at DESC, u.email COLLATE NOCASE`,
  ).all();
  return c.json({ customers: result.results ?? [] });
});

app.get("/v1/users", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const result = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.display_name AS displayName, u.status AS userStatus,
            m.role, m.created_at AS joinedAt,
            (SELECT COUNT(*) FROM hosting_account_memberships hm WHERE hm.user_id = u.id AND hm.organization_id = m.organization_id AND hm.status = 'ACTIVE') AS hostingAccounts
     FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.organization_id = ?
     ORDER BY CASE m.role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, u.email COLLATE NOCASE`,
  ).bind(identity.organizationId).all();
  return c.json({ users: result.results ?? [] });
});

app.delete("/v1/users/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const userId = c.req.param("id");
  if (userId === identity.id) return c.json({ message: "You cannot remove your own active login." }, 409);
  const target = await c.env.DB.prepare(
    "SELECT u.id, u.email, m.role FROM users u JOIN memberships m ON m.user_id = u.id WHERE u.id = ? AND m.organization_id = ? LIMIT 1",
  ).bind(userId, identity.organizationId).first<{ id: string; email: string; role: Role }>();
  if (!target) return c.json({ message: "Workspace user not found." }, 404);
  if (target.role === "OWNER" || target.role === "ADMIN") {
    const admins = await c.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM memberships WHERE organization_id = ? AND role IN ('OWNER', 'ADMIN')",
    ).bind(identity.organizationId).first<{ count: number }>();
    if ((admins?.count ?? 0) <= 1) return c.json({ message: "The last active administrator cannot be removed. Promote another administrator first." }, 409);
  }
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM hosting_account_memberships WHERE user_id = ? AND organization_id = ?").bind(userId, identity.organizationId),
    c.env.DB.prepare("DELETE FROM memberships WHERE user_id = ? AND organization_id = ?").bind(userId, identity.organizationId),
    c.env.DB.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND organization_id = ? AND revoked_at IS NULL").bind(new Date().toISOString(), userId, identity.organizationId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'workspace.user_removed', 'user', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, userId, JSON.stringify({ email: target.email, role: target.role })),
  ]);
  return c.json({ success: true, message: "User removed from this workspace and active sessions revoked. Their Nexora login may remain active in other workspaces." });
});

// Audit log viewer — organization-scoped with filters.
app.get("/v1/audit-logs", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  if (!isPlatformAdmin && identity.role !== "OWNER" && identity.role !== "ADMIN") {
    return c.json({ message: "Organization administrator access required to view audit logs." }, 403);
  }
  const requestedOrg = c.req.query("organizationId");
  const organizationFilter = (isPlatformAdmin && requestedOrg && /^[a-f0-9\-]{36}$/i.test(requestedOrg)) ? requestedOrg : identity.organizationId;
  const action = c.req.query("action");
  const resourceType = c.req.query("resourceType");
  const actorUserId = c.req.query("actorUserId");
  const before = c.req.query("before");
  const after = c.req.query("after");
  const pageLimit = Math.min(Math.max(parseInt(c.req.query("limit") ?? "100", 10) || 100, 1), 200);
  const conditions: string[] = ["organization_id = ?"];
  const binds: (string | number)[] = [organizationFilter];
  if (action && /^[a-z0-9_.]{1,64}$/i.test(action)) { conditions.push("action = ?"); binds.push(action); }
  if (resourceType && /^[a-z0-9_]{1,32}$/i.test(resourceType)) { conditions.push("resource_type = ?"); binds.push(resourceType); }
  if (actorUserId && /^[a-f0-9\-]{36}$/i.test(actorUserId)) { conditions.push("actor_user_id = ?"); binds.push(actorUserId); }
  if (before && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(before)) { conditions.push("created_at <= ?"); binds.push(before); }
  if (after && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(after)) { conditions.push("created_at >= ?"); binds.push(after); }
  const rows = await c.env.DB.prepare(
    "SELECT id, organization_id AS organizationId, actor_user_id AS actorUserId, action, resource_type AS resourceType, resource_id AS resourceId, source_ip AS sourceIp, metadata, created_at AS createdAt FROM audit_logs WHERE " + conditions.join(" AND ") + " ORDER BY created_at DESC LIMIT ?",
  ).bind(...binds, pageLimit).all<{ id: string; organizationId: string | null; actorUserId: string | null; action: string; resourceType: string; resourceId: string | null; sourceIp: string | null; metadata: string | null; createdAt: string }>();
  const entries = (rows.results ?? []).map((row) => {
    let metadata: unknown = null;
    if (row.metadata) { try { metadata = JSON.parse(row.metadata); } catch { metadata = null; } }
    return { id: row.id, organizationId: row.organizationId, actorUserId: row.actorUserId, action: row.action, resourceType: row.resourceType, resourceId: row.resourceId, sourceIp: row.sourceIp, metadata, createdAt: row.createdAt };
  });
  return c.json({ entries, count: entries.length, limit: pageLimit });
});

app.patch("/v1/hosting-accounts/:id/suspend", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN" && identity.platformRole !== "PLATFORM_OWNER" && identity.platformRole !== "PLATFORM_ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id, username, status FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string; username: string; status: string }>();
  if (!account) return c.json({ message: "Hosting account not found." }, 404);
  if (account.status === "SUSPENDED") return c.json({ message: "Hosting account is already suspended." }, 409);
  if (account.status === "DELETED") return c.json({ message: "Hosting account has been deleted." }, 409);
  const jobId = crypto.randomUUID();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_accounts SET status = 'SUSPENDED', updated_at = datetime('now') WHERE id = ? AND organization_id = ? AND status = 'ACTIVE'").bind(accountId, identity.organizationId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'SUSPEND_HOSTING_ACCOUNT', 'QUEUED', ?)").bind(jobId, accountId, `suspend-account:${accountId}`),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.suspended', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, accountId, JSON.stringify({ username: account.username, jobId })),
  ]);
  return c.json({ success: true, jobId, status: "SUSPENDED", message: "Hosting account suspended." });
});

app.patch("/v1/hosting-accounts/:id/reactivate", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN" && identity.platformRole !== "PLATFORM_OWNER" && identity.platformRole !== "PLATFORM_ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id, username, status FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string; username: string; status: string }>();
  if (!account) return c.json({ message: "Hosting account not found." }, 404);
  if (account.status === "ACTIVE") return c.json({ message: "Hosting account is already active." }, 409);
  if (account.status === "DELETED") return c.json({ message: "Hosting account has been deleted and cannot be reactivated." }, 409);
  const jobId = crypto.randomUUID();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_accounts SET status = 'ACTIVE', updated_at = datetime('now') WHERE id = ? AND organization_id = ? AND status = 'SUSPENDED'").bind(accountId, identity.organizationId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'REACTIVATE_HOSTING_ACCOUNT', 'QUEUED', ?)").bind(jobId, accountId, `reactivate-account:${accountId}`),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.reactivated', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, accountId, JSON.stringify({ username: account.username, jobId })),
  ]);
  return c.json({ success: true, jobId, status: "ACTIVE", message: "Hosting account reactivated." });
});

app.delete("/v1/hosting-accounts/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const account = await c.env.DB.prepare(
    "SELECT id, username, status FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; username: string; status: string }>();
  if (!account || account.status === "DELETED") return c.json({ message: "Hosting account not found." }, 404);
  if (account.status !== "PENDING") return c.json({ message: "This account has progressed beyond the safe pre-provisioning stage. Active or partially provisioned Linux accounts require the agent-backed deprovisioning workflow; no data has been changed." }, 409);
  const jobs = await c.env.DB.prepare(
    "SELECT id, status FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'CREATE_HOSTING_ACCOUNT' ORDER BY requested_at DESC LIMIT 1",
  ).bind(account.id).first<{ id: string; status: string }>();
  if (jobs && jobs.status !== "QUEUED" && jobs.status !== "CANCELLED") {
    return c.json({ message: "The provisioning job is already running or finished. Wait for it to stop or complete before deletion." }, 409);
  }
  const now = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE provisioning_jobs SET status = 'CANCELLED', finished_at = ? WHERE hosting_account_id = ? AND operation = 'CREATE_HOSTING_ACCOUNT' AND status = 'QUEUED'").bind(now, account.id),
    c.env.DB.prepare("UPDATE hosting_account_memberships SET status = 'REVOKED', updated_at = ? WHERE hosting_account_id = ? AND organization_id = ?").bind(now, account.id, identity.organizationId),
    c.env.DB.prepare("UPDATE hosting_accounts SET status = 'DELETED', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'PENDING'").bind(now, account.id, identity.organizationId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.cancelled_before_provisioning', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, account.id, JSON.stringify({ username: account.username })),
  ]);
  return c.json({ deleted: true, message: "Unprovisioned hosting account removed. No Linux account or website data was present to delete." });
});

app.get("/v1/hosting-accounts", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT a.id, a.username, a.primary_domain, a.status, a.created_at,
            a.server_id, s.hostname AS server_hostname,
            a.plan_id, p.name AS plan_name,
            (SELECT j.status FROM provisioning_jobs j
             WHERE j.hosting_account_id = a.id AND j.operation = 'CREATE_HOSTING_ACCOUNT'
             ORDER BY j.requested_at DESC LIMIT 1) AS job_status
     FROM hosting_accounts a
     JOIN servers s ON s.id = a.server_id
     JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.organization_id = ? AND a.status != 'DELETED'
     ORDER BY a.created_at DESC`,
  ).bind(identity.organizationId).all<HostingAccountRow>();
  return c.json({ accounts: result.results ?? [] });
});

app.post("/v1/hosting-accounts", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const serverId = typeof input.serverId === "string" ? input.serverId : "";
  const planId = typeof input.planId === "string" ? input.planId : "";
  const username = typeof input.username === "string" ? input.username.trim().toLowerCase() : "";
  const primaryDomain = typeof input.primaryDomain === "string" ? input.primaryDomain.trim().toLowerCase() : "";

  if (!/^[a-z][a-z0-9_]{2,15}$/.test(username)) {
    return c.json({ message: "Username must be 3–16 characters, start with a letter, and contain only lowercase letters, numbers or underscores." }, 400);
  }
  if (primaryDomain && !validDomain(primaryDomain)) {
    return c.json({ message: "Enter a valid primary domain, such as example.com." }, 400);
  }

  const server = await c.env.DB.prepare(
    "SELECT id, hostname FROM servers WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(serverId, identity.organizationId).first<{ id: string; hostname: string }>();
  if (!server) return c.json({ message: "Select a server in your active workspace." }, 404);

  const plan = await c.env.DB.prepare(
    "SELECT id, name, active, website_limit FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(planId, identity.organizationId).first<{ id: string; name: string; active: number; website_limit: number }>();
  if (!plan || plan.active !== 1) return c.json({ message: "Select an active hosting plan in your workspace." }, 404);
  if (primaryDomain && plan.website_limit < 1) return c.json({ message: "This hosting plan does not include a website slot." }, 409);

  const id = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const documentRoot = `/home/${username}/public_html`;
  const statements = [
    c.env.DB.prepare(
      `INSERT INTO hosting_accounts
       (id, organization_id, server_id, plan_id, username, primary_domain, status)
       VALUES (?, ?, ?, ?, ?, ?, 'PENDING')`,
    ).bind(id, identity.organizationId, serverId, planId, username, primaryDomain || null),
  ];
  if (primaryDomain) {
    statements.push(c.env.DB.prepare(
      `INSERT INTO domains (id, hosting_account_id, name, document_root, is_primary)
       VALUES (?, ?, ?, ?, 1)`,
    ).bind(crypto.randomUUID(), id, primaryDomain, documentRoot));
  }
  statements.push(
    c.env.DB.prepare(
      `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key)
       VALUES (?, ?, 'CREATE_HOSTING_ACCOUNT', 'QUEUED', ?)`,
    ).bind(jobId, id, `create-account:${id}`),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'hosting_account.create_requested', 'hosting_account', ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
  );

  try {
    await c.env.DB.batch(statements);
    return c.json({
      account: {
        id, username, primary_domain: primaryDomain || null, status: "PENDING",
        server_id: server.id, server_hostname: server.hostname, plan_id: plan.id,
        plan_name: plan.name, job_status: "QUEUED",
      },
      provisioningJob: { id: jobId, status: "QUEUED", operation: "CREATE_HOSTING_ACCOUNT" },
      message: "Hosting account request queued. It will remain pending until a connected Linux agent provisions it.",
    }, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_accounts.server_id, hosting_accounts.username/i.test(message)) {
      return c.json({ message: "That username already exists on the selected server." }, 409);
    }
    if (/UNIQUE constraint failed: domains.name/i.test(message)) {
      return c.json({ message: "That domain is already assigned to another hosting account." }, 409);
    }
    return c.json({ message: "Unable to queue the hosting account. Check the username and domain are not already in use." }, 409);
  }
});


function validManagedRelativePath(value: string, allowRoot = false): boolean {
  if (value === "") return allowRoot;
  if (value.length > 1024 || value.startsWith("/") || value.includes("\\")) return false;
  return value.split("/").every(part =>
    part.length > 0 && part.length <= 128 && part !== "." && part !== ".." &&
    /^[A-Za-z0-9._ -]+$/.test(part)
  );
}

app.post("/v1/hosting-accounts/:id/files", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const rawBody = await c.req.text();
  if (rawBody.length > 400000) return c.json({ message: "File operation request exceeds the 400 KB limit" }, 413);
  let input: Record<string, unknown>;
  try { input = JSON.parse(rawBody) as Record<string, unknown>; }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }

  const operation = typeof input.operation === "string" ? input.operation : "";
  const filePath = typeof input.path === "string" ? input.path : "";
  const newPath = typeof input.newPath === "string" ? input.newPath : "";
  const contentBase64 = typeof input.contentBase64 === "string" ? input.contentBase64 : "";
  const supported = ["LIST_FILES", "READ_FILE", "WRITE_FILE", "CREATE_DIRECTORY", "RENAME_PATH", "DELETE_PATH"];
  if (!supported.includes(operation)) return c.json({ message: "Unsupported file operation" }, 400);
  if (!validManagedRelativePath(filePath, operation === "LIST_FILES")) return c.json({ message: "Invalid file path" }, 400);
  if (operation !== "LIST_FILES" && !filePath) return c.json({ message: "A file path is required" }, 400);
  if (operation === "RENAME_PATH" && !validManagedRelativePath(newPath)) return c.json({ message: "Invalid destination path" }, 400);
  if (operation === "WRITE_FILE" && (typeof input.contentBase64 !== "string" || contentBase64.length > 350000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(contentBase64))) {
    return c.json({ message: "File content must be valid Base64 and no larger than 256 KiB" }, 400);
  }

  const account = await c.env.DB.prepare(
    "SELECT id, username, server_id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; username: string; server_id: string }>();
  if (!account) return c.json({ message: "Active hosting account not found" }, 404);

  const requestPayload = JSON.stringify({ fileOperation: operation, path: filePath, ...(operation === "RENAME_PATH" ? { newPath } : {}), ...(operation === "WRITE_FILE" ? { contentBase64 } : {}) });
  const jobId = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'FILE_MANAGER', 'QUEUED', ?, ?)").bind(jobId, account.id, "file-manager:" + jobId, requestPayload),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'file_manager.operation_requested', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, account.id, JSON.stringify({ operation, path: filePath })),
    ]);
  } catch {
    return c.json({ message: "Unable to queue the file operation" }, 500);
  }
  return c.json({ job: { id: jobId, status: "QUEUED", operation }, message: "File operation queued for the connected Linux agent." }, 202);
});

app.get("/v1/file-manager/jobs/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const job = await c.env.DB.prepare(
    `SELECT j.id, j.status, j.operation, j.error_message AS errorMessage, j.result_payload AS resultPayload,
            j.requested_at AS requestedAt, j.finished_at AS finishedAt
     FROM provisioning_jobs j JOIN hosting_accounts a ON a.id = j.hosting_account_id
     WHERE j.id = ? AND j.operation = 'FILE_MANAGER' AND a.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; status: string; operation: string; errorMessage: string | null; resultPayload: string | null; requestedAt: string; finishedAt: string | null }>();
  if (!job) return c.json({ message: "File operation not found" }, 404);
  let result: unknown = null;
  if (job.resultPayload) {
    try { result = JSON.parse(job.resultPayload); } catch { return c.json({ message: "Stored file operation result is invalid" }, 500); }
  }
  return c.json({ job: { id: job.id, status: job.status, operation: job.operation, errorMessage: job.errorMessage, requestedAt: job.requestedAt, finishedAt: job.finishedAt, result } });
});


app.get("/v1/hosting-accounts/:id/backups", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Active hosting account not found" }, 404);
  const result = await c.env.DB.prepare("SELECT id, status, archive_name AS archiveName, size_bytes AS sizeBytes, sha256, database_names_json AS databaseNamesJson, error_message AS errorMessage, created_at AS createdAt, completed_at AS completedAt, staged_at AS stagedAt FROM hosting_backups WHERE hosting_account_id = ? AND organization_id = ? ORDER BY created_at DESC LIMIT 100").bind(account.id, identity.organizationId).all<{ id: string; status: string; archiveName: string | null; sizeBytes: number | null; sha256: string | null; databaseNamesJson: string; errorMessage: string | null; createdAt: string; completedAt: string | null; stagedAt: string | null }>();
  const backups = (result.results ?? []).map((row) => ({ ...row, databaseNames: (() => { try { const parsed = JSON.parse(row.databaseNamesJson); return Array.isArray(parsed) ? parsed : []; } catch { return []; } })() }));
  return c.json({ backups });
});

app.post("/v1/hosting-accounts/:id/backups", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const account = await c.env.DB.prepare("SELECT id, username, server_id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string; username: string; server_id: string }>();
  if (!account) return c.json({ message: "Active hosting account not found" }, 404);
  const databases = await c.env.DB.prepare("SELECT name FROM hosting_databases WHERE hosting_account_id = ? AND organization_id = ? AND status = 'ACTIVE' ORDER BY name LIMIT 20").bind(account.id, identity.organizationId).all<{ name: string }>();
  const databaseNames = (databases.results ?? []).map((row) => row.name);
  const backupId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();
  const requestPayload = JSON.stringify({ backupId, databaseNames });
  // Atomic exclusion: conditional INSERT (NOT EXISTS) checks for an active
  // backup AND inserts in a single SQL statement. D1's atomic execution
  // guarantees no race. The partial unique index
  // idx_hosting_backups_active_exclusion is the database-level backstop:
  // if two racing requests both pass the NOT EXISTS check, the index
  // rejects the second with SQLITE_CONSTRAINT_UNIQUE.
  //
  // Conflicts surface in two ways and both map to 409:
  //   1. changes() = 0 — the NOT EXISTS check saw an active backup.
  //   2. A UNIQUE constraint error — the index rejected a racing insert.
  // Unrelated database errors are NOT swallowed — they propagate as 500.
  let insertResult: { meta?: { changes?: number } };
  try {
    insertResult = await c.env.DB.prepare(
      "INSERT INTO hosting_backups (id, organization_id, hosting_account_id, server_id, status, database_names_json, requested_by_user_id, created_at) " +
      "SELECT ?, ?, ?, ?, 'QUEUED', ?, ?, ? " +
      "WHERE NOT EXISTS (SELECT 1 FROM hosting_backups WHERE hosting_account_id = ? AND status IN ('QUEUED', 'RUNNING'))",
    ).bind(backupId, identity.organizationId, account.id, account.server_id, JSON.stringify(databaseNames), identity.id, now, account.id).run();
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return c.json({ message: "A backup is already queued or running for this hosting account. Wait for it to complete before requesting another." }, 409);
    }
    return c.json({ message: "Unable to queue the hosting backup" }, 500);
  }
  if ((insertResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "A backup is already queued or running for this hosting account. Wait for it to complete before requesting another." }, 409);
  }
  // Backup row inserted. Now queue the job + audit. If this fails, clean
  // up the orphan backup so the exclusion is released.
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'CREATE_BACKUP', 'QUEUED', ?, ?)").bind(jobId, account.id, "backup-create:" + backupId, requestPayload),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'backup.create_requested', 'hosting_backup', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, backupId, JSON.stringify({ accountId: account.id, username: account.username, databaseCount: databaseNames.length })),
    ]);
  } catch {
    await c.env.DB.prepare("DELETE FROM hosting_backups WHERE id = ? AND status = 'QUEUED'").bind(backupId).run();
    return c.json({ message: "Unable to queue the hosting backup" }, 500);
  }
  return c.json({ backup: { id: backupId, status: "QUEUED", databaseNames }, job: { id: jobId, status: "QUEUED" }, message: "Backup queued for the connected Linux agent." }, 202);
});

app.post("/v1/backups/:id/restore", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const backup = await c.env.DB.prepare("SELECT b.id, b.hosting_account_id AS accountId, a.username, b.sha256 AS sha256 FROM hosting_backups b JOIN hosting_accounts a ON a.id = b.hosting_account_id WHERE b.id = ? AND b.organization_id = ? AND b.status = 'AVAILABLE' AND a.status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string; accountId: string; username: string; sha256: string | null }>();
  if (!backup) return c.json({ message: "Available backup not found" }, 404);
  if (!backup.sha256 || !/^[a-f0-9]{64}$/.test(backup.sha256)) return c.json({ message: "Backup integrity metadata is missing or invalid; restore is blocked." }, 409);
  const jobId = crypto.randomUUID();
  const results = await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_backups SET status = 'RESTORING', error_message = NULL WHERE id = ? AND organization_id = ? AND status = 'AVAILABLE'").bind(backup.id, identity.organizationId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) SELECT ?, ?, 'RESTORE_BACKUP', 'QUEUED', ?, ? WHERE changes() = 1").bind(jobId, backup.accountId, "backup-restore:" + backup.id + ":" + jobId, JSON.stringify({ backupId: backup.id, databaseNames: [], sha256: backup.sha256 })),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) SELECT ?, ?, ?, 'backup.restore_requested', 'hosting_backup', ?, ? WHERE changes() = 1").bind(crypto.randomUUID(), identity.organizationId, identity.id, backup.id, JSON.stringify({ accountId: backup.accountId, username: backup.username, mode: "STAGING_ONLY" })),
  ]);
  if ((results[0]?.meta?.changes ?? 0) !== 1) return c.json({ message: "Backup is already being processed. Refresh and try again later." }, 409);
  return c.json({ job: { id: jobId, status: "QUEUED" }, message: "Restore queued. Files and database dumps will be extracted to a protected staging directory; live website files and databases will not be overwritten." }, 202);
});

app.delete("/v1/backups/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const backup = await c.env.DB.prepare("SELECT b.id, b.hosting_account_id AS accountId FROM hosting_backups b JOIN hosting_accounts a ON a.id = b.hosting_account_id WHERE b.id = ? AND b.organization_id = ? AND b.status = 'AVAILABLE' AND a.status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string; accountId: string }>();
  if (!backup) return c.json({ message: "Available backup not found" }, 404);
  const jobId = crypto.randomUUID();
  const results = await c.env.DB.batch([
    c.env.DB.prepare("UPDATE hosting_backups SET status = 'DELETING' WHERE id = ? AND organization_id = ? AND status = 'AVAILABLE'").bind(backup.id, identity.organizationId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) SELECT ?, ?, 'DELETE_BACKUP', 'QUEUED', ?, ? WHERE changes() = 1").bind(jobId, backup.accountId, "backup-delete:" + backup.id + ":" + jobId, JSON.stringify({ backupId: backup.id, databaseNames: [] })),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'backup.delete_requested', 'hosting_backup', ? WHERE changes() = 1").bind(crypto.randomUUID(), identity.organizationId, identity.id, backup.id),
  ]);
  if ((results[0]?.meta?.changes ?? 0) !== 1) return c.json({ message: "Backup is already being processed. Refresh and try again later." }, 409);
  return c.json({ job: { id: jobId, status: "QUEUED" }, message: "Backup deletion queued." }, 202);
});

// ---------------------------------------------------------------------------
// PHP admin API. The agent already generates per-account PHP-FPM pools;
// these endpoints expose the settings to the dashboard so administrators
// can change PHP version, memory limits, execution time, upload limits,
// and display_errors without SSH access. Changes queue an
// UPDATE_PHP_POOL provisioning job so the agent rewrites and reloads.
// ---------------------------------------------------------------------------

app.get("/v1/hosting-accounts/:id/php", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  const settings = await c.env.DB.prepare(
    "SELECT php_version AS phpVersion, memory_limit_mib AS memoryLimitMib, max_execution_time_seconds AS maxExecutionTimeSeconds, upload_max_filesize_mib AS uploadMaxFilesizeMib, max_input_vars AS maxInputVars, display_errors AS displayErrors, updated_at AS updatedAt FROM hosting_account_php_settings WHERE hosting_account_id = ? LIMIT 1",
  ).bind(accountId).first<{ phpVersion: string; memoryLimitMib: number; maxExecutionTimeSeconds: number; uploadMaxFilesizeMib: number; maxInputVars: number; displayErrors: number; updatedAt: string }>();
  if (!settings) {
    // Return defaults if no row exists yet (account was created before this migration).
    return c.json({ phpVersion: "8.3", memoryLimitMib: 256, maxExecutionTimeSeconds: 30, uploadMaxFilesizeMib: 64, maxInputVars: 1000, displayErrors: 0, updatedAt: null });
  }
  return c.json(settings);
});

app.put("/v1/hosting-accounts/:id/php", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const SUPPORTED_PHP_VERSIONS = ["8.1", "8.2", "8.3", "8.4"];
  const phpVersion = typeof input.phpVersion === "string" ? input.phpVersion.trim() : "";
  if (!SUPPORTED_PHP_VERSIONS.includes(phpVersion)) {
    return c.json({ message: `PHP version must be one of: ${SUPPORTED_PHP_VERSIONS.join(", ")}` }, 400);
  }
  const memoryLimitMib = Number(input.memoryLimitMib);
  const maxExecutionTimeSeconds = Number(input.maxExecutionTimeSeconds);
  const uploadMaxFilesizeMib = Number(input.uploadMaxFilesizeMib);
  const maxInputVars = Number(input.maxInputVars);
  const displayErrors = input.displayErrors === true ? 1 : 0;
  if (!Number.isInteger(memoryLimitMib) || memoryLimitMib < 64 || memoryLimitMib > 4096) return c.json({ message: "Memory limit must be between 64 and 4096 MiB" }, 400);
  if (!Number.isInteger(maxExecutionTimeSeconds) || maxExecutionTimeSeconds < 5 || maxExecutionTimeSeconds > 300) return c.json({ message: "Max execution time must be between 5 and 300 seconds" }, 400);
  if (!Number.isInteger(uploadMaxFilesizeMib) || uploadMaxFilesizeMib < 1 || uploadMaxFilesizeMib > 2048) return c.json({ message: "Upload max filesize must be between 1 and 2048 MiB" }, 400);
  if (!Number.isInteger(maxInputVars) || maxInputVars < 100 || maxInputVars > 10000) return c.json({ message: "Max input vars must be between 100 and 10000" }, 400);

  const phpRequestPayload = JSON.stringify({ phpVersion, memoryLimitMib, maxExecutionTimeSeconds, uploadMaxFilesizeMib, maxInputVars, displayErrors });
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO hosting_account_php_settings (hosting_account_id, php_version, memory_limit_mib, max_execution_time_seconds, upload_max_filesize_mib, max_input_vars, display_errors, updated_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now')) " +
      "ON CONFLICT(hosting_account_id) DO UPDATE SET php_version = excluded.php_version, memory_limit_mib = excluded.memory_limit_mib, max_execution_time_seconds = excluded.max_execution_time_seconds, upload_max_filesize_mib = excluded.upload_max_filesize_mib, max_input_vars = excluded.max_input_vars, display_errors = excluded.display_errors, updated_at = datetime('now')",
    ).bind(accountId, phpVersion, memoryLimitMib, maxExecutionTimeSeconds, uploadMaxFilesizeMib, maxInputVars, displayErrors),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'UPDATE_PHP_POOL', 'QUEUED', ?, ?)").bind(crypto.randomUUID(), accountId, `update-php:${accountId}`, phpRequestPayload),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'hosting_account.php_updated', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, accountId, JSON.stringify({ phpVersion, memoryLimitMib, maxExecutionTimeSeconds })),
  ]);
  return c.json({ success: true, message: "PHP settings updated. The agent will regenerate the PHP-FPM pool." });
});

// ---------------------------------------------------------------------------
// Organization update. Workspace OWNER can rename the organization.
// Platform admins can update any organization.
// ---------------------------------------------------------------------------

app.put("/v1/organizations/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const isPlatformAdmin = identity.platformRole === "PLATFORM_OWNER" || identity.platformRole === "PLATFORM_ADMIN";
  if (!isPlatformAdmin && identity.role !== "OWNER") return c.json({ message: "Workspace owner access required" }, 403);
  // Verify the user belongs to this org (unless platform admin).
  if (!isPlatformAdmin && identity.organizationId !== orgId) return c.json({ message: "You can only update your own organization" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (!name || name.length > 120) return c.json({ message: "Organization name is required (max 120 characters)" }, 400);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE organizations SET name = ?, updated_at = datetime('now') WHERE id = ?").bind(name, orgId),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'organization.updated', 'organization', ?, ?)").bind(crypto.randomUUID(), orgId, identity.id, orgId, JSON.stringify({ name })),
  ]);
  return c.json({ success: true, message: "Organization updated." });
});

// ---------------------------------------------------------------------------
// Organization administration.
//
// Every route re-derives authorization from the authenticated session —
// an organization ID supplied by the browser is never trusted on its own.
// Route helpers resolve the caller's relationship to the target org:
//   - a membership row in the target organization (with its role), or
//   - a platform membership (PLATFORM_OWNER / PLATFORM_ADMIN).
// Destructive membership changes enforce last-OWNER/last-admin protection,
// and revocation invalidates the affected user's sessions for that org.
// ---------------------------------------------------------------------------

// resolveOrgAccess returns the caller's role in the target org, or that the
// caller is a platform admin, or null when the caller has no relationship.
async function resolveOrgAccess(
  db: D1Database,
  userId: string,
  organizationId: string,
  platformRole: PlatformRole | null,
): Promise<{ role: Role | null; isPlatformAdmin: boolean }> {
  if (platformRole === "PLATFORM_OWNER" || platformRole === "PLATFORM_ADMIN") {
    return { role: null, isPlatformAdmin: true };
  }
  const membership = await db.prepare(
    "SELECT role FROM memberships WHERE user_id = ? AND organization_id = ? LIMIT 1",
  ).bind(userId, organizationId).first<{ role: Role }>();
  return { role: membership?.role ?? null, isPlatformAdmin: false };
}

// countOrgAdmins counts active OWNER and OWNER+ADMIN memberships. Used to
// enforce that an organization always keeps at least one OWNER and one
// member who can administer it.
async function countOrgAdmins(db: D1Database, organizationId: string) {
  const row = await db.prepare(
    `SELECT
       SUM(CASE WHEN role = 'OWNER' THEN 1 ELSE 0 END) AS owners,
       SUM(CASE WHEN role IN ('OWNER','ADMIN') THEN 1 ELSE 0 END) AS admins
     FROM memberships WHERE organization_id = ?`,
  ).bind(organizationId).first<{ owners: number | null; admins: number | null }>();
  return { owners: row?.owners ?? 0, admins: row?.admins ?? 0 };
}

// List the authenticated user's organizations. Platform admins may request
// the full platform inventory with scope=all. This backs the organization
// switcher and the platform organization directory.
app.get("/v1/organizations", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const scope = c.req.query("scope");
  if (scope === "all") {
    if (identity.platformRole !== "PLATFORM_OWNER" && identity.platformRole !== "PLATFORM_ADMIN") {
      return c.json({ message: "Platform administrator access required" }, 403);
    }
    const result = await c.env.DB.prepare(
      `SELECT o.id, o.name, o.slug, o.status, o.created_at AS createdAt,
              (SELECT COUNT(*) FROM memberships m WHERE m.organization_id = o.id) AS memberCount,
              (SELECT COUNT(*) FROM hosting_accounts a WHERE a.organization_id = o.id AND a.status != 'DELETED') AS hostingAccountCount
       FROM organizations o ORDER BY o.created_at DESC`,
    ).all();
    return c.json({ organizations: result.results ?? [], scope: "all" });
  }
  const result = await c.env.DB.prepare(
    `SELECT o.id, o.name, o.slug, o.status, o.created_at AS createdAt, m.role
     FROM memberships m JOIN organizations o ON o.id = m.organization_id
     WHERE m.user_id = ? ORDER BY o.created_at DESC`,
  ).bind(identity.id).all();
  return c.json({ organizations: result.results ?? [] });
});

// Organization details with the member inventory. Any member of the org can
// see who belongs to their workspace; platform admins can inspect any org.
app.get("/v1/organizations/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  if (!access.isPlatformAdmin && !access.role) return c.json({ message: "Organization not found" }, 404);
  const organization = await c.env.DB.prepare(
    `SELECT o.id, o.name, o.slug, o.status, o.created_at AS createdAt, o.updated_at AS updatedAt,
            (SELECT COUNT(*) FROM hosting_accounts a WHERE a.organization_id = o.id AND a.status != 'DELETED') AS hostingAccountCount,
            (SELECT COUNT(*) FROM hosting_accounts a WHERE a.organization_id = o.id AND a.status = 'ACTIVE') AS activeHostingAccountCount
     FROM organizations o WHERE o.id = ? LIMIT 1`,
  ).bind(orgId).first();
  if (!organization) return c.json({ message: "Organization not found" }, 404);
  const members = await c.env.DB.prepare(
    `SELECT m.user_id AS userId, u.email, u.display_name AS displayName, u.status AS userStatus,
            m.role, m.created_at AS memberSince
     FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.organization_id = ? ORDER BY m.created_at ASC`,
  ).bind(orgId).all();
  const admins = await countOrgAdmins(c.env.DB, orgId);
  return c.json({ organization, members: members.results ?? [], owners: admins.owners, admins: admins.admins });
});

// Add an existing, active Nexora user to the organization. OWNER or ADMIN
// (or a platform admin) may invite; only OWNER may grant the OWNER role.
app.post("/v1/organizations/:id/members", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  const canManage = access.isPlatformAdmin || access.role === "OWNER" || access.role === "ADMIN";
  if (!canManage) return c.json({ message: "Organization administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const email = normalizeEmail(input.email);
  const role = typeof input.role === "string" ? input.role : "MEMBER";
  const allowedRoles: Role[] = ["OWNER", "ADMIN", "BILLING", "SUPPORT", "MEMBER"];
  if (!validEmail(email)) return c.json({ message: "Enter a valid user email address." }, 400);
  if (!allowedRoles.includes(role as Role)) return c.json({ message: "Select a valid organization role." }, 400);
  if (role === "OWNER" && !access.isPlatformAdmin && access.role !== "OWNER") {
    return c.json({ message: "Only an organization owner can grant owner access." }, 403);
  }
  const organization = await c.env.DB.prepare(
    "SELECT id, status FROM organizations WHERE id = ? LIMIT 1",
  ).bind(orgId).first<{ id: string; status: string }>();
  if (!organization) return c.json({ message: "Organization not found" }, 404);
  if (organization.status !== "ACTIVE") return c.json({ message: "Members can only be added to an active organization." }, 409);
  const user = await c.env.DB.prepare(
    "SELECT id, email FROM users WHERE email = ? COLLATE NOCASE AND status = 'ACTIVE' LIMIT 1",
  ).bind(email).first<{ id: string; email: string }>();
  if (!user) return c.json({ message: "No active Nexora login exists for that email. Ask the user to register first." }, 404);
  const existing = await c.env.DB.prepare(
    "SELECT role FROM memberships WHERE user_id = ? AND organization_id = ? LIMIT 1",
  ).bind(user.id, orgId).first<{ role: Role }>();
  if (existing) return c.json({ message: "This user is already a member of the organization." }, 409);
  const now = new Date().toISOString();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO memberships (id, user_id, organization_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
      ).bind(crypto.randomUUID(), user.id, orgId, role, now),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'organization.member_added', 'membership', ?, ?)",
      ).bind(crypto.randomUUID(), orgId, identity.id, user.id, JSON.stringify({ email: user.email, role })),
    ]);
  } catch {
    return c.json({ message: "Unable to add this member." }, 409);
  }
  return c.json({ success: true, userId: user.id, role, message: "Organization member added." }, 201);
});

// Change a member's organization role. OWNER (or platform admin) may set any
// role; ADMIN may only manage non-owner roles. The last OWNER can never be
// demoted, and the last administrator can never lose admin access.
app.patch("/v1/organizations/:id/members/:userId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const targetUserId = c.req.param("userId");
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  const canManage = access.isPlatformAdmin || access.role === "OWNER" || access.role === "ADMIN";
  if (!canManage) return c.json({ message: "Organization administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const role = typeof input.role === "string" ? input.role : "";
  const allowedRoles: Role[] = ["OWNER", "ADMIN", "BILLING", "SUPPORT", "MEMBER"];
  if (!allowedRoles.includes(role as Role)) return c.json({ message: "Select a valid organization role." }, 400);
  if (role === "OWNER" && !access.isPlatformAdmin && access.role !== "OWNER") {
    return c.json({ message: "Only an organization owner can grant owner access." }, 403);
  }
  const target = await c.env.DB.prepare(
    `SELECT m.role AS currentRole, u.email FROM memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.user_id = ? AND m.organization_id = ? LIMIT 1`,
  ).bind(targetUserId, orgId).first<{ currentRole: Role; email: string }>();
  if (!target) return c.json({ message: "Membership not found in this organization." }, 404);
  if (target.currentRole === role) return c.json({ success: true, message: "Member already has that role." });
  const admins = await countOrgAdmins(c.env.DB, orgId);
  if (target.currentRole === "OWNER" && role !== "OWNER" && (admins.owners ?? 0) <= 1) {
    return c.json({ message: "The last organization owner cannot be demoted. Grant owner access to another member first." }, 409);
  }
  const stillAdminAfter = (admins.admins ?? 0)
    - (target.currentRole === "ADMIN" || target.currentRole === "OWNER" ? 1 : 0)
    + (role === "ADMIN" || role === "OWNER" ? 1 : 0);
  if ((target.currentRole === "OWNER" || target.currentRole === "ADMIN") && role !== "OWNER" && role !== "ADMIN" && stillAdminAfter < 1) {
    return c.json({ message: "The organization must keep at least one owner or administrator." }, 409);
  }
  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE memberships SET role = ? WHERE user_id = ? AND organization_id = ?",
    ).bind(role, targetUserId, orgId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'organization.member_role_changed', 'membership', ?, ?)",
    ).bind(crypto.randomUUID(), orgId, identity.id, targetUserId, JSON.stringify({ email: target.email, previousRole: target.currentRole, newRole: role })),
  ]);
  return c.json({ success: true, userId: targetUserId, role, message: "Organization role updated." });
});

// Revoke an organization membership. The last OWNER and the last active
// administrator can never be removed. Revocation also invalidates the
// member's sessions scoped to this organization so cached access ends
// immediately. Members may leave on their own (self-removal) unless they
// are the last owner/administrator.
app.delete("/v1/organizations/:id/members/:userId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const targetUserId = c.req.param("userId");
  const selfRemoval = targetUserId === identity.id;
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  if (!selfRemoval && !(access.isPlatformAdmin || access.role === "OWNER" || access.role === "ADMIN")) {
    return c.json({ message: "Organization administrator access required" }, 403);
  }
  const target = await c.env.DB.prepare(
    `SELECT m.role AS role, u.email FROM memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.user_id = ? AND m.organization_id = ? LIMIT 1`,
  ).bind(targetUserId, orgId).first<{ role: Role; email: string }>();
  if (!target) return c.json({ message: "Membership not found in this organization." }, 404);
  const admins = await countOrgAdmins(c.env.DB, orgId);
  if (target.role === "OWNER" && (admins.owners ?? 0) <= 1) {
    return c.json({ message: "The last organization owner cannot be removed. Grant owner access to another member first." }, 409);
  }
  if ((target.role === "OWNER" || target.role === "ADMIN") && (admins.admins ?? 0) <= 1) {
    return c.json({ message: "The organization must keep at least one owner or administrator." }, 409);
  }
  await c.env.DB.batch([
    c.env.DB.prepare(
      "DELETE FROM memberships WHERE user_id = ? AND organization_id = ?",
    ).bind(targetUserId, orgId),
    c.env.DB.prepare(
      "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND organization_id = ? AND revoked_at IS NULL",
    ).bind(new Date().toISOString(), targetUserId, orgId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'organization.member_removed', 'membership', ?, ?)",
    ).bind(crypto.randomUUID(), orgId, identity.id, targetUserId, JSON.stringify({ email: target.email, previousRole: target.role, selfRemoval, sessionsRevoked: true })),
  ]);
  return c.json({ success: true, message: "Membership revoked. The member's sessions for this organization were invalidated." });
});

// Close an organization. This is a soft deletion: hosting accounts, payment
// orders, and subscriptions reference the organization with restrictive
// foreign keys, so history is preserved and the workspace is closed instead.
// Closing requires no active hosting resources, no open payment orders, and
// no live subscriptions. All member sessions for the org are invalidated.
app.delete("/v1/organizations/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  if (!access.isPlatformAdmin && access.role !== "OWNER") {
    return c.json({ message: "Organization owner access required" }, 403);
  }
  const organization = await c.env.DB.prepare(
    "SELECT id, name, status FROM organizations WHERE id = ? LIMIT 1",
  ).bind(orgId).first<{ id: string; name: string; status: string }>();
  if (!organization) return c.json({ message: "Organization not found" }, 404);
  if (organization.status === "CLOSED") return c.json({ message: "This organization is already closed." }, 409);
  const hostingAccounts = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM hosting_accounts WHERE organization_id = ? AND status NOT IN ('DELETED')",
  ).bind(orgId).first<{ count: number }>();
  if ((hostingAccounts?.count ?? 0) > 0) {
    return c.json({ message: `This organization still has ${hostingAccounts?.count} hosting account(s). Cancel every hosting account before closing.` }, 409);
  }
  const openOrders = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM payment_orders WHERE organization_id = ? AND status IN ('AWAITING_PAYMENT','RECEIPT_SUBMITTED','UNDER_REVIEW','PROVISIONING')",
  ).bind(orgId).first<{ count: number }>();
  if ((openOrders?.count ?? 0) > 0) {
    return c.json({ message: `This organization has ${openOrders?.count} open payment order(s). Resolve them before closing.` }, 409);
  }
  const liveSubscriptions = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM subscriptions WHERE organization_id = ? AND status IN ('TRIALING','ACTIVE','PAST_DUE')",
  ).bind(orgId).first<{ count: number }>();
  if ((liveSubscriptions?.count ?? 0) > 0) {
    return c.json({ message: `This organization has ${liveSubscriptions?.count} live subscription(s). Cancel them before closing.` }, 409);
  }
  const now = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE organizations SET status = 'CLOSED', updated_at = ? WHERE id = ? AND status != 'CLOSED'",
    ).bind(now, orgId),
    c.env.DB.prepare(
      "UPDATE auth_sessions SET revoked_at = ? WHERE organization_id = ? AND revoked_at IS NULL",
    ).bind(now, orgId),
    c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'organization.closed', 'organization', ?, ?)",
    ).bind(crypto.randomUUID(), orgId, identity.id, orgId, JSON.stringify({ name: organization.name })),
  ]);
  return c.json({ success: true, message: "Organization closed. All member sessions were invalidated." });
});

// Organization audit history. Owners/admins (or platform admins) can read
// the audit trail scoped to their organization.
app.get("/v1/organizations/:id/audit-logs", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const orgId = c.req.param("id");
  const access = await resolveOrgAccess(c.env.DB, identity.id, orgId, identity.platformRole);
  if (!(access.isPlatformAdmin || access.role === "OWNER" || access.role === "ADMIN")) {
    return c.json({ message: "Organization administrator access required" }, 403);
  }
  const limitRaw = Number(c.req.query("limit"));
  const limit = Number.isInteger(limitRaw) && limitRaw >= 1 && limitRaw <= 200 ? limitRaw : 50;
  const result = await c.env.DB.prepare(
    `SELECT a.id, a.action, a.resource_type AS resourceType, a.resource_id AS resourceId,
            a.metadata, a.created_at AS createdAt, u.email AS actorEmail
     FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE a.organization_id = ? ORDER BY a.created_at DESC LIMIT ?`,
  ).bind(orgId, limit).all();
  return c.json({ events: result.results ?? [] });
});

// ---------------------------------------------------------------------------
// Backup scheduling. Per-account schedule for automated backups.
// ---------------------------------------------------------------------------

app.get("/v1/hosting-accounts/:id/backup-schedule", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  const schedule = await c.env.DB.prepare("SELECT frequency, retention_count AS retentionCount, next_run_at AS nextRunAt, last_run_at AS lastRunAt, updated_at AS updatedAt FROM backup_schedules WHERE hosting_account_id = ? LIMIT 1").bind(accountId).first<{ frequency: string; retentionCount: number; nextRunAt: string | null; lastRunAt: string | null; updatedAt: string }>();
  if (!schedule) return c.json({ frequency: "weekly", retentionCount: 4, nextRunAt: null, lastRunAt: null, updatedAt: null });
  return c.json(schedule);
});

app.put("/v1/hosting-accounts/:id/backup-schedule", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const accountId = c.req.param("id");
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Hosting account not found" }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const frequency = typeof input.frequency === "string" && ["daily","weekly","monthly","disabled"].includes(input.frequency) ? input.frequency : "weekly";
  const retentionCount = Number(input.retentionCount);
  if (!Number.isInteger(retentionCount) || retentionCount < 1 || retentionCount > 52) return c.json({ message: "Retention count must be between 1 and 52" }, 400);
  // For monthly schedules, capture the anchor day (1-31) from the current
  // UTC date. This preserves the original intended day-of-month across
  // short-month clamping: a schedule created on Jan 31 always targets day
  // 31, so Feb clamps to 28, March expands back to 31. Without the anchor,
  // computing next_run from the execution date causes permanent drift
  // (Jan 31 → Feb 28 → March 28 → April 28 → ...).
  const anchorDayOfMonth = frequency === "monthly" ? new Date().getUTCDate() : null;
  await c.env.DB.batch([
    c.env.DB.prepare("INSERT INTO backup_schedules (hosting_account_id, frequency, retention_count, anchor_day_of_month, updated_at) VALUES (?, ?, ?, ?, datetime('now')) ON CONFLICT(hosting_account_id) DO UPDATE SET frequency = excluded.frequency, retention_count = excluded.retention_count, anchor_day_of_month = excluded.anchor_day_of_month, updated_at = datetime('now')").bind(accountId, frequency, retentionCount, anchorDayOfMonth),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'backup_schedule.updated', 'hosting_account', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, accountId, JSON.stringify({ frequency, retentionCount, anchorDayOfMonth })),
  ]);
  return c.json({ success: true, message: "Backup schedule updated." });
});

type DomainRecord = { id: string; name: string; document_root: string; is_primary: number; created_at: string; hosting_account_id: string; username: string; account_status: string; server_hostname: string; job_status: string | null };
app.get("/v1/domains/:id/dns-check", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const domain = await c.env.DB.prepare(
    `SELECT d.id, d.name, s.primary_ip
     FROM domains d
     JOIN hosting_accounts a ON a.id = d.hosting_account_id
     JOIN servers s ON s.id = a.server_id
     WHERE d.id = ? AND a.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; name: string; primary_ip: string }>();
  if (!domain) return c.json({ message: "Domain not found" }, 404);

  const name = domain.name.toLowerCase();
  const ip = domain.primary_ip;
  const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip);
  const isPublicIPv4 = isIPv4 && (() => {
    const octets = ip.split(".").map(Number);
    if (octets.some((part) => part < 0 || part > 255)) return false;
    const [a, b] = octets;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)));
  })();
  const reservedTest = name.endsWith(".test") || name.endsWith(".localhost") || name.endsWith(".invalid");
  if (reservedTest) return c.json({
    domain: name, status: "NOT_PUBLIC_DOMAIN", expectedAddress: ip,
    isPublicAddress: isPublicIPv4,
    records: [{ type: "A", name: "@", value: ip }],
    message: "This is a reserved testing domain. It cannot be verified through public DNS or issued a publicly trusted SSL certificate.",
  });
  if (!isPublicIPv4) return c.json({
    domain: name, status: "SERVER_IP_NOT_PUBLIC", expectedAddress: ip,
    isPublicAddress: false,
    records: [{ type: "A", name: "@", value: ip }],
    message: "The registered server address is not a public IPv4 address. Assign a public IP before configuring public DNS.",
  });

  try {
    const response = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=A", {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(6000),
    });
    if (!response.ok) throw new Error("DNS resolver returned HTTP " + response.status);
    const answer = await response.json() as { Answer?: Array<{ type?: number; data?: string }> };
    const addresses = (answer.Answer ?? []).filter((record) => record.type === 1 && typeof record.data === "string").map((record) => record.data as string);
    const verified = addresses.includes(ip);
    return c.json({
      domain: name, status: verified ? "VERIFIED" : "PENDING",
      expectedAddress: ip, observedAddresses: addresses, isPublicAddress: true,
      records: [{ type: "A", name: "@", value: ip }],
      message: verified ? "The domain resolves to this server." : "Create or update the A record to point to the server IP, then check again.",
    });
  } catch {
    return c.json({
      domain: name, status: "CHECK_FAILED", expectedAddress: ip,
      isPublicAddress: true, records: [{ type: "A", name: "@", value: ip }],
      message: "The public DNS lookup could not be completed. Try again shortly.",
    }, 502);
  }
});

app.get("/v1/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    "SELECT d.id, d.name, d.document_root, d.is_primary, d.created_at, d.cloudflare_custom_hostname_id, d.cloudflare_hostname_status, d.cloudflare_ssl_status, d.cloudflare_cname_target, d.cloudflare_error, a.id AS hosting_account_id, a.username, a.status AS account_status, s.hostname AS server_hostname, " +
    "(SELECT j.status FROM provisioning_jobs j WHERE j.idempotency_key = 'add-domain:' || d.id AND j.operation = 'ADD_DOMAIN' LIMIT 1) AS job_status " +
    "FROM domains d JOIN hosting_accounts a ON a.id = d.hosting_account_id JOIN servers s ON s.id = a.server_id " +
    "WHERE a.organization_id = ? AND d.status = 'ACTIVE' ORDER BY d.created_at DESC",
  ).bind(identity.organizationId).all<DomainRecord>();
  return c.json({ domains: result.results ?? [] });
});
app.post("/v1/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const accountId = typeof input.accountId === "string" ? input.accountId : "";
  const name = typeof input.name === "string" ? input.name.trim().toLowerCase() : "";
  const account = await c.env.DB.prepare(
    `SELECT a.id, a.username, a.status, p.website_limit,
            (SELECT COUNT(*) FROM domains d WHERE d.hosting_account_id = a.id) AS website_count
     FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.id = ? AND a.organization_id = ? AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(accountId, identity.organizationId).first<{ id: string; username: string; status: string; website_limit: number; website_count: number }>();
  if (!account) return c.json({ message: "Select an active hosting account in this workspace before adding a domain." }, 404);
  if (account.website_count >= account.website_limit) return c.json({ message: "This hosting plan has reached its website limit." }, 409);
  if (!validDomain(name)) return c.json({ message: "Enter a valid domain name, such as example.com." }, 400);
  const suppliedRoot = typeof input.documentRoot === "string" ? input.documentRoot.trim() : "";
  const accountWebRoot = "/home/" + account.username + "/public_html";
  const root = suppliedRoot || accountWebRoot + "/" + name;
  if (!(root === accountWebRoot || root.startsWith(accountWebRoot + "/")) || root.includes("..") || root.length > 240 ||
      !/^\/home\/[a-z][a-z0-9_]{2,15}\/public_html(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/.test(root)) {
    return c.json({ message: "Document root must be inside this account's public_html directory and cannot contain hidden or unsafe path components." }, 400);
  }
  const id = crypto.randomUUID(); const jobId = crypto.randomUUID(); const primary = input.isPrimary === true;
  const statements = [];
  if (primary) statements.push(c.env.DB.prepare("UPDATE domains SET is_primary = 0 WHERE hosting_account_id = ?").bind(account.id));
  statements.push(c.env.DB.prepare("INSERT INTO domains (id, hosting_account_id, name, document_root, is_primary) VALUES (?, ?, ?, ?, ?)").bind(id, account.id, name, root, primary ? 1 : 0));
  statements.push(c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'ADD_DOMAIN', 'QUEUED', ?)").bind(jobId, account.id, "add-domain:" + id));
  statements.push(c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'domain.create_requested', 'domain', ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, id));
  if (primary) {
    statements.push(c.env.DB.prepare("UPDATE hosting_accounts SET primary_domain = ?, updated_at = ? WHERE id = ? AND organization_id = ?")
      .bind(name, new Date().toISOString(), account.id, identity.organizationId));
  }
  try { await c.env.DB.batch(statements); }
  catch (error) { const message = error instanceof Error ? error.message : ""; if (/UNIQUE constraint failed: domains.name/i.test(message)) return c.json({ message: "This domain is already registered." }, 409); return c.json({ message: "Unable to save this domain." }, 500); }
  return c.json({ domain: { id, name, document_root: root, is_primary: primary ? 1 : 0, hosting_account_id: account.id, username: account.username, account_status: account.status }, provisioningJob: { id: jobId, status: "QUEUED" }, message: "Domain saved. Server configuration is queued and awaits a connected Linux agent." }, 201);
});


type CloudflareHostnameResponse = {
  success?: boolean;
  errors?: Array<{ message?: string }>;
  result?: {
    id?: string;
    hostname?: string;
    status?: string;
    ssl?: {
      status?: string;
      method?: string;
      type?: string;
      settings?: Record<string, unknown>;
      validation_records?: unknown[];
      validation_errors?: unknown[];
    };
    ownership_verification?: { name?: string; type?: string; value?: string };
    ownership_verification_http?: { http_url?: string; http_body?: string };
    verification_errors?: string[];
  };
};

async function cloudflareHostnameRequest(
  env: Bindings,
  hostnameId: string | null,
  method: "GET" | "POST" | "PATCH",
  body?: Record<string, unknown>,
): Promise<CloudflareHostnameResponse> {
  if (!env.CLOUDFLARE_API_TOKEN || !env.CLOUDFLARE_ZONE_ID) {
    throw new Error("Cloudflare custom hostname integration is not configured. Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID as Worker secrets.");
  }
  const endpoint = hostnameId
    ? `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(env.CLOUDFLARE_ZONE_ID)}/custom_hostnames/${encodeURIComponent(hostnameId)}`
    : `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(env.CLOUDFLARE_ZONE_ID)}/custom_hostnames`;
  const response = await fetch(endpoint, {
    method,
    headers: {
      authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      accept: "application/json",
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000),
  });
  const payload = await response.json() as CloudflareHostnameResponse;
  if (!response.ok || payload.success !== true || !payload.result) {
    const detail = payload.errors?.map((item) => item.message).filter(Boolean).join("; ");
    throw new Error(detail || `Cloudflare API returned HTTP ${response.status}`);
  }
  return payload;
}

async function saveCloudflareHostnameState(
  db: D1Database,
  domainId: string,
  response: CloudflareHostnameResponse,
  target: string,
) {
  const result = response.result!;
  const validation = {
    ownershipVerification: result.ownership_verification ?? null,
    ownershipVerificationHttp: result.ownership_verification_http ?? null,
    sslValidationRecords: result.ssl?.validation_records ?? [],
    sslValidationErrors: result.ssl?.validation_errors ?? [],
    verificationErrors: result.verification_errors ?? [],
  };
  await db.prepare(
    `UPDATE domains SET cloudflare_custom_hostname_id = ?,
       cloudflare_hostname_status = ?, cloudflare_ssl_status = ?,
       cloudflare_validation_records = ?, cloudflare_cname_target = ?,
       cloudflare_last_checked_at = ?, cloudflare_error = NULL, updated_at = ?
     WHERE id = ?`,
  ).bind(
    result.id ?? null, result.status ?? "pending", result.ssl?.status ?? "pending",
    JSON.stringify(validation), target, new Date().toISOString(), new Date().toISOString(), domainId,
  ).run();
  return {
    id: result.id ?? null,
    hostname: result.hostname ?? null,
    hostnameStatus: result.status ?? "pending",
    sslStatus: result.ssl?.status ?? "pending",
    cnameTarget: target,
    validation,
    ready: result.status === "active" && result.ssl?.status === "active",
  };
}

app.post("/v1/domains/:id/cloudflare-hostname", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const domain = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.cloudflare_custom_hostname_id AS hostnameId,
            a.organization_id AS organizationId
     FROM domains d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     WHERE d.id = ? AND a.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; name: string; hostnameId: string | null; organizationId: string }>();
  if (!domain) return c.json({ message: "Domain not found" }, 404);

  const target = (c.env.CLOUDFLARE_SAAS_TARGET || "").trim().toLowerCase();
  if (!target) return c.json({ message: "Cloudflare for SaaS is not fully configured. Set CLOUDFLARE_SAAS_TARGET to the exact CNAME target shown in your Cloudflare for SaaS settings." }, 503);
  if (!validDomain(target)) return c.json({ message: "The configured Cloudflare SaaS CNAME target is invalid." }, 503);
  try {
    let current: CloudflareHostnameResponse;
    if (domain.hostnameId) {
      current = await cloudflareHostnameRequest(c.env, domain.hostnameId, "GET");
    } else {
      const created = await cloudflareHostnameRequest(c.env, null, "POST", {
        hostname: domain.name,
        ssl: { method: "txt", type: "dv", settings: { min_tls_version: "1.2" } },
      });
      const id = created.result?.id;
      if (!id) throw new Error("Cloudflare created the hostname but did not return its identifier.");
      // Persist the identifier before the follow-up GET so a transient read failure
      // cannot cause a retry to create a duplicate custom hostname.
      await c.env.DB.prepare(
        "UPDATE domains SET cloudflare_custom_hostname_id = ?, cloudflare_hostname_status = ?, cloudflare_ssl_status = ?, cloudflare_cname_target = ?, cloudflare_last_checked_at = ?, cloudflare_error = NULL WHERE id = ?",
      ).bind(id, created.result?.status ?? "pending", created.result?.ssl?.status ?? "pending", target, new Date().toISOString(), domain.id).run();
      // Cloudflare may omit validation records from POST; retrieve the full record.
      current = await cloudflareHostnameRequest(c.env, id, "GET");
    }
    const state = await saveCloudflareHostnameState(c.env.DB, domain.id, current, target);
    let dnsProvisioning: Awaited<ReturnType<typeof ensureSaasDnsRecord>>;
    try {
      dnsProvisioning = await ensureSaasDnsRecord(c.env, domain.name, target);
    } catch (dnsError) {
      dnsProvisioning = { status: "MANUAL_REQUIRED", hostname: domain.name, target, message: dnsError instanceof Error ? dnsError.message : "DNS automation failed" };
    }
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.cloudflare_hostname_synced', 'domain', ?, ?)",
    ).bind(crypto.randomUUID(), identity.organizationId, identity.id, domain.id, JSON.stringify({ hostnameStatus: state.hostnameStatus, sslStatus: state.sslStatus })).run();
    return c.json({ cloudflare: state, dnsProvisioning, message: state.ready ? "Hostname and SSL certificate are active." : "Cloudflare hostname registered. Complete any required DNS validation, then refresh its status." }, domain.hostnameId ? 200 : 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Cloudflare hostname operation failed";
    await c.env.DB.prepare("UPDATE domains SET cloudflare_error = ?, cloudflare_last_checked_at = ? WHERE id = ?")
      .bind(message.slice(0, 500), new Date().toISOString(), domain.id).run();
    return c.json({ message }, 502);
  }
});

app.get("/v1/domains/:id/cloudflare-hostname", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const domain = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.cloudflare_custom_hostname_id AS hostnameId,
            d.cloudflare_cname_target AS cnameTarget, d.cloudflare_error AS cloudflareError
     FROM domains d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     WHERE d.id = ? AND a.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; name: string; hostnameId: string | null; cnameTarget: string | null; cloudflareError: string | null }>();
  if (!domain) return c.json({ message: "Domain not found" }, 404);
  if (!domain.hostnameId) return c.json({ cloudflare: { hostnameStatus: "NOT_CREATED", sslStatus: "NOT_CREATED", cnameTarget: c.env.CLOUDFLARE_SAAS_TARGET || "customers.nexoraedge.digital", error: domain.cloudflareError } });
  try {
    const current = await cloudflareHostnameRequest(c.env, domain.hostnameId, "GET");
    const state = await saveCloudflareHostnameState(c.env.DB, domain.id, current, domain.cnameTarget || c.env.CLOUDFLARE_SAAS_TARGET || "customers.nexoraedge.digital");
    return c.json({ cloudflare: state });
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to refresh Cloudflare status" }, 502);
  }
});

app.post("/v1/domains/:id/cloudflare-hostname/revalidate", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  const domain = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.cloudflare_custom_hostname_id AS hostnameId,
            d.cloudflare_cname_target AS cnameTarget
     FROM domains d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     WHERE d.id = ? AND a.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{
    id: string; name: string; hostnameId: string | null; cnameTarget: string | null;
  }>();
  if (!domain) return c.json({ message: "Domain not found" }, 404);
  if (!domain.hostnameId) return c.json({ message: "Register the Cloudflare hostname before revalidating its certificate." }, 409);

  try {
    // Read the live SSL configuration first. PATCH must echo the existing method,
    // certificate type and settings so revalidation does not reset customer TLS options.
    const before = await cloudflareHostnameRequest(c.env, domain.hostnameId, "GET");
    const ssl = before.result?.ssl;
    if (!ssl?.method || !ssl.type) {
      throw new Error("Cloudflare did not return the current SSL method and certificate type; no settings were changed.");
    }
    const sslPatch: Record<string, unknown> = { method: ssl.method, type: ssl.type };
    if (ssl.settings !== undefined) sslPatch.settings = ssl.settings;

    await cloudflareHostnameRequest(c.env, domain.hostnameId, "PATCH", { ssl: sslPatch });
    const after = await cloudflareHostnameRequest(c.env, domain.hostnameId, "GET");
    const target = domain.cnameTarget || c.env.CLOUDFLARE_SAAS_TARGET || "customers.nexoraedge.digital";
    const state = await saveCloudflareHostnameState(c.env.DB, domain.id, after, target);

    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.cloudflare_certificate_revalidated', 'domain', ?, ?)",
    ).bind(
      crypto.randomUUID(), identity.organizationId, identity.id, domain.id,
      JSON.stringify({ hostnameStatus: state.hostnameStatus, sslStatus: state.sslStatus }),
    ).run();

    return c.json({
      cloudflare: state,
      message: state.sslStatus === "active"
        ? "Cloudflare reports the SSL certificate as active."
        : "Cloudflare revalidation was triggered. The certificate is still processing; refresh status again in a few minutes.",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Cloudflare certificate revalidation failed";
    await c.env.DB.prepare("UPDATE domains SET cloudflare_error = ?, cloudflare_last_checked_at = ? WHERE id = ?")
      .bind(message.slice(0, 500), new Date().toISOString(), domain.id).run();
    return c.json({ message }, 502);
  }
});

app.post("/v1/domains/:id/retry", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  const domainId = c.req.param("id");
  const domain = await c.env.DB.prepare(
    `SELECT d.id, d.name, a.id AS account_id, a.server_id
     FROM domains d
     JOIN hosting_accounts a ON a.id = d.hosting_account_id
     WHERE d.id = ? AND a.organization_id = ? AND a.status = 'ACTIVE'
     LIMIT 1`,
  ).bind(domainId, identity.organizationId).first<{ id: string; name: string; account_id: string; server_id: string }>();
  if (!domain) return c.json({ message: "Domain or active hosting account not found" }, 404);

  const idempotencyKey = "add-domain:" + domain.id;
  const job = await c.env.DB.prepare(
    "SELECT id, status FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'ADD_DOMAIN' AND idempotency_key = ? LIMIT 1",
  ).bind(domain.account_id, idempotencyKey).first<{ id: string; status: string }>();

  const now = new Date().toISOString();
  let jobId = job?.id ?? "";
  if (!job) {
    jobId = crypto.randomUUID();
    await c.env.DB.prepare(
      "INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'ADD_DOMAIN', 'QUEUED', ?)",
    ).bind(jobId, domain.account_id, idempotencyKey).run();
  } else {
    if (job.status !== "FAILED") return c.json({ message: "Only failed or missing domain setup can be queued again", status: job.status }, 409);
    const update = await c.env.DB.prepare(
      `UPDATE provisioning_jobs
       SET status = 'QUEUED', attempts = 0, started_at = NULL, finished_at = NULL,
           lease_expires_at = NULL, claimed_by_node_id = NULL,
           error_code = NULL, error_message = NULL, requested_at = ?
       WHERE id = ? AND status = 'FAILED'`,
    ).bind(now, job.id).run();
    if ((update.meta?.changes ?? 0) !== 1) return c.json({ message: "Job status changed; refresh and try again" }, 409);
  }

  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.provisioning_retried', 'domain', ?, ?)",
  ).bind(crypto.randomUUID(), identity.organizationId, identity.id, domain.id, JSON.stringify({ jobId, created: !job })).run();

  return c.json({ domainId: domain.id, jobId, status: "QUEUED", message: "Domain website configuration has been queued for the connected Linux agent." });
});

app.delete("/v1/domains/:id", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);
  const domainId = c.req.param("id");
  const domain = await c.env.DB.prepare(
    "SELECT d.id, d.name, d.is_primary AS isPrimary, d.status, a.id AS accountId, a.status AS accountStatus FROM domains d JOIN hosting_accounts a ON a.id = d.hosting_account_id WHERE d.id = ? AND a.organization_id = ? LIMIT 1",
  ).bind(domainId, identity.organizationId).first<{ id: string; name: string; isPrimary: number; status: string; accountId: string; accountStatus: string }>();
  if (!domain) return c.json({ message: "Domain not found in this workspace." }, 404);
  if (domain.status === "DELETED") return c.json({ message: "Domain is already deleted." }, 409);
  if (domain.isPrimary === 1) return c.json({ message: "The primary domain cannot be removed. Set another domain as primary first." }, 409);
  const jobId = crypto.randomUUID();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE domains SET status = 'DELETED', updated_at = datetime('now') WHERE id = ? AND status != 'DELETED'").bind(domainId),
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'REMOVE_DOMAIN', 'QUEUED', ?)").bind(jobId, domain.accountId, `remove-domain:${domainId}`),
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'domain.deleted', 'domain', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, domainId, JSON.stringify({ name: domain.name, jobId })),
  ]);
  return c.json({ success: true, domainId, jobId, status: "DELETED", message: "Domain removal queued." });
});

type HostingDatabaseRow = {
  id: string; name: string; engine: string; status: string; created_at: string;
  hosting_account_id: string; account_username: string; plan_database_limit: number; users: number;
  used_bytes: number | null; usage_collected_at: string | null;
};
app.get("/v1/databases", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.engine, d.status, d.created_at, d.hosting_account_id,
            a.username AS account_username, p.database_limit AS plan_database_limit,
            (SELECT COUNT(*) FROM hosting_database_users u WHERE u.database_id = d.id AND u.status != 'REVOKED') AS users,
            du.used_bytes, du.collected_at AS usage_collected_at
     FROM hosting_databases d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     JOIN hosting_plans p ON p.id = a.plan_id
     LEFT JOIN database_usage du ON du.database_id = d.id
     WHERE d.organization_id = ? AND d.status != 'DELETED' ORDER BY d.created_at DESC`,
  ).bind(identity.organizationId).all<HostingDatabaseRow>();
  return c.json({ databases: result.results ?? [] });
});

app.post("/v1/databases", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const accountId = typeof input.accountId === "string" ? input.accountId : "";
  const requestedName = typeof input.name === "string" ? input.name.toLowerCase() : "";
  if (!accountId || !/^[a-z][a-z0-9_]{1,30}$/.test(requestedName)) {
    return c.json({ message: "Choose a hosting account and a database name using 2–31 lowercase letters, numbers, or underscores." }, 400);
  }

  const account = await c.env.DB.prepare(
    "SELECT a.id, a.username, a.server_id AS serverId, p.database_limit AS databaseLimit FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id WHERE a.id = ? AND a.organization_id = ? AND a.status = 'ACTIVE' LIMIT 1",
  ).bind(accountId, identity.organizationId).first<{ id: string; username: string; serverId: string; databaseLimit: number }>();
  if (!account) return c.json({ message: "The selected hosting account is not active or does not belong to this workspace." }, 404);
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(account.username)) {
    return c.json({ message: "The hosting account username is invalid." }, 409);
  }
  const databaseName = `${account.username}_${requestedName}`;
  if (!/^[a-z][a-z0-9_]{1,63}$/.test(databaseName) || databaseName.length > 64) {
    return c.json({ message: "The generated database name is invalid or too long." }, 400);
  }

  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) AS count FROM hosting_databases WHERE hosting_account_id = ? AND status != 'DELETED'",
  ).bind(account.id).first<{ count: number }>();
  if ((count?.count ?? 0) >= account.databaseLimit) {
    return c.json({ message: "This hosting account has reached its database limit." }, 409);
  }

  const databaseId = crypto.randomUUID();

  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();
  const payload = JSON.stringify({ databaseId, databaseName });
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO hosting_databases (id, organization_id, hosting_account_id, name, engine, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'MARIADB', 'PENDING', ?, ?)",
      ).bind(databaseId, identity.organizationId, account.id, databaseName, now, now),
      c.env.DB.prepare(
        "INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'CREATE_DATABASE', 'QUEUED', ?, ?)",
      ).bind(jobId, account.id, "create-database:" + databaseId, payload),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database.provisioning_queued', 'database', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, databaseId, JSON.stringify({ hostingAccountId: account.id, jobId })),
    ]);
  } catch {
    return c.json({ message: "Unable to queue database provisioning. Refresh and try again." }, 409);
  }
  return c.json({ databaseId, jobId, status: "PENDING", name: databaseName, engine: "MARIADB", message: "Database creation has been queued for the connected Linux agent." }, 202);
});

app.post("/v1/databases/:id/delete", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const database = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.status, d.hosting_account_id AS accountId,
            a.username AS accountUsername, a.server_id AS serverId
     FROM hosting_databases d
     JOIN hosting_accounts a ON a.id = d.hosting_account_id AND a.organization_id = d.organization_id
     WHERE d.id = ? AND d.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId)
    .first<{ id: string; name: string; status: string; accountId: string; accountUsername: string; serverId: string }>();
  if (!database) return c.json({ message: "Database not found." }, 404);
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(database.accountUsername) ||
      !/^[a-z][a-z0-9_]{1,63}$/.test(database.name) || database.name.length > 64 ||
      !database.name.startsWith(database.accountUsername + "_") ||
      database.name.length <= database.accountUsername.length + 1) {
    return c.json({ message: "The database name does not belong to its hosting account." }, 409);
  }
  if (database.status === "DELETED") return c.json({ message: "This database has already been deleted." }, 409);
  const existingDelete = await c.env.DB.prepare(
    "SELECT id, status FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'DELETE_DATABASE' AND json_extract(request_payload, '$.databaseName') = ? ORDER BY requested_at DESC LIMIT 1",
  ).bind(database.accountId, database.name).first<{ id: string; status: string }>();
  if (database.status === "DELETING" && existingDelete && ["QUEUED", "RUNNING"].includes(existingDelete.status)) {
    return c.json({ databaseId: database.id, jobId: existingDelete.id, status: "DELETING", message: "Database deletion is already in progress." }, 202);
  }
  if (!["ACTIVE", "FAILED", "DELETING"].includes(database.status)) {
    return c.json({ message: "Only an active or failed database can be deleted." }, 409);
  }
  const usersResult = await c.env.DB.prepare(
    "SELECT username, status FROM hosting_database_users WHERE database_id = ? AND organization_id = ?",
  ).bind(database.id, identity.organizationId).all<{ username: string; status: string }>();
  const dbUsers = usersResult.results ?? [];
  if (dbUsers.some((u) => u.status === "PENDING" || u.status === "REVOKING")) {
    return c.json({ message: "Wait for pending user creation or revocation to finish before deleting this database." }, 409);
  }
  const prefix = database.accountUsername + "_";
  const databaseUserNames: string[] = [];
  for (const user of dbUsers) {
    if (user.status === "REVOKED") continue;
    if (!user.username.startsWith(prefix)) {
      return c.json({ message: "A stored database username does not belong to this hosting account. Deletion was blocked." }, 409);
    }
    const suffix = user.username.slice(prefix.length);
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(suffix) || user.username.length > 80) {
      return c.json({ message: "A stored database username is invalid. Deletion was blocked." }, 409);
    }
    databaseUserNames.push(user.username);
  }
  if (databaseUserNames.length > 100) return c.json({ message: "This database has too many users for a safe deletion request." }, 409);
  const activeJobs = await c.env.DB.prepare(
    `SELECT id FROM provisioning_jobs
     WHERE hosting_account_id = ? AND status IN ('QUEUED', 'RUNNING')
       AND operation IN ('CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER')
       AND json_extract(request_payload, '$.databaseName') = ? LIMIT 1`,
  ).bind(database.accountId, database.name).first<{ id: string }>();
  if (activeJobs) return c.json({ message: "A database provisioning or user-management job is still running. Refresh after it finishes." }, 409);

  const jobId = crypto.randomUUID();
  const idempotencyKey = "delete-database:" + database.id + ":" + jobId;
  const now = new Date().toISOString();
  const payload = JSON.stringify({ databaseName: database.name, databaseUserNames });
  try {
    const results = await c.env.DB.batch([
      c.env.DB.prepare(
        `UPDATE hosting_databases SET status = 'DELETING', updated_at = ?
         WHERE id = ? AND organization_id = ? AND status IN ('ACTIVE', 'FAILED', 'DELETING')
           AND NOT EXISTS (SELECT 1 FROM hosting_database_users u
             WHERE u.database_id = hosting_databases.id AND u.status IN ('PENDING', 'REVOKING'))
           AND NOT EXISTS (SELECT 1 FROM provisioning_jobs j
             WHERE j.hosting_account_id = hosting_databases.hosting_account_id
               AND j.status IN ('QUEUED', 'RUNNING')
               AND j.operation IN ('CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER')
               AND json_extract(j.request_payload, '$.databaseName') = hosting_databases.name)`,
      ).bind(now, database.id, identity.organizationId),
      c.env.DB.prepare(
        `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload)
         SELECT ?, ?, 'DELETE_DATABASE', 'QUEUED', ?, ?
         WHERE EXISTS (SELECT 1 FROM hosting_databases WHERE id = ? AND organization_id = ? AND status = 'DELETING')
           AND NOT EXISTS (SELECT 1 FROM provisioning_jobs
             WHERE hosting_account_id = ? AND operation = 'DELETE_DATABASE'
               AND status IN ('QUEUED', 'RUNNING')
               AND json_extract(request_payload, '$.databaseName') = ?)`,
      ).bind(jobId, database.accountId, idempotencyKey, payload, database.id, identity.organizationId, database.accountId, database.name),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database.deletion_queued', 'database', ?, ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, database.id, JSON.stringify({ jobId, serverId: database.serverId, databaseName: database.name, userCount: databaseUserNames.length })),
    ]);
    if ((results[0]?.meta?.changes ?? 0) !== 1 || (results[1]?.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "Database state changed or another operation is in progress. Refresh and try again." }, 409);
    }
  } catch {
    return c.json({ message: "Unable to queue database deletion. Refresh and try again." }, 409);
  }
  return c.json({ databaseId: database.id, jobId, status: "DELETING", message: "Database deletion has been queued. The database will remain listed until the server confirms deletion." }, 202);
});

app.get("/v1/databases/:id/users", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const database = await c.env.DB.prepare("SELECT id FROM hosting_databases WHERE id = ? AND organization_id = ? LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!database) return c.json({ message: "Database not found" }, 404);
  const result = await c.env.DB.prepare("SELECT u.id, u.username, u.privileges, u.status, u.created_at, EXISTS (SELECT 1 FROM database_user_secrets s WHERE s.database_user_id = u.id AND s.revealed_at IS NULL AND s.expires_at > ?) AS secret_available FROM hosting_database_users u WHERE u.database_id = ? ORDER BY u.created_at DESC").bind(new Date().toISOString(), database.id).all<{ id: string; username: string; privileges: string; status: string; created_at: string; secret_available: number }>();
  return c.json({ users: result.results ?? [] });
});

app.post("/v1/databases/:id/users", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  try { databaseSecretKey(c.env); } catch { return c.json({ message: "Secure credential delivery is not configured. No user was created." }, 503); }
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const submittedName = typeof input.username === "string" ? input.username.trim().toLowerCase() : "";
  const requestedPrivileges = Array.isArray(input.privileges) ? input.privileges : [];
  const allowed = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "INDEX"]);
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(submittedName) || requestedPrivileges.length < 1 || requestedPrivileges.length > allowed.size ||
      requestedPrivileges.some((value) => typeof value !== "string" || !allowed.has(value)) ||
      new Set(requestedPrivileges).size !== requestedPrivileges.length) {
    return c.json({ message: "Choose a valid username and one or more supported privileges." }, 400);
  }
  const database = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.hosting_account_id AS accountId, d.status, a.username AS accountUsername
     FROM hosting_databases d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     WHERE d.id = ? AND d.organization_id = ? AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(c.req.param("id"), identity.organizationId).first<{ id: string; name: string; accountId: string; status: string; accountUsername: string }>();
  if (!database || database.status !== "ACTIVE") return c.json({ message: "An active database is required." }, 404);
  const accountPrefix = database.accountUsername + "_";
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(database.accountUsername) ||
      !/^[a-z][a-z0-9_]{1,63}$/.test(database.name) ||
      database.name.length > 64 ||
      !database.name.startsWith(accountPrefix) ||
      database.name.length <= accountPrefix.length) {
    return c.json({ message: "The database name does not belong to its hosting account." }, 409);
  }
  const requestedName = submittedName.startsWith(accountPrefix) ? submittedName.slice(accountPrefix.length) : submittedName;
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(requestedName)) {
    return c.json({ message: "Enter a database username suffix such as app_user, not a full account login." }, 400);
  }
  const physicalUsername = accountPrefix + requestedName;
  if (physicalUsername.length > 80) return c.json({ message: "The resulting database username is too long." }, 400);
  const userId = crypto.randomUUID(), jobId = crypto.randomUUID(), now = new Date().toISOString();
  const payload = JSON.stringify({ databaseName: database.name, databaseUserName: requestedName, privileges: requestedPrivileges });
  try {
    const results = await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO hosting_database_users (id, organization_id, database_id, username, privileges, status, created_at)
         SELECT ?, ?, d.id, ?, ?, 'PENDING', ? FROM hosting_databases d
         WHERE d.id = ? AND d.organization_id = ? AND d.status = 'ACTIVE'`,
      ).bind(userId, identity.organizationId, physicalUsername, JSON.stringify(requestedPrivileges), now, database.id, identity.organizationId),
      c.env.DB.prepare(
        `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload)
         SELECT ?, ?, 'CREATE_DATABASE_USER', 'QUEUED', ?, ?
         WHERE EXISTS (SELECT 1 FROM hosting_database_users u JOIN hosting_databases d ON d.id = u.database_id
                       WHERE u.id = ? AND u.status = 'PENDING' AND d.status = 'ACTIVE')`,
      ).bind(jobId, database.accountId, "create-database-user:" + userId, payload, userId),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database_user.provisioning_queued', 'database_user', ?, ?)")
        .bind(crypto.randomUUID(), identity.organizationId, identity.id, userId, JSON.stringify({ databaseId: database.id, jobId, privileges: requestedPrivileges })),
    ]);
    if ((results[0]?.meta?.changes ?? 0) !== 1 || (results[1]?.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "The database is no longer active. Refresh and try again." }, 409);
    }
  } catch { return c.json({ message: "Unable to queue database-user provisioning. Check for a duplicate username." }, 409); }
  return c.json({ databaseUserId: userId, jobId, status: "PENDING", username: physicalUsername, message: "Database user creation has been queued. Its generated password will be available once, after provisioning succeeds." }, 202);
});

app.post("/v1/databases/:id/users/:userId/revoke", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const user = await c.env.DB.prepare(
    `SELECT u.id, u.username, u.status, d.name AS databaseName, d.hosting_account_id AS accountId, a.username AS accountUsername
     FROM hosting_database_users u
     JOIN hosting_databases d ON d.id = u.database_id AND d.organization_id = u.organization_id
     JOIN hosting_accounts a ON a.id = d.hosting_account_id AND a.organization_id = d.organization_id
     WHERE u.id = ? AND d.id = ? AND u.organization_id = ? AND a.status = 'ACTIVE' LIMIT 1`,
  ).bind(c.req.param("userId"), c.req.param("id"), identity.organizationId)
    .first<{ id: string; username: string; status: string; databaseName: string; accountId: string; accountUsername: string }>();
  if (!user) return c.json({ message: "Database user not found." }, 404);
  const accountPrefix = user.accountUsername + "_";
  if (!/^[a-z][a-z0-9_]{2,15}$/.test(user.accountUsername) ||
      !/^[a-z][a-z0-9_]{1,63}$/.test(user.databaseName) ||
      user.databaseName.length > 64 ||
      !user.databaseName.startsWith(accountPrefix) ||
      user.databaseName.length <= accountPrefix.length) {
    return c.json({ message: "The database name does not belong to its hosting account." }, 409);
  }
  if (user.status !== "ACTIVE") return c.json({ message: "Only an active database user can be revoked." }, 409);
  const requestedName = user.username.startsWith(user.accountUsername + "_") ? user.username.slice(user.accountUsername.length + 1) : "";
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(requestedName)) return c.json({ message: "The stored database username is invalid." }, 409);
  const jobId = crypto.randomUUID(), now = new Date().toISOString();
  try {
    const results = await c.env.DB.batch([
      c.env.DB.prepare(
        `UPDATE hosting_database_users SET status = 'REVOKING'
         WHERE id = ? AND organization_id = ? AND status = 'ACTIVE'
           AND EXISTS (SELECT 1 FROM hosting_databases d WHERE d.id = hosting_database_users.database_id AND d.status = 'ACTIVE')`,
      ).bind(user.id, identity.organizationId),
      c.env.DB.prepare(
        `INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload)
         SELECT ?, ?, 'REVOKE_DATABASE_USER', 'QUEUED', ?, ?
         WHERE EXISTS (SELECT 1 FROM hosting_database_users u JOIN hosting_databases d ON d.id = u.database_id
                       WHERE u.id = ? AND u.status = 'REVOKING' AND d.status = 'ACTIVE')`,
      ).bind(jobId, user.accountId, "revoke-database-user:" + user.id, JSON.stringify({ databaseUserName: requestedName, databaseName: user.databaseName }), user.id),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database_user.revocation_queued', 'database_user', ?, ?)")
        .bind(crypto.randomUUID(), identity.organizationId, identity.id, user.id, JSON.stringify({ jobId, databaseId: c.req.param("id") })),
    ]);
    if ((results[0]?.meta?.changes ?? 0) !== 1 || (results[1]?.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "The database is no longer active or the user state changed. Refresh and try again." }, 409);
    }
  } catch { return c.json({ message: "Unable to queue database-user revocation." }, 409); }
  return c.json({ databaseUserId: user.id, jobId, status: "REVOKING" }, 202);
});

app.get("/v1/databases/:id/users/:userId/secret", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  let secret: { ciphertext: string; iv: string } | null;
  try {
    secret = await c.env.DB.prepare(
      "UPDATE database_user_secrets SET revealed_at = ? WHERE database_user_id = ? AND organization_id = ? AND revealed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM hosting_database_users u JOIN hosting_databases d ON d.id = u.database_id WHERE u.id = database_user_secrets.database_user_id AND d.id = ? AND u.organization_id = ? AND d.status = 'ACTIVE') RETURNING ciphertext, iv",
    ).bind(new Date().toISOString(), c.req.param("userId"), identity.organizationId, new Date().toISOString(), c.req.param("id"), identity.organizationId).first<{ ciphertext: string; iv: string }>();
  } catch { return c.json({ message: "Unable to retrieve the database credential." }, 503); }
  if (!secret) return c.json({ message: "The one-time password is unavailable, expired, or has already been revealed." }, 410);
  try {
    const credential = JSON.parse(await decryptDatabaseSecret(c.env, secret.ciphertext, secret.iv)) as { username: string; password: string };
    return c.json({ credential, oneTime: true });
  } catch { return c.json({ message: "The encrypted database credential could not be opened." }, 500); }
});

// Database user password reset — generates a new password, encrypts it,
// stores it as a new one-time secret, and queues a provisioning job to
// update MySQL/MariaDB. The old secret is expired.
app.post("/v1/databases/:id/users/:userId/reset-password", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  const databaseId = c.req.param("id");
  const userId = c.req.param("userId");

  // Verify the database user exists and belongs to this org.
  const user = await c.env.DB.prepare(
    "SELECT u.id, u.username, u.database_id, d.hosting_account_id AS accountId, d.name AS databaseName " +
    "FROM hosting_database_users u JOIN hosting_databases d ON d.id = u.database_id " +
    "WHERE u.id = ? AND d.id = ? AND u.organization_id = ? AND u.status = 'ACTIVE' AND d.status = 'ACTIVE' LIMIT 1",
  ).bind(userId, databaseId, identity.organizationId).first<{ id: string; username: string; database_id: string; accountId: string; databaseName: string }>();
  if (!user) return c.json({ message: "Database user not found" }, 404);

  // Generate a new random password.
  const newPassword = generateDatabasePassword();
  const encrypted = await encryptDatabaseSecret(c.env, JSON.stringify({ username: user.username, password: newPassword })).catch(() => null);
  if (!encrypted) return c.json({ message: "Unable to encrypt the new database credential" }, 500);

  const secretId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const nowIso = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  await c.env.DB.batch([
    // Expire any existing unrevealed secrets for this user.
    c.env.DB.prepare("UPDATE database_user_secrets SET expires_at = ? WHERE database_user_id = ? AND revealed_at IS NULL AND expires_at > ?").bind(nowIso, user.id, nowIso),
    // Insert the new secret, bound to the exact job that will consume it.
    // The job_id binding lets the agent fetch the credential via
    // /internal/v1/agent/jobs/:jobId/credential — but only for the job
    // it is actually executing, never for any other job on the same user.
    c.env.DB.prepare("INSERT INTO database_user_secrets (id, database_user_id, organization_id, job_id, ciphertext, iv, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(secretId, user.id, identity.organizationId, jobId, encrypted.ciphertext, encrypted.iv, expiresAt),
    // Queue the password reset job. The payload contains only the
    // database name and username — the password itself is never placed
    // in the job payload, audit log, or any plaintext store. The agent
    // retrieves it via the authenticated credential endpoint below.
    c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'RESET_DATABASE_USER_PASSWORD', 'QUEUED', ?, ?)").bind(jobId, user.accountId, `reset-db-user:${user.id}`, JSON.stringify({ databaseName: user.databaseName, databaseUserName: user.username, jobId })),
    // Audit log — records who requested the reset and for which user,
    // but never the password itself.
    c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database.user_password_reset', 'hosting_database_user', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, user.id, JSON.stringify({ databaseId, userId: user.id, jobId })),
  ]);

  return c.json({ success: true, jobId, message: "Database user password reset queued. Use the secret reveal endpoint to retrieve the new password." }, 202);
});

// Agent credential retrieval — authenticated, short-lived, one-time.
//
// The Go agent calls this endpoint when it picks up a
// RESET_DATABASE_USER_PASSWORD job. The endpoint:
//   1. Authenticates the agent via the standard HMAC-SHA256 scheme.
//   2. Verifies the job exists, belongs to a hosting account on the
//      agent's server, is a RESET_DATABASE_USER_PASSWORD operation,
//      and is currently in QUEUED or RUNNING status.
//   3. Looks up the secret bound to that job_id.
//   4. Verifies the secret belongs to a database user in the agent's
//      organization (cross-tenant isolation).
//   5. Verifies the secret has not expired.
//   6. Atomically sets agent_revealed_at = now WHERE agent_revealed_at
//      IS NULL — replay prevention. The atomic UPDATE guarantees that
//      only one request can retrieve the credential; a second request
//      (even concurrent) receives 410 GONE.
//   7. Decrypts the credential and returns it to the agent over the
//      Cloudflare Tunnel (TLS). The credential exists in the agent's
//      memory only long enough to apply it to MariaDB.
//
// The admin's reveal endpoint (/v1/databases/:id/users/:userId/secret)
// is independent: it sets revealed_at, not agent_revealed_at. Both can
// fire in either order. The credential remains available to the admin
// for the full 15-minute window even after the agent has retrieved it.
app.post("/internal/v1/agent/jobs/:jobId/credential", async (c) => {
  const rawBody = await c.req.text();
  if (rawBody.length > 4096) return c.json({ message: "Request body is too large" }, 413);
  const auth = await authenticateAgentRequest(c.req.raw, c.env.DB, rawBody);
  if (auth.error) return c.json({ message: auth.error.message }, auth.error.status as 401 | 409);
  const jobId = c.req.param("jobId");
  if (!/^[a-f0-9-]{36}$/.test(jobId)) return c.json({ message: "Invalid job id" }, 400);

  // Pre-check for clear error messages. These checks are advisory — the
  // real security enforcement is in the atomic UPDATE below, which
  // re-verifies every condition inside the SQL WHERE clause so no TOCTOU
  // race is possible even if two requests pass the pre-check simultaneously.
  const job = await c.env.DB.prepare(
    "SELECT j.operation AS operation, j.status AS status, j.claimed_by_node_id AS claimedByNodeId, " +
    "j.hosting_account_id AS accountId, ha.server_id AS serverId, ha.organization_id AS organizationId " +
    "FROM provisioning_jobs j JOIN hosting_accounts ha ON ha.id = j.hosting_account_id " +
    "WHERE j.id = ? LIMIT 1",
  ).bind(jobId).first<{ operation: string; status: string; claimedByNodeId: string | null; accountId: string; serverId: string; organizationId: string }>();
  if (!job) return c.json({ message: "Job not found" }, 404);
  if (job.operation !== "RESET_DATABASE_USER_PASSWORD") return c.json({ message: "Job does not carry a database credential" }, 400);
  if (job.serverId !== auth.credential.serverId) return c.json({ message: "Job is not assigned to this server" }, 403);
  // The job MUST be RUNNING (claimed), not QUEUED. A QUEUED job has no
  // claimed_by_node_id, so the exact-node binding cannot be verified.
  // Returning 410 here is correct: the credential is not yet revealable.
  if (job.status !== "RUNNING") return c.json({ message: "Credential is not available for a job that has not been claimed" }, 410);
  if (job.organizationId !== auth.credential.organizationId) return c.json({ message: "Job does not belong to this organization" }, 403);
  if (job.claimedByNodeId !== auth.credential.nodeId) return c.json({ message: "Job is not claimed by this node" }, 403);

  // Atomic one-time retrieval. The UPDATE's WHERE clause enforces ALL of
  // the following in a single SQL statement — no TOCTOU race possible:
  //   - The secret is bound to this exact job_id.
  //   - The secret belongs to this organization.
  //   - The secret has not been agent-retrieved (one-time consumption).
  //   - The secret has not expired.
  //   - The job is RUNNING (not QUEUED, not COMPLETED, not FAILED).
  //   - The job's claimed_by_node_id is this exact agent's node ID.
  //   - The job belongs to a hosting account on this agent's server.
  //   - The hosting account's organization matches the secret's organization.
  //   - The database user + database are still ACTIVE (not revoked/deleted
  //     between the reset request and the agent retrieval).
  // The EXISTS subquery joins provisioning_jobs → hosting_accounts so the
  // node binding is checked at the database level, not in application
  // memory. Even if two concurrent requests from different nodes on the
  // same server both pass the pre-check above, only one can match the
  // claimed_by_node_id = ? condition in the UPDATE — the other gets zero
  // rows back and receives 410.
  const nowIso = new Date().toISOString();
  let secret: { ciphertext: string; iv: string } | null;
  try {
    secret = await c.env.DB.prepare(
      "UPDATE database_user_secrets SET agent_revealed_at = ? " +
      "WHERE job_id = ? AND organization_id = ? AND agent_revealed_at IS NULL AND expires_at > ? " +
      "AND EXISTS (SELECT 1 FROM provisioning_jobs j " +
      "  JOIN hosting_accounts ha ON ha.id = j.hosting_account_id " +
      "  WHERE j.id = database_user_secrets.job_id " +
      "  AND j.status = 'RUNNING' " +
      "  AND j.claimed_by_node_id = ? " +
      "  AND ha.server_id = ? " +
      "  AND ha.organization_id = database_user_secrets.organization_id) " +
      "AND EXISTS (SELECT 1 FROM hosting_database_users u JOIN hosting_databases d ON d.id = u.database_id " +
      "  WHERE u.id = database_user_secrets.database_user_id AND d.id = u.database_id " +
      "  AND u.organization_id = database_user_secrets.organization_id " +
      "  AND u.status = 'ACTIVE' AND d.status = 'ACTIVE') " +
      "RETURNING ciphertext, iv",
    ).bind(nowIso, jobId, auth.credential.organizationId, nowIso, auth.credential.nodeId, auth.credential.serverId).first<{ ciphertext: string; iv: string }>();
  } catch {
    return c.json({ message: "Unable to retrieve the database credential." }, 503);
  }
  if (!secret) return c.json({ message: "The database credential is unavailable, expired, already retrieved, or does not belong to this node." }, 410);

  try {
    const credential = JSON.parse(await decryptDatabaseSecret(c.env, secret.ciphertext, secret.iv)) as { username: string; password: string };
    // Audit the agent retrieval (no password in the audit row).
    await c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, 'database.secret_agent_retrieval', 'provisioning_job', ?, ?)",
    ).bind(crypto.randomUUID(), auth.credential.organizationId, jobId, JSON.stringify({ nodeId: auth.credential.nodeId })).run();
    return c.json({ credential, oneTime: true });
  } catch {
    return c.json({ message: "The encrypted database credential could not be opened." }, 500);
  }
});

type AgentCredential = { secretHash: string; serverId: string; organizationId: string };
async function authenticateAgentRequest(request: Request, db: D1Database, rawBody: string) {
  const nodeId = request.headers.get("X-Nexora-Node") ?? "";
  const timestamp = request.headers.get("X-Nexora-Timestamp") ?? "";
  const nonce = request.headers.get("X-Nexora-Nonce") ?? "";
  const signature = (request.headers.get("X-Nexora-Signature") ?? "").toLowerCase();
  if (!nodeId || !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) {
    return { error: { status: 401, message: "Missing or invalid agent authentication headers" } } as const;
  }
  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() / 1000 - requestTime) > 300) {
    return { error: { status: 401, message: "Agent request timestamp is outside the allowed five-minute window" } } as const;
  }
  const credential = await db.prepare(
    "SELECT ac.secret_hash AS secretHash, ac.server_id AS serverId, ac.organization_id AS organizationId FROM agent_credentials ac JOIN servers s ON s.id = ac.server_id AND s.organization_id = ac.organization_id WHERE ac.node_id = ? AND ac.revoked_at IS NULL LIMIT 1",
  ).bind(nodeId).first<AgentCredential>();
  if (!credential) return { error: { status: 401, message: "Agent identity is unknown or revoked" } } as const;
  const bodyHash = await sha256(rawBody);
  const path = new URL(request.url).pathname;
  const canonical = [timestamp, nonce, request.method.toUpperCase(), path, bodyHash].join("\n");
  const expected = await hmacSha256(credential.secretHash, canonical);
  if (!constantTimeEqual(expected, signature)) {
    return { error: { status: 401, message: "Agent signature is invalid" } } as const;
  }
  try {
    await db.prepare("INSERT INTO agent_nonces (node_id, nonce) VALUES (?, ?)").bind(nodeId, nonce).run();
  } catch {
    return { error: { status: 409, message: "Agent request nonce has already been used" } } as const;
  }
  // Heartbeats update last_seen_at. Do not write it on every job poll.
  return { credential: { ...credential, nodeId } } as const;
}

app.get("/v1/agent/jobs/next", async (c) => {
  const auth = await authenticateAgentRequest(c.req.raw, c.env.DB, "");
  if (auth.error) return c.json({ message: auth.error.message }, auth.error.status as 401 | 409);
  const now = new Date().toISOString();
  const leaseUntil = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const claimed = await c.env.DB.prepare(
    "UPDATE provisioning_jobs SET status = 'RUNNING', started_at = COALESCE(started_at, ?), attempts = attempts + 1, lease_expires_at = ?, claimed_by_node_id = ? " +
    "WHERE id = (SELECT j.id FROM provisioning_jobs j JOIN hosting_accounts a ON a.id = j.hosting_account_id " +
    "WHERE a.server_id = ? AND j.operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER', 'CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE', 'CREATE_BACKUP', 'RESTORE_BACKUP', 'DELETE_BACKUP', 'UPDATE_PHP_POOL', 'SUSPEND_HOSTING_ACCOUNT', 'REACTIVATE_HOSTING_ACCOUNT', 'REMOVE_DOMAIN', 'RESET_DATABASE_USER_PASSWORD') AND (j.operation NOT IN ('CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE') OR EXISTS (SELECT 1 FROM hosting_databases d WHERE d.hosting_account_id = j.hosting_account_id AND d.name = json_extract(j.request_payload, '$.databaseName') AND ((j.operation = 'CREATE_DATABASE' AND d.status = 'PENDING') OR (j.operation IN ('CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER') AND d.status = 'ACTIVE') OR (j.operation = 'DELETE_DATABASE' AND d.status = 'DELETING')))) " +
    "AND (j.status = 'QUEUED' OR (j.status = 'RUNNING' AND j.lease_expires_at < ?)) " +
    "ORDER BY j.requested_at ASC LIMIT 1) " +
    "AND (status = 'QUEUED' OR (status = 'RUNNING' AND lease_expires_at < ?)) " +
    "RETURNING id, hosting_account_id AS hostingAccountId, operation, attempts, request_payload AS requestPayload",
  ).bind(now, leaseUntil, auth.credential.nodeId, auth.credential.serverId, now, now)
    .first<{ id: string; hostingAccountId: string; operation: string; attempts: number; requestPayload: string | null }>();
  if (!claimed) return c.json({ job: null });
  if (claimed.operation === "CREATE_BACKUP") {
    const key = await c.env.DB.prepare("SELECT idempotency_key AS idempotencyKey FROM provisioning_jobs WHERE id = ? LIMIT 1").bind(claimed.id).first<{ idempotencyKey: string }>();
    const backupId = key?.idempotencyKey.split(":")[1] ?? "";
    if (backupId) await c.env.DB.prepare("UPDATE hosting_backups SET status = 'RUNNING' WHERE id = ? AND status = 'QUEUED' AND server_id = ? AND organization_id = ?").bind(backupId, auth.credential.serverId, auth.credential.organizationId).run();
  }
  const account = await c.env.DB.prepare(
    "SELECT a.id AS accountId, a.username, a.primary_domain AS primaryDomain, p.disk_limit_bytes AS diskLimitBytes, " +
    "d.name AS domain, d.document_root AS documentRoot " +
    "FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id " +
    "JOIN provisioning_jobs j ON j.id = ? AND j.hosting_account_id = a.id " +
    "LEFT JOIN domains d ON d.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = a.id AND ((j.operation = 'ADD_DOMAIN' AND d2.id = substr(j.idempotency_key, 12) AND d2.status = 'ACTIVE') OR (j.operation = 'REMOVE_DOMAIN' AND d2.id = substr(j.idempotency_key, 15) AND d2.status = 'DELETED')) LIMIT 1) " +
    "WHERE a.id = ? AND a.server_id = ? AND a.organization_id = ? " +
    "AND ((? = 'CREATE_HOSTING_ACCOUNT' AND a.status = 'PENDING') OR (? = 'ADD_DOMAIN' AND a.status = 'ACTIVE' AND d.id IS NOT NULL) OR (? = 'FILE_MANAGER' AND a.status = 'ACTIVE') OR (? = 'CREATE_DATABASE' AND a.status = 'ACTIVE') OR (? = 'CREATE_DATABASE_USER' AND a.status = 'ACTIVE') OR (? = 'REVOKE_DATABASE_USER' AND a.status = 'ACTIVE') OR (? = 'DELETE_DATABASE' AND a.status = 'ACTIVE') OR (? = 'CREATE_BACKUP' AND a.status = 'ACTIVE') OR (? = 'RESTORE_BACKUP' AND a.status = 'ACTIVE') OR (? = 'DELETE_BACKUP' AND a.status = 'ACTIVE') OR (? = 'UPDATE_PHP_POOL' AND a.status = 'ACTIVE') OR (? = 'SUSPEND_HOSTING_ACCOUNT' AND a.status = 'ACTIVE') OR (? = 'REACTIVATE_HOSTING_ACCOUNT' AND a.status = 'SUSPENDED') OR (? = 'REMOVE_DOMAIN' AND a.status = 'ACTIVE') OR (? = 'RESET_DATABASE_USER_PASSWORD' AND a.status = 'ACTIVE')) LIMIT 1",
  ).bind(claimed.id, claimed.hostingAccountId, auth.credential.serverId, auth.credential.organizationId, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation)
    .first<{ accountId: string; username: string; primaryDomain: string | null; diskLimitBytes: number; domain: string | null; documentRoot: string | null }>();
  if (!account) {
    await c.env.DB.prepare(
      "UPDATE provisioning_jobs SET status = 'FAILED', finished_at = ?, error_code = 'ACCOUNT_NOT_PROVISIONABLE', error_message = 'Hosting account is missing or not pending', request_payload = NULL, lease_expires_at = NULL WHERE id = ? AND claimed_by_node_id = ?",
    ).bind(new Date().toISOString(), claimed.id, auth.credential.nodeId).run();
    return c.json({ job: null });
  }
  let requestPayload: unknown = null;
  if (claimed.requestPayload) { try { requestPayload = JSON.parse(claimed.requestPayload); } catch { requestPayload = null; } }
  return c.json({ job: { id: claimed.id, operation: claimed.operation, attempts: claimed.attempts, leaseExpiresAt: leaseUntil, requestPayload, account } });
});

app.post("/v1/agent/jobs/:id/result", async (c) => {
  const rawBody = await c.req.text();
  if (rawBody.length > 400000) return c.json({ message: "Job result payload is too large" }, 413);
  const auth = await authenticateAgentRequest(c.req.raw, c.env.DB, rawBody);
  if (auth.error) return c.json({ message: auth.error.message }, auth.error.status as 401 | 409);
  let input: Record<string, unknown>;
  try { input = JSON.parse(rawBody) as Record<string, unknown>; }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  if (typeof input.success !== "boolean") return c.json({ message: "A boolean success result is required" }, 400);
  const errorCode = typeof input.errorCode === "string" ? input.errorCode.slice(0, 80) : null;
  const errorMessage = typeof input.errorMessage === "string" ? input.errorMessage.slice(0, 500) : null;
  const jobId = c.req.param("id");
  const pendingJob = await c.env.DB.prepare("SELECT operation, idempotency_key AS idempotencyKey FROM provisioning_jobs WHERE id = ? AND status = 'RUNNING' AND claimed_by_node_id = ? LIMIT 1")
    .bind(jobId, auth.credential.nodeId).first<{ operation: string; idempotencyKey: string }>();
  if (!pendingJob) return c.json({ message: "Provisioning job is not available to this agent." }, 409);
  const incomingResult = input.result && typeof input.result === "object" ? input.result as Record<string, unknown> : null;
  const resultPayload = pendingJob.operation === "CREATE_DATABASE_USER" ? null : (incomingResult ? JSON.stringify(incomingResult) : null);
  const now = new Date().toISOString();
  const status = input.success ? "SUCCEEDED" : "FAILED";
  const updateStatement = c.env.DB.prepare(
    "UPDATE provisioning_jobs SET status = ?, finished_at = ?, error_code = ?, error_message = ?, request_payload = NULL, result_payload = ?, lease_expires_at = NULL " +
    "WHERE id = ? AND status = 'RUNNING' AND claimed_by_node_id = ? AND lease_expires_at > ? " +
    "AND operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER', 'CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE', 'CREATE_BACKUP', 'RESTORE_BACKUP', 'DELETE_BACKUP', 'UPDATE_PHP_POOL', 'SUSPEND_HOSTING_ACCOUNT', 'REACTIVATE_HOSTING_ACCOUNT', 'REMOVE_DOMAIN', 'RESET_DATABASE_USER_PASSWORD') " +
    "AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?)",
  ).bind(status, now, input.success ? null : errorCode || "PROVISIONING_FAILED",
    input.success ? null : errorMessage || "The Linux agent could not provision this account", resultPayload,
    jobId, auth.credential.nodeId, now, auth.credential.serverId, auth.credential.organizationId);

  if (pendingJob.operation === "FILE_MANAGER") {
    const auditAction = input.success
      ? "file_manager.operation_completed"
      : "file_manager.operation_failed";

    const auditStatement = c.env.DB.prepare(
      "INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) " +
      "SELECT ?, ?, ?, 'provisioning_job', ?, ? WHERE EXISTS (" +
      "SELECT 1 FROM provisioning_jobs WHERE id = ? AND operation = 'FILE_MANAGER' " +
      "AND status = ? AND finished_at = ? AND claimed_by_node_id = ? " +
      "AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?))"
    ).bind(
      crypto.randomUUID(),
      auth.credential.organizationId,
      auditAction,
      jobId,
      JSON.stringify({
        serverId: auth.credential.serverId,
        operation: "FILE_MANAGER",
        errorCode: input.success ? null : errorCode,
      }),
      jobId,
      status,
      now,
      auth.credential.nodeId,
      auth.credential.serverId,
      auth.credential.organizationId,
    );

    const results = await c.env.DB.batch([updateStatement, auditStatement]);

    if ((results[0]?.meta?.changes ?? 0) !== 1 ||
        (results[1]?.meta?.changes ?? 0) !== 1) {
      return c.json({ message: "Job lease is missing, expired, or belongs to another server" }, 409);
    }

    return c.json({ accepted: true, jobId, status });
  }

  const update = await updateStatement.run();
  if ((update.meta?.changes ?? 0) !== 1) return c.json({ message: "Job lease is missing, expired, or belongs to another server" }, 409);
  const completedJob = await c.env.DB.prepare("SELECT operation, idempotency_key AS idempotencyKey, hosting_account_id AS hostingAccountId FROM provisioning_jobs WHERE id = ? AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?) LIMIT 1")
    .bind(jobId, auth.credential.serverId, auth.credential.organizationId).first<{ operation: string; idempotencyKey: string; hostingAccountId: string }>();
  if (completedJob?.operation === "CREATE_BACKUP" || completedJob?.operation === "RESTORE_BACKUP" || completedJob?.operation === "DELETE_BACKUP") {
    const parts = completedJob.idempotencyKey.split(":");
    const backupId = parts[1] ?? "";
    if (completedJob.operation === "CREATE_BACKUP") {
      if (input.success) {
        const result = incomingResult;
        const archiveName = result && typeof result.archiveName === "string" ? result.archiveName : "";
        const sizeBytes = result && typeof result.sizeBytes === "number" ? result.sizeBytes : 0;
        const digest = result && typeof result.sha256 === "string" ? result.sha256 : "";
        const resultBackupId = result && typeof result.backupId === "string" ? result.backupId : "";
        if (!/^[a-f0-9-]{36}$/.test(backupId) || resultBackupId !== backupId || archiveName !== backupId + ".tar.gz" || !Number.isSafeInteger(sizeBytes) || sizeBytes < 1 || !/^[a-f0-9]{64}$/.test(digest)) {
          await c.env.DB.prepare("UPDATE hosting_backups SET status = 'FAILED', error_message = 'The agent returned invalid backup metadata' WHERE id = ? AND organization_id = ?").bind(backupId, auth.credential.organizationId).run();
          return c.json({ message: "The agent returned invalid backup metadata." }, 422);
        }
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'AVAILABLE', archive_name = ?, size_bytes = ?, sha256 = ?, completed_at = ?, error_message = NULL WHERE id = ? AND organization_id = ? AND status IN ('QUEUED', 'RUNNING')").bind(archiveName, sizeBytes, digest, new Date().toISOString(), backupId, auth.credential.organizationId).run();
        // Clear the scheduler lease now that the backup has landed. This
        // unblocks the next scheduled run even if the lease window has
        // not expired yet. Then enforce retention: keep the N most-
        // recent AVAILABLE backups for this account, queue DELETE_BACKUP
        // jobs for the rest. Retention runs AFTER successful completion,
        // not before scheduling, so a failed backup never counts as a
        // completed retention entry. We also refuse to delete the only
        // AVAILABLE backup (the just-completed one) — if retention_count
        // is 1 we keep it.
        const schedule = await c.env.DB.prepare(
          "SELECT retention_count AS retentionCount FROM backup_schedules WHERE hosting_account_id = ? LIMIT 1",
        ).bind(completedJob.hostingAccountId).first<{ retentionCount: number }>();
        if (schedule && schedule.retentionCount > 0) {
          await c.env.DB.prepare(
            "UPDATE backup_schedules SET lease_expires_at = NULL WHERE hosting_account_id = ?",
          ).bind(completedJob.hostingAccountId).run();
          const allBackups = await c.env.DB.prepare(
            "SELECT id FROM hosting_backups WHERE hosting_account_id = ? AND organization_id = ? AND status = 'AVAILABLE' ORDER BY completed_at DESC",
          ).bind(completedJob.hostingAccountId, auth.credential.organizationId).all<{ id: string }>();
          const keepIds = (allBackups.results ?? []).slice(0, schedule.retentionCount);
          const deleteBackups = (allBackups.results ?? []).slice(schedule.retentionCount);
          if (keepIds.length > 0 && deleteBackups.length > 0) {
            for (const backup of deleteBackups) {
              // Atomically transition the backup to DELETING. The
              // WHERE status = 'AVAILABLE' clause ensures only one
              // concurrent retention run can claim a given backup —
              // if another run already transitioned it, this UPDATE
              // affects 0 rows and we skip queuing a duplicate
              // DELETE_BACKUP job. This is the idempotency guarantee
              // for retention deletions.
              const transition = await c.env.DB.prepare(
                "UPDATE hosting_backups SET status = 'DELETING' WHERE id = ? AND status = 'AVAILABLE' AND organization_id = ?",
              ).bind(backup.id, auth.credential.organizationId).run();
              if ((transition.meta?.changes ?? 0) === 0) continue;
              const deleteJobId = crypto.randomUUID();
              await c.env.DB.batch([
                c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'DELETE_BACKUP', 'QUEUED', ?, ?)")
                  .bind(deleteJobId, completedJob.hostingAccountId, `backup-delete:${backup.id}`, JSON.stringify({ backupId: backup.id, databaseNames: [] })),
                c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, 'backup.retention_delete', 'hosting_backup', ?, ?)")
                  .bind(crypto.randomUUID(), auth.credential.organizationId, backup.id, JSON.stringify({ jobId: deleteJobId })),
              ]);
            }
          }
        }
      } else {
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'FAILED', error_message = ? WHERE id = ? AND organization_id = ?").bind(errorMessage || "The backup could not be created", backupId, auth.credential.organizationId).run();
        // Clear the scheduler lease on failure so the next scheduled run
        // is not blocked by this failed attempt. A failed backup never
        // counts as a completed retention entry.
        await c.env.DB.prepare("UPDATE backup_schedules SET lease_expires_at = NULL WHERE hosting_account_id = ?").bind(completedJob.hostingAccountId).run();
      }
    } else if (completedJob.operation === "RESTORE_BACKUP") {
      if (input.success) {
        const account = await c.env.DB.prepare("SELECT a.username FROM provisioning_jobs j JOIN hosting_accounts a ON a.id = j.hosting_account_id WHERE j.id = ? AND a.organization_id = ? LIMIT 1").bind(jobId, auth.credential.organizationId).first<{ username: string }>();
        const stagingPath = incomingResult && typeof incomingResult.stagingPath === "string" ? incomingResult.stagingPath : "";
        const expectedPath = account ? "/var/lib/nexora/restore-staging/" + account.username + "/" + backupId : "";
        if (!expectedPath || stagingPath !== expectedPath) {
          await c.env.DB.prepare("UPDATE hosting_backups SET status = 'AVAILABLE', error_message = 'The agent returned an invalid staging location' WHERE id = ? AND organization_id = ?").bind(backupId, auth.credential.organizationId).run();
          return c.json({ message: "The agent returned an invalid restore staging location." }, 422);
        }
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'RESTORE_STAGED', staged_at = ?, error_message = NULL WHERE id = ? AND organization_id = ? AND status = 'RESTORING'").bind(new Date().toISOString(), backupId, auth.credential.organizationId).run();
      } else {
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'AVAILABLE', error_message = ? WHERE id = ? AND organization_id = ? AND status = 'RESTORING'").bind(errorMessage || "The restore could not be staged", backupId, auth.credential.organizationId).run();
      }
    } else {
      if (input.success) {
        await c.env.DB.prepare("DELETE FROM hosting_backups WHERE id = ? AND organization_id = ? AND status = 'DELETING'").bind(backupId, auth.credential.organizationId).run();
      } else {
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'AVAILABLE', error_message = ? WHERE id = ? AND organization_id = ? AND status = 'DELETING'").bind(errorMessage || "The backup could not be deleted", backupId, auth.credential.organizationId).run();
      }
    }
  }
  if (completedJob?.operation === "CREATE_HOSTING_ACCOUNT") {
    const accountId = await c.env.DB.prepare(
      "SELECT hosting_account_id AS accountId FROM provisioning_jobs WHERE id = ? AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?) LIMIT 1",
    ).bind(jobId, auth.credential.serverId, auth.credential.organizationId).first<{ accountId: string }>();
    if (input.success && accountId) {
      const primaryDomain = await c.env.DB.prepare(
        "SELECT id FROM domains WHERE hosting_account_id = ? AND is_primary = 1 LIMIT 1",
      ).bind(accountId.accountId).first<{ id: string }>();
      const statements = [
        c.env.DB.prepare("UPDATE hosting_accounts SET status = 'ACTIVE', updated_at = ? WHERE id = ? AND server_id = ?")
          .bind(now, accountId.accountId, auth.credential.serverId),
      ];
      if (primaryDomain) {
        const domainJobId = crypto.randomUUID();
        statements.push(c.env.DB.prepare(
          "INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) " +
          "SELECT ?, ?, 'ADD_DOMAIN', 'QUEUED', ? WHERE NOT EXISTS " +
          "(SELECT 1 FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'ADD_DOMAIN' AND idempotency_key = ?)",
        ).bind(domainJobId, accountId.accountId, "add-domain:" + primaryDomain.id, accountId.accountId, "add-domain:" + primaryDomain.id));
      }
      await c.env.DB.batch(statements);
    } else if (accountId) {
      await c.env.DB.prepare("UPDATE hosting_accounts SET status = 'FAILED', updated_at = ? WHERE id = ? AND server_id = ?")
        .bind(now, accountId.accountId, auth.credential.serverId).run();
    }
  }
  if (completedJob?.operation === "REVOKE_DATABASE_USER" && completedJob.idempotencyKey?.startsWith("revoke-database-user:")) {
    const databaseUserId = completedJob.idempotencyKey.slice("revoke-database-user:".length);
    if (input.success) {
      await c.env.DB.batch([
        c.env.DB.prepare("UPDATE hosting_database_users SET status = 'REVOKED' WHERE id = ? AND organization_id = ? AND status = 'REVOKING'").bind(databaseUserId, auth.credential.organizationId),
        c.env.DB.prepare("DELETE FROM database_user_secrets WHERE database_user_id = ? AND organization_id = ?").bind(databaseUserId, auth.credential.organizationId),
      ]);
    } else {
      await c.env.DB.prepare("UPDATE hosting_database_users SET status = 'ACTIVE' WHERE id = ? AND organization_id = ? AND status = 'REVOKING'").bind(databaseUserId, auth.credential.organizationId).run();
    }
  }
  if (completedJob?.operation === "CREATE_DATABASE_USER" && completedJob.idempotencyKey?.startsWith("create-database-user:")) {
    const databaseUserId = completedJob.idempotencyKey.slice("create-database-user:".length);
    if (input.success) {
      const expectedUser = await c.env.DB.prepare(
        `SELECT u.username
         FROM hosting_database_users u
         JOIN hosting_databases d ON d.id = u.database_id AND d.organization_id = u.organization_id
         WHERE u.id = ? AND u.organization_id = ? AND u.status = 'PENDING'
           AND d.hosting_account_id = ? AND d.status = 'ACTIVE'
         LIMIT 1`,
      ).bind(databaseUserId, auth.credential.organizationId, completedJob.hostingAccountId).first<{ username: string }>();
      const credential = incomingResult && typeof incomingResult.username === "string" && typeof incomingResult.password === "string"
        ? { username: incomingResult.username, password: incomingResult.password } : null;
      if (!expectedUser || !credential || credential.username !== expectedUser.username ||
          credential.password.length < 32 || credential.password.length > 128 ||
          !/^[a-z][a-z0-9_]{2,80}$/.test(credential.username)) {
        await c.env.DB.prepare("UPDATE hosting_database_users SET status = 'FAILED' WHERE id = ? AND organization_id = ? AND status = 'PENDING'")
          .bind(databaseUserId, auth.credential.organizationId).run();
        return c.json({ message: "The agent returned a database credential that does not match the pending user." }, 422);
      }
      try {
        const encrypted = await encryptDatabaseSecret(c.env, JSON.stringify(credential));
        await c.env.DB.batch([
          c.env.DB.prepare("INSERT INTO database_user_secrets (database_user_id, organization_id, ciphertext, iv, expires_at) VALUES (?, ?, ?, ?, ?)")
            .bind(databaseUserId, auth.credential.organizationId, encrypted.ciphertext, encrypted.iv, new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()),
          c.env.DB.prepare("UPDATE hosting_database_users SET status = 'ACTIVE' WHERE id = ? AND organization_id = ? AND status = 'PENDING'")
            .bind(databaseUserId, auth.credential.organizationId),
        ]);
      } catch {
        await c.env.DB.prepare("UPDATE hosting_database_users SET status = 'FAILED' WHERE id = ? AND organization_id = ?").bind(databaseUserId, auth.credential.organizationId).run();
        return c.json({ message: "The credential could not be stored securely." }, 503);
      }
    } else {
      await c.env.DB.prepare("UPDATE hosting_database_users SET status = 'FAILED' WHERE id = ? AND organization_id = ? AND status = 'PENDING'").bind(databaseUserId, auth.credential.organizationId).run();
    }
  }
  if (completedJob?.operation === "DELETE_DATABASE" && completedJob.idempotencyKey?.startsWith("delete-database:")) {
    const databaseId = completedJob.idempotencyKey.split(":")[1] ?? "";
    if (input.success) {
      await c.env.DB.batch([
        c.env.DB.prepare("UPDATE hosting_databases SET status = 'DELETED', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'DELETING'")
          .bind(now, databaseId, auth.credential.organizationId),
        c.env.DB.prepare("UPDATE hosting_database_users SET status = 'REVOKED' WHERE database_id = ? AND organization_id = ?")
          .bind(databaseId, auth.credential.organizationId),
        c.env.DB.prepare("DELETE FROM database_user_secrets WHERE organization_id = ? AND database_user_id IN (SELECT id FROM hosting_database_users WHERE database_id = ?)")
          .bind(auth.credential.organizationId, databaseId),
        c.env.DB.prepare("DELETE FROM database_usage WHERE database_id = ? AND organization_id = ?")
          .bind(databaseId, auth.credential.organizationId),
      ]);
    } else {
      // A failed DROP may have removed some users before MariaDB returned an
      // error. FAILED is retryable by the delete endpoint, and the helper uses
      // DROP USER/DATABASE IF EXISTS so the same request is safe to retry.
      await c.env.DB.prepare(
        "UPDATE hosting_databases SET status = 'FAILED', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'DELETING'",
      ).bind(now, databaseId, auth.credential.organizationId).run();
    }
  }
  if (completedJob?.operation === "CREATE_DATABASE" && completedJob.idempotencyKey?.startsWith("create-database:")) {
    const databaseId = completedJob.idempotencyKey.slice("create-database:".length);
    await c.env.DB.prepare(
      "UPDATE hosting_databases SET status = ?, updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'PENDING'",
    ).bind(input.success ? "ACTIVE" : "FAILED", now, databaseId, auth.credential.organizationId).run();
  }
  // SUSPEND_HOSTING_ACCOUNT: on failure revert the account back to ACTIVE.
  if (completedJob?.operation === "SUSPEND_HOSTING_ACCOUNT" && !input.success) {
    const jobId_parts = completedJob.idempotencyKey.split(":");
    const accountId = jobId_parts[1] ?? "";
    if (/^[a-f0-9-]{36}$/.test(accountId)) {
      await c.env.DB.prepare("UPDATE hosting_accounts SET status = 'ACTIVE', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'SUSPENDED'").bind(now, accountId, auth.credential.organizationId).run();
    }
  }
  // REACTIVATE_HOSTING_ACCOUNT: on failure revert the account back to SUSPENDED.
  if (completedJob?.operation === "REACTIVATE_HOSTING_ACCOUNT" && !input.success) {
    const jobId_parts = completedJob.idempotencyKey.split(":");
    const accountId = jobId_parts[1] ?? "";
    if (/^[a-f0-9-]{36}$/.test(accountId)) {
      await c.env.DB.prepare("UPDATE hosting_accounts SET status = 'SUSPENDED', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'ACTIVE'").bind(now, accountId, auth.credential.organizationId).run();
    }
  }
  // REMOVE_DOMAIN: on failure revert the domain back to ACTIVE.
  if (completedJob?.operation === "REMOVE_DOMAIN" && !input.success && completedJob.idempotencyKey?.startsWith("remove-domain:")) {
    const domainId = completedJob.idempotencyKey.slice("remove-domain:".length);
    if (/^[a-f0-9-]{36}$/.test(domainId)) {
      await c.env.DB.prepare("UPDATE domains SET status = 'ACTIVE', updated_at = ? WHERE id = ? AND status = 'DELETED'").bind(now, domainId).run();
    }
  }
  // RESET_DATABASE_USER_PASSWORD: on failure delete the new secret bound
  // to this job so it can never be revealed. Deleting by job_id (not just
  // user_id) is more precise — it cannot accidentally delete a different
  // reset attempt's secret for the same user.
  if (completedJob?.operation === "RESET_DATABASE_USER_PASSWORD" && !input.success && completedJob.idempotencyKey?.startsWith("reset-db-user:")) {
    await c.env.DB.prepare(
      "DELETE FROM database_user_secrets WHERE job_id = ? AND organization_id = ? AND revealed_at IS NULL",
    ).bind(jobId, auth.credential.organizationId).run();
  }
  const auditActionName = input.success ? ({
    "FILE_MANAGER": "file_manager.operation_completed", "ADD_DOMAIN": "domain.configured",
    "CREATE_DATABASE": "database.provisioned", "CREATE_DATABASE_USER": "database_user.provisioned",
    "REVOKE_DATABASE_USER": "database_user.revoked", "DELETE_DATABASE": "database.deleted",
    "CREATE_BACKUP": "backup.created", "RESTORE_BACKUP": "backup.restore_staged",
    "DELETE_BACKUP": "backup.deleted", "CREATE_HOSTING_ACCOUNT": "hosting_account.provisioned",
    "UPDATE_PHP_POOL": "hosting_account.php_updated", "SUSPEND_HOSTING_ACCOUNT": "hosting_account.suspended",
    "REACTIVATE_HOSTING_ACCOUNT": "hosting_account.reactivated", "REMOVE_DOMAIN": "domain.removed",
    "RESET_DATABASE_USER_PASSWORD": "database_user.password_reset",
  } as Record<string, string>)[completedJob?.operation ?? ""] ?? "hosting_account.provisioned" : ({
    "FILE_MANAGER": "file_manager.operation_failed", "ADD_DOMAIN": "domain.configuration_failed",
    "CREATE_DATABASE": "database.provisioning_failed", "CREATE_DATABASE_USER": "database_user.provisioning_failed",
    "REVOKE_DATABASE_USER": "database_user.revocation_failed", "DELETE_DATABASE": "database.deletion_failed",
    "CREATE_BACKUP": "backup.creation_failed", "RESTORE_BACKUP": "backup.restore_stage_failed",
    "DELETE_BACKUP": "backup.deletion_failed", "CREATE_HOSTING_ACCOUNT": "hosting_account.provisioning_failed",
    "UPDATE_PHP_POOL": "hosting_account.php_update_failed", "SUSPEND_HOSTING_ACCOUNT": "hosting_account.suspension_failed",
    "REACTIVATE_HOSTING_ACCOUNT": "hosting_account.reactivation_failed", "REMOVE_DOMAIN": "domain.removal_failed",
    "RESET_DATABASE_USER_PASSWORD": "database_user.password_reset_failed",
  } as Record<string, string>)[completedJob?.operation ?? ""] ?? "hosting_account.provisioning_failed";
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'provisioning_job', ?, ?)")
    .bind(crypto.randomUUID(), auth.credential.organizationId, auditActionName,
      jobId, JSON.stringify({ serverId: auth.credential.serverId, operation: completedJob?.operation ?? null, errorCode: input.success ? null : errorCode })).run();
  return c.json({ accepted: true, jobId, status });
});

app.notFound((c) => c.json({ error: "Not found" }, 404));


type NotificationEventType = "OPENED" | "RESOLVED";

function notificationOutboxStatement(
  db: D1Database,
  organizationId: string,
  serverId: string,
  incidentKey: string,
  eventType: NotificationEventType,
  eventAt: string,
): D1PreparedStatement {
  const eventColumn = eventType === "OPENED" ? "opened_at" : "resolved_at";
  return db.prepare(
    `INSERT OR IGNORE INTO incident_notification_outbox
       (id, organization_id, incident_id, event_type, recipients_json,
        payload_json, status, next_attempt_at, created_at, updated_at)
     SELECT ?, i.organization_id, i.id, ?, n.recipients_json,
            json_object(
              'eventType', ?,
              'hostname', s.hostname,
              'incidentType', i.incident_type,
              'severity', i.severity,
              'title', i.title,
              'description', i.description,
              'openedAt', i.opened_at,
              'resolvedAt', i.resolved_at,
              'observedAt', i.last_observed_at
            ),
            'PENDING', ?, ?, ?
     FROM server_incidents i
     JOIN servers s
       ON s.id = i.server_id AND s.organization_id = i.organization_id
     JOIN incident_notification_settings n
       ON n.organization_id = i.organization_id AND n.enabled = 1
     WHERE i.server_id = ?
       AND i.organization_id = ?
       AND i.incident_key = ?
       AND i.${eventColumn} = ?
       AND json_array_length(n.recipients_json) > 0
       AND NOT EXISTS (
         SELECT 1 FROM incident_notification_outbox o
         WHERE o.incident_id = i.id AND o.event_type = ?
       )`,
  ).bind(
    crypto.randomUUID(),
    eventType,
    eventType,
    eventAt,
    eventAt,
    eventAt,
    serverId,
    organizationId,
    incidentKey,
    eventAt,
    eventType,
  );
}

function escapeEmailHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

type NotificationOutboxRow = {
  id: string;
  recipients_json: string;
  payload_json: string;
  attempts: number;
};

async function dispatchIncidentNotifications(env: Bindings): Promise<void> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return;

  const now = new Date();
  const nowIso = now.toISOString();
  const due = await env.DB.prepare(
    `SELECT id FROM incident_notification_outbox
     WHERE (
       status IN ('PENDING', 'RETRY') AND next_attempt_at <= ?
     ) OR (
       status = 'PROCESSING' AND locked_until IS NOT NULL AND locked_until <= ?
     )
     ORDER BY next_attempt_at ASC
     LIMIT 10`,
  ).bind(nowIso, nowIso).all<{ id: string }>();

  for (const candidate of due.results ?? []) {
    const lockedUntil = new Date(Date.now() + 2 * 60 * 1000).toISOString();
    const claim = await env.DB.prepare(
      `UPDATE incident_notification_outbox
       SET status = 'PROCESSING', locked_until = ?,
           attempts = attempts + 1, updated_at = ?
       WHERE id = ? AND (
         (status IN ('PENDING', 'RETRY') AND next_attempt_at <= ?)
         OR (status = 'PROCESSING' AND locked_until IS NOT NULL AND locked_until <= ?)
       )`,
    ).bind(lockedUntil, nowIso, candidate.id, nowIso, nowIso).run();

    if ((claim.meta?.changes ?? 0) !== 1) continue;

    const row = await env.DB.prepare(
      `SELECT id, recipients_json, payload_json, attempts
       FROM incident_notification_outbox WHERE id = ? LIMIT 1`,
    ).bind(candidate.id).first<NotificationOutboxRow>();

    if (!row) continue;

    try {
      const recipients: unknown = JSON.parse(row.recipients_json);
      const payload: Record<string, unknown> = JSON.parse(row.payload_json);

      if (!Array.isArray(recipients) || recipients.length === 0 ||
          recipients.length > 10 ||
          recipients.some((email) => typeof email !== "string" || !validEmail(email))) {
        throw new Error("Outbox recipient list is invalid");
      }

      const opened = payload.eventType === "OPENED";
      const eventLabel = opened ? "Incident opened" : "Incident recovered";
      const subject = `[Nexora] ${eventLabel}: ${String(payload.title ?? "Server incident")}`;
      const hostname = escapeEmailHtml(payload.hostname);
      const title = escapeEmailHtml(payload.title);
      const description = escapeEmailHtml(payload.description);
      const severity = escapeEmailHtml(payload.severity);
      const incidentType = escapeEmailHtml(payload.incidentType);
      const observedAt = escapeEmailHtml(payload.observedAt);
      const html = `
        <div style="font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#172033">
          <h2>${escapeEmailHtml(eventLabel)}</h2>
          <p><strong>Server:</strong> ${hostname}</p>
          <p><strong>Incident:</strong> ${title}</p>
          <p><strong>Severity:</strong> ${severity}</p>
          <p><strong>Type:</strong> ${incidentType}</p>
          <p>${description}</p>
          <p><strong>Observed:</strong> ${observedAt}</p>
          <hr/>
          <p style="font-size:12px;color:#64748b">Nexora Control Panel · Automated infrastructure notification</p>
        </div>`;

      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: env.EMAIL_FROM,
          to: recipients,
          subject,
          html,
        }),
      });

      if (!response.ok) {
        const responseText = (await response.text()).slice(0, 800);
        throw new Error(`Resend HTTP ${response.status}: ${responseText}`);
      }

      await env.DB.prepare(
        `UPDATE incident_notification_outbox
         SET status = 'SENT', sent_at = ?, locked_until = NULL,
             last_error = NULL, updated_at = ?
         WHERE id = ? AND status = 'PROCESSING'`,
      ).bind(new Date().toISOString(), new Date().toISOString(), row.id).run();
    } catch (error) {
      const failedAt = new Date();
      const attempts = row.attempts;
      const exhausted = attempts >= 8;
      const delaySeconds = Math.min(6 * 60 * 60, 60 * (2 ** Math.max(0, attempts - 1)));
      const nextAttempt = new Date(failedAt.getTime() + delaySeconds * 1000).toISOString();
      const message = (error instanceof Error ? error.message : "Unknown email delivery error").slice(0, 1000);

      await env.DB.prepare(
        `UPDATE incident_notification_outbox
         SET status = ?, next_attempt_at = ?, locked_until = NULL,
             last_error = ?, updated_at = ?
         WHERE id = ? AND status = 'PROCESSING'`,
      ).bind(
        exhausted ? "FAILED" : "RETRY",
        nextAttempt,
        message,
        failedAt.toISOString(),
        row.id,
      ).run();
    }
  }
}

async function checkMissedHeartbeats(env: Bindings): Promise<void> {
  const now = new Date();
  const cutoff = new Date(now.getTime() - 3 * 60 * 1000).toISOString();
  const observedAt = now.toISOString();

  const stale = await env.DB.prepare(
    `SELECT id, organization_id AS organizationId, hostname, last_heartbeat_at AS lastHeartbeatAt
     FROM servers
     WHERE last_heartbeat_at IS NOT NULL
       AND last_heartbeat_at <= ?
       AND status IN ('ONLINE', 'DEGRADED')`,
  ).bind(cutoff).all<{
    id: string;
    organizationId: string;
    hostname: string;
    lastHeartbeatAt: string;
  }>();

  for (const server of stale.results ?? []) {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE servers SET status = 'OFFLINE', updated_at = ? WHERE id = ? AND organization_id = ? AND last_heartbeat_at = ? AND last_heartbeat_at <= ? AND status IN ('ONLINE', 'DEGRADED')",
      ).bind(observedAt, server.id, server.organizationId, server.lastHeartbeatAt, cutoff),
      env.DB.prepare(
        "INSERT OR IGNORE INTO server_incidents (id, organization_id, server_id, incident_type, incident_key, severity, status, title, description, opened_at, updated_at, last_observed_at) SELECT ?, ?, id, 'SERVER_HEARTBEAT', 'server-heartbeat', 'CRITICAL', 'OPEN', ?, ?, ?, ?, ? FROM servers WHERE id = ? AND organization_id = ? AND status = 'OFFLINE' AND last_heartbeat_at = ?",
      ).bind(
        crypto.randomUUID(), server.organizationId,
        `${server.hostname} is offline`,
        `No authenticated heartbeat has been received since ${server.lastHeartbeatAt}.`,
        observedAt, observedAt, server.lastHeartbeatAt,
        server.id, server.organizationId, server.lastHeartbeatAt,
      ),
      notificationOutboxStatement(
        env.DB, server.organizationId, server.id,
        "server-heartbeat", "OPENED", observedAt,
      ),
    ]);
  }
}

// GitHub App OAuth: the app's configured repository permissions, not broad OAuth scopes,
// determine what the customer grants. Build execution is intentionally not part of these routes.
function githubEncryptionKey(env: Bindings): Uint8Array {
  const value = env.GITHUB_TOKEN_ENCRYPTION_KEY ?? "";
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error("GitHub token encryption is not configured");
  return new Uint8Array(value.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
}

async function encryptGithubToken(env: Bindings, token: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", githubEncryptionKey(env), "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(token));
  return { iv: base64(iv), ciphertext: base64(new Uint8Array(encrypted)) };
}

async function decryptGithubToken(env: Bindings, ciphertext: string, iv: string): Promise<string> {
  const decode = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", githubEncryptionKey(env), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(iv) }, key, decode(ciphertext));
  return new TextDecoder().decode(plaintext);
}

async function githubAccessToken(env: Bindings, db: D1Database, organizationId: string): Promise<string> {
  type ConnectionTokenRow = {
    encrypted_access_token: string; access_token_iv: string;
    encrypted_refresh_token: string | null; refresh_token_iv: string | null;
    token_expires_at: string | null; refresh_token_expires_at: string | null;
  };
  const load = () => db.prepare(
    "SELECT encrypted_access_token, access_token_iv, encrypted_refresh_token, refresh_token_iv, token_expires_at, refresh_token_expires_at FROM github_connections WHERE organization_id = ? LIMIT 1",
  ).bind(organizationId).first<ConnectionTokenRow>();
  const row = await load();
  if (!row) throw new Error("GitHub connection not found");
  const expiresAt = row.token_expires_at ? Date.parse(row.token_expires_at) : Number.POSITIVE_INFINITY;
  if (expiresAt > Date.now() + 5 * 60 * 1000) return decryptGithubToken(env, row.encrypted_access_token, row.access_token_iv);
  if (!row.encrypted_refresh_token || !row.refresh_token_iv ||
      (row.refresh_token_expires_at && Date.parse(row.refresh_token_expires_at) <= Date.now()) ||
      !env.GITHUB_APP_CLIENT_ID || !env.GITHUB_APP_CLIENT_SECRET) {
    throw new Error("GitHub authorization expired; reconnect the GitHub App");
  }
  const refreshToken = await decryptGithubToken(env, row.encrypted_refresh_token, row.refresh_token_iv);
  try {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: env.GITHUB_APP_CLIENT_ID, client_secret: env.GITHUB_APP_CLIENT_SECRET, grant_type: "refresh_token", refresh_token: refreshToken }),
    });
    if (!response.ok) throw new Error("GitHub token refresh failed");
    const data = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number; refresh_token_expires_in?: number; token_type?: string };
    if (!data.access_token || !data.refresh_token || data.token_type?.toLowerCase() !== "bearer" ||
        !Number.isFinite(data.expires_in) || !Number.isFinite(data.refresh_token_expires_in)) throw new Error("GitHub returned invalid refreshed credentials");
    const access = await encryptGithubToken(env, data.access_token);
    const refresh = await encryptGithubToken(env, data.refresh_token);
    const issuedAt = Date.now();
    const accessExpiry = new Date(issuedAt + Number(data.expires_in) * 1000).toISOString();
    const refreshExpiry = new Date(issuedAt + Number(data.refresh_token_expires_in) * 1000).toISOString();
    const update = await db.prepare(
      "UPDATE github_connections SET encrypted_access_token = ?, access_token_iv = ?, encrypted_refresh_token = ?, refresh_token_iv = ?, token_expires_at = ?, refresh_token_expires_at = ?, updated_at = datetime('now') WHERE organization_id = ? AND encrypted_refresh_token = ?",
    ).bind(access.ciphertext, access.iv, refresh.ciphertext, refresh.iv, accessExpiry, refreshExpiry, organizationId, row.encrypted_refresh_token).run();
    if ((update.meta?.changes ?? 0) === 1) return data.access_token;
    const latest = await load();
    if (latest?.token_expires_at && Date.parse(latest.token_expires_at) > Date.now()) return decryptGithubToken(env, latest.encrypted_access_token, latest.access_token_iv);
    throw new Error("GitHub token refresh was superseded; retry the request");
  } catch {
    const latest = await load();
    if (latest?.token_expires_at && Date.parse(latest.token_expires_at) > Date.now()) return decryptGithubToken(env, latest.encrypted_access_token, latest.access_token_iv);
    throw new Error("GitHub authorization expired; reconnect the GitHub App");
  }
}


function base64Url(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function derTlv(tag: number, value: Uint8Array): Uint8Array {
  const length = value.length;
  let encodedLength: number[];
  if (length < 128) encodedLength = [length];
  else {
    const bytes: number[] = [];
    let remaining = length;
    while (remaining > 0) { bytes.unshift(remaining & 0xff); remaining >>>= 8; }
    encodedLength = [0x80 | bytes.length, ...bytes];
  }
  return Uint8Array.from([tag, ...encodedLength, ...value]);
}

function githubPrivateKeyDer(pem: string): Uint8Array {
  const normalized = pem.replace(/\r/g, "").trim();
  const match = /^-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY)-----([\s\S]+)-----END \1-----$/.exec(normalized);
  if (!match) throw new Error("GitHub App private key must be a PKCS#8 or RSA PKCS#1 PEM");
  const binary = atob(match[2].replace(/\s/g, ""));
  const keyBytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (match[1] === "PRIVATE KEY") return keyBytes;

  // Web Crypto imports PKCS#8, while GitHub's downloaded App keys are commonly PKCS#1.
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  const rsaAlgorithm = Uint8Array.of(
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  );
  const octetString = derTlv(0x04, keyBytes);
  const body = new Uint8Array(version.length + rsaAlgorithm.length + octetString.length);
  body.set(version, 0);
  body.set(rsaAlgorithm, version.length);
  body.set(octetString, version.length + rsaAlgorithm.length);
  return derTlv(0x30, body);
}

async function githubAppJwt(env: Bindings): Promise<string> {
  const appId = env.GITHUB_APP_ID ?? "";
  if (!/^\d+$/.test(appId) || !env.GITHUB_APP_PRIVATE_KEY) throw new Error("GitHub App signing credentials are not configured");
  const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64Url(new TextEncoder().encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId })));
  const message = header + "." + payload;
  const key = await crypto.subtle.importKey("pkcs8", githubPrivateKeyDer(env.GITHUB_APP_PRIVATE_KEY), {
    name: "RSASSA-PKCS1-v1_5", hash: "SHA-256",
  }, false, ["sign"]);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(message));
  return message + "." + base64Url(new Uint8Array(signature));
}

async function githubInstallationToken(env: Bindings, installationId: string, repositoryId: string): Promise<string> {
  const jwt = await githubAppJwt(env);
  const response = await fetch(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`, Accept: "application/vnd.github+json",
      "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Nexora-Control-Panel",
    },
    body: JSON.stringify({
      repository_ids: [Number(repositoryId)],
      permissions: { actions: "write", contents: "read", metadata: "read" },
    }),
  });
  if (!response.ok) throw new Error("Unable to mint a repository-scoped GitHub installation token");
  const data = await response.json() as { token?: string; expires_at?: string };
  if (!data.token || !data.expires_at || Date.parse(data.expires_at) <= Date.now()) throw new Error("GitHub returned an invalid installation token");
  return data.token;
}

function githubDashboardRedirect(env: Bindings, status: string, customer = false): string {
  const base = env.DASHBOARD_URL ?? "";
  let url: URL;
  try { url = new URL(base); } catch { throw new Error("Dashboard URL is not configured"); }
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("Dashboard URL must be an HTTPS origin");
  url.pathname = customer ? "/customer/deploy" : "/github-deployments";
  url.search = new URLSearchParams({ github: status }).toString();
  url.hash = "";
  return url.toString();
}

async function githubApi(token: string, path: string): Promise<Response> {
  return fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Nexora-Control-Panel",
    },
  });
}

type GithubApiDetail = {
  status: number;
  ok: boolean;
  requestId: string | null;
  rateLimitRemaining: number | null;
  rateLimitReset: string | null;
  retryAfter: number | null;
  body: unknown | null;
};

// Performs a GitHub API call and captures safe diagnostics (request id, rate
// limit headers, parsed JSON). The Authorization header and tokens are never
// included in the returned detail, logs, or API responses.
async function githubApiDetail(token: string, path: string): Promise<GithubApiDetail> {
  const response = await githubApi(token, path);
  const remainingRaw = response.headers.get("x-ratelimit-remaining");
  const resetRaw = response.headers.get("x-ratelimit-reset");
  const retryAfterRaw = response.headers.get("retry-after");
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return {
    status: response.status,
    ok: response.ok,
    requestId: response.headers.get("x-github-request-id"),
    rateLimitRemaining: remainingRaw === null ? null : Number.parseInt(remainingRaw, 10),
    rateLimitReset: resetRaw === null || Number.isNaN(Number.parseInt(resetRaw, 10))
      ? null
      : new Date(Number.parseInt(resetRaw, 10) * 1000).toISOString(),
    retryAfter: retryAfterRaw === null || Number.isNaN(Number.parseInt(retryAfterRaw, 10))
      ? null
      : Number.parseInt(retryAfterRaw, 10),
    body,
  };
}

// Extracts GitHub's own (safe) error message from a JSON body when present.
function githubErrorMessage(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;
  if (typeof record.message === "string" && record.message.length > 0 && record.message.length <= 400) {
    return record.message;
  }
  return null;
}

function githubDetailPayload(detail: GithubApiDetail | null): { requestId?: string; rateLimitRemaining?: number; rateLimitReset?: string } {
  if (!detail) return {};
  const payload: { requestId?: string; rateLimitRemaining?: number; rateLimitReset?: string } = {};
  if (detail.requestId) payload.requestId = detail.requestId;
  if (detail.rateLimitRemaining !== null && Number.isFinite(detail.rateLimitRemaining)) payload.rateLimitRemaining = detail.rateLimitRemaining;
  if (detail.rateLimitReset) payload.rateLimitReset = detail.rateLimitReset;
  return payload;
}

app.get("/v1/github/connection", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const connection = await c.env.DB.prepare(
    "SELECT github_login, scopes, created_at FROM github_connections WHERE organization_id = ? LIMIT 1",
  ).bind(identity.organizationId).first<{ github_login: string; scopes: string; created_at: string }>();
  return c.json({ connected: Boolean(connection), connection: connection ? { login: connection.github_login, scopes: connection.scopes, connectedAt: connection.created_at } : null });
});

app.post("/v1/github/connect", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!identity.platformRole && identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization owner or administrator access required" }, 403);
  if (!c.env.GITHUB_APP_CLIENT_ID || !c.env.GITHUB_OAUTH_CALLBACK_URL || !c.env.GITHUB_TOKEN_ENCRYPTION_KEY) {
    return c.json({ message: "GitHub App credentials, callback URL, and token encryption key must be configured first." }, 503);
  }
  try { const callback = new URL(c.env.GITHUB_OAUTH_CALLBACK_URL); githubEncryptionKey(c.env); if (callback.protocol !== "https:" || callback.username || callback.password) throw new Error("Invalid callback URL"); }
  catch { return c.json({ message: "GitHub OAuth configuration is invalid." }, 503); }
  const state = randomHex(32);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM github_oauth_states WHERE expires_at <= ? OR consumed_at IS NOT NULL").bind(new Date().toISOString()),
    c.env.DB.prepare("INSERT INTO github_oauth_states (state_hash, organization_id, user_id, expires_at) VALUES (?, ?, ?, ?)")
      .bind(await sha256(state), identity.organizationId, identity.id, expiresAt),
  ]);
  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", c.env.GITHUB_APP_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", c.env.GITHUB_OAUTH_CALLBACK_URL);
  authorize.searchParams.set("state", state);
  return c.json({ authorizationUrl: authorize.toString() });
});

app.get("/v1/github/callback", async (c) => {
  const state = c.req.query("state") ?? "";
  if (!/^[a-f0-9]{64}$/i.test(state)) return c.text("Invalid GitHub OAuth callback.", 400);
  const stateHash = await sha256(state);
  const pending = await c.env.DB.prepare(
    "SELECT organization_id, user_id FROM github_oauth_states WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1",
  ).bind(stateHash, new Date().toISOString()).first<{ organization_id: string; user_id: string }>();
  if (!pending) return c.text("GitHub authorization state is invalid or expired.", 400);
  const platformMembership = await c.env.DB.prepare(
    "SELECT user_id FROM platform_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
  ).bind(pending.user_id).first<{ user_id: string }>();
  const customerRedirect = !platformMembership;
  const consumeState = async () => {
    const now = new Date().toISOString();
    const consumed = await c.env.DB.prepare(
      "UPDATE github_oauth_states SET consumed_at = ? WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ?",
    ).bind(now, stateHash, now).run();
    return (consumed.meta?.changes ?? 0) === 1;
  };
  const providerError = c.req.query("error");
  if (providerError) {
    if (!(await consumeState())) return c.text("GitHub authorization state has already been used.", 400);
    try { return c.redirect(githubDashboardRedirect(c.env, "denied", customerRedirect)); }
    catch { return c.text("GitHub connection was not completed.", 503); }
  }
  const code = c.req.query("code") ?? "";
  if (!/^[A-Za-z0-9._-]{1,200}$/.test(code)) return c.text("Invalid GitHub OAuth callback.", 400);
  if (!c.env.GITHUB_APP_CLIENT_ID || !c.env.GITHUB_APP_CLIENT_SECRET || !c.env.GITHUB_OAUTH_CALLBACK_URL || !c.env.GITHUB_TOKEN_ENCRYPTION_KEY) return c.text("GitHub OAuth is not configured.", 503);
  if (!(await consumeState())) return c.text("GitHub authorization state has already been used.", 400);
  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: c.env.GITHUB_APP_CLIENT_ID, client_secret: c.env.GITHUB_APP_CLIENT_SECRET, code, redirect_uri: c.env.GITHUB_OAUTH_CALLBACK_URL }),
    });
    if (!tokenResponse.ok) throw new Error("GitHub token exchange failed");
    const tokenData = await tokenResponse.json() as { access_token?: string; refresh_token?: string; expires_in?: number; refresh_token_expires_in?: number; token_type?: string; scope?: string; error?: string };
    if (!tokenData.access_token || tokenData.token_type?.toLowerCase() !== "bearer") throw new Error("GitHub did not issue a usable access token");
    const userResponse = await githubApi(tokenData.access_token, "/user");
    if (!userResponse.ok) throw new Error("Unable to verify GitHub account");
    const githubUser = await userResponse.json() as { id?: number; login?: string };
    if (!Number.isSafeInteger(githubUser.id) || !githubUser.login || !/^[A-Za-z0-9-]{1,39}$/.test(githubUser.login)) throw new Error("GitHub account response is invalid");
    const encrypted = await encryptGithubToken(c.env, tokenData.access_token);
    const encryptedRefresh = tokenData.refresh_token ? await encryptGithubToken(c.env, tokenData.refresh_token) : null;
    const tokenExpiresAt = Number.isFinite(tokenData.expires_in) ? new Date(Date.now() + Number(tokenData.expires_in) * 1000).toISOString() : null;
    const refreshTokenExpiresAt = Number.isFinite(tokenData.refresh_token_expires_in) ? new Date(Date.now() + Number(tokenData.refresh_token_expires_in) * 1000).toISOString() : null;
    await c.env.DB.prepare(
      `INSERT INTO github_connections (id, organization_id, github_user_id, github_login, encrypted_access_token, access_token_iv, encrypted_refresh_token, refresh_token_iv, token_expires_at, refresh_token_expires_at, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(organization_id) DO UPDATE SET github_user_id = excluded.github_user_id, github_login = excluded.github_login,
         encrypted_access_token = excluded.encrypted_access_token, access_token_iv = excluded.access_token_iv,
         encrypted_refresh_token = excluded.encrypted_refresh_token, refresh_token_iv = excluded.refresh_token_iv,
         token_expires_at = excluded.token_expires_at, refresh_token_expires_at = excluded.refresh_token_expires_at,
         scopes = excluded.scopes, updated_at = datetime('now')`,
    ).bind(crypto.randomUUID(), pending.organization_id, String(githubUser.id), githubUser.login,
      encrypted.ciphertext, encrypted.iv, encryptedRefresh?.ciphertext ?? null, encryptedRefresh?.iv ?? null,
      tokenExpiresAt, refreshTokenExpiresAt, tokenData.scope ?? "GitHub App permissions").run();
    await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, metadata) VALUES (?, ?, ?, 'github.connected', 'github_connection', ?)")
      .bind(crypto.randomUUID(), pending.organization_id, pending.user_id, JSON.stringify({ githubLogin: githubUser.login })).run();
    return c.redirect(githubDashboardRedirect(c.env, "connected", customerRedirect));
  } catch {
    try { return c.redirect(githubDashboardRedirect(c.env, "error", customerRedirect)); }
    catch { return c.text("GitHub connection failed. Check server configuration and try again.", 502); }
  }
});

app.get("/v1/github/repositories", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!identity.platformRole && identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization owner or administrator access required" }, 403);
  const connection = await c.env.DB.prepare(
    "SELECT id FROM github_connections WHERE organization_id = ? LIMIT 1",
  ).bind(identity.organizationId).first<{ id: string }>();
  if (!connection) return c.json({ message: "Connect a GitHub account first." }, 409);

  const CONFIG_REQUIREMENTS = "GITHUB_TOKEN_ENCRYPTION_KEY (64 hex chars) must be configured to read stored credentials.";

  let token: string;
  try {
    token = await githubAccessToken(c.env, c.env.DB, identity.organizationId);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error("GitHub repositories: credential resolution failed:", detail);
    // Never log tokens; the thrown messages describe the failure class only.
    if (/GitHub authorization expired/i.test(detail)) {
      return c.json({
        error: "github_authorization_expired",
        message: "GitHub authorization expired. Reconnect the Nexora GitHub App from this page and try again.",
      }, 409);
    }
    return c.json({
      error: "credential_resolution_failed",
      message: `Unable to read the stored GitHub credentials. ${CONFIG_REQUIREMENTS}`,
    }, 502);
  }

  type InstallationRow = { id: number; account: string | null; repositorySelection: string | null; suspended: boolean; permissionIssues: string[] };
  const installations: InstallationRow[] = [];
  const installationErrors: Array<{ installationId: number; account: string | null; status: number; message: string; requestId?: string }> = [];
  const repositories: Array<{ id: number; name: string; fullName: string; private: boolean; defaultBranch: string; htmlUrl: string; installationId: number; owner: string }> = [];
  let lastDetail: GithubApiDetail | null = null;
  let appSlug: string | null = null;
  let clientConfigMismatch = false;

  try {
    // Verify the configured App identity directly with the GitHub API. GET /app
    // authenticates with the App JWT, so this confirms GITHUB_APP_ID/PRIVATE_KEY
    // describe a real, enabled app and returns its public slug for the
    // installation link. If GitHub echoes client_id we can also detect a
    // mismatch between the OAuth client and the App used for installations.
    if (envHasAppCredentials(c.env)) {
      try {
        const appJwt = await githubAppJwt(c.env);
        const appDetail = await githubApiDetail(`Bearer ${appJwt}`, "/app");
        lastDetail = appDetail;
        if (appDetail.ok && appDetail.body && typeof appDetail.body === "object") {
          const appInfo = appDetail.body as { slug?: unknown; client_id?: unknown };
          if (typeof appInfo.slug === "string" && appInfo.slug) appSlug = appInfo.slug;
          if (typeof appInfo.client_id === "string" && appInfo.client_id &&
              c.env.GITHUB_APP_CLIENT_ID && appInfo.client_id !== c.env.GITHUB_APP_CLIENT_ID) {
            clientConfigMismatch = true;
          }
        }
      } catch (error) {
        console.error("GitHub repositories: app identity check failed:", error instanceof Error ? error.message : "unknown error");
      }
    }

    // GET /user/installations uses the user access token and lists only
    // installations of the App that issued that token. Paginate honestly.
    const MAX_INSTALLATION_PAGES = 10;
    const MAX_INSTALLATIONS = 50;
    for (let page = 1; page <= MAX_INSTALLATION_PAGES && installations.length < MAX_INSTALLATIONS; page++) {
      const detail = await githubApiDetail(token, `/user/installations?per_page=100&page=${page}`);
      lastDetail = detail;
      if (!detail.ok) return githubListErrorResponse(c, detail, "list GitHub App installations");
      const data = detail.body as { installations?: Array<{ id?: unknown; account?: { login?: unknown }; repository_selection?: unknown; suspended_at?: unknown }> } | null;
      const rows = data?.installations ?? [];
      for (const row of rows) {
        if (installations.length >= MAX_INSTALLATIONS) break;
        if (!Number.isSafeInteger(row.id)) continue;
        installations.push({
          id: row.id as number,
          account: typeof row.account?.login === "string" ? row.account.login : null,
          repositorySelection: typeof row.repository_selection === "string" ? row.repository_selection : null,
          suspended: typeof row.suspended_at === "string" && row.suspended_at.length > 0,
          permissionIssues: [],
        });
      }
      if (rows.length < 100) break;
    }

    if (installations.length === 0) {
      const installationUrl = appSlug
        ? `https://github.com/apps/${encodeURIComponent(appSlug)}/installations/new`
        : (c.env.GITHUB_APP_SLUG ? `https://github.com/apps/${encodeURIComponent(c.env.GITHUB_APP_SLUG)}/installations/new` : null);
      const mismatchNotice = clientConfigMismatch
        ? " Additionally, the configured GITHUB_APP_CLIENT_ID does not match the GitHub App identified by GITHUB_APP_ID; fix this configuration before reconnecting."
        : "";
      return c.json({
        repositories,
        installations,
        installationErrors,
        app: { slug: appSlug, installationUrl, clientConfigMismatch: clientConfigMismatch || undefined },
        github: githubDetailPayload(lastDetail),
        message: `The connected GitHub account has no Nexora GitHub App installations. OAuth authorization alone does not grant repository access: install the GitHub App${installationUrl ? ` at ${installationUrl}` : ""} and grant it access to the repositories you want to deploy.${mismatchNotice}`,
      });
    }

    // Per-installation repository discovery with pagination. Errors are
    // surfaced per installation instead of silently skipped.
    const MAX_REPO_PAGES = 10;
    for (const installation of installations) {
      let pagesFetched = 0;
      let page = 1;
      while (pagesFetched < MAX_REPO_PAGES) {
        const detail = await githubApiDetail(token, `/user/installations/${installation.id}/repositories?per_page=100&page=${page}`);
        lastDetail = detail;
        if (!detail.ok) {
          const upstream = githubErrorMessage(detail.body);
          const rateLimited = detail.status === 403 && detail.rateLimitRemaining === 0;
          installationErrors.push({
            installationId: installation.id,
            account: installation.account,
            status: detail.status,
            message: rateLimited
              ? "GitHub API rate limit exceeded while listing repositories."
              : detail.status === 401
                ? "GitHub rejected the stored authorization for this installation."
                : detail.status === 403 && upstream && /not accessible/i.test(upstream)
                  ? "The stored authorization cannot list this installation's repositories. Reconnect the Nexora GitHub App so the user token is issued by the same App."
                  : upstream ?? `GitHub returned ${detail.status} while listing repositories.`,
            requestId: detail.requestId ?? undefined,
          });
          break;
        }
        const data = detail.body as { repositories?: Array<{ id?: unknown; name?: unknown; full_name?: unknown; private?: unknown; default_branch?: unknown; html_url?: unknown; owner?: { login?: unknown } }> } | null;
        const rows = data?.repositories ?? [];
        for (const repo of rows) {
          if (!Number.isSafeInteger(repo.id) || typeof repo.full_name !== "string" ||
              typeof repo.name !== "string" || typeof repo.default_branch !== "string") continue;
          repositories.push({
            id: repo.id as number, name: repo.name, fullName: repo.full_name,
            private: Boolean(repo.private), defaultBranch: repo.default_branch,
            htmlUrl: typeof repo.html_url === "string" ? repo.html_url : `https://github.com/${repo.full_name}`,
            installationId: installation.id,
            owner: typeof repo.owner?.login === "string" ? repo.owner.login : installation.account ?? "",
          });
        }
        if (rows.length < 100) break;
        page++;
        pagesFetched++;
      }
    }

    // Verify App-level installation permissions with the App JWT so missing
    // Metadata/Contents access is reported precisely instead of surfacing as
    // a generic repository-list failure.
    if (envHasAppCredentials(c.env)) {
      for (const installation of installations.slice(0, 25)) {
        try {
          const appJwt = await githubAppJwt(c.env);
          const detail = await githubApiDetail(`Bearer ${appJwt}`, `/app/installations/${installation.id}`);
          lastDetail = detail;
          if (!detail.ok || !detail.body || typeof detail.body !== "object") continue;
          const info = detail.body as { permissions?: Record<string, unknown>; suspended_at?: unknown };
          const permissions = info.permissions ?? {};
          if (permissions.metadata !== "read") installation.permissionIssues.push("metadata:read");
          if (permissions.contents !== "read") installation.permissionIssues.push("contents:read");
          if (typeof info.suspended_at === "string" && info.suspended_at) installation.suspended = true;
        } catch (error) {
          console.error("GitHub repositories: installation permission check failed:", error instanceof Error ? error.message : "unknown error");
        }
      }
    }

    const installationUrl = appSlug
      ? `https://github.com/apps/${encodeURIComponent(appSlug)}/installations/new`
      : (c.env.GITHUB_APP_SLUG ? `https://github.com/apps/${encodeURIComponent(c.env.GITHUB_APP_SLUG)}/installations/new` : null);
    return c.json({
      repositories,
      installations,
      installationErrors,
      app: { slug: appSlug, installationUrl, clientConfigMismatch: clientConfigMismatch || undefined },
      github: githubDetailPayload(lastDetail),
      message: installationErrors.length > 0
        ? "Some installations could not be listed. Their errors are reported in installationErrors."
        : undefined,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error("GitHub repositories: discovery failed:", detail);
    return c.json({
      error: "github_unreachable",
      message: "GitHub could not be reached while listing repositories. Check network connectivity and try again.",
      github: githubDetailPayload(lastDetail),
    }, 502);
  }
});

// Maps a failed GitHub API response during installation/repository listing to
// a specific, actionable API error. Request ids and rate-limit headers are
// surfaced safely; tokens and authorization headers never leave the server.
function githubListErrorResponse(c: { json: (body: unknown, status?: number) => Response }, detail: GithubApiDetail, action: string): Response {
  const upstream = githubErrorMessage(detail.body);
  const github = githubDetailPayload(detail);
  if (detail.status === 401) {
    return c.json({
      error: "github_authorization_invalid",
      message: `GitHub rejected the stored authorization with 401 while trying to ${action}. Reconnect the Nexora GitHub App to refresh it.`,
      github,
    }, 409);
  }
  if (detail.status === 403 && detail.rateLimitRemaining === 0) {
    return c.json({
      error: "github_rate_limited",
      message: `GitHub API rate limit exceeded while trying to ${action}. Try again after the reset time.`,
      retryAfterSeconds: detail.retryAfter ?? undefined,
      github,
    }, 429);
  }
  if (detail.status === 403) {
    return c.json({
      error: "github_forbidden",
      message: `GitHub denied the request to ${action} (403)${upstream ? `: ${upstream}` : ""}. This usually means the OAuth authorization and the Nexora GitHub App are not the same App, or the user no longer has access to the installation. Reconnect the GitHub App and verify the installation.`,
      github,
    }, 403);
  }
  if (detail.status === 404) {
    return c.json({
      error: "github_not_found",
      message: `GitHub could not find the resource needed to ${action} (404). The installation may have been removed. Reconnect the GitHub App and verify the installation.`,
      github,
    }, 409);
  }
  if (detail.status === 422) {
    return c.json({
      error: "github_unprocessable",
      message: `GitHub could not process the request to ${action} (422)${upstream ? `: ${upstream}` : ""}.`,
      github,
    }, 502);
  }
  return c.json({
    error: "github_upstream",
    message: `GitHub returned ${detail.status} while trying to ${action}${upstream ? `: ${upstream}` : ""}.`,
    github,
  }, 502);
}

function envHasAppCredentials(env: Bindings): boolean {
  return Boolean(env.GITHUB_APP_ID && /^\d+$/.test(env.GITHUB_APP_ID) && env.GITHUB_APP_PRIVATE_KEY);
}

app.post("/v1/github/projects", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!identity.platformRole && identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization owner or administrator access required" }, 403);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const hostingAccountId = typeof input.hostingAccountId === "string" ? input.hostingAccountId : "";
  const repositoryId = Number(input.repositoryId);
  const installationId = Number(input.installationId);
  const repositoryFullName = typeof input.repositoryFullName === "string" ? input.repositoryFullName.trim() : "";
  const branch = typeof input.productionBranch === "string" ? input.productionBranch.trim() : "";
  const rootDirectory = typeof input.rootDirectory === "string" ? input.rootDirectory.trim() : ".";
  const outputDirectory = typeof input.outputDirectory === "string" ? input.outputDirectory.trim() : "dist";
  const framework = typeof input.framework === "string" ? input.framework : "auto";
  if (!hostingAccountId || !Number.isSafeInteger(repositoryId) || repositoryId <= 0 || !Number.isSafeInteger(installationId) || installationId <= 0 || !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repositoryFullName) || !/^[A-Za-z0-9._/-]{1,120}$/.test(branch) || branch.startsWith("/") || branch.includes("..") || !/^[A-Za-z0-9._/-]{1,160}$/.test(rootDirectory) || rootDirectory.startsWith("/") || rootDirectory.split("/").includes("..") || !/^[A-Za-z0-9._/-]{1,160}$/.test(outputDirectory) || outputDirectory.startsWith("/") || outputDirectory.split("/").includes("..") || !["auto", "static", "vite", "react", "vue", "astro", "next-static"].includes(framework)) {
    return c.json({ message: "Invalid repository, branch, directory, framework, or hosting account configuration." }, 400);
  }
  const account = identity.platformRole
    ? await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(hostingAccountId, identity.organizationId).first<{ id: string }>()
    : await c.env.DB.prepare(
        `SELECT a.id FROM hosting_accounts a JOIN hosting_account_memberships m ON m.hosting_account_id = a.id AND m.organization_id = a.organization_id WHERE a.id = ? AND a.organization_id = ? AND a.status = 'ACTIVE' AND m.user_id = ? AND m.status = 'ACTIVE' AND m.role IN ('ACCOUNT_OWNER', 'ACCOUNT_ADMIN', 'ACCOUNT_DEVELOPER') LIMIT 1`,
      ).bind(hostingAccountId, identity.organizationId, identity.id).first<{ id: string }>();
  if (!account) return c.json({ message: "Choose an active hosting account in this workspace." }, 404);
  const connection = await c.env.DB.prepare("SELECT id FROM github_connections WHERE organization_id = ? LIMIT 1").bind(identity.organizationId).first<{ id: string }>();
  if (!connection) return c.json({ message: "Connect GitHub first." }, 409);
  try {
    const token = await githubAccessToken(c.env, c.env.DB, identity.organizationId);
    const installationResponse = await githubApi(token, `/user/installations/${installationId}/repositories?per_page=100`);
    if (!installationResponse.ok) return c.json({ message: "GitHub App installation is not accessible to this workspace." }, 403);
    const installationData = await installationResponse.json() as { repositories?: Array<{ id: number; full_name: string; default_branch: string }> };
    const repo = (installationData.repositories ?? []).find((item) => item.id === repositoryId);
    if (!repo || repo.full_name?.toLowerCase() !== repositoryFullName.toLowerCase()) return c.json({ message: "Repository does not belong to the selected GitHub App installation." }, 400);
    const id = crypto.randomUUID();
    await c.env.DB.prepare(
      `INSERT INTO github_projects (id, organization_id, hosting_account_id, github_connection_id, github_repository_id, repository_full_name, github_installation_id, production_branch, root_directory, output_directory, framework, status)
       VALUES (?, ?, ?, (SELECT id FROM github_connections WHERE organization_id = ?), ?, ?, ?, ?, ?, ?, ?, 'configured')`
    ).bind(id, identity.organizationId, hostingAccountId, identity.organizationId, String(repositoryId), repo.full_name, String(installationId), branch || repo.default_branch || "main", rootDirectory || ".", outputDirectory || "dist", framework).run();
    await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'github.project_configured', 'github_project', ?, ?)")
      .bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ repository: repo.full_name, hostingAccountId })).run();
    return c.json({ project: { id, repositoryFullName: repo.full_name, productionBranch: branch || repo.default_branch || "main", framework, outputDirectory, status: "configured" }, message: "Repository linked. Build execution will be enabled after the isolated build worker is deployed." }, 201);
  } catch (error) {
    const message = error instanceof Error && /UNIQUE constraint failed/.test(error.message) ? "This hosting account already has a GitHub project linked." : "Unable to configure the GitHub project.";
    return c.json({ message }, 409);
  }
});

app.get("/v1/github/projects", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = identity.platformRole
    ? await c.env.DB.prepare(
        `SELECT id, hosting_account_id AS hostingAccountId, repository_full_name AS repositoryFullName, production_branch AS productionBranch, root_directory AS rootDirectory, output_directory AS outputDirectory, framework, auto_deploy AS autoDeploy, status, created_at AS createdAt FROM github_projects WHERE organization_id = ? ORDER BY created_at DESC`,
      ).bind(identity.organizationId).all()
    : await c.env.DB.prepare(
        `SELECT p.id, p.hosting_account_id AS hostingAccountId, p.repository_full_name AS repositoryFullName, p.production_branch AS productionBranch, p.root_directory AS rootDirectory, p.output_directory AS outputDirectory, p.framework, p.auto_deploy AS autoDeploy, p.status, p.created_at AS createdAt FROM github_projects p JOIN hosting_account_memberships m ON m.hosting_account_id = p.hosting_account_id AND m.organization_id = p.organization_id WHERE p.organization_id = ? AND m.user_id = ? AND m.status = 'ACTIVE' ORDER BY p.created_at DESC`,
      ).bind(identity.organizationId, identity.id).all();
  return c.json({ projects: result.results ?? [] });
});

// ---------------------------------------------------------------------------
// Nexora Deploy: framework presets, detection, and environment variables.
//
// Framework presets are the single source of truth for build commands and
// output directories; detection inspects a repository's git tree and
// package.json to suggest one. Environment variables are encrypted at rest
// with AES-GCM under DEPLOY_ENV_ENCRYPTION_KEY (independent from the GitHub
// token key so credentials rotate separately) and are never returned in API
// responses — only metadata is exposed.
// ---------------------------------------------------------------------------

type FrameworkPreset = {
  slug: "static" | "vite" | "react" | "vue" | "astro" | "next-static";
  label: string;
  description: string;
  requiresBuild: boolean;
  installCommand: string | null;
  buildCommand: string | null;
  outputDirectory: string;
};

const FRAMEWORK_PRESETS: FrameworkPreset[] = [
  {
    slug: "static",
    label: "Static site",
    description: "Plain HTML/CSS/JS served as uploaded. No build step.",
    requiresBuild: false,
    installCommand: null,
    buildCommand: null,
    outputDirectory: ".",
  },
  {
    slug: "vite",
    label: "Vite",
    description: "Vite or Vue + Vite single-page application.",
    requiresBuild: true,
    installCommand: "npm ci",
    buildCommand: "npm run build",
    outputDirectory: "dist",
  },
  {
    slug: "react",
    label: "React (Create React App)",
    description: "React app scaffolded with react-scripts.",
    requiresBuild: true,
    installCommand: "npm ci",
    buildCommand: "npm run build",
    outputDirectory: "build",
  },
  {
    slug: "vue",
    label: "Vue CLI",
    description: "Vue application scaffolded with @vue/cli-service.",
    requiresBuild: true,
    installCommand: "npm ci",
    buildCommand: "npm run build",
    outputDirectory: "dist",
  },
  {
    slug: "astro",
    label: "Astro (static output)",
    description: "Astro site built to a fully static output directory.",
    requiresBuild: true,
    installCommand: "npm ci",
    buildCommand: "npm run build",
    outputDirectory: "dist",
  },
  {
    slug: "next-static",
    label: "Next.js (static export)",
    description: "Next.js with output: 'export' producing a static out/ directory.",
    requiresBuild: true,
    installCommand: "npm ci",
    buildCommand: "npm run build",
    outputDirectory: "out",
  },
];

app.get("/v1/deploy/framework-presets", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  return c.json({ presets: FRAMEWORK_PRESETS });
});

function deployEnvEncryptionKey(env: Bindings): Uint8Array {
  const value = env.DEPLOY_ENV_ENCRYPTION_KEY ?? "";
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error("Deploy environment variable encryption is not configured");
  return new Uint8Array(value.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
}

const DEPLOY_ENV_CONFIG_REQUIREMENTS =
  "DEPLOY_ENV_ENCRYPTION_KEY (64 hex chars) must be configured before environment variables can be stored.";

async function encryptDeployEnvValue(env: Bindings, plaintext: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", deployEnvEncryptionKey(env), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: base64(iv), ciphertext: base64(new Uint8Array(ciphertext)) };
}

async function decryptDeployEnvValue(env: Bindings, ciphertext: string, iv: string): Promise<string> {
  const decode = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", deployEnvEncryptionKey(env), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(iv) }, key, decode(ciphertext));
  return new TextDecoder().decode(plaintext);
}

// Loads a GitHub project for the caller with the same access model as
// POST /v1/github/projects: platform staff get organization-wide access,
// customers need an ACTIVE membership on the linked hosting account with the
// OWNER/ADMIN/DEVELOPER role. Returns null when the project does not exist
// in the caller's workspace (never leaks existence across tenants).
async function deployProjectForIdentity(
  db: D1Database,
  identity: { id: string; organizationId: string; platformRole: string | null },
  projectId: string,
): Promise<{ id: string; organization_id: string } | null> {
  if (identity.platformRole) {
    return db.prepare("SELECT id, organization_id FROM github_projects WHERE id = ? AND organization_id = ? LIMIT 1")
      .bind(projectId, identity.organizationId).first<{ id: string; organization_id: string }>();
  }
  return db.prepare(
    `SELECT p.id, p.organization_id FROM github_projects p
     JOIN hosting_accounts a ON a.id = p.hosting_account_id AND a.organization_id = p.organization_id AND a.status = 'ACTIVE'
     JOIN hosting_account_memberships m ON m.hosting_account_id = p.hosting_account_id AND m.organization_id = p.organization_id
     WHERE p.id = ? AND p.organization_id = ? AND m.user_id = ? AND m.status = 'ACTIVE'
       AND m.role IN ('ACCOUNT_OWNER', 'ACCOUNT_ADMIN', 'ACCOUNT_DEVELOPER')
     LIMIT 1`,
  ).bind(projectId, identity.organizationId, identity.id).first<{ id: string; organization_id: string }>();
}

// Posts to the content API are avoided; the trees API plus the contents API
// for package.json give detection everything it needs.
type DetectionEvidence = { source: string; detail: string };

function detectFrameworkFromRepository(
  treePaths: string[],
  treeTruncated: boolean,
  packageJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> } | null,
): { framework: FrameworkPreset["slug"]; requiresBuild: boolean; installCommand: string | null; buildCommand: string | null; outputDirectory: string; detectedFrom: string; evidence: DetectionEvidence[] } {
  const evidence: DetectionEvidence[] = [];
  const rootFiles = new Set(treePaths.filter((path) => !path.includes("/")));
  const dependencies = { ...(packageJson?.dependencies ?? {}), ...(packageJson?.devDependencies ?? {}) };

  if (packageJson) {
    evidence.push({ source: "package.json", detail: "parsed dependencies" });
  }
  for (const rootFile of ["next.config.js", "next.config.mjs", "next.config.ts"]) {
    if (rootFiles.has(rootFile)) evidence.push({ source: "root-files", detail: rootFile });
  }
  for (const rootFile of ["astro.config.mjs", "astro.config.js", "astro.config.ts"]) {
    if (rootFiles.has(rootFile)) evidence.push({ source: "root-files", detail: rootFile });
  }
  for (const rootFile of ["vite.config.js", "vite.config.mjs", "vite.config.ts"]) {
    if (rootFiles.has(rootFile)) evidence.push({ source: "root-files", detail: rootFile });
  }

  const pick = (slug: FrameworkPreset["slug"], detectedFrom: string): {
    framework: FrameworkPreset["slug"]; requiresBuild: boolean; installCommand: string | null; buildCommand: string | null; outputDirectory: string; detectedFrom: string; evidence: DetectionEvidence[];
  } => {
    const preset = FRAMEWORK_PRESETS.find((item) => item.slug === slug)!;
    return {
      framework: preset.slug,
      requiresBuild: preset.requiresBuild,
      installCommand: preset.installCommand,
      buildCommand: preset.buildCommand,
      outputDirectory: preset.outputDirectory,
      detectedFrom,
      evidence,
    };
  };

  if (dependencies.next) return pick("next-static", "package.json:dependencies:next");
  if (dependencies.astro || rootFiles.has("astro.config.mjs") || rootFiles.has("astro.config.js") || rootFiles.has("astro.config.ts")) {
    return pick("astro", dependencies.astro ? "package.json:dependencies:astro" : "root-files:astro.config");
  }
  if (dependencies["react-scripts"]) return pick("react", "package.json:dependencies:react-scripts");
  if (dependencies["@vue/cli-service"]) return pick("vue", "package.json:dependencies:@vue/cli-service");
  if (dependencies.vue && dependencies.vite) return pick("vue", "package.json:dependencies:vue+vite");
  if (dependencies.vite || rootFiles.has("vite.config.js") || rootFiles.has("vite.config.mjs") || rootFiles.has("vite.config.ts")) {
    return pick("vite", dependencies.vite ? "package.json:dependencies:vite" : "root-files:vite.config");
  }
  if (packageJson) {
    evidence.push({ source: "package.json", detail: "no recognized framework in dependencies" });
  }
  if (treeTruncated) evidence.push({ source: "git-tree", detail: "tree listing truncated by GitHub; detection used the first page" });
  if (!packageJson && rootFiles.has("index.html")) evidence.push({ source: "root-files", detail: "index.html without package.json" });

  const preset = FRAMEWORK_PRESETS.find((item) => item.slug === "static")!;
  return {
    framework: preset.slug,
    requiresBuild: preset.requiresBuild,
    installCommand: preset.installCommand,
    buildCommand: preset.buildCommand,
    outputDirectory: preset.outputDirectory,
    detectedFrom: packageJson ? "package.json:fallback" : rootFiles.has("index.html") ? "root-files:index.html" : "root-files:fallback",
    evidence,
  };
}

app.post("/v1/github/projects/detect-framework", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const repositoryId = Number(input.repositoryId);
  const installationId = Number(input.installationId);
  const repositoryFullName = typeof input.repositoryFullName === "string" ? input.repositoryFullName.trim() : "";
  const branch = typeof input.branch === "string" ? input.branch.trim() : "";
  if (!Number.isSafeInteger(repositoryId) || repositoryId <= 0 || !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repositoryFullName) || repositoryFullName.includes("..") || !/^[A-Za-z0-9._/-]{1,120}$/.test(branch) || branch.startsWith("/") || branch.includes("..")) {
    return c.json({ message: "Invalid repository, branch, or installation configuration." }, 400);
  }

  let token: string;
  try {
    token = await githubAccessToken(c.env, c.env.DB, identity.organizationId);
  } catch {
    return c.json({ message: "Connect GitHub first." }, 409);
  }

  const treeDetail = await githubApiDetail(token, `/repos/${repositoryFullName}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (!treeDetail.ok) {
    if (treeDetail.status === 404) return c.json({ message: "Repository or branch not found in the connected GitHub account.", ...(githubDetailPayload(treeDetail) as object) }, 404);
    if (treeDetail.status === 403 && treeDetail.rateLimitRemaining === 0) {
      return c.json({ message: "GitHub API rate limit exhausted. Try again after the reset time.", ...(githubDetailPayload(treeDetail) as object) }, 429);
    }
    return c.json({ message: githubErrorMessage(treeDetail.body) ?? "Unable to inspect the repository tree.", ...(githubDetailPayload(treeDetail) as object) }, 502);
  }
  const tree = treeDetail.body as { tree?: Array<{ path?: string; type?: string }>; truncated?: boolean };
  const treePaths = (tree.tree ?? []).filter((entry) => entry.type === "blob" && typeof entry.path === "string").map((entry) => entry.path as string);

  let packageJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> } | null = null;
  if (treePaths.includes("package.json")) {
    const contentDetail = await githubApiDetail(token, `/repos/${repositoryFullName}/contents/package.json?ref=${encodeURIComponent(branch)}`);
    if (contentDetail.ok && contentDetail.body && typeof (contentDetail.body as { content?: unknown }).content === "string") {
      try {
        const decoded = new TextDecoder().decode(Uint8Array.from(atob((contentDetail.body as { content: string }).content.replace(/\n/g, "")), (char) => char.charCodeAt(0)));
        packageJson = JSON.parse(decoded) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      } catch {
        packageJson = null;
      }
    } else if (!contentDetail.ok && contentDetail.status !== 404) {
      return c.json({ message: githubErrorMessage(contentDetail.body) ?? "Unable to read package.json.", ...(githubDetailPayload(contentDetail) as object) }, 502);
    }
  }

  const detection = detectFrameworkFromRepository(treePaths, tree.truncated === true, packageJson);
  return c.json({ repositoryFullName, branch, ...detection });
});

app.get("/v1/github/projects/:projectId/env-vars", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  if (!/^[0-9a-fA-F-]{36}$/.test(projectId)) return c.json({ message: "Invalid project id" }, 400);
  const project = await deployProjectForIdentity(c.env.DB, identity, projectId);
  if (!project) return c.json({ message: "Project not found in this workspace." }, 404);
  const rows = await c.env.DB.prepare(
    `SELECT id, key_name, environment, target, is_secret, created_at, updated_at
     FROM application_env_vars WHERE project_id = ? AND organization_id = ?
     ORDER BY key_name ASC, environment ASC`,
  ).bind(projectId, project.organization_id).all<{
    id: string; key_name: string; environment: string; target: string; is_secret: number; created_at: string; updated_at: string;
  }>();
  // Values (or their ciphertext) are intentionally never returned.
  return c.json({
    variables: (rows.results ?? []).map((row) => ({
      id: row.id,
      keyName: row.key_name,
      environment: row.environment,
      target: row.target,
      isSecret: row.is_secret === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  });
});

app.post("/v1/github/projects/:projectId/env-vars", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  if (!/^[0-9a-fA-F-]{36}$/.test(projectId)) return c.json({ message: "Invalid project id" }, 400);
  const project = await deployProjectForIdentity(c.env.DB, identity, projectId);
  if (!project) return c.json({ message: "Project not found in this workspace." }, 404);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const keyName = typeof input.key === "string" ? input.key.trim() : "";
  const value = typeof input.value === "string" ? input.value : "";
  const environment = typeof input.environment === "string" ? input.environment : "production";
  const target = typeof input.target === "string" ? input.target : "runtime";
  const isSecret = input.isSecret === undefined ? true : input.isSecret === true;
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(keyName)) {
    return c.json({ message: "Variable keys must start with a letter or underscore and contain only letters, digits, and underscores (max 128 characters)." }, 400);
  }
  if (value.length === 0 || value.length > 32_768) {
    return c.json({ message: "Variable values must be between 1 and 32768 characters." }, 400);
  }
  if (environment !== "production" && environment !== "preview" && environment !== "development") {
    return c.json({ message: "Environment must be production, preview, or development." }, 400);
  }
  if (target !== "build" && target !== "runtime" && target !== "both") {
    return c.json({ message: "Target must be build, runtime, or both." }, 400);
  }

  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) AS total FROM application_env_vars WHERE project_id = ? AND organization_id = ?",
  ).bind(projectId, project.organization_id).first<{ total: number }>();
  if ((count?.total ?? 0) >= 128) {
    return c.json({ message: "This project already has 128 environment variables. Remove one before adding another." }, 409);
  }

  let encrypted: { iv: string; ciphertext: string };
  try {
    encrypted = await encryptDeployEnvValue(c.env, value);
  } catch {
    return c.json({ message: DEPLOY_ENV_CONFIG_REQUIREMENTS }, 503);
  }
  const id = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO application_env_vars (id, organization_id, project_id, key_name, environment, target, encrypted_value, value_iv, is_secret, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, project.organization_id, projectId, keyName, environment, target, encrypted.ciphertext, encrypted.iv, isSecret ? 1 : 0, identity.id).run();
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return c.json({ message: `A variable named ${keyName} already exists for the ${environment} environment.` }, 409);
    }
    throw error;
  }
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'deploy.env_var.created', 'github_project', ?, ?)")
    .bind(crypto.randomUUID(), project.organization_id, identity.id, projectId, JSON.stringify({ key: keyName, environment, target, isSecret })).run();
  return c.json({ variable: { id, keyName, environment, target, isSecret } }, 201);
});

app.patch("/v1/github/projects/:projectId/env-vars/:envVarId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  const envVarId = c.req.param("envVarId");
  if (!/^[0-9a-fA-F-]{36}$/.test(projectId) || !/^[0-9a-fA-F-]{36}$/.test(envVarId)) return c.json({ message: "Invalid identifier" }, 400);
  const project = await deployProjectForIdentity(c.env.DB, identity, projectId);
  if (!project) return c.json({ message: "Project not found in this workspace." }, 404);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); } catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const existing = await c.env.DB.prepare(
    "SELECT id, environment, target, is_secret FROM application_env_vars WHERE id = ? AND project_id = ? AND organization_id = ? LIMIT 1",
  ).bind(envVarId, projectId, project.organization_id).first<{ id: string; environment: string; target: string; is_secret: number }>();
  if (!existing) return c.json({ message: "Variable not found." }, 404);

  const hasValue = typeof input.value === "string";
  const value = hasValue ? input.value as string : null;
  if (hasValue && (value!.length === 0 || value!.length > 32_768)) {
    return c.json({ message: "Variable values must be between 1 and 32768 characters." }, 400);
  }
  const target = typeof input.target === "string" ? input.target : existing.target;
  if (target !== "build" && target !== "runtime" && target !== "both") {
    return c.json({ message: "Target must be build, runtime, or both." }, 400);
  }
  const isSecret = input.isSecret === undefined ? existing.is_secret === 1 : input.isSecret === true;

  let encrypted: { iv: string; ciphertext: string } | null = null;
  if (hasValue) {
    try {
      encrypted = await encryptDeployEnvValue(c.env, value!);
    } catch {
      return c.json({ message: DEPLOY_ENV_CONFIG_REQUIREMENTS }, 503);
    }
  }
  const result = encrypted
    ? await c.env.DB.prepare(
        "UPDATE application_env_vars SET encrypted_value = ?, value_iv = ?, target = ?, is_secret = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ? AND organization_id = ?",
      ).bind(encrypted.ciphertext, encrypted.iv, target, isSecret ? 1 : 0, envVarId, projectId, project.organization_id).run()
    : await c.env.DB.prepare(
        "UPDATE application_env_vars SET target = ?, is_secret = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ? AND organization_id = ?",
      ).bind(target, isSecret ? 1 : 0, envVarId, projectId, project.organization_id).run();
  if (!result.meta.changes) return c.json({ message: "Variable not found." }, 404);

  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'deploy.env_var.updated', 'github_project', ?, ?)")
    .bind(crypto.randomUUID(), project.organization_id, identity.id, projectId, JSON.stringify({ id: envVarId, valueRotated: hasValue, target, isSecret })).run();
  return c.json({ variable: { id: envVarId, target, isSecret, valueRotated: hasValue } });
});

app.delete("/v1/github/projects/:projectId/env-vars/:envVarId", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  const envVarId = c.req.param("envVarId");
  if (!/^[0-9a-fA-F-]{36}$/.test(projectId) || !/^[0-9a-fA-F-]{36}$/.test(envVarId)) return c.json({ message: "Invalid identifier" }, 400);
  const project = await deployProjectForIdentity(c.env.DB, identity, projectId);
  if (!project) return c.json({ message: "Project not found in this workspace." }, 404);
  const result = await c.env.DB.prepare(
    "DELETE FROM application_env_vars WHERE id = ? AND project_id = ? AND organization_id = ?",
  ).bind(envVarId, projectId, project.organization_id).run();
  if (!result.meta.changes) return c.json({ message: "Variable not found." }, 404);
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'deploy.env_var.deleted', 'github_project', ?, ?)")
    .bind(crypto.randomUUID(), project.organization_id, identity.id, projectId, JSON.stringify({ id: envVarId })).run();
  return c.json({ deleted: true });
});



const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_OIDC_DEFAULT_AUDIENCE = "https://api.nexoraedge.digital/github-deployments";

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function verifyGitHubActionsOidc(env: Bindings, token: string): Promise<Record<string, unknown>> {
  if (token.length > 16_384) throw new Error("OIDC token is too large");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed OIDC token");
  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0]))) as Record<string, unknown>;
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1]))) as Record<string, unknown>;
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("Unsupported OIDC signing algorithm");
  if (claims.iss !== GITHUB_OIDC_ISSUER) throw new Error("Unexpected OIDC issuer");
  const expectedAudience = env.GITHUB_OIDC_AUDIENCE || GITHUB_OIDC_DEFAULT_AUDIENCE;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.length !== 1 || audiences[0] !== expectedAudience) throw new Error("Unexpected OIDC audience");

  const now = Math.floor(Date.now() / 1000);
  const exp = Number(claims.exp);
  const iat = Number(claims.iat);
  if (!Number.isFinite(exp) || !Number.isFinite(iat) || exp <= now || exp > now + 600 || iat > now + 60 || iat < now - 600) {
    throw new Error("OIDC token is expired or outside the accepted time window");
  }
  if (claims.nbf !== undefined) {
    const notBefore = Number(claims.nbf);
    if (!Number.isFinite(notBefore) || notBefore > now + 60) throw new Error("OIDC token is not active yet");
  }

  const response = await fetch(GITHUB_OIDC_ISSUER + "/.well-known/jwks", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("Unable to retrieve GitHub OIDC signing keys");
  const jwks = await response.json() as { keys?: (JsonWebKey & { kid?: string })[] };
  const jwk = (jwks.keys ?? []).find((key) => key.kid === header.kid);
  if (!jwk) throw new Error("Unknown GitHub OIDC signing key");
  const publicKey = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", publicKey, decodeBase64Url(parts[2]),
    new TextEncoder().encode(parts[0] + "." + parts[1]),
  );
  if (!valid) throw new Error("Invalid GitHub OIDC signature");
  return claims;
}


app.put("/v1/github/projects/:projectId/workflow-trust", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);

  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const workflowSha = typeof input.workflowSha === "string" ? input.workflowSha.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{40}$/.test(workflowSha)) {
    return c.json({ message: "workflowSha must be a full 40-character Git commit SHA reviewed by an administrator." }, 400);
  }

  const projectId = c.req.param("projectId");
  const updated = await c.env.DB.prepare(
    "UPDATE github_projects SET trusted_workflow_sha = ?, updated_at = datetime('now') WHERE id = ? AND organization_id = ?",
  ).bind(workflowSha, projectId, identity.organizationId).run();
  if ((updated.meta.changes ?? 0) !== 1) return c.json({ message: "GitHub project not found." }, 404);

  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'github.workflow_trust_updated', 'github_project', ?, ?)",
  ).bind(crypto.randomUUID(), identity.organizationId, identity.id, projectId, JSON.stringify({ workflowSha })).run();
  return c.json({ projectId, trustedWorkflowSha: workflowSha });
});

app.post("/v1/github/deployments/:deploymentId/oidc/exchange", async (c) => {
  const authorization = c.req.header("authorization") ?? "";
  const match = /^Bearer\s+([A-Za-z0-9._-]+)$/.exec(authorization);
  if (!match) return c.json({ message: "GitHub Actions OIDC bearer token is required." }, 401);

  let claims: Record<string, unknown>;
  try {
    claims = await verifyGitHubActionsOidc(c.env, match[1]);
  } catch (error) {
    console.warn("GitHub OIDC verification rejected:", error instanceof Error ? error.message : "invalid token");
    return c.json({ message: "GitHub Actions identity could not be verified." }, 401);
  }

  const deployment = await c.env.DB.prepare(
    "SELECT d.id, d.organization_id AS organizationId, d.project_id AS projectId, d.commit_sha AS commitSha, d.branch, d.status, p.github_repository_id AS repositoryId, p.repository_full_name AS repositoryFullName, p.trusted_workflow_sha AS trustedWorkflowSha FROM github_deployments d JOIN github_projects p ON p.id = d.project_id AND p.organization_id = d.organization_id WHERE d.id = ? LIMIT 1",
  ).bind(c.req.param("deploymentId")).first<{
    id: string; organizationId: string; projectId: string; commitSha: string; branch: string;
    status: string; repositoryId: string; repositoryFullName: string; trustedWorkflowSha: string | null;
  }>();
  if (!deployment || deployment.status !== "queued") {
    return c.json({ message: "Deployment not found or no longer accepting a runner." }, 409);
  }

  if (!deployment.trustedWorkflowSha || !/^[a-f0-9]{40}$/i.test(deployment.trustedWorkflowSha)) {
    return c.json({ message: "An administrator must approve and pin the deployment workflow revision before builds can run." }, 409);
  }
  const expectedWorkflowRef = deployment.repositoryFullName + "/.github/workflows/nexora-deploy.yml@refs/heads/" + deployment.branch;
  const runId = String(claims.run_id ?? "");
  const runAttempt = Number(claims.run_attempt);
  const workflowSha = String(claims.workflow_sha ?? "");
  if (
    claims.repository !== deployment.repositoryFullName ||
    String(claims.repository_id ?? "") !== deployment.repositoryId ||
    claims.ref !== "refs/heads/" + deployment.branch ||
    claims.sha !== deployment.commitSha ||
    claims.event_name !== "workflow_dispatch" ||
    claims.workflow_ref !== expectedWorkflowRef ||
    claims.runner_environment !== "github-hosted" ||
    !/^[a-f0-9]{40}$/i.test(workflowSha) ||
    workflowSha.toLowerCase() !== deployment.trustedWorkflowSha.toLowerCase() ||
    !/^\d{1,20}$/.test(runId) ||
    !Number.isSafeInteger(runAttempt) || runAttempt < 1 || runAttempt > 100
  ) {
    return c.json({ message: "GitHub Actions identity does not match this deployment." }, 403);
  }

  // The capability is withheld until a private R2 bucket is bound to this Worker.
  if (!c.env.ARTIFACTS) {
    return c.json({ message: "Private artifact storage is not configured; no upload capability was issued." }, 503);
  }

  const applicationRelease = await c.env.DB.prepare(
    "SELECT id, state FROM application_releases WHERE deployment_id = ? AND organization_id = ? LIMIT 1",
  ).bind(deployment.id, deployment.organizationId).first<{ id: string; state: string }>();
  if (applicationRelease && applicationRelease.state !== "queued") {
    return c.json({ message: "Application release is not waiting for its isolated builder." }, 409);
  }

  const capability = randomHex(32);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  try {
    const claimStatements = [
      c.env.DB.prepare(
        "INSERT INTO github_deployment_upload_tokens (id, token_hash, organization_id, project_id, deployment_id, repository_id, branch, commit_sha, run_id, run_attempt, expires_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM github_deployments WHERE id = ? AND organization_id = ? AND status = 'queued')",
      ).bind(
        crypto.randomUUID(), await sha256(capability), deployment.organizationId, deployment.projectId,
        deployment.id, deployment.repositoryId, deployment.branch, deployment.commitSha,
        runId, runAttempt, expiresAt, deployment.id, deployment.organizationId,
      ),
      c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'building', started_at = datetime('now'), workflow_run_id = ?, workflow_run_attempt = ?, workflow_sha = ? WHERE id = ? AND organization_id = ? AND status = 'queued'",
      ).bind(runId, runAttempt, workflowSha, deployment.id, deployment.organizationId),
    ];
    if (applicationRelease) {
      claimStatements.push(c.env.DB.prepare(
        "UPDATE application_releases SET state = 'authorized', updated_at = datetime('now') " +
        "WHERE id = ? AND organization_id = ? AND state = 'queued'",
      ).bind(applicationRelease.id, deployment.organizationId));
      claimStatements.push(c.env.DB.prepare(
        "INSERT INTO application_release_events " +
        "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
        "SELECT ?, organization_id, id, 'queued', 'authorized', 'builder', ?, 'builder_authorized', ? " +
        "FROM application_releases WHERE id = ? AND organization_id = ? AND state = 'authorized'",
      ).bind(crypto.randomUUID(), runId, JSON.stringify({ workflowSha }), applicationRelease.id, deployment.organizationId));
      claimStatements.push(c.env.DB.prepare(
        "UPDATE application_releases SET state = 'building', started_at = datetime('now'), updated_at = datetime('now') " +
        "WHERE id = ? AND organization_id = ? AND state = 'authorized'",
      ).bind(applicationRelease.id, deployment.organizationId));
      claimStatements.push(c.env.DB.prepare(
        "INSERT INTO application_release_events " +
        "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
        "SELECT ?, organization_id, id, 'authorized', 'building', 'builder', ?, 'build_started', ? " +
        "FROM application_releases WHERE id = ? AND organization_id = ? AND state = 'building'",
      ).bind(crypto.randomUUID(), runId, JSON.stringify({ workflowSha }), applicationRelease.id, deployment.organizationId));
    }
    const results = await c.env.DB.batch(claimStatements);
    if ((results[0]?.meta.changes ?? 0) !== 1 || (results[1]?.meta.changes ?? 0) !== 1 ||
        (applicationRelease && ((results[2]?.meta.changes ?? 0) !== 1 ||
          (results[3]?.meta.changes ?? 0) !== 1 || (results[4]?.meta.changes ?? 0) !== 1 ||
          (results[5]?.meta.changes ?? 0) !== 1))) {
      return c.json({ message: "A runner has already claimed this deployment or the application release could not enter building state." }, 409);
    }
  } catch {
    return c.json({ message: "This deployment already has an upload capability or could not be claimed." }, 409);
  }

  return c.json({
    uploadToken: capability,
    expiresAt,
    maxBytes: 104857600,
    contentType: "application/gzip",
  }, 201);
});


app.put("/v1/github/deployments/:deploymentId/artifact", async (c) => {
  const authorization = c.req.header("authorization") ?? "";
  const match = /^Bearer\s+([a-f0-9]{64})$/i.exec(authorization);
  if (!match) return c.json({ message: "A valid one-time upload token is required." }, 401);
  if (!c.env.ARTIFACTS) return c.json({ message: "Private artifact storage is not configured." }, 503);
  if ((c.req.header("content-type") ?? "").split(";")[0].trim().toLowerCase() !== "application/gzip") {
    return c.json({ message: "Artifact must be a gzip-compressed tar archive." }, 415);
  }

  const contentLength = Number(c.req.header("content-length"));
  const maxBytes = 100 * 1024 * 1024;
  if (!Number.isSafeInteger(contentLength) || contentLength < 1 || contentLength > maxBytes) {
    return c.json({ message: "Artifact size must be between 1 byte and 100 MiB." }, 413);
  }
  const artifactSHA256 = (c.req.header("x-artifact-sha256") ?? "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(artifactSHA256)) {
    return c.json({ message: "A lowercase SHA-256 artifact checksum is required." }, 400);
  }
  if (!c.req.raw.body) return c.json({ message: "Artifact body is required." }, 400);

  const deploymentId = c.req.param("deploymentId");
  const tokenHash = await sha256(match[1]);
  const token = await c.env.DB.prepare(
    "SELECT t.organization_id AS organizationId, t.project_id AS projectId, t.deployment_id AS deploymentId, t.commit_sha AS commitSha, d.status FROM github_deployment_upload_tokens t JOIN github_deployments d ON d.id = t.deployment_id AND d.organization_id = t.organization_id WHERE t.token_hash = ? AND t.deployment_id = ? AND t.consumed_at IS NULL AND t.expires_at > ? LIMIT 1",
  ).bind(tokenHash, deploymentId, new Date().toISOString()).first<{
    organizationId: string; projectId: string; deploymentId: string; commitSha: string; status: string;
  }>();
  if (!token || token.status !== "building") {
    return c.json({ message: "Upload token is invalid, expired, or already used." }, 401);
  }

  const consumed = await c.env.DB.prepare(
    "UPDATE github_deployment_upload_tokens SET consumed_at = datetime('now') WHERE token_hash = ? AND deployment_id = ? AND consumed_at IS NULL AND expires_at > datetime('now')",
  ).bind(tokenHash, deploymentId).run();
  if ((consumed.meta.changes ?? 0) !== 1) return c.json({ message: "Upload token has already been consumed." }, 409);

  const objectKey = "staging/" + token.organizationId + "/" + token.projectId + "/" + token.deploymentId + "/" + randomHex(16) + ".tar.gz";
  try {
    let receivedBytes = 0;
    const fixedLength = new FixedLengthStream(contentLength);
    const writer = fixedLength.writable.getWriter();
    const reader = c.req.raw.body.getReader();
    const putPromise = c.env.ARTIFACTS.put(objectKey, fixedLength.readable, {
      sha256: artifactSHA256,
      httpMetadata: { contentType: "application/gzip" },
      customMetadata: {
        organizationId: token.organizationId,
        projectId: token.projectId,
        deploymentId: token.deploymentId,
        commitSha: token.commitSha,
        artifactSha256: artifactSHA256,
      },
    });
    const pumpPromise = (async () => {
      try {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          receivedBytes += chunk.value.byteLength;
          if (receivedBytes > maxBytes || receivedBytes > contentLength) {
            throw new Error("Artifact exceeds its declared or maximum size");
          }
          await writer.write(chunk.value);
        }
        if (receivedBytes !== contentLength) throw new Error("Content-Length mismatch");
        await writer.close();
      } catch (error) {
        await writer.abort(error).catch(() => undefined);
        await reader.cancel(error).catch(() => undefined);
        throw error;
      } finally {
        reader.releaseLock();
        writer.releaseLock();
      }
    })();
    const [pumpResult, putResult] = await Promise.allSettled([pumpPromise, putPromise]);
    if (pumpResult.status === "rejected") throw pumpResult.reason;
    if (putResult.status === "rejected") throw putResult.reason;
    const storedObject = putResult.value;
    if (!storedObject || storedObject.size !== receivedBytes) {
      throw new Error("R2 stored object size does not match the received artifact");
    }
    const storedChecksum = storedObject.checksums.sha256;
    if (!storedChecksum || hex(new Uint8Array(storedChecksum)) !== artifactSHA256) {
      throw new Error("R2 stored object checksum does not match the declared artifact digest");
    }
  
    const updates = await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE github_deployments SET artifact_key = ?, artifact_bytes = ?, artifact_sha256 = ?, log_excerpt = 'Build artifact received; awaiting archive validation and publication.' WHERE id = ? AND organization_id = ? AND status = 'building' AND artifact_key IS NULL",
      ).bind(objectKey, receivedBytes, artifactSHA256, token.deploymentId, token.organizationId),
      c.env.DB.prepare(
        "UPDATE application_releases SET artifact_digest = ?, artifact_bytes = ?, state = 'artifact_uploaded', updated_at = datetime('now') " +
        "WHERE deployment_id = ? AND organization_id = ? AND state = 'building'",
      ).bind(artifactSHA256, receivedBytes, token.deploymentId, token.organizationId),
      c.env.DB.prepare(
        "INSERT INTO application_release_events " +
        "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
        "SELECT ?, organization_id, id, 'building', 'artifact_uploaded', 'builder', NULL, 'artifact_uploaded', ? " +
        "FROM application_releases WHERE deployment_id = ? AND organization_id = ? AND state = 'artifact_uploaded' " +
        "AND artifact_digest = ? AND artifact_bytes = ?",
      ).bind(crypto.randomUUID(), JSON.stringify({ bytes: receivedBytes }), token.deploymentId,
        token.organizationId, artifactSHA256, receivedBytes),
    ]);
    if (updates.some((result) => Number(result?.meta?.changes ?? 0) !== 1)) {
      throw new Error("Artifact metadata, application release state, and release audit event were not committed together");
    }
    return c.json({
      received: true,
      deploymentId: token.deploymentId,
      bytes: receivedBytes,
      applicationReleaseUpdated: Number(updates[1]?.meta?.changes ?? 0) === 1,
      applicationReleaseEventRecorded: Number(updates[2]?.meta?.changes ?? 0) === 1,
    }, 202);
  } catch (error) {
    await c.env.ARTIFACTS.delete(objectKey).catch(() => undefined);
    await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), artifact_key = NULL, " +
        "artifact_bytes = NULL, artifact_sha256 = NULL, log_excerpt = 'Artifact upload failed.' " +
        "WHERE id = ? AND organization_id = ? AND status = 'building'",
      ).bind(token.deploymentId, token.organizationId),
      c.env.DB.prepare(
        "UPDATE application_releases SET state = 'failed', finished_at = datetime('now'), failure_code = 'artifact_upload_failed', " +
        "failure_message_redacted = 'Build artifact upload failed.', updated_at = datetime('now') " +
        "WHERE deployment_id = ? AND organization_id = ? AND state IN ('building','artifact_uploaded')",
      ).bind(token.deploymentId, token.organizationId),
      c.env.DB.prepare(
        "INSERT INTO application_release_events " +
        "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
        "SELECT ?, organization_id, id, CASE WHEN artifact_digest IS NULL THEN 'building' ELSE 'artifact_uploaded' END, " +
        "'failed', 'control_plane', NULL, 'artifact_upload_failed', '{}' " +
        "FROM application_releases WHERE deployment_id = ? AND organization_id = ? AND state = 'failed' " +
        "AND failure_code = 'artifact_upload_failed' " +
        "AND NOT EXISTS (SELECT 1 FROM application_release_events e WHERE e.release_id = application_releases.id AND e.event_code = 'artifact_upload_failed')",
      ).bind(crypto.randomUUID(), token.deploymentId, token.organizationId),
    ]).catch(() => undefined);
    console.error("GitHub artifact upload failed:", error instanceof Error ? error.message : "unknown error");
    return c.json({ message: "Artifact upload failed; the one-time capability has been consumed." }, 502);
  }
});

app.post("/v1/github/projects/:projectId/deployments", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  if (!c.env.GITHUB_APP_ID || !c.env.GITHUB_APP_PRIVATE_KEY) {
    return c.json({ message: "GitHub App ID and private key are required before deployments can be dispatched." }, 503);
  }
  const project = await c.env.DB.prepare(
    `SELECT p.id, p.github_repository_id AS repositoryId, p.repository_full_name AS repositoryFullName,
            p.github_installation_id AS installationId, p.production_branch AS productionBranch,
            p.trusted_workflow_sha AS trustedWorkflowSha, p.status,
            COALESCE(NULLIF(s.output_directory, ''), p.output_directory) AS outputDirectory
     FROM github_projects p
     LEFT JOIN application_project_settings s ON s.project_id = p.id AND s.organization_id = p.organization_id
     WHERE p.id = ? AND p.organization_id = ? LIMIT 1`,
  ).bind(c.req.param("projectId"), identity.organizationId).first<{
    id: string; repositoryId: string; repositoryFullName: string; installationId: string | null;
    productionBranch: string; trustedWorkflowSha: string | null; status: string; outputDirectory: string;
  }>();
  if (!project) return c.json({ message: "GitHub project not found." }, 404);
  if (!project.installationId) return c.json({ message: "Reconnect the GitHub App and relink this repository." }, 409);
  if (!project.trustedWorkflowSha || !/^[a-f0-9]{40}$/i.test(project.trustedWorkflowSha)) {
    return c.json({ message: "Review the Nexora workflow and approve its full commit SHA before dispatching deployments." }, 409);
  }
  const runtimeAssignment = await c.env.DB.prepare(
    "SELECT s.runtime_profile_id AS runtimeProfileId, s.spec_version AS specVersion, " +
    "s.node_pool_id AS nodePoolId, rp.enabled AS runtimeEnabled, rp.profile_key AS profileKey, " +
    "rp.runtime_family AS runtimeFamily, s.build_method AS buildMethod, p.status AS poolStatus, " +
    "p.isolation_level AS isolationLevel, " +
    "(SELECT n.id FROM application_nodes n WHERE n.node_pool_id = s.node_pool_id " +
    "AND n.node_role = 'runtime' AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key IS NOT NULL ORDER BY n.last_heartbeat_at DESC, n.id LIMIT 1) AS assignedNodeId " +
    "FROM application_project_settings s " +
    "JOIN application_runtime_profiles rp ON rp.id = s.runtime_profile_id " +
    "LEFT JOIN application_node_pools p ON p.id = s.node_pool_id " +
    "WHERE s.project_id = ? AND s.organization_id = ? LIMIT 1",
  ).bind(project.id, identity.organizationId).first<{
    runtimeProfileId: string; specVersion: number; nodePoolId: string | null;
    runtimeEnabled: number; profileKey: string; runtimeFamily: string; buildMethod: string;
    poolStatus: string | null; isolationLevel: string | null; assignedNodeId: string | null;
  }>();
  // Fail closed: missing settings or any incomplete trust prerequisite blocks dispatch.
  if (!runtimeAssignment || !isRuntimeAssignmentAdmitted(runtimeAssignment)) {
    return c.json({
      message: "Application deployment is not admitted: configure an enabled runtime assigned to a ready isolated pool with an online runtime node.",
    }, 409);
  }
  // The checked-in customer workflow currently stages static artifacts only.
  // Do not dispatch OCI/managed profiles through that incompatible pipeline.
  if (runtimeAssignment.profileKey !== "static-v1" ||
      runtimeAssignment.runtimeFamily !== "static" ||
      runtimeAssignment.buildMethod !== "static") {
    return c.json({
      message: "This deployment workflow currently supports only the static-v1 runtime with static output. Other runtime profiles remain disabled until their dedicated build and execution pipelines pass acceptance.",
    }, 409);
  }
  if (typeof project.outputDirectory !== "string" ||
      !/^[A-Za-z0-9._/-]{1,160}$/.test(project.outputDirectory) ||
      project.outputDirectory.startsWith("/") ||
      project.outputDirectory.split("/").some((part) => part === "." || part === "..")) {
    return c.json({ message: "Configure a valid relative static output directory before dispatching this deployment." }, 409);
  }

  const active = await c.env.DB.prepare(
    "SELECT id FROM github_deployments WHERE project_id = ? AND status IN ('queued','cloning','installing','building','publishing') LIMIT 1",
  ).bind(project.id).first<{ id: string }>();
  if (active) return c.json({ message: "A deployment is already in progress for this project.", deploymentId: active.id }, 409);

  const deploymentId = crypto.randomUUID();
  const applicationReleaseId = crypto.randomUUID();
  let deploymentCreated = false;
  let dispatchAccepted = false;
  try {
    const token = await githubInstallationToken(c.env, project.installationId, project.repositoryId);
    const refResponse = await fetch(`https://api.github.com/repos/${project.repositoryFullName}/commits/${encodeURIComponent(project.productionBranch)}`, {
      headers: {
        Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Nexora-Control-Panel",
      },
    });
    if (!refResponse.ok) return c.json({ message: "Unable to resolve the configured production branch in GitHub." }, 502);
    const commitData = await refResponse.json() as { sha?: string; commit?: { message?: string } };
    if (!commitData.sha || !/^[a-f0-9]{40}$/i.test(commitData.sha)) return c.json({ message: "GitHub returned an invalid commit SHA." }, 502);

    const creationStatements = [
      c.env.DB.prepare(
        `INSERT INTO github_deployments (id, organization_id, project_id, commit_sha, branch, trigger_type, status, commit_message)
         VALUES (?, ?, ?, ?, ?, 'manual', 'queued', ?)`,
      ).bind(deploymentId, identity.organizationId, project.id, commitData.sha.toLowerCase(), project.productionBranch,
        (commitData.commit?.message ?? "").slice(0, 500)),
    ];
    if (runtimeAssignment && applicationReleaseId) {
      creationStatements.push(c.env.DB.prepare(
        "INSERT INTO application_releases " +
        "(id, organization_id, project_id, deployment_id, node_pool_id, runtime_profile_id, assigned_node_id, spec_version, state, source_commit_sha) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
      ).bind(applicationReleaseId, identity.organizationId, project.id, deploymentId,
        runtimeAssignment.nodePoolId, runtimeAssignment.runtimeProfileId, runtimeAssignment.assignedNodeId,
        runtimeAssignment.specVersion, commitData.sha.toLowerCase()));
      creationStatements.push(c.env.DB.prepare(
        "INSERT INTO application_release_events " +
        "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
        "VALUES (?, ?, ?, NULL, 'queued', 'user', ?, 'deployment_queued', ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, applicationReleaseId, identity.id,
        JSON.stringify({ source: "github_manual_dispatch", nodePoolId: runtimeAssignment.nodePoolId, assignedNodeId: runtimeAssignment.assignedNodeId })));
    }
    const created = await c.env.DB.batch(creationStatements);
    if (Number(created[0]?.meta?.changes ?? 0) !== 1 ||
        (runtimeAssignment && Number(created[1]?.meta?.changes ?? 0) !== 1)) {
      throw new Error("Unable to create the deployment and its application release atomically");
    }
    deploymentCreated = true;

    const workflowPath = ".github/workflows/nexora-deploy.yml";
    const dispatch = await fetch(
      `https://api.github.com/repos/${project.repositoryFullName}/actions/workflows/${encodeURIComponent(workflowPath)}/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
          "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "Nexora-Control-Panel",
        },
        body: JSON.stringify({
          ref: project.productionBranch,
          inputs: {
            deployment_id: deploymentId,
            commit_sha: commitData.sha,
            output_directory: project.outputDirectory,
          },
        }),
      },
    );
    if (dispatch.status !== 204) {
      await c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), log_excerpt = ? WHERE id = ? AND organization_id = ? AND status = 'queued'",
      ).bind(`GitHub workflow dispatch rejected (HTTP ${dispatch.status}).`, deploymentId, identity.organizationId).run();
      if (applicationReleaseId) {
        await c.env.DB.batch([
          c.env.DB.prepare(
            "UPDATE application_releases SET state = 'failed', finished_at = datetime('now'), failure_code = 'workflow_dispatch_rejected', " +
            "failure_message_redacted = 'GitHub workflow dispatch was rejected.', updated_at = datetime('now') " +
            "WHERE id = ? AND organization_id = ? AND state = 'queued'",
          ).bind(applicationReleaseId, identity.organizationId),
          c.env.DB.prepare(
            "INSERT INTO application_release_events " +
            "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
            "SELECT ?, organization_id, id, 'queued', 'failed', 'control_plane', NULL, 'workflow_dispatch_rejected', '{}' " +
            "FROM application_releases WHERE id = ? AND organization_id = ? AND state = 'failed' " +
            "AND NOT EXISTS (SELECT 1 FROM application_release_events e WHERE e.release_id = application_releases.id AND e.event_code = 'workflow_dispatch_rejected')",
          ).bind(crypto.randomUUID(), applicationReleaseId, identity.organizationId),
        ]);
      }
      return c.json({
        message: dispatch.status === 404
          ? "Add .github/workflows/nexora-deploy.yml to this repository and grant the Nexora GitHub App Actions: write permission."
          : "GitHub did not accept the deployment workflow dispatch.",
        deploymentId,
      }, dispatch.status === 404 ? 409 : 502);
    }

    dispatchAccepted = true;
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE github_projects SET status = 'building', updated_at = datetime('now') WHERE id = ? AND organization_id = ?")
        .bind(project.id, identity.organizationId),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'github.deployment_dispatched', 'github_deployment', ?, ?)")
        .bind(crypto.randomUUID(), identity.organizationId, identity.id, deploymentId,
          JSON.stringify({ repository: project.repositoryFullName, branch: project.productionBranch, commitSha: commitData.sha })),
    ]);
    return c.json({
      deployment: { id: deploymentId, commitSha: commitData.sha, branch: project.productionBranch, status: "queued" },
      applicationRelease: applicationReleaseId ? {
        id: applicationReleaseId,
        deploymentId,
        nodePoolId: runtimeAssignment?.nodePoolId,
        assignedNodeId: runtimeAssignment?.assignedNodeId,
        state: "queued",
      } : null,
      message: "GitHub Actions accepted the workflow dispatch. Application releases remain gated until the isolated runtime validates and publishes the artifact.",
    }, 202);
  } catch (error) {
    if (deploymentCreated && !dispatchAccepted) {
      await c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), log_excerpt = 'GitHub did not accept the workflow dispatch.' WHERE id = ? AND organization_id = ? AND status = 'queued'",
      ).bind(deploymentId, identity.organizationId).run().catch(() => undefined);
      if (applicationReleaseId) {
        await c.env.DB.batch([
          c.env.DB.prepare(
            "UPDATE application_releases SET state = 'failed', finished_at = datetime('now'), failure_code = 'workflow_dispatch_error', " +
            "failure_message_redacted = 'GitHub workflow dispatch did not complete.', updated_at = datetime('now') " +
            "WHERE id = ? AND organization_id = ? AND state = 'queued'",
          ).bind(applicationReleaseId, identity.organizationId),
          c.env.DB.prepare(
            "INSERT INTO application_release_events " +
            "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
            "SELECT ?, organization_id, id, 'queued', 'failed', 'control_plane', NULL, 'workflow_dispatch_error', '{}' " +
            "FROM application_releases WHERE id = ? AND organization_id = ? AND state = 'failed' " +
            "AND NOT EXISTS (SELECT 1 FROM application_release_events e WHERE e.release_id = application_releases.id AND e.event_code = 'workflow_dispatch_error')",
          ).bind(crypto.randomUUID(), applicationReleaseId, identity.organizationId),
        ]).catch(() => undefined);
      }
    }
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error("GitHub deployment dispatch failed:", detail);
    if (/UNIQUE constraint failed/i.test(detail)) {
      return c.json({ message: "A deployment is already queued or running for this project." }, 409);
    }
    return c.json({ message: "Unable to dispatch the GitHub deployment. Check the GitHub App installation and permissions.", deploymentId: deploymentCreated ? deploymentId : undefined }, 502);
  }
});


// Runtime catalog is metadata only. Disabled profiles cannot be selected for execution.
app.get("/v1/applications/runtime-profiles", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const rows = await c.env.DB.prepare(
    `SELECT id, runtime_family AS runtimeFamily, profile_key AS profileKey,
            display_name AS displayName, profile_version AS profileVersion,
            execution_kind AS executionKind, default_port AS defaultPort,
            enabled
     FROM application_runtime_profiles
     ORDER BY runtime_family, profile_key`,
  ).all<{
    id: string; runtimeFamily: string; profileKey: string; displayName: string;
    profileVersion: number; executionKind: string; defaultPort: number | null; enabled: number;
  }>();
  return c.json({
    profiles: (rows.results ?? []).map((profile) => ({
      ...profile,
      enabled: profile.enabled === 1,
      selectable: profile.enabled === 1,
    })),
    executionEnabled: false,
    message: "Runtime execution remains disabled until isolated builders and application nodes pass platform acceptance tests.",
  });
});

app.put("/v1/applications/projects/:projectId/settings", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (identity.role !== "OWNER" && identity.role !== "ADMIN") return c.json({ message: "Organization administrator access required" }, 403);

  const projectId = c.req.param("projectId");
  const project = await c.env.DB.prepare(
    `SELECT p.id, hp.app_cpu_millis AS appCpuMillis,
            hp.app_memory_mib AS appMemoryMiB,
            hp.app_disk_mib AS appDiskMiB,
            hp.app_process_limit AS appProcessLimit,
            hp.disk_limit_bytes AS accountDiskLimitBytes
     FROM github_projects p
     JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = p.organization_id
     JOIN hosting_plans hp ON hp.id = h.plan_id AND hp.organization_id = p.organization_id
     WHERE p.id = ? AND p.organization_id = ?
       AND (? = 1 OR EXISTS (
         SELECT 1 FROM hosting_account_memberships m
         WHERE m.hosting_account_id = p.hosting_account_id
           AND m.organization_id = p.organization_id
           AND m.user_id = ? AND m.status = 'ACTIVE'
           AND m.role IN ('ACCOUNT_OWNER', 'ACCOUNT_ADMIN')
       ))
     LIMIT 1`,
  ).bind(projectId, identity.organizationId, identity.platformRole ? 1 : 0, identity.id).first<{
    id: string; appCpuMillis: number; appMemoryMiB: number;
    appDiskMiB: number; appProcessLimit: number; accountDiskLimitBytes: number;
  }>();
  if (!project) return c.json({ message: "GitHub project not found." }, 404);

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ message: "Request body must be valid JSON." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return c.json({ message: "Request body must be a JSON object." }, 400);
  }

  const allowed = new Set([
    "runtimeProfileId", "buildMethod", "buildContext", "buildCommand",
    "outputDirectory", "startCommand", "listenPort", "healthCheckPath",
    "cpuMillis", "memoryMiB", "diskMiB", "processLimit",
  ]);
  if (Object.keys(body).some((key) => !allowed.has(key))) {
    return c.json({ message: "Request contains unsupported settings." }, 400);
  }

  const runtimeProfileId = typeof body.runtimeProfileId === "string" ? body.runtimeProfileId.trim() : "";
  if (!runtimeProfileId || runtimeProfileId.length > 128) {
    return c.json({ message: "A valid runtimeProfileId is required." }, 400);
  }
  const profile = await c.env.DB.prepare(
    "SELECT id, runtime_family AS runtimeFamily, enabled FROM application_runtime_profiles WHERE id = ? LIMIT 1",
  ).bind(runtimeProfileId).first<{ id: string; runtimeFamily: string; enabled: number }>();
  if (!profile) return c.json({ message: "Unknown runtime profile." }, 400);

  const buildMethod = body.buildMethod ?? "managed";
  if (buildMethod !== "static" && buildMethod !== "managed" && buildMethod !== "dockerfile") {
    return c.json({ message: "buildMethod must be static, managed, or dockerfile." }, 400);
  }
  if (profile.runtimeFamily === "static" && buildMethod !== "static") {
    return c.json({ message: "Static websites must use the static build method." }, 400);
  }
  if (profile.runtimeFamily === "container" && buildMethod !== "dockerfile") {
    return c.json({ message: "Custom OCI profiles must use the Dockerfile build method." }, 400);
  }

  const relativePath = (value: unknown, fallback: string, field: string): string | null => {
    const raw = value === undefined ? fallback : value;
    if (typeof raw !== "string" || raw.length > 240 || raw.startsWith("/") ||
        raw.includes("\\") || raw.split("/").some((part) => part === ".." || part === "." && raw !== ".")) {
      return null;
    }
    return raw;
  };
  const buildContext = relativePath(body.buildContext, ".", "buildContext");
  if (buildContext === null) return c.json({ message: "buildContext must be a safe relative path." }, 400);

  const outputDirectory = body.outputDirectory === undefined
    ? (profile.runtimeFamily === "static" ? "dist" : null)
    : body.outputDirectory;
  if (outputDirectory !== null &&
      (typeof outputDirectory !== "string" || outputDirectory.length > 240 ||
       outputDirectory.startsWith("/") || outputDirectory.includes("\\") ||
       outputDirectory.split("/").some((part) => part === ".." || part === "."))) {
    return c.json({ message: "outputDirectory must be null or a safe relative path." }, 400);
  }

  const boundedText = (value: unknown, field: string, max: number): string | null => {
    if (value === undefined || value === null || value === "") return null;
    if (typeof value !== "string" || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) {
      throw new Error(field + " is invalid or too long.");
    }
    return value;
  };
  let buildCommand: string | null;
  let startCommand: string | null;
  let healthCheckPath: string | null;
  try {
    buildCommand = boundedText(body.buildCommand, "buildCommand", 1000);
    startCommand = boundedText(body.startCommand, "startCommand", 1000);
    healthCheckPath = boundedText(body.healthCheckPath, "healthCheckPath", 200);
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Invalid command field." }, 400);
  }
  if (healthCheckPath !== null && !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%\-\/]*$/.test(healthCheckPath)) {
    return c.json({ message: "healthCheckPath must be an absolute URL path without query or fragment." }, 400);
  }

  const boundedInteger = (value: unknown, fallback: number, min: number, max: number, field: string): number | null => {
    const n = value === undefined ? fallback : value;
    return typeof n === "number" && Number.isInteger(n) && n >= min && n <= max ? n : null;
  };
  const listenPort = body.listenPort === undefined || body.listenPort === null
    ? null : boundedInteger(body.listenPort, 0, 1, 65535, "listenPort");
  const cpuMillis = boundedInteger(body.cpuMillis, 500, 100, 8000, "cpuMillis");
  const memoryMiB = boundedInteger(body.memoryMiB, 512, 128, 16384, "memoryMiB");
  const diskMiB = boundedInteger(body.diskMiB, 2048, 128, 65536, "diskMiB");
  const processLimit = boundedInteger(body.processLimit, 128, 16, 512, "processLimit");
  if (listenPort === null && body.listenPort !== undefined && body.listenPort !== null ||
      cpuMillis === null || memoryMiB === null || diskMiB === null || processLimit === null) {
    return c.json({ message: "Resource values are outside the permitted platform bounds." }, 400);
  }

  const planDiskLimitMiB = Math.min(
    project.appDiskMiB,
    Math.floor(project.accountDiskLimitBytes / (1024 * 1024)),
  );
  if (cpuMillis > project.appCpuMillis || memoryMiB > project.appMemoryMiB ||
      diskMiB > planDiskLimitMiB || processLimit > project.appProcessLimit) {
    return c.json({
      message: "Requested runtime resources exceed the hosting plan quotas assigned to this project.",
      planResourceLimits: {
        cpuMillis: project.appCpuMillis,
        memoryMiB: project.appMemoryMiB,
        diskMiB: planDiskLimitMiB,
        processLimit: project.appProcessLimit,
      },
    }, 400);
  }

  const settingsId = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO application_project_settings
      (id, organization_id, project_id, runtime_profile_id, spec_version,
       build_method, build_context, build_command, output_directory, start_command,
       listen_port, health_check_path, cpu_millis, memory_mib, disk_mib, process_limit,
       updated_at)
     VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(project_id) DO UPDATE SET
       runtime_profile_id = excluded.runtime_profile_id,
       spec_version = application_project_settings.spec_version + 1,
       build_method = excluded.build_method,
       build_context = excluded.build_context,
       build_command = excluded.build_command,
       output_directory = excluded.output_directory,
       start_command = excluded.start_command,
       listen_port = excluded.listen_port,
       health_check_path = excluded.health_check_path,
       cpu_millis = excluded.cpu_millis,
       memory_mib = excluded.memory_mib,
       disk_mib = excluded.disk_mib,
       process_limit = excluded.process_limit,
       updated_at = datetime('now')
     WHERE application_project_settings.organization_id = excluded.organization_id`,
  ).bind(
    settingsId, identity.organizationId, projectId, runtimeProfileId,
    buildMethod, buildContext, buildCommand, outputDirectory, startCommand,
    listenPort, healthCheckPath, cpuMillis, memoryMiB, diskMiB, processLimit,
  ).run();

  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'application.settings_updated', 'github_project', ?, ?)",
  ).bind(
    crypto.randomUUID(), identity.organizationId, identity.id, projectId,
    JSON.stringify({
      runtimeProfileId, buildMethod, cpuMillis, memoryMiB, diskMiB, processLimit,
      executionEnabled: false,
    }),
  ).run();

  return c.json({
    saved: true,
    projectId,
    runtimeProfileId,
    runtimeEnabled: profile.enabled === 1,
    executionEnabled: false,
    platformResourceBounds: { cpuMillis: [100, 8000], memoryMiB: [128, 16384], diskMiB: [128, 65536], processLimit: [16, 512] },
    planResourceLimits: {
      cpuMillis: project.appCpuMillis,
      memoryMiB: project.appMemoryMiB,
      diskMiB: planDiskLimitMiB,
      processLimit: project.appProcessLimit,
    },
    planQuotasEnforced: true,
    message: "Configuration saved as metadata only within the assigned hosting plan quotas. Customer builds and runtime execution remain disabled.",
  });
});

app.get("/v1/applications/projects/:projectId/usage", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  const now = new Date();
  const periodStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString().slice(0, 10);
  const row = await c.env.DB.prepare(
    `SELECT p.id, COALESCE(u.build_seconds_used, 0) AS buildSecondsUsed,
            COALESCE(u.build_minutes_limit, hp.app_build_minutes_month) AS buildMinutesLimit,
            EXISTS (SELECT 1 FROM application_usage_events e WHERE e.organization_id = p.organization_id
                    AND e.project_id = p.id AND e.period_start = ?) AS hasUsageEvents
     FROM github_projects p
     JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = p.organization_id
     JOIN hosting_plans hp ON hp.id = h.plan_id AND hp.organization_id = p.organization_id
     LEFT JOIN application_usage_periods u
       ON u.organization_id = p.organization_id AND u.project_id = p.id AND u.period_start = ?
     WHERE p.id = ? AND p.organization_id = ?
       AND (? = 1 OR EXISTS (
         SELECT 1 FROM hosting_account_memberships m
         WHERE m.hosting_account_id = p.hosting_account_id
           AND m.organization_id = p.organization_id
           AND m.user_id = ? AND m.status = 'ACTIVE'
       ))
     LIMIT 1`,
  ).bind(periodStart, periodStart, projectId, identity.organizationId, identity.platformRole ? 1 : 0, identity.id).first<{
    id: string; buildMinutesLimit: number; buildSecondsUsed: number; hasUsageEvents: number;
  }>();
  if (!row) return c.json({ message: "GitHub project not found." }, 404);
  const quotaSeconds = row.buildMinutesLimit * 60;
  return c.json({
    periodStart,
    buildMinutesLimit: row.buildMinutesLimit,
    buildSecondsUsed: row.buildSecondsUsed,
    buildMinutesUsed: Math.round((row.buildSecondsUsed / 60) * 100) / 100,
    buildSecondsRemaining: Math.max(0, quotaSeconds - row.buildSecondsUsed),
    quotaExhausted: row.buildSecondsUsed >= quotaSeconds,
    meteringStatus: row.hasUsageEvents ? "active" : "not_connected",
    executionEnabled: false,
    message: "Usage reports are accepted only from the authenticated isolated builder; build dispatch quota enforcement remains disabled.",
  });
});

app.get("/internal/v1/operator/application-node-pools", async (c) => {
  if (!c.env.APPLICATION_NODE_OPERATOR_TOKEN || c.env.APPLICATION_NODE_OPERATOR_TOKEN.length < 32) {
    return c.json({ message: "Node operator controls are not configured." }, 503);
  }
  if (!await nodeOperatorAuthorized(c.req.raw, c.env)) {
    return c.json({ message: "Node operator authorization required." }, 401);
  }
  const rows = await c.env.DB.prepare(
    "SELECT p.id, p.name, p.environment, p.region, p.runtime_engine AS runtimeEngine, " +
    "p.isolation_level AS isolationLevel, " +
    "(SELECT COUNT(*) FROM application_nodes n WHERE n.node_pool_id = p.id AND n.node_role = 'runtime' " +
    "AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') AND n.signing_public_key IS NOT NULL) AS onlineRuntimeNodes " +
    "FROM application_node_pools p WHERE p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "ORDER BY p.environment, p.region, p.name",
  ).all<{
    id: string; name: string; environment: string; region: string;
    runtimeEngine: string; isolationLevel: string; onlineRuntimeNodes: number;
  }>();
  return c.json({
    pools: (rows.results ?? []).filter((pool) => pool.onlineRuntimeNodes > 0),
    capacityAllocated: false,
    executionEnabled: false,
  });
});

app.post("/internal/v1/operator/application-projects/:projectId/runtime-pool", async (c) => {
  if (!c.env.APPLICATION_NODE_OPERATOR_TOKEN || c.env.APPLICATION_NODE_OPERATOR_TOKEN.length < 32) {
    return c.json({ message: "Node operator controls are not configured." }, 503);
  }
  if (!await nodeOperatorAuthorized(c.req.raw, c.env)) {
    return c.json({ message: "Node operator authorization required." }, 401);
  }
  const rawBody = await c.req.text();
  if (rawBody.length < 2 || rawBody.length > 2048) {
    return c.json({ message: "Request body must be between 2 and 2048 bytes." }, 413);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid JSON body." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => key !== "nodePoolId") ||
      typeof body.nodePoolId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.nodePoolId)) {
    return c.json({ message: "A valid nodePoolId is required." }, 400);
  }
  const projectId = c.req.param("projectId");
  const assignment = await c.env.DB.prepare(
    "SELECT s.id AS settingsId, s.node_pool_id AS previousNodePoolId, " +
    "rp.enabled AS runtimeEnabled, " +
    "EXISTS (SELECT 1 FROM application_workloads w WHERE w.project_id = s.project_id " +
    "AND w.organization_id = s.organization_id AND w.status IN ('starting','healthy')) AS hasActiveWorkload " +
    "FROM application_project_settings s " +
    "JOIN application_runtime_profiles rp ON rp.id = s.runtime_profile_id " +
    "WHERE s.project_id = ? LIMIT 1",
  ).bind(projectId).first<{
    settingsId: string; previousNodePoolId: string | null;
    runtimeEnabled: number; hasActiveWorkload: number;
  }>();
  if (!assignment) return c.json({ message: "Application project settings not found." }, 404);
  if (assignment.runtimeEnabled !== 1) {
    return c.json({ message: "The selected runtime profile is disabled and cannot be assigned for execution." }, 409);
  }
  if (assignment.hasActiveWorkload === 1) {
    return c.json({ message: "Stop or drain the active workload before changing its runtime pool." }, 409);
  }
  const pool = await c.env.DB.prepare(
    "SELECT p.id FROM application_node_pools p " +
    "WHERE p.id = ? AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND EXISTS (SELECT 1 FROM application_nodes n WHERE n.node_pool_id = p.id " +
    "AND n.node_role = 'runtime' AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key IS NOT NULL) LIMIT 1",
  ).bind(body.nodePoolId).first<{ id: string }>();
  if (!pool) {
    return c.json({ message: "Runtime pool must be ready, isolated, and contain an enrolled online runtime node." }, 409);
  }
  const updated = await c.env.DB.prepare(
    "UPDATE application_project_settings SET node_pool_id = ?, updated_at = datetime('now') " +
    "WHERE id = ? AND NOT EXISTS (SELECT 1 FROM application_workloads w WHERE w.project_id = application_project_settings.project_id " +
    "AND w.organization_id = application_project_settings.organization_id AND w.status IN ('starting','healthy'))",
  ).bind(pool.id, assignment.settingsId).run();
  if (Number(updated.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Runtime pool assignment changed concurrently or the project became active." }, 409);
  }
  return c.json({
    assigned: true,
    projectId,
    nodePoolId: pool.id,
    previousNodePoolId: assignment.previousNodePoolId,
    executionEnabled: false,
    capacityAllocated: false,
    message: "Runtime pool assigned as metadata. This does not start an application or allocate physical capacity.",
  });
});

app.post("/internal/v1/operator/application-nodes", async (c) => {
  if (!c.env.APPLICATION_NODE_OPERATOR_TOKEN || c.env.APPLICATION_NODE_OPERATOR_TOKEN.length < 32) {
    return c.json({ message: "Node operator controls are not configured." }, 503);
  }
  if (!await nodeOperatorAuthorized(c.req.raw, c.env)) {
    return c.json({ message: "Node operator authorization required." }, 401);
  }
  const rawBody = await c.req.text();
  if (rawBody.length < 2 || rawBody.length > 2048) {
    return c.json({ message: "Request body must be between 2 and 2048 bytes." }, 413);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch {
    return c.json({ message: "Invalid JSON body." }, 400);
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => !["nodePoolId", "nodeIdentity"].includes(key)) ||
      typeof body.nodePoolId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.nodePoolId) ||
      typeof body.nodeIdentity !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(body.nodeIdentity)) {
    return c.json({ message: "A valid nodePoolId and nodeIdentity are required." }, 400);
  }
  const nodeId = crypto.randomUUID();
  const auditId = crypto.randomUUID();
  const enrollmentToken = randomHex(32);
  const enrollmentKeyHash = await sha256(enrollmentToken);
  const metadata = JSON.stringify({ nodeIdentity: body.nodeIdentity, nodePoolId: body.nodePoolId, nodeRole: "runtime" });
  let results: D1Result[];
  try {
    results = await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO application_nodes " +
        "(id, node_pool_id, node_identity, enrollment_key_hash, node_role, status) " +
        "SELECT ?, p.id, ?, ?, 'runtime', 'pending' FROM application_node_pools p " +
        "WHERE p.id = ? AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
        "ON CONFLICT(node_identity) DO NOTHING",
      ).bind(nodeId, body.nodeIdentity, enrollmentKeyHash, body.nodePoolId),
      c.env.DB.prepare(
        "INSERT INTO audit_logs " +
        "(id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) " +
        "SELECT ?, NULL, NULL, 'application.node_enrollment_issued', 'application_node', ?, ? " +
        "WHERE EXISTS (SELECT 1 FROM application_nodes WHERE id = ?)",
      ).bind(auditId, nodeId, metadata, nodeId),
    ]);
  } catch {
    return c.json({ message: "Node enrollment could not be issued safely." }, 500);
  }
  if (Number(results[0]?.meta?.changes ?? 0) !== 1 ||
      Number(results[1]?.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Node identity already exists, or the selected pool is not ready and isolated." }, 409);
  }
  return c.json({
    created: true,
    node: { id: nodeId, identity: body.nodeIdentity, nodePoolId: body.nodePoolId, role: "runtime", status: "pending" },
    enrollmentToken,
    tokenUsage: "single_use",
    executionEnabled: false,
  }, 201);
});

app.post("/internal/v1/operator/application-nodes/:nodeId/revoke", async (c) => {
  if (!c.env.APPLICATION_NODE_OPERATOR_TOKEN || c.env.APPLICATION_NODE_OPERATOR_TOKEN.length < 32) {
    return c.json({ message: "Node operator controls are not configured." }, 503);
  }
  if (!await nodeOperatorAuthorized(c.req.raw, c.env)) return c.json({ message: "Node operator authorization required." }, 401);
  const nodeId = c.req.param("nodeId");
  let input: unknown = {};
  const rawBody = await c.req.text();
  if (rawBody.length > 1024) return c.json({ message: "Request body is too large." }, 413);
  if (rawBody) {
    try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid JSON body." }, 400); }
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) return c.json({ message: "A JSON object is required." }, 400);
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => key !== "reason") ||
      (body.reason !== undefined && (typeof body.reason !== "string" || body.reason.length > 500 ||
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(body.reason)))) {
    return c.json({ message: "Invalid revocation payload." }, 400);
  }
  const result = await c.env.DB.prepare(
    "UPDATE application_nodes SET status = 'revoked', revoked_at = datetime('now'), revoked_reason = ?, " +
    "key_rotation_challenge_hash = NULL, key_rotation_challenge_expires_at = NULL, " +
    "enrollment_key_hash = ?, updated_at = datetime('now') " +
    "WHERE id = ? AND status <> 'revoked'",
  ).bind(body.reason ?? "Revoked by platform operator", randomHex(32), nodeId).run();
  if (Number(result.meta?.changes ?? 0) !== 1) return c.json({ message: "Node not found or already revoked." }, 404);
  return c.json({ revoked: true, nodeId, terminal: true });
});

app.post("/internal/v1/operator/application-nodes/:nodeId/key-rotation-challenge", async (c) => {
  if (!c.env.APPLICATION_NODE_OPERATOR_TOKEN || c.env.APPLICATION_NODE_OPERATOR_TOKEN.length < 32) {
    return c.json({ message: "Node operator controls are not configured." }, 503);
  }
  if (!await nodeOperatorAuthorized(c.req.raw, c.env)) return c.json({ message: "Node operator authorization required." }, 401);
  const nodeId = c.req.param("nodeId");
  const challenge = randomHex(32);
  const challengeHash = await sha256(challenge);
  const result = await c.env.DB.prepare(
    "UPDATE application_nodes SET key_rotation_challenge_hash = ?, " +
    "key_rotation_challenge_expires_at = datetime('now', '+10 minutes'), updated_at = datetime('now') " +
    "WHERE id = ? AND status IN ('online','draining') AND signing_public_key IS NOT NULL AND revoked_at IS NULL",
  ).bind(challengeHash, nodeId).run();
  if (Number(result.meta?.changes ?? 0) !== 1) return c.json({ message: "Active enrolled node not found." }, 404);
  return c.json({ nodeId, challenge, expiresInSeconds: 600, proofRequired: "current Ed25519 signing key" });
});

app.post("/internal/v1/application-nodes/rotate-key", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = c.req.header("x-nexora-node-signature") ?? "";
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity)) return c.json({ message: "Node identity is required." }, 401);
  const rawBody = await c.req.text();
  if (rawBody.length > 2048) return c.json({ message: "Request body is too large." }, 413);
  const node = await c.env.DB.prepare(
    "SELECT id, signing_public_key AS signingPublicKey, key_rotation_challenge_hash AS challengeHash, " +
    "key_rotation_challenge_expires_at AS challengeExpiresAt FROM application_nodes " +
    "WHERE node_identity = ? AND status IN ('online','draining') AND revoked_at IS NULL " +
    "AND signing_public_key IS NOT NULL AND key_rotation_challenge_hash IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; signingPublicKey: string; challengeHash: string; challengeExpiresAt: string }>();
  if (!node || !await verifyNodeSignature(node.signingPublicKey, timestamp, nonce, rawBody, signature)) {
    return c.json({ message: "Invalid node identity or signature." }, 401);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid JSON body." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) return c.json({ message: "A JSON object is required." }, 400);
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => !["newPublicKey", "challenge"].includes(key)) ||
      typeof body.newPublicKey !== "string" || !/^[a-f0-9]{64}$/i.test(body.newPublicKey) ||
      typeof body.challenge !== "string" || !/^[a-f0-9]{64}$/i.test(body.challenge)) {
    return c.json({ message: "Invalid key rotation payload." }, 400);
  }
  if (await sha256(body.challenge) !== node.challengeHash || Date.parse(node.challengeExpiresAt + "Z") <= Date.now()) {
    return c.json({ message: "Key rotation challenge is invalid or expired." }, 409);
  }
  if (body.newPublicKey.toLowerCase() === node.signingPublicKey) return c.json({ message: "New key must differ from the current key." }, 400);
  const previouslyUsedKey = await c.env.DB.prepare(
    "SELECT id FROM application_node_signing_key_history WHERE node_id = ? AND public_key = ? LIMIT 1",
  ).bind(node.id, body.newPublicKey.toLowerCase()).first<{ id: string }>();
  if (previouslyUsedKey) return c.json({ message: "A previously used signing key cannot be reactivated." }, 409);
  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) return c.json({ message: "Request nonce has already been used." }, 409);
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE application_nodes SET signing_public_key = ?, key_rotation_challenge_hash = NULL, " +
      "key_rotation_challenge_expires_at = NULL, signing_key_rotated_at = datetime('now'), " +
      "last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND signing_public_key = ? AND key_rotation_challenge_hash = ? " +
      "AND key_rotation_challenge_expires_at > datetime('now') AND status IN ('online','draining') AND revoked_at IS NULL",
    ).bind(body.newPublicKey.toLowerCase(), node.id, nodeIdentity, node.signingPublicKey, node.challengeHash),
    c.env.DB.prepare(
      "UPDATE application_node_signing_key_history SET retired_at = datetime('now') " +
      "WHERE node_id = ? AND public_key = ? AND retired_at IS NULL",
    ).bind(node.id, node.signingPublicKey),
    c.env.DB.prepare(
      "INSERT INTO application_node_signing_key_history (id,node_id,public_key) VALUES (?,?,?)",
    ).bind(crypto.randomUUID(), node.id, body.newPublicKey.toLowerCase()),
  ]);
  if (Number(results[0]?.meta?.changes ?? 0) !== 1) return c.json({ message: "Key rotation challenge was consumed or node is no longer authorized." }, 409);
  return c.json({ rotated: true, nodeIdentity, credentialModel: "ed25519_per_node" });
});

app.post("/internal/v1/application-nodes/enroll", async (c) => {
  const rawBody = await c.req.text();
  if (rawBody.length > 4096) return c.json({ message: "Request body is too large." }, 413);
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid JSON body." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) return c.json({ message: "A JSON object is required." }, 400);
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => !["nodeIdentity", "enrollmentToken", "publicKey", "agentVersion"].includes(key)) ||
      typeof body.nodeIdentity !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(body.nodeIdentity) ||
      typeof body.enrollmentToken !== "string" || !/^[a-f0-9]{64}$/i.test(body.enrollmentToken) ||
      typeof body.publicKey !== "string" || !/^[a-f0-9]{64}$/i.test(body.publicKey) ||
      typeof body.agentVersion !== "string" || body.agentVersion.length < 1 || body.agentVersion.length > 64 ||
      /[\u0000-\u001f\u007f]/.test(body.agentVersion)) {
    return c.json({ message: "Invalid node enrollment payload." }, 400);
  }
  const tokenHash = await sha256(body.enrollmentToken);
  let enrollmentResults: D1Result[];
  try {
    // D1 batch is transactional: the active key and immutable key-history record
    // must commit together, or neither enrollment change is persisted.
    enrollmentResults = await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE application_nodes SET signing_public_key = ?, enrollment_consumed_at = datetime('now'), " +
        "status = 'online', agent_version = ?, last_heartbeat_at = datetime('now'), updated_at = datetime('now') " +
        "WHERE node_identity = ? AND enrollment_key_hash = ? AND enrollment_consumed_at IS NULL " +
        "AND signing_public_key IS NULL AND status = 'pending' " +
        "AND EXISTS (SELECT 1 FROM application_node_pools p WHERE p.id = application_nodes.node_pool_id AND p.status = 'ready')",
      ).bind(body.publicKey.toLowerCase(), body.agentVersion, body.nodeIdentity, tokenHash),
      c.env.DB.prepare(
        "INSERT INTO application_node_signing_key_history (id,node_id,public_key) " +
        "SELECT ?, id, signing_public_key FROM application_nodes " +
        "WHERE node_identity = ? AND signing_public_key = ? AND enrollment_consumed_at IS NOT NULL",
      ).bind(crypto.randomUUID(), body.nodeIdentity, body.publicKey.toLowerCase()),
    ]);
  } catch (error) {
    console.error("Node enrollment transaction failed:", error instanceof Error ? error.message : "unknown error");
    return c.json({ message: "Node enrollment could not be committed safely." }, 500);
  }
  if (Number(enrollmentResults[0]?.meta?.changes ?? 0) !== 1 ||
      Number(enrollmentResults[1]?.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Enrollment token is invalid, already consumed, or the node pool is not ready." }, 409);
  }
  const node = await c.env.DB.prepare(
    "SELECT id, node_identity AS nodeIdentity, status, agent_version AS agentVersion " +
    "FROM application_nodes WHERE node_identity = ? LIMIT 1",
  ).bind(body.nodeIdentity).first<{ id: string; nodeIdentity: string; status: string; agentVersion: string }>();
  if (!node) return c.json({ message: "Node enrollment could not be confirmed." }, 500);
  return c.json({ enrolled: true, node: { id: node.id, identity: node.nodeIdentity, status: node.status, agentVersion: node.agentVersion },
    credentialModel: "ed25519_per_node", executionEnabled: false });
});

app.post("/internal/v1/application-nodes/heartbeat", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node heartbeat proof." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Heartbeat requests must use application/json." }, 415);
  }
  const rawBody = await c.req.text();
  if (rawBody.length < 2 || rawBody.length > 2048) {
    return c.json({ message: "Heartbeat body is empty or exceeds 2048 bytes." }, 413);
  }
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.signing_public_key AS signingPublicKey FROM application_nodes n " +
    "JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.node_role = 'runtime' AND n.status = 'online' " +
    "AND n.revoked_at IS NULL AND p.status = 'ready' " +
    "AND p.isolation_level IN ('rootless','microvm') AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", path, rawBody, signature,
  )) {
    return c.json({ message: "Runtime node identity or heartbeat signature is not authorized." }, 401);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid heartbeat JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => key !== "agentVersion") ||
      typeof body.agentVersion !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/.test(body.agentVersion)) {
    return c.json({ message: "Invalid runtime heartbeat payload." }, 400);
  }
  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Runtime heartbeat nonce has already been used." }, 409);
  }
  const result = await c.env.DB.prepare(
    "UPDATE application_nodes SET agent_version = ?, last_heartbeat_at = datetime('now'), " +
    "last_signature_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE id = ? AND node_identity = ? AND node_role = 'runtime' AND status = 'online' " +
    "AND revoked_at IS NULL AND signing_public_key = ? " +
    "AND EXISTS (SELECT 1 FROM application_node_pools p WHERE p.id = application_nodes.node_pool_id " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm'))",
  ).bind(body.agentVersion, node.id, nodeIdentity, node.signingPublicKey).run();
  if (Number(result.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Runtime node is no longer eligible to heartbeat." }, 409);
  }
  return c.json({ accepted: true, nodeIdentity, status: "heartbeat_recorded", executionEnabled: false });
});

app.get("/internal/v1/application-nodes/desired-state", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node authentication headers." }, 401);
  }
  if (c.req.raw.body !== null) {
    return c.json({ message: "Desired-state polling does not accept a request body." }, 400);
  }
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'runtime' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' " +
    "AND p.isolation_level IN ('rootless','microvm') AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "GET", path, "", signature,
  )) {
    return c.json({ message: "Application node is not authorized to poll desired state." }, 401);
  }
  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  // Return only node-assigned workload and successful release metadata.
  // Customer commands, environment values, secrets and arbitrary spec_json
  // are deliberately excluded. This endpoint cannot authorize execution.
  const rows = await c.env.DB.prepare(
    "SELECT w.id AS workloadId, w.project_id AS projectId, w.workload_kind AS workloadKind, " +
    "w.status AS workloadStatus, w.desired_replicas AS desiredReplicas, " +
    "w.observed_replicas AS observedReplicas, r.id AS releaseId, r.state AS releaseState, " +
    "r.spec_version AS releaseSpecVersion, r.image_digest AS imageDigest, " +
    "r.artifact_digest AS artifactDigest, s.spec_version AS settingsSpecVersion, " +
    "s.runtime_profile_id AS runtimeProfileId, rp.profile_key AS runtimeProfileKey, " +
    "rp.runtime_family AS runtimeFamily, rp.execution_kind AS executionKind, " +
    "COALESCE(s.listen_port, rp.default_port) AS listenPort, " +
    "s.cpu_millis AS cpuMillis, s.memory_mib AS memoryMiB, " +
    "s.disk_mib AS diskMiB, s.process_limit AS processLimit " +
    "FROM application_workloads w " +
    "JOIN application_releases r ON r.id = w.active_release_id " +
    "AND r.project_id = w.project_id AND r.organization_id = w.organization_id " +
    "AND r.assigned_node_id = w.node_id AND r.state = 'succeeded' " +
    "JOIN application_project_settings s ON s.project_id = w.project_id " +
    "AND s.organization_id = w.organization_id " +
    "JOIN application_runtime_profiles rp ON rp.id = s.runtime_profile_id " +
    "WHERE w.node_id = ? AND rp.enabled = 1 AND rp.profile_key = 'nodejs-v1' " +
    "AND rp.runtime_family = 'nodejs' AND rp.execution_kind = 'oci' " +
    "ORDER BY w.updated_at DESC LIMIT 100",
  ).bind(node.id).all<{
    workloadId: string; projectId: string; workloadKind: string; workloadStatus: string;
    desiredReplicas: number; observedReplicas: number; releaseId: string; releaseState: string;
    releaseSpecVersion: number; imageDigest: string | null; artifactDigest: string | null;
    settingsSpecVersion: number; runtimeProfileId: string; runtimeProfileKey: string;
    runtimeFamily: string; executionKind: string; listenPort: number | null;
    cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number;
  }>();
  return c.json({
    nodeIdentity,
    polledAt: new Date().toISOString(),
    executionEnabled: false,
    workloads: (rows.results ?? []).map((row) => ({
      ...row,
      desiredState: row.desiredReplicas > 0 ? "running" : "stopped",
    })),
    commandsIncluded: false,
    secretsIncluded: false,
  }, 200, { "cache-control": "no-store" });
});


function validStaticHealthCheckPath(value: string): boolean {
  if (!value || value.length > 512 || !value.startsWith("/") ||
      value.startsWith("//") || /[?#\\\r\n\u0000-\u001f\u007f]/.test(value)) return false;
  try {
    const decoded = decodeURIComponent(value);
    if (decoded.split("/").some((part) => part === "." || part === "..")) return false;
    const parsed = new URL(value, "https://nexora.invalid");
    return parsed.origin === "https://nexora.invalid" &&
      parsed.pathname === value && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

const STATIC_PENDING_RELEASES_PATH = "/internal/v1/application-nodes/pending-static-releases";

app.get(STATIC_PENDING_RELEASES_PATH, async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature) || c.req.raw.body !== null) {
    return c.json({ message: "Invalid static-publisher request proof." }, 401);
  }
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.node_role = 'runtime' AND n.status = 'online' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "GET", STATIC_PENDING_RELEASES_PATH, "", signature,
  )) {
    return c.json({ message: "Runtime node is not authorized to poll static releases." }, 401);
  }
  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }
  // Releases are returned in three lifecycle states:
  //   - artifact_uploaded / publishing: the publisher must download, validate,
  //     extract, install the Nginx vhost, activate and report.
  //   - health_checking: the publisher has already activated and acknowledged;
  //     a process restart must NOT republish or reactivate. The publisher
  //     enters the recovery path: verify the local active symlink and the
  //     trusted manifest, then probe and report.
  // Terminal states (succeeded / failed) are never returned; once a release
  // reaches a terminal state, the workload's active_release_id and the
  // release's own state are the durable decision and a retried poll must not
  // reprocess the release.
  const rows = await c.env.DB.prepare(
    "SELECT r.id AS releaseId, r.state AS state, r.artifact_digest AS artifactSha256, " +
    "r.deployment_id AS deploymentId, r.organization_id AS organizationId, " +
    "r.project_id AS projectId, p.hosting_account_id AS hostingAccountId, " +
    "dom.id AS domainId, lower(dom.name) AS hostname, " +
    "p.github_repository_id AS repositoryId, r.source_commit_sha AS commitSha, " +
    "COALESCE(s.health_check_path, '/') AS healthCheckPath, " +
    "COALESCE(previous.deployment_id, '') AS previousDeploymentId " +
    "FROM application_releases r " +
    "JOIN github_projects p ON p.id = r.project_id AND p.organization_id = r.organization_id " +
    "JOIN hosting_accounts ha ON ha.id = p.hosting_account_id AND ha.organization_id = p.organization_id AND ha.status = 'ACTIVE' " +
    "JOIN domains dom ON dom.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = ha.id " +
    "ORDER BY d2.is_primary DESC, d2.name ASC LIMIT 1) " +
    "JOIN application_project_settings s ON s.project_id = r.project_id AND s.organization_id = r.organization_id " +
    "JOIN application_runtime_profiles rp ON rp.id = s.runtime_profile_id " +
    "JOIN application_nodes n ON n.id = r.assigned_node_id AND n.node_pool_id = r.node_pool_id " +
    "JOIN application_node_pools pool ON pool.id = n.node_pool_id " +
    "LEFT JOIN application_workloads w ON w.organization_id = r.organization_id " +
    "AND w.project_id = r.project_id AND w.workload_kind = 'web' " +
    "LEFT JOIN application_releases previous ON previous.id = w.active_release_id " +
    "AND previous.organization_id = r.organization_id AND previous.project_id = r.project_id " +
    "WHERE r.assigned_node_id = ? AND r.node_pool_id = ? " +
    "AND r.state IN ('artifact_uploaded','publishing','health_checking') " +
    "AND r.artifact_digest IS NOT NULL " +
    "AND rp.profile_key = 'static-v1' AND rp.runtime_family = 'static' AND rp.enabled = 1 " +
    "AND s.build_method = 'static' AND n.node_identity = ? AND n.node_role = 'runtime' " +
    "AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND pool.status = 'ready' AND pool.isolation_level IN ('rootless','microvm') " +
    "ORDER BY r.requested_at LIMIT 10",
  ).bind(node.id, node.nodePoolId, nodeIdentity).all<{
    releaseId: string; state: string; artifactSha256: string;
    deploymentId: string; organizationId: string; projectId: string;
    hostingAccountId: string; domainId: string; hostname: string; repositoryId: string; commitSha: string; healthCheckPath: string; previousDeploymentId: string;
  }>();
  const rollbackRows = await c.env.DB.prepare(
    "SELECT failed.deployment_id AS failedDeploymentId, target.deployment_id AS targetDeploymentId, " +
    "failed.id AS failedReleaseId, target.id AS targetReleaseId, " +
    "failed.organization_id AS organizationId, failed.project_id AS projectId, " +
    "p.hosting_account_id AS hostingAccountId, lower(dom.name) AS hostname, " +
    "COALESCE(s.health_check_path, '/') AS healthCheckPath, " +
    "target.artifact_digest AS targetArtifactSha256 " +
    "FROM application_releases failed " +
    "JOIN application_workloads w ON w.organization_id = failed.organization_id " +
    "AND w.project_id = failed.project_id AND w.workload_kind = 'web' " +
    "JOIN application_releases target ON target.id = w.active_release_id " +
    "AND target.organization_id = failed.organization_id AND target.project_id = failed.project_id " +
    "JOIN github_projects p ON p.id = failed.project_id AND p.organization_id = failed.organization_id " +
    "JOIN hosting_accounts ha ON ha.id = p.hosting_account_id AND ha.organization_id = p.organization_id AND ha.status = 'ACTIVE' " +
    "JOIN domains dom ON dom.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = ha.id " +
    "ORDER BY d2.is_primary DESC, d2.name ASC LIMIT 1) " +
    "JOIN application_project_settings s ON s.project_id = failed.project_id AND s.organization_id = failed.organization_id " +
    "WHERE failed.assigned_node_id = ? AND failed.node_pool_id = ? AND failed.state = 'failed' " +
    "AND target.assigned_node_id = ? AND target.node_pool_id = ? AND target.state = 'succeeded' " +
    "AND target.artifact_digest IS NOT NULL AND w.node_id = ? AND w.status IN ('unhealthy','healthy') " +
    "AND NOT EXISTS (SELECT 1 FROM application_rollback_acknowledgements a WHERE a.failed_release_id = failed.id) " +
    "ORDER BY failed.finished_at ASC LIMIT 10",
  ).bind(node.id, node.nodePoolId, node.id, node.nodePoolId, node.id).all<{
    failedDeploymentId: string; targetDeploymentId: string; failedReleaseId: string; targetReleaseId: string; organizationId: string;
    projectId: string; hostingAccountId: string; hostname: string;
    healthCheckPath: string; targetArtifactSha256: string;
  }>();
  await c.env.DB.prepare(
    "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE id = ? AND node_identity = ? AND status = 'online' AND revoked_at IS NULL",
  ).bind(node.id, nodeIdentity).run();
  return c.json({
    nodeIdentity,
    polledAt: new Date().toISOString(),
    releases: (rows.results ?? []).filter((row) =>
      validStaticHealthCheckPath(row.healthCheckPath ?? "/") &&
      validDomain(row.hostname) &&
      /^[a-f0-9]{40}$/i.test(row.commitSha) &&
      // Every returned release must carry a release row ID, a known
      // non-terminal lifecycle state, and the artifact SHA-256 that the
      // publisher will verify against the local trusted manifest.
      /^[A-Za-z0-9_-]{1,128}$/.test(row.releaseId ?? "") &&
      ["artifact_uploaded", "publishing", "health_checking"].includes(row.state) &&
      /^[a-f0-9]{64}$/i.test(row.artifactSha256 ?? ""),
    ).map((row) => ({
      releaseId: row.releaseId,
      state: row.state,
      artifactSha256: row.artifactSha256,
      deploymentId: row.deploymentId,
      organizationId: row.organizationId,
      projectId: row.projectId,
      hostingAccountId: row.hostingAccountId,
      domainId: row.domainId,
      hostname: row.hostname,
      repositoryId: row.repositoryId,
      commitSha: row.commitSha,
      healthCheckPath: row.healthCheckPath,
      previousDeploymentId: row.previousDeploymentId,
    })),
    rollbacks: (rollbackRows.results ?? []).filter((row) =>
      validStaticHealthCheckPath(row.healthCheckPath ?? "/") &&
      validDomain(row.hostname) &&
      /^[A-Za-z0-9_-]{1,128}$/.test(row.failedDeploymentId) &&
      /^[A-Za-z0-9_-]{1,128}$/.test(row.targetDeploymentId) &&
      /^[A-Za-z0-9_-]{1,128}$/.test(row.failedReleaseId) &&
      /^[A-Za-z0-9_-]{1,128}$/.test(row.targetReleaseId) &&
      /^[a-f0-9]{64}$/i.test(row.targetArtifactSha256),
    ),
  }, 200, { "cache-control": "no-store" });
});

app.post("/internal/v1/application-nodes/artifact", async (c) => {
  if (!c.env.ARTIFACTS) return c.json({ message: "Private application artifact storage is unavailable." }, 503);
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node authentication headers." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Artifact requests must use application/json." }, 415);
  }
  const declaredLength = c.req.header("content-length");
  if (declaredLength !== undefined) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 2 || parsedLength > 1024) {
      return c.json({ message: "Artifact request body is empty or exceeds 1024 bytes." }, 413);
    }
  }
  const reader = c.req.raw.body?.getReader();
  if (!reader) return c.json({ message: "Artifact request body is required." }, 400);
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bodyBytes += chunk.value.byteLength;
      if (bodyBytes > 1024) {
        await reader.cancel();
        return c.json({ message: "Artifact request body exceeds 1024 bytes." }, 413);
      }
      chunks.push(chunk.value);
    }
  } catch {
    return c.json({ message: "Unable to read artifact request body." }, 400);
  } finally {
    reader.releaseLock();
  }
  if (bodyBytes < 2) return c.json({ message: "Artifact request body is empty." }, 400);
  const rawBytes = new Uint8Array(bodyBytes);
  let offset = 0;
  for (const chunk of chunks) {
    rawBytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const decodedBody = new TextDecoder("utf-8").decode(rawBytes);
  const encodedBody = new TextEncoder().encode(decodedBody);
  if (encodedBody.byteLength !== rawBytes.byteLength ||
      encodedBody.some((value, index) => value !== rawBytes[index])) {
    return c.json({ message: "Artifact request body must be valid UTF-8." }, 400);
  }
  const rawBody = decodedBody;
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'runtime' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", path, rawBody, signature,
  )) {
    return c.json({ message: "Application node is not authorized for artifact delivery." }, 401);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid artifact request JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  const purpose = body.purpose === undefined ? "publish" : body.purpose;
  if (Object.keys(body).some((key) => !["deploymentId", "purpose"].includes(key)) ||
      typeof body.deploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.deploymentId) ||
      (purpose !== "validate" && purpose !== "publish")) {
    return c.json({ message: "Invalid artifact request payload." }, 400);
  }
  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  const release = await c.env.DB.prepare(
    "SELECT r.id AS releaseId, r.organization_id AS organizationId, r.project_id AS projectId, " +
    "r.deployment_id AS deploymentId, r.node_pool_id AS nodePoolId, r.state, " +
    "r.artifact_digest AS releaseArtifactDigest, r.artifact_bytes AS releaseArtifactBytes, " +
    "d.commit_sha AS commitSha, d.artifact_key AS artifactKey, d.artifact_bytes AS artifactBytes, " +
    "d.artifact_sha256 AS artifactSha256, p.hosting_account_id AS hostingAccountId, " +
    "dom.id AS domainId, lower(dom.name) AS hostname, p.github_repository_id AS repositoryId FROM application_releases r " +
    "JOIN github_deployments d ON d.id = r.deployment_id AND d.organization_id = r.organization_id AND d.project_id = r.project_id " +
    "JOIN github_projects p ON p.id = r.project_id AND p.organization_id = r.organization_id " +
    "JOIN hosting_accounts ha ON ha.id = p.hosting_account_id AND ha.organization_id = p.organization_id AND ha.status = 'ACTIVE' " +
    "JOIN domains dom ON dom.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = ha.id " +
    "ORDER BY d2.is_primary DESC, d2.name ASC LIMIT 1) " +
    "WHERE r.deployment_id = ? AND r.node_pool_id = ? AND r.assigned_node_id = ? " +
    "AND ((? = 'validate' AND r.state IN ('artifact_uploaded','validating','publishing')) " +
    "OR (? = 'publish' AND r.state IN ('ready_to_publish','publishing'))) LIMIT 1",
  ).bind(body.deploymentId, node.nodePoolId, node.id, purpose, purpose).first<{
    releaseId: string; organizationId: string; projectId: string; deploymentId: string;
    nodePoolId: string; state: string; releaseArtifactDigest: string | null;
    releaseArtifactBytes: number | null; commitSha: string; artifactKey: string | null;
    artifactBytes: number | null; artifactSha256: string | null;
    hostingAccountId: string; domainId: string; hostname: string; repositoryId: string;
  }>();
  if (!release) return c.json({ message: "No publishable release is assigned to this runtime node pool." }, 404);
  if (!release.artifactKey || !Number.isSafeInteger(release.artifactBytes) ||
      !Number.isSafeInteger(release.releaseArtifactBytes) ||
      release.artifactBytes !== release.releaseArtifactBytes ||
      release.artifactSha256 !== release.releaseArtifactDigest ||
      (release.artifactBytes ?? 0) < 1 || (release.artifactBytes ?? 0) > 100 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(release.artifactSha256 ?? "") ||
      !/^[a-f0-9]{40}$/.test(release.commitSha) ||
      !/^[1-9][0-9]{0,19}$/.test(release.repositoryId)) {
    return c.json({ message: "Release artifact metadata is missing or inconsistent." }, 409);
  }
  const object = await c.env.ARTIFACTS.get(release.artifactKey);
  if (!object || object.size !== release.artifactBytes ||
      object.customMetadata?.organizationId !== release.organizationId ||
      object.customMetadata?.projectId !== release.projectId ||
      object.customMetadata?.deploymentId !== release.deploymentId ||
      object.customMetadata?.commitSha !== release.commitSha ||
      object.customMetadata?.artifactSha256 !== release.artifactSha256) {
    return c.json({ message: "Stored artifact integrity metadata does not match its release." }, 409);
  }
  let envelope: string;
  try {
    envelope = await signDeploymentEnvelope(c.env, {
      organizationId: release.organizationId, projectId: release.projectId,
      deploymentId: release.deploymentId, hostingAccountId: release.hostingAccountId,
      domainId: release.domainId, hostname: release.hostname,
      repositoryId: release.repositoryId, commitSha: release.commitSha,
      artifactSha256: release.artifactSha256, artifactBytes: release.artifactBytes!,
    });
  } catch (error) {
    console.error("Application deployment envelope signing unavailable:", error instanceof Error ? error.message : "unknown error");
    return c.json({ message: "Application deployment envelope signing is not configured." }, 503);
  }
  if (purpose === "publish" && release.state === "ready_to_publish") {
    const transition = await c.env.DB.prepare(
      "UPDATE application_releases SET state = 'publishing', started_at = COALESCE(started_at, datetime('now')), updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'ready_to_publish' AND node_pool_id = ? AND assigned_node_id = ? " +
      "AND EXISTS (SELECT 1 FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
      "WHERE n.id = ? AND n.node_identity = ? AND n.node_role = 'runtime' AND n.status = 'online' " +
      "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
      "AND n.signing_public_key = ? AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm'))",
    ).bind(release.releaseId, release.nodePoolId, node.id, node.id, nodeIdentity, node.signingPublicKey).run();
    if (Number(transition.meta?.changes ?? 0) !== 1) {
      const latest = await c.env.DB.prepare("SELECT state FROM application_releases WHERE id = ? LIMIT 1")
        .bind(release.releaseId).first<{ state: string }>();
      if (latest?.state !== "publishing") {
        return c.json({ message: "Release is no longer eligible for artifact delivery." }, 409);
      }
    }
  }
  const stillEligible = await c.env.DB.prepare(
    "SELECT n.id FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.id = ? AND n.node_identity = ? AND n.node_role = 'runtime' AND n.status = 'online' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key = ? AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') LIMIT 1",
  ).bind(node.id, nodeIdentity, node.signingPublicKey).first<{ id: string }>();
  if (!stillEligible) return c.json({ message: "Runtime node or isolated pool became ineligible during artifact delivery." }, 409);
  await c.env.DB.prepare(
    "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE id = ? AND node_identity = ? AND status = 'online' AND node_role = 'runtime' " +
    "AND revoked_at IS NULL AND signing_public_key = ?",
  ).bind(node.id, nodeIdentity, node.signingPublicKey).run();
  return new Response(object.body, {
    status: 200,
    headers: {
      "Content-Type": "application/gzip",
      "Content-Length": String(release.artifactBytes),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Nexora-Deployment-Envelope": envelope,
      "X-Nexora-Artifact-SHA256": release.artifactSha256,
      "X-Nexora-Release-ID": release.releaseId,
    },
  });
});

app.post("/internal/v1/application-nodes/releases/validated", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node authentication headers." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Validation reports must use application/json." }, 415);
  }
  const rawBody = await c.req.text();
  if (rawBody.length < 2 || rawBody.length > 2048) {
    return c.json({ message: "Validation report body is empty or exceeds 2048 bytes." }, 413);
  }
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'runtime' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", path, rawBody, signature,
  )) {
    return c.json({ message: "Application node is not authorized to report archive validation." }, 401);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid validation report JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  const allowedKeys = new Set(["deploymentId", "artifactSha256", "archiveEntries", "archiveFiles", "archiveBytes"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key)) ||
      typeof body.deploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.deploymentId) ||
      typeof body.artifactSha256 !== "string" || !/^[a-f0-9]{64}$/.test(body.artifactSha256) ||
      !Number.isSafeInteger(body.archiveEntries) || Number(body.archiveEntries) < 1 || Number(body.archiveEntries) > 10000 ||
      !Number.isSafeInteger(body.archiveFiles) || Number(body.archiveFiles) < 0 ||
      Number(body.archiveFiles) > Number(body.archiveEntries) ||
      !Number.isSafeInteger(body.archiveBytes) || Number(body.archiveBytes) < 0 || Number(body.archiveBytes) > 500 * 1024 * 1024) {
    return c.json({ message: "Archive validation report is outside permitted bounds." }, 400);
  }

  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  const release = await c.env.DB.prepare(
    "SELECT r.id AS releaseId, r.state, r.artifact_digest AS artifactDigest, " +
    "r.artifact_bytes AS releaseArtifactBytes, d.artifact_sha256 AS deploymentArtifactDigest, " +
    "d.artifact_bytes AS deploymentArtifactBytes " +
    "FROM application_releases r JOIN github_deployments d " +
    "ON d.id = r.deployment_id AND d.organization_id = r.organization_id AND d.project_id = r.project_id " +
    "WHERE r.deployment_id = ? AND r.node_pool_id = ? AND r.assigned_node_id = ? LIMIT 1",
  ).bind(body.deploymentId, node.nodePoolId, node.id).first<{
    releaseId: string; state: string; artifactDigest: string | null;
    releaseArtifactBytes: number | null; deploymentArtifactDigest: string | null;
    deploymentArtifactBytes: number | null;
  }>();
  if (!release) return c.json({ message: "Assigned application release was not found." }, 404);
  if (release.artifactDigest !== body.artifactSha256 ||
      release.deploymentArtifactDigest !== body.artifactSha256 ||
      !Number.isSafeInteger(release.releaseArtifactBytes) ||
      release.releaseArtifactBytes !== release.deploymentArtifactBytes) {
    return c.json({ message: "Archive validation report does not match the assigned artifact metadata." }, 409);
  }
  const details = JSON.stringify({
    artifactSha256: body.artifactSha256,
    archiveEntries: body.archiveEntries,
    archiveFiles: body.archiveFiles,
    archiveBytes: body.archiveBytes,
  });
  if (release.state === "publishing") {
    const prior = await c.env.DB.prepare(
      "SELECT id FROM application_release_events WHERE release_id = ? " +
      "AND event_code = 'archive_validated_for_publish' AND details_redacted_json = ? LIMIT 1",
    ).bind(release.releaseId, details).first<{ id: string }>();
    if (!prior) return c.json({ message: "Release is publishing without a matching validation record." }, 409);
    return c.json({ accepted: true, duplicate: true, deploymentId: body.deploymentId, releaseState: "publishing" });
  }
  if (release.state !== "artifact_uploaded") {
    return c.json({ message: "Application release is not awaiting archive validation." }, 409);
  }

  const activeNodePredicate =
    " AND EXISTS (SELECT 1 FROM application_nodes n " +
    "JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.id = ? AND n.node_identity = ? AND n.node_role = 'runtime' " +
    "AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key = ? AND p.status = 'ready' " +
    "AND p.isolation_level IN ('rootless','microvm'))";
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'validating', updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'artifact_uploaded'" + activeNodePredicate,
    ).bind(release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'artifact_uploaded', 'validating', 'node', ?, 'archive_validation_started', ? " +
      "FROM application_releases WHERE id = ? AND state = 'validating'" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'ready_to_publish', updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'validating'" + activeNodePredicate,
    ).bind(release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'validating', 'ready_to_publish', 'node', ?, 'archive_validation_succeeded', ? " +
      "FROM application_releases WHERE id = ? AND state = 'ready_to_publish'" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'publishing', started_at = COALESCE(started_at, datetime('now')), updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'ready_to_publish'" + activeNodePredicate,
    ).bind(release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'ready_to_publish', 'publishing', 'node', ?, 'archive_validated_for_publish', ? " +
      "FROM application_releases WHERE id = ? AND state = 'publishing'" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseId, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND status = 'online' AND node_role = 'runtime' " +
      "AND revoked_at IS NULL AND signing_public_key = ?",
    ).bind(node.id, nodeIdentity, node.signingPublicKey),
  ]);
  if ([0, 2, 4, 6].some((index) => Number(results[index]?.meta?.changes ?? 0) !== 1) ||
      [1, 3, 5].some((index) => Number(results[index]?.meta?.changes ?? 0) !== 1)) {
    return c.json({ message: "Archive validation state transition could not be committed atomically." }, 409);
  }
  return c.json({
    accepted: true,
    duplicate: false,
    deploymentId: body.deploymentId,
    releaseState: "publishing",
    archive: {
      entries: body.archiveEntries,
      files: body.archiveFiles,
      bytes: body.archiveBytes,
    },
  });
});

app.post("/internal/v1/application-nodes/releases/activated", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node authentication headers." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Activation reports must use application/json." }, 415);
  }
  const reader = c.req.raw.body?.getReader();
  if (!reader) return c.json({ message: "Activation report body is required." }, 400);
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bodyBytes += chunk.value.byteLength;
      if (bodyBytes > 1024) {
        await reader.cancel();
        return c.json({ message: "Activation report exceeds 1024 bytes." }, 413);
      }
      chunks.push(chunk.value);
    }
  } catch {
    return c.json({ message: "Unable to read activation report body." }, 400);
  } finally {
    reader.releaseLock();
  }
  if (bodyBytes < 2) return c.json({ message: "Activation report body is empty." }, 400);
  const rawBytes = new Uint8Array(bodyBytes);
  let offset = 0;
  for (const chunk of chunks) { rawBytes.set(chunk, offset); offset += chunk.byteLength; }
  const decodedBody = new TextDecoder("utf-8").decode(rawBytes);
  const encodedBody = new TextEncoder().encode(decodedBody);
  if (encodedBody.byteLength !== rawBytes.byteLength ||
      encodedBody.some((value, index) => value !== rawBytes[index])) {
    return c.json({ message: "Activation report must be valid UTF-8." }, 400);
  }

  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'runtime' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", path, decodedBody, signature,
  )) {
    return c.json({ message: "Application node is not authorized to report release activation." }, 401);
  }

  let input: unknown;
  try { input = JSON.parse(decodedBody); } catch { return c.json({ message: "Invalid activation report JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((key) => !["deploymentId", "releaseId", "artifactSha256"].includes(key)) ||
      typeof body.deploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.deploymentId) ||
      typeof body.releaseId !== "string" || body.releaseId !== body.deploymentId ||
      typeof body.artifactSha256 !== "string" || !/^[a-f0-9]{64}$/.test(body.artifactSha256)) {
    return c.json({ message: "Release activation report is outside permitted bounds." }, 400);
  }

  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  const release = await c.env.DB.prepare(
    "SELECT r.id AS releaseId, r.state, r.artifact_digest AS artifactDigest, " +
    "d.artifact_sha256 AS deploymentArtifactDigest, r.node_pool_id AS nodePoolId " +
    "FROM application_releases r JOIN github_deployments d " +
    "ON d.id = r.deployment_id AND d.organization_id = r.organization_id AND d.project_id = r.project_id " +
    "WHERE r.deployment_id = ? AND r.node_pool_id = ? AND r.assigned_node_id = ? LIMIT 1",
  ).bind(body.deploymentId, node.nodePoolId, node.id).first<{
    releaseId: string; state: string; artifactDigest: string | null;
    deploymentArtifactDigest: string | null; nodePoolId: string;
  }>();
  if (!release) return c.json({ message: "Assigned application release was not found." }, 404);
  if (release.artifactDigest !== body.artifactSha256 ||
      release.deploymentArtifactDigest !== body.artifactSha256) {
    return c.json({ message: "Activation report digest does not match the assigned release artifact." }, 409);
  }

  const details = JSON.stringify({
    releaseId: body.releaseId,
    artifactSha256: body.artifactSha256,
  });
  if (release.state === "health_checking") {
    const prior = await c.env.DB.prepare(
      "SELECT id FROM application_release_events WHERE release_id = ? " +
      "AND event_code = 'release_files_activated' AND details_redacted_json = ? LIMIT 1",
    ).bind(release.releaseId, details).first<{ id: string }>();
    if (!prior) return c.json({ message: "Release is health_checking without a matching activation event." }, 409);
    return c.json({
      accepted: true, duplicate: true, deploymentId: body.deploymentId,
      releaseState: "health_checking", workloadHealth: "pending",
    });
  }
  if (release.state !== "publishing") {
    return c.json({ message: "Application release is not awaiting filesystem activation." }, 409);
  }

  const activeNodePredicate =
    " AND EXISTS (SELECT 1 FROM application_nodes n " +
    "JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.id = ? AND n.node_identity = ? AND n.node_role = 'runtime' " +
    "AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key = ? AND p.status = 'ready' " +
    "AND p.isolation_level IN ('rootless','microvm'))";
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'health_checking', updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'publishing' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(release.releaseId, body.artifactSha256, node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'publishing', 'health_checking', 'node', ?, 'release_files_activated', ? " +
      "FROM application_releases WHERE id = ? AND state = 'health_checking' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseId, body.artifactSha256,
      node.id, nodeIdentity, node.signingPublicKey),
    c.env.DB.prepare(
      "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND status = 'online' AND node_role = 'runtime' " +
      "AND revoked_at IS NULL AND signing_public_key = ?",
    ).bind(node.id, nodeIdentity, node.signingPublicKey),
  ]);
  if (results.some((result) => Number(result?.meta?.changes ?? 0) !== 1)) {
    return c.json({ message: "Release activation acknowledgement could not be committed safely." }, 409);
  }
  return c.json({
    accepted: true,
    duplicate: false,
    deploymentId: body.deploymentId,
    releaseState: "health_checking",
    workloadHealth: "pending",
  });
});

app.post("/internal/v1/application-nodes/releases/health-check", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  const path = new URL(c.req.url).pathname;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid application-node authentication headers." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Health-check reports must use application/json." }, 415);
  }
  const reader = c.req.raw.body?.getReader();
  if (!reader) return c.json({ message: "Health-check report body is required." }, 400);
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bodyBytes += chunk.value.byteLength;
      if (bodyBytes > 2048) {
        await reader.cancel();
        return c.json({ message: "Health-check report exceeds 2048 bytes." }, 413);
      }
      chunks.push(chunk.value);
    }
  } catch {
    return c.json({ message: "Unable to read health-check report body." }, 400);
  } finally {
    reader.releaseLock();
  }
  if (bodyBytes < 2) return c.json({ message: "Health-check report body is empty." }, 400);
  const rawBytes = new Uint8Array(bodyBytes);
  let offset = 0;
  for (const chunk of chunks) { rawBytes.set(chunk, offset); offset += chunk.byteLength; }
  const decodedBody = new TextDecoder("utf-8").decode(rawBytes);
  const encodedBody = new TextEncoder().encode(decodedBody);
  if (encodedBody.byteLength !== rawBytes.byteLength ||
      encodedBody.some((value, index) => value !== rawBytes[index])) {
    return c.json({ message: "Health-check report must be valid UTF-8." }, 400);
  }

  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'runtime' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", path, decodedBody, signature,
  )) {
    return c.json({ message: "Application node is not authorized to report health checks." }, 401);
  }

  let input: unknown;
  try { input = JSON.parse(decodedBody); } catch { return c.json({ message: "Invalid health-check report JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  const allowedKeys = new Set([
    "deploymentId", "artifactSha256", "probePath", "healthStatus",
    "httpStatus", "durationMs", "failureCode",
  ]);
  const failureCodes = new Set([
    "connection_refused", "timeout", "http_4xx", "http_5xx",
    "invalid_response", "process_exit", "probe_error",
  ]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key)) ||
      typeof body.deploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.deploymentId) ||
      typeof body.artifactSha256 !== "string" || !/^[a-f0-9]{64}$/.test(body.artifactSha256) ||
      typeof body.probePath !== "string" || !validStaticHealthCheckPath(body.probePath) ||
      body.probePath.length > 512 || /[?#\r\n]/.test(body.probePath) ||
      /[\x00-\x1F\x7F]/.test(body.probePath) ||
      !["healthy", "unhealthy"].includes(String(body.healthStatus)) ||
      !Number.isInteger(body.httpStatus) || Number(body.httpStatus) < 0 || Number(body.httpStatus) > 599 ||
      !Number.isInteger(body.durationMs) || Number(body.durationMs) < 0 || Number(body.durationMs) > 30000) {
    return c.json({ message: "Health-check report is outside permitted bounds." }, 400);
  }
  const healthStatus = String(body.healthStatus);
  const httpStatus = Number(body.httpStatus);
  const durationMs = Number(body.durationMs);
  const failureCode = body.failureCode === undefined ? "" : String(body.failureCode);
  if ((healthStatus === "healthy" && (httpStatus < 200 || httpStatus > 299 || failureCode !== "")) ||
      (healthStatus === "unhealthy" && (!failureCodes.has(failureCode) ||
        (httpStatus >= 200 && httpStatus <= 299)))) {
    return c.json({ message: "Health-check status, HTTP status, and failure code are inconsistent." }, 400);
  }

  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  const release = await c.env.DB.prepare(
    "SELECT r.id AS releaseRowId, r.state, r.artifact_digest AS artifactDigest, " +
    "d.artifact_sha256 AS deploymentArtifactDigest, r.project_id AS projectId, " +
    "r.organization_id AS organizationId, s.health_check_path AS healthCheckPath, " +
    "w.active_release_id AS previousActiveReleaseId, previous.deployment_id AS previousDeploymentId, " +
    "previous.artifact_digest AS previousArtifactDigest, previous_node.id AS previousActiveNodeId, " +
    "previous_node.node_identity AS previousActiveNodeIdentity " +
    "FROM application_releases r " +
    "JOIN github_deployments d ON d.id = r.deployment_id AND d.organization_id = r.organization_id AND d.project_id = r.project_id " +
    "JOIN application_project_settings s ON s.project_id = r.project_id AND s.organization_id = r.organization_id " +
    "LEFT JOIN application_workloads w ON w.project_id = r.project_id AND w.organization_id = r.organization_id AND w.workload_kind = 'web' " +
    "LEFT JOIN application_releases previous ON previous.id = w.active_release_id AND previous.project_id = r.project_id AND previous.organization_id = r.organization_id " +
    "LEFT JOIN application_nodes previous_node ON previous_node.id = w.node_id " +
    "WHERE r.deployment_id = ? AND r.node_pool_id = ? AND r.assigned_node_id = ? LIMIT 1",
  ).bind(body.deploymentId, node.nodePoolId, node.id).first<{
    releaseRowId: string; state: string; artifactDigest: string | null;
    deploymentArtifactDigest: string | null; projectId: string; organizationId: string;
    healthCheckPath: string | null; previousActiveReleaseId: string | null;
    previousDeploymentId: string | null;
    previousArtifactDigest: string | null;
    previousActiveNodeId: string | null;
    previousActiveNodeIdentity: string | null;
  }>();
  if (!release) return c.json({ message: "Assigned application release was not found." }, 404);
  if (release.artifactDigest !== body.artifactSha256 ||
      release.deploymentArtifactDigest !== body.artifactSha256) {
    return c.json({ message: "Health-check report digest does not match the assigned release artifact." }, 409);
  }
  const expectedProbePath = release.healthCheckPath ?? "/";
  if (body.probePath !== expectedProbePath) {
    return c.json({ message: "Health-check path does not match the project runtime settings." }, 409);
  }

  // Rollback is executable only when the previously active release is still
  // assigned to this exact node and no completion has already been acknowledged.
  // A different-node workload remains untouched; an acknowledged rollback must
  // not be advertised again by a retried terminal health-check report.
  const rollbackAcknowledgement = healthStatus === "unhealthy"
    ? await c.env.DB.prepare(
        "SELECT operation_id AS operationId FROM application_rollback_acknowledgements " +
        "WHERE failed_release_id = ? LIMIT 1",
      ).bind(release.releaseRowId).first<{ operationId: string }>()
    : null;
  const sameNodeRollbackAvailable = healthStatus === "unhealthy" &&
    !rollbackAcknowledgement &&
    Boolean(release.previousDeploymentId && release.previousActiveReleaseId &&
      release.previousArtifactDigest && release.previousActiveNodeIdentity === nodeIdentity);

  const details = JSON.stringify({
    artifactSha256: body.artifactSha256,
    probePath: body.probePath,
    healthStatus,
    httpStatus,
    durationMs,
    failureCode: failureCode || null,
  });
  // A retried health-check report for an already-terminal release is idempotent
  // when the outcome agrees with the recorded terminal state. Probe duration
  // and HTTP status may vary slightly between retries (network jitter, probe
  // restart); the durable decision is the outcome itself, so we match on the
  // release and event_code only. A retry that disagrees with the terminal
  // outcome remains a conflict and is rejected. A terminal release with no
  // corresponding health-check event in history is treated as a data-integrity
  // failure and rejected so a stale or replayed report cannot silently agree
  // with a state that was reached by a different path.
  const eventCode = healthStatus === "healthy" ? "health_check_succeeded" : "health_check_failed";
  const targetState = healthStatus === "healthy" ? "succeeded" : "failed";
  if (release.state === "succeeded" || release.state === "failed") {
    if (release.state !== targetState) {
      return c.json({ message: "Health-check outcome conflicts with the terminal release state." }, 409);
    }
    const prior = await c.env.DB.prepare(
      "SELECT id FROM application_release_events WHERE release_id = ? AND event_code = ? " +
      "LIMIT 1",
    ).bind(release.releaseRowId, eventCode).first<{ id: string }>();
    if (!prior) return c.json({ message: "Terminal release has no matching health-check event." }, 409);
    return c.json({
      accepted: true, duplicate: true, deploymentId: body.deploymentId,
      releaseState: targetState,
      workloadHealth: healthStatus === "healthy" ? "healthy" : "unhealthy",
      rollbackRequired: sameNodeRollbackAvailable,
      rollbackTargetDeploymentId: sameNodeRollbackAvailable
        ? release.previousDeploymentId : null,
      rollbackTargetReleaseId: sameNodeRollbackAvailable
        ? release.previousActiveReleaseId : null,
      rollbackTargetNodeIdentity: sameNodeRollbackAvailable
        ? release.previousActiveNodeIdentity : null,
      rollbackTargetArtifactSha256: sameNodeRollbackAvailable
        ? release.previousArtifactDigest : null,
    });
  }
  if (release.state !== "health_checking") {
    return c.json({ message: "Application release is not awaiting a health-check report." }, 409);
  }

  const activeNodePredicate =
    " AND EXISTS (SELECT 1 FROM application_nodes n " +
    "JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.id = ? AND n.node_identity = ? AND n.node_role = 'runtime' " +
    "AND n.status = 'online' AND n.revoked_at IS NULL " +
    "AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND n.signing_public_key = ? AND p.status = 'ready' " +
    "AND p.isolation_level IN ('rootless','microvm'))";
  const commonNodeArgs = [node.id, nodeIdentity, node.signingPublicKey];
  const statements = healthStatus === "healthy" ? [
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'succeeded', finished_at = datetime('now'), " +
      "failure_code = NULL, failure_message_redacted = NULL, updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'health_checking' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(release.releaseRowId, body.artifactSha256, ...commonNodeArgs),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'health_checking', 'succeeded', 'node', ?, 'health_check_succeeded', ? " +
      "FROM application_releases WHERE id = ? AND state = 'succeeded' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseRowId, body.artifactSha256, ...commonNodeArgs),
    c.env.DB.prepare(
      "INSERT INTO application_workloads " +
      "(id, organization_id, project_id, active_release_id, node_id, workload_kind, status, desired_replicas, observed_replicas) " +
      "VALUES (?, ?, ?, ?, ?, 'web', 'healthy', 1, 1) " +
      "ON CONFLICT(organization_id, project_id, workload_kind) DO UPDATE SET " +
      "active_release_id = excluded.active_release_id, node_id = excluded.node_id, status = 'healthy', " +
      "desired_replicas = 1, observed_replicas = 1, updated_at = datetime('now')",
    ).bind(crypto.randomUUID(), release.organizationId, release.projectId, release.releaseRowId, node.id),
    c.env.DB.prepare(
      "UPDATE github_deployments SET status = 'succeeded', finished_at = datetime('now'), " +
      "log_excerpt = 'Application health check succeeded.' " +
      "WHERE id = ? AND organization_id = ? AND project_id = ? AND status = 'building'",
    ).bind(body.deploymentId, release.organizationId, release.projectId),
    c.env.DB.prepare(
      "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND status = 'online' AND node_role = 'runtime' " +
      "AND revoked_at IS NULL AND signing_public_key = ?",
    ).bind(node.id, nodeIdentity, node.signingPublicKey),
  ] : [
    c.env.DB.prepare(
      "UPDATE application_releases SET state = 'failed', finished_at = datetime('now'), " +
      "failure_code = ?, failure_message_redacted = 'Initial application health check failed.', updated_at = datetime('now') " +
      "WHERE id = ? AND state = 'health_checking' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(failureCode, release.releaseRowId, body.artifactSha256, ...commonNodeArgs),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, organization_id, id, 'health_checking', 'failed', 'node', ?, 'health_check_failed', ? " +
      "FROM application_releases WHERE id = ? AND state = 'failed' AND artifact_digest = ?" + activeNodePredicate,
    ).bind(crypto.randomUUID(), node.id, details, release.releaseRowId, body.artifactSha256, ...commonNodeArgs),
    c.env.DB.prepare(
      "INSERT INTO application_workloads " +
      "(id, organization_id, project_id, active_release_id, node_id, workload_kind, status, desired_replicas, observed_replicas) " +
      "VALUES (?, ?, ?, ?, ?, 'web', 'unhealthy', 1, 0) " +
      "ON CONFLICT(organization_id, project_id, workload_kind) DO UPDATE SET " +
      "status = CASE WHEN application_workloads.active_release_id IS NOT NULL " +
      "THEN application_workloads.status ELSE 'unhealthy' END, " +
      "observed_replicas = CASE WHEN application_workloads.active_release_id IS NOT NULL " +
      "THEN application_workloads.observed_replicas ELSE 0 END, updated_at = datetime('now')",
    ).bind(crypto.randomUUID(), release.organizationId, release.projectId,
      release.previousActiveReleaseId, release.previousActiveNodeId ?? node.id),
    c.env.DB.prepare(
      "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), " +
      "log_excerpt = 'Application health check failed.' " +
      "WHERE id = ? AND organization_id = ? AND project_id = ? AND status = 'building'",
    ).bind(body.deploymentId, release.organizationId, release.projectId),
    c.env.DB.prepare(
      "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND status = 'online' AND node_role = 'runtime' " +
      "AND revoked_at IS NULL AND signing_public_key = ?",
    ).bind(node.id, nodeIdentity, node.signingPublicKey),
  ];

  const results = await c.env.DB.batch(statements);
  if (results.some((result) => Number(result?.meta?.changes ?? 0) !== 1)) {
    return c.json({ message: "Health-check outcome could not be committed safely." }, 409);
  }
  return c.json({
    accepted: true,
    duplicate: false,
    deploymentId: body.deploymentId,
    releaseState: targetState,
    workloadHealth: healthStatus,
    rollbackRequired: sameNodeRollbackAvailable,
    rollbackTargetDeploymentId: sameNodeRollbackAvailable
      ? release.previousDeploymentId : null,
    rollbackTargetReleaseId: sameNodeRollbackAvailable
      ? release.previousActiveReleaseId : null,
    rollbackTargetNodeIdentity: sameNodeRollbackAvailable
      ? release.previousActiveNodeIdentity : null,
    rollbackTargetArtifactSha256: sameNodeRollbackAvailable
      ? release.previousArtifactDigest : null,
  });
});


const ROLLBACK_COMPLETION_PATH = "/internal/v1/application-nodes/releases/rollback-completed";

app.post(ROLLBACK_COMPLETION_PATH, async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = (c.req.header("x-nexora-node-signature") ?? "").toLowerCase();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity) ||
      !/^\d{10}$/.test(timestamp) || !/^[a-f0-9]{32}$/i.test(nonce) ||
      !/^[a-f0-9]{128}$/.test(signature)) {
    return c.json({ message: "Missing or invalid rollback completion proof." }, 401);
  }
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")) {
    return c.json({ message: "Rollback completion reports must use application/json." }, 415);
  }

  const reader = c.req.raw.body?.getReader();
  if (!reader) return c.json({ message: "Rollback completion report body is required." }, 400);
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bodyBytes += chunk.value.byteLength;
      if (bodyBytes > 2048) {
        await reader.cancel();
        return c.json({ message: "Rollback completion report exceeds 2048 bytes." }, 413);
      }
      chunks.push(chunk.value);
    }
  } catch {
    return c.json({ message: "Unable to read rollback completion report." }, 400);
  } finally {
    reader.releaseLock();
  }
  if (bodyBytes < 2) return c.json({ message: "Rollback completion report body is empty." }, 400);
  const rawBytes = new Uint8Array(bodyBytes);
  let offset = 0;
  for (const chunk of chunks) { rawBytes.set(chunk, offset); offset += chunk.byteLength; }
  const decodedBody = new TextDecoder("utf-8").decode(rawBytes);
  const encodedBody = new TextEncoder().encode(decodedBody);
  if (encodedBody.byteLength !== rawBytes.byteLength ||
      encodedBody.some((value, index) => value !== rawBytes[index])) {
    return c.json({ message: "Rollback completion report must be valid UTF-8." }, 400);
  }

  const node = await c.env.DB.prepare(
    "SELECT n.id, n.node_pool_id AS nodePoolId, n.signing_public_key AS signingPublicKey " +
    "FROM application_nodes n JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.node_role = 'runtime' AND n.status = 'online' " +
    "AND n.revoked_at IS NULL AND n.last_heartbeat_at >= datetime('now', '-15 minutes') " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; nodePoolId: string; signingPublicKey: string }>();
  if (!node || !await verifyApplicationNodeRequestSignature(
    node.signingPublicKey, nodeIdentity, timestamp, nonce, "POST", ROLLBACK_COMPLETION_PATH, decodedBody, signature,
  )) {
    return c.json({ message: "Runtime node is not authorized to report rollback completion." }, 401);
  }

  let input: unknown;
  try { input = JSON.parse(decodedBody); } catch { return c.json({ message: "Invalid rollback completion JSON." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return c.json({ message: "A JSON object is required." }, 400);
  }
  const body = input as Record<string, unknown>;
  const allowedKeys = new Set([
    "operationId", "failedDeploymentId", "targetDeploymentId",
    "targetArtifactSha256", "httpStatus", "durationMs",
  ]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key)) ||
      typeof body.operationId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(body.operationId) ||
      typeof body.failedDeploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.failedDeploymentId) ||
      typeof body.targetDeploymentId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.targetDeploymentId) ||
      body.failedDeploymentId === body.targetDeploymentId ||
      typeof body.targetArtifactSha256 !== "string" || !/^[a-f0-9]{64}$/.test(body.targetArtifactSha256) ||
      !Number.isInteger(body.httpStatus) || Number(body.httpStatus) < 200 || Number(body.httpStatus) > 299 ||
      !Number.isInteger(body.durationMs) || Number(body.durationMs) < 0 || Number(body.durationMs) > 30000) {
    return c.json({ message: "Rollback completion report is outside permitted bounds." }, 400);
  }

  const nonceResult = await c.env.DB.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Application-node request nonce has already been used." }, 409);
  }

  const priorAcknowledgement = await c.env.DB.prepare(
    "SELECT node_id AS nodeId, failed_deployment_id AS failedDeploymentId, " +
    "target_deployment_id AS targetDeploymentId, target_artifact_sha256 AS targetArtifactSha256, " +
    "http_status AS httpStatus, probe_duration_ms AS durationMs " +
    "FROM application_rollback_acknowledgements WHERE operation_id = ? LIMIT 1",
  ).bind(body.operationId).first<{
    nodeId: string; failedDeploymentId: string; targetDeploymentId: string;
    targetArtifactSha256: string; httpStatus: number; durationMs: number;
  }>();
  if (priorAcknowledgement) {
    if (priorAcknowledgement.nodeId !== node.id ||
        priorAcknowledgement.failedDeploymentId !== body.failedDeploymentId ||
        priorAcknowledgement.targetDeploymentId !== body.targetDeploymentId ||
        priorAcknowledgement.targetArtifactSha256 !== body.targetArtifactSha256 ||
        priorAcknowledgement.httpStatus !== body.httpStatus ||
        priorAcknowledgement.durationMs !== body.durationMs) {
      return c.json({ message: "Rollback operation ID conflicts with an existing acknowledgement." }, 409);
    }
    return c.json({
      accepted: true, duplicate: true, operationId: body.operationId, state: "reported",
    }, 200, { "cache-control": "no-store" });
  }

  // Local symlink rollback is permitted only when both immutable releases are
  // assigned to this same node. Cross-node recovery requires a separate traffic
  // and scheduler protocol and is deliberately rejected here.
  const binding = await c.env.DB.prepare(
    "SELECT failed.id AS failedReleaseId, failed.organization_id AS organizationId, " +
    "failed.project_id AS projectId, target.id AS targetReleaseId, " +
    "target.artifact_digest AS targetArtifactDigest, w.id AS workloadId " +
    "FROM application_releases failed " +
    "JOIN application_releases target ON target.deployment_id = ? " +
    "AND target.organization_id = failed.organization_id AND target.project_id = failed.project_id " +
    "JOIN application_workloads w ON w.organization_id = failed.organization_id " +
    "AND w.project_id = failed.project_id AND w.workload_kind = 'web' " +
    "WHERE failed.deployment_id = ? AND failed.assigned_node_id = ? " +
    "AND target.assigned_node_id = ? AND failed.node_pool_id = ? AND target.node_pool_id = ? " +
    "AND failed.state = 'failed' AND target.state = 'succeeded' " +
    "AND target.artifact_digest = ? AND w.active_release_id = target.id " +
    "AND w.node_id = ? AND w.status IN ('unhealthy','healthy') LIMIT 1",
  ).bind(body.targetDeploymentId, body.failedDeploymentId, node.id, node.id,
    node.nodePoolId, node.nodePoolId, body.targetArtifactSha256, node.id).first<{
      failedReleaseId: string; organizationId: string; projectId: string;
      targetReleaseId: string; targetArtifactDigest: string; workloadId: string;
    }>();
  if (!binding) {
    return c.json({ message: "Rollback does not match a failed release and successful same-node target assignment." }, 409);
  }

  const details = JSON.stringify({
    operationId: body.operationId,
    failedDeploymentId: body.failedDeploymentId,
    targetDeploymentId: body.targetDeploymentId,
    targetArtifactSha256: body.targetArtifactSha256,
    httpStatus: body.httpStatus,
    durationMs: body.durationMs,
  });
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT OR IGNORE INTO application_rollback_acknowledgements " +
      "(operation_id, organization_id, project_id, node_id, failed_release_id, target_release_id, " +
      "failed_deployment_id, target_deployment_id, target_artifact_sha256, http_status, probe_duration_ms) " +
      "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " +
      "WHERE EXISTS (SELECT 1 FROM application_workloads w WHERE w.id = ? " +
      "AND w.active_release_id = ? AND w.node_id = ? AND w.status IN ('unhealthy','healthy'))",
    ).bind(body.operationId, binding.organizationId, binding.projectId, node.id,
      binding.failedReleaseId, binding.targetReleaseId, body.failedDeploymentId,
      body.targetDeploymentId, body.targetArtifactSha256, body.httpStatus, body.durationMs,
      binding.workloadId, binding.targetReleaseId, node.id),
    c.env.DB.prepare(
      "UPDATE application_workloads SET status = 'healthy', desired_replicas = 1, " +
      "observed_replicas = 1, updated_at = datetime('now') " +
      "WHERE id = ? AND active_release_id = ? AND node_id = ? AND status IN ('unhealthy','healthy') " +
      "AND EXISTS (SELECT 1 FROM application_rollback_acknowledgements a " +
      "WHERE a.operation_id = ? AND a.node_id = ? AND a.failed_release_id = ? " +
      "AND a.target_release_id = ? AND a.target_artifact_sha256 = ? " +
      "AND a.http_status = ? AND a.probe_duration_ms = ?)",
    ).bind(binding.workloadId, binding.targetReleaseId, node.id, body.operationId, node.id,
      binding.failedReleaseId, binding.targetReleaseId, body.targetArtifactSha256,
      body.httpStatus, body.durationMs),
    c.env.DB.prepare(
      "INSERT INTO application_release_events " +
      "(id, organization_id, release_id, from_state, to_state, actor_type, actor_id, event_code, details_redacted_json) " +
      "SELECT ?, ?, ?, 'succeeded', 'succeeded', 'node', ?, 'rollback_completed', ? " +
      "WHERE EXISTS (SELECT 1 FROM application_rollback_acknowledgements a " +
      "WHERE a.operation_id = ? AND a.node_id = ? AND a.target_release_id = ?) " +
      "AND NOT EXISTS (SELECT 1 FROM application_release_events e WHERE e.release_id = ? " +
      "AND e.event_code = 'rollback_completed' AND e.details_redacted_json = ?)",
    ).bind(crypto.randomUUID(), binding.organizationId, binding.targetReleaseId, node.id, details,
      body.operationId, node.id, binding.targetReleaseId, binding.targetReleaseId, details),
    c.env.DB.prepare(
      "UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') " +
      "WHERE id = ? AND node_identity = ? AND node_role = 'runtime' AND status = 'online' " +
      "AND revoked_at IS NULL AND signing_public_key = ?",
    ).bind(node.id, nodeIdentity, node.signingPublicKey),
  ]);
  if (Number(results[3]?.meta?.changes ?? 0) !== 1) {
    return c.json({ message: "Runtime node was revoked or changed during rollback acknowledgement." }, 409);
  }

  const saved = await c.env.DB.prepare(
    "SELECT node_id AS nodeId, failed_release_id AS failedReleaseId, target_release_id AS targetReleaseId, " +
    "target_artifact_sha256 AS targetArtifactSha256, http_status AS httpStatus, " +
    "probe_duration_ms AS durationMs FROM application_rollback_acknowledgements WHERE operation_id = ? LIMIT 1",
  ).bind(body.operationId).first<{
    nodeId: string; failedReleaseId: string; targetReleaseId: string;
    targetArtifactSha256: string; httpStatus: number; durationMs: number;
  }>();
  if (!saved || saved.nodeId !== node.id || saved.failedReleaseId !== binding.failedReleaseId ||
      saved.targetReleaseId !== binding.targetReleaseId || saved.targetArtifactSha256 !== body.targetArtifactSha256 ||
      saved.httpStatus !== body.httpStatus || saved.durationMs !== body.durationMs) {
    return c.json({ message: "Rollback operation ID conflicts with an existing acknowledgement." }, 409);
  }
  const workload = await c.env.DB.prepare(
    "SELECT status, active_release_id AS activeReleaseId, node_id AS nodeId " +
    "FROM application_workloads WHERE id = ? LIMIT 1",
  ).bind(binding.workloadId).first<{ status: string; activeReleaseId: string; nodeId: string }>();
  if (!workload || workload.status !== "healthy" || workload.activeReleaseId !== binding.targetReleaseId ||
      workload.nodeId !== node.id) {
    return c.json({ message: "Rollback acknowledgement was stored but workload state could not be confirmed." }, 409);
  }

  return c.json({
    accepted: true,
    duplicate: Number(results[0]?.meta?.changes ?? 0) === 0,
    operationId: body.operationId,
    state: "reported",
  }, 200, { "cache-control": "no-store" });
});

app.post("/internal/v1/application-build-usage", async (c) => {
  const nodeIdentity = c.req.header("x-nexora-node-identity") ?? "";
  const timestamp = c.req.header("x-nexora-node-timestamp") ?? "";
  const nonce = c.req.header("x-nexora-node-nonce") ?? "";
  const signature = c.req.header("x-nexora-node-signature") ?? "";
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/.test(nodeIdentity)) {
    return c.json({ message: "Node identity is required." }, 401);
  }
  const rawBody = await c.req.text();
  if (rawBody.length > 4096) return c.json({ message: "Request body is too large." }, 413);
  const node = await c.env.DB.prepare(
    "SELECT n.id, n.signing_public_key AS signingPublicKey FROM application_nodes n " +
    "JOIN application_node_pools p ON p.id = n.node_pool_id " +
    "WHERE n.node_identity = ? AND n.status = 'online' AND n.node_role = 'builder' " +
    "AND p.status = 'ready' AND p.isolation_level IN ('rootless','microvm') " +
    "AND n.signing_public_key IS NOT NULL LIMIT 1",
  ).bind(nodeIdentity).first<{ id: string; signingPublicKey: string }>();
  if (!node || !await verifyNodeSignature(node.signingPublicKey, timestamp, nonce, rawBody, signature)) {
    return c.json({ message: "Invalid node identity or signature." }, 401);
  }
  let input: unknown;
  try { input = JSON.parse(rawBody); } catch { return c.json({ message: "Invalid JSON body." }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) return c.json({ message: "A JSON object is required." }, 400);
  const body = input as Record<string, unknown>;
  const allowedKeys = new Set(["deploymentId", "buildSeconds", "buildResult"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key)) ||
      typeof body.deploymentId !== "string" || body.deploymentId.length < 1 || body.deploymentId.length > 128 ||
      !Number.isInteger(body.buildSeconds) || Number(body.buildSeconds) < 1 || Number(body.buildSeconds) > 604800 ||
      !["succeeded", "failed", "cancelled"].includes(String(body.buildResult))) {
    return c.json({ message: "Invalid builder usage payload." }, 400);
  }
  const deploymentId = body.deploymentId;
  const buildSeconds = Number(body.buildSeconds);
  const buildResult = String(body.buildResult);
  const db = c.env.DB;
  const nonceResult = await db.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) return c.json({ message: "Request nonce has already been used." }, 409);

  const priorEvent = await db.prepare(
    "SELECT e.id, e.period_start AS periodStart, e.organization_id AS organizationId, e.project_id AS projectId, " +
    "e.build_seconds AS buildSeconds, e.build_result AS buildResult " +
    "FROM application_usage_events e WHERE e.deployment_id = ? AND e.node_id = ? LIMIT 1",
  ).bind(deploymentId, node.id).first<{ id: string; periodStart: string; organizationId: string; projectId: string; buildSeconds: number; buildResult: string }>();

  if (priorEvent) {
    if (priorEvent.buildSeconds !== buildSeconds || priorEvent.buildResult !== buildResult) {
      return c.json({ message: "A conflicting report already exists for this deployment and node." }, 409);
    }
    const priorUsage = await db.prepare(
      "SELECT build_seconds_used AS buildSecondsUsed, build_minutes_limit AS buildMinutesLimit " +
      "FROM application_usage_periods WHERE organization_id = ? AND project_id = ? AND period_start = ? LIMIT 1",
    ).bind(priorEvent.organizationId, priorEvent.projectId, priorEvent.periodStart)
      .first<{ buildSecondsUsed: number; buildMinutesLimit: number }>();
    if (!priorUsage) return c.json({ message: "Usage aggregate is unavailable." }, 500);
    return c.json({ accepted: true, duplicate: true, periodStart: priorEvent.periodStart,
      buildSecondsUsed: priorUsage.buildSecondsUsed, buildMinutesLimit: priorUsage.buildMinutesLimit,
      quotaExhausted: priorUsage.buildSecondsUsed >= priorUsage.buildMinutesLimit * 60,
      quotaEnforcement: "not_enabled" });
  }

  const deployment = await db.prepare(
    "SELECT d.id, d.organization_id AS organizationId, d.project_id AS projectId " +
    "FROM github_deployments d WHERE d.id = ? AND d.status IN ('cloning', 'installing', 'building') LIMIT 1",
  ).bind(deploymentId).first<{ id: string; organizationId: string; projectId: string }>();
  if (!deployment) return c.json({ message: "Deployment is not active or does not exist." }, 409);



  const now = new Date();
  const periodStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString().slice(0, 10);
  const results = await db.batch([
    db.prepare(
      "INSERT OR IGNORE INTO application_usage_periods " +
      "(id, organization_id, project_id, period_start, build_seconds_used, build_minutes_limit) " +
      "SELECT ?, p.organization_id, p.id, ?, 0, hp.app_build_minutes_month " +
      "FROM github_projects p JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = p.organization_id " +
      "JOIN hosting_plans hp ON hp.id = h.plan_id AND hp.organization_id = p.organization_id " +
      "WHERE p.id = ? AND p.organization_id = ?",
    ).bind(crypto.randomUUID(), periodStart, deployment.projectId, deployment.organizationId),
    db.prepare(
      "INSERT OR IGNORE INTO application_usage_events " +
      "(id, organization_id, project_id, deployment_id, period_start, build_seconds, source, build_result, node_id) " +
      "SELECT ?, d.organization_id, d.project_id, d.id, ?, ?, 'isolated_builder', ?, ? " +
      "FROM github_deployments d WHERE d.id = ? AND d.organization_id = ? AND d.project_id = ? " +
      "AND d.status IN ('cloning', 'installing', 'building') " +
      "AND EXISTS (SELECT 1 FROM application_usage_periods u WHERE u.organization_id = d.organization_id " +
      "AND u.project_id = d.project_id AND u.period_start = ?)",
    ).bind(crypto.randomUUID(), periodStart, buildSeconds, buildResult, node.id, deploymentId, deployment.organizationId, deployment.projectId, periodStart),
    db.prepare(
      "UPDATE application_usage_periods SET build_seconds_used = build_seconds_used + (" +
      "SELECT COALESCE(SUM(e.build_seconds), 0) FROM application_usage_events e " +
      "WHERE e.organization_id = ? AND e.project_id = ? AND e.period_start = ? AND e.aggregated_at IS NULL" +
      "), updated_at = datetime('now') WHERE organization_id = ? AND project_id = ? AND period_start = ?",
    ).bind(deployment.organizationId, deployment.projectId, periodStart, deployment.organizationId, deployment.projectId, periodStart),
    db.prepare(
      "UPDATE application_usage_events SET aggregated_at = datetime('now') " +
      "WHERE organization_id = ? AND project_id = ? AND period_start = ? AND aggregated_at IS NULL",
    ).bind(deployment.organizationId, deployment.projectId, periodStart),
    db.prepare("UPDATE application_nodes SET last_signature_at = datetime('now'), updated_at = datetime('now') WHERE id = ?").bind(node.id),
  ]);

  const event = await db.prepare(
    "SELECT id, period_start AS periodStart FROM application_usage_events WHERE organization_id = ? AND project_id = ? AND deployment_id = ? AND node_id = ? LIMIT 1",
  ).bind(deployment.organizationId, deployment.projectId, deploymentId, node.id).first<{ id: string; periodStart: string }>();
  if (!event) return c.json({ message: "Usage report could not be associated with an active deployment." }, 409);
  const usage = await db.prepare(
    "SELECT build_seconds_used AS buildSecondsUsed, build_minutes_limit AS buildMinutesLimit " +
    "FROM application_usage_periods WHERE organization_id = ? AND project_id = ? AND period_start = ? LIMIT 1",
  ).bind(deployment.organizationId, deployment.projectId, event.periodStart).first<{ buildSecondsUsed: number; buildMinutesLimit: number }>();
  if (!usage) return c.json({ message: "Usage aggregate is unavailable." }, 500);
  const inserted = Number(results[1]?.meta?.changes ?? 0) > 0;
  return c.json({
    accepted: true,
    duplicate: !inserted,
    periodStart: event.periodStart,
    buildSecondsUsed: usage.buildSecondsUsed,
    buildMinutesLimit: usage.buildMinutesLimit,
    quotaExhausted: usage.buildSecondsUsed >= usage.buildMinutesLimit * 60,
    quotaEnforcement: "not_enabled",
  });
});

app.get("/v1/applications/projects/:projectId/settings", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const projectId = c.req.param("projectId");
  const project = await c.env.DB.prepare(
    `SELECT p.id, p.repository_full_name AS repositoryFullName,
            s.id AS settingsId, s.runtime_profile_id AS runtimeProfileId,
            rp.runtime_family AS runtimeFamily, rp.profile_key AS runtimeProfileKey,
            rp.enabled AS runtimeEnabled, s.spec_version AS specVersion,
            s.build_method AS buildMethod, s.build_context AS buildContext,
            s.build_command AS buildCommand, s.output_directory AS outputDirectory,
            s.start_command AS startCommand, s.listen_port AS listenPort,
            s.health_check_path AS healthCheckPath, s.cpu_millis AS cpuMillis,
            s.memory_mib AS memoryMiB, s.disk_mib AS diskMiB,
            s.process_limit AS processLimit, s.updated_at AS updatedAt,
            hp.app_cpu_millis AS planCpuMillis, hp.app_memory_mib AS planMemoryMiB,
            MIN(hp.app_disk_mib, CAST(hp.disk_limit_bytes / 1048576 AS INTEGER)) AS planDiskMiB,
            hp.app_process_limit AS planProcessLimit,
            hp.app_build_minutes_month AS planBuildMinutesMonth
     FROM github_projects p
     JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = p.organization_id
     JOIN hosting_plans hp ON hp.id = h.plan_id AND hp.organization_id = p.organization_id
     LEFT JOIN application_project_settings s
       ON s.project_id = p.id AND s.organization_id = p.organization_id
     LEFT JOIN application_runtime_profiles rp ON rp.id = s.runtime_profile_id
     WHERE p.id = ? AND p.organization_id = ?
       AND (? = 1 OR EXISTS (
         SELECT 1 FROM hosting_account_memberships m
         WHERE m.hosting_account_id = p.hosting_account_id
           AND m.organization_id = p.organization_id
           AND m.user_id = ? AND m.status = 'ACTIVE'
       ))
     LIMIT 1`,
  ).bind(projectId, identity.organizationId, identity.platformRole ? 1 : 0, identity.id).first<Record<string, unknown>>();
  if (!project) return c.json({ message: "GitHub project not found." }, 404);
  return c.json({
    project: { id: project.id, repositoryFullName: project.repositoryFullName },
    planLimits: {
      cpuMillis: project.planCpuMillis,
      memoryMiB: project.planMemoryMiB,
      diskMiB: project.planDiskMiB,
      processLimit: project.planProcessLimit,
      buildMinutesPerMonth: project.planBuildMinutesMonth,
    },
    settings: project.settingsId ? {
      id: project.settingsId,
      runtimeProfileId: project.runtimeProfileId,
      runtimeFamily: project.runtimeFamily,
      runtimeProfileKey: project.runtimeProfileKey,
      runtimeEnabled: project.runtimeEnabled === 1,
      specVersion: project.specVersion,
      buildMethod: project.buildMethod,
      buildContext: project.buildContext,
      buildCommand: project.buildCommand,
      outputDirectory: project.outputDirectory,
      startCommand: project.startCommand,
      listenPort: project.listenPort,
      healthCheckPath: project.healthCheckPath,
      resources: {
        cpuMillis: project.cpuMillis,
        memoryMiB: project.memoryMiB,
        diskMiB: project.diskMiB,
        processLimit: project.processLimit,
      },
      selectable: project.runtimeEnabled === 1,
    } : null,
    executionEnabled: false,
  });
});

app.get("/v1/github/projects/:projectId/deployments", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const project = await c.env.DB.prepare(
    "SELECT p.id FROM github_projects p WHERE p.id = ? AND p.organization_id = ? " +
    "AND (? = 1 OR EXISTS (SELECT 1 FROM hosting_account_memberships m " +
    "WHERE m.hosting_account_id = p.hosting_account_id AND m.organization_id = p.organization_id " +
    "AND m.user_id = ? AND m.status = 'ACTIVE')) LIMIT 1",
  ).bind(c.req.param("projectId"), identity.organizationId, identity.platformRole ? 1 : 0, identity.id).first<{ id: string }>();
  if (!project) return c.json({ message: "GitHub project not found." }, 404);
  const rows = await c.env.DB.prepare(
    `SELECT id, commit_sha AS commitSha, branch, trigger_type AS triggerType, status,
            commit_message AS commitMessage, deployment_url AS deploymentUrl, log_excerpt AS logExcerpt,
            requested_at AS requestedAt, started_at AS startedAt, finished_at AS finishedAt
     FROM github_deployments WHERE project_id = ? AND organization_id = ?
     ORDER BY requested_at DESC LIMIT 50`,
  ).bind(project.id, identity.organizationId).all();
  return c.json({ deployments: rows.results ?? [] });
});

app.delete("/v1/github/connection", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!Boolean(identity.platformRole)) return c.json({ message: "Administrator access required" }, 403);
  if (c.env.GITHUB_APP_CLIENT_ID && c.env.GITHUB_APP_CLIENT_SECRET) {
    try {
      const token = await githubAccessToken(c.env, c.env.DB, identity.organizationId);
      const credentials = btoa(`${c.env.GITHUB_APP_CLIENT_ID}:${c.env.GITHUB_APP_CLIENT_SECRET}`);
      await fetch(`https://api.github.com/applications/${encodeURIComponent(c.env.GITHUB_APP_CLIENT_ID)}/grant`, {
        method: "DELETE",
        headers: { Authorization: `Basic ${credentials}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28" },
        body: JSON.stringify({ access_token: token }),
      });
    } catch {
      // Local credential deletion remains authoritative even if remote revocation is unavailable.
    }
  }
  await c.env.DB.prepare("DELETE FROM github_connections WHERE organization_id = ?").bind(identity.organizationId).run();
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type) VALUES (?, ?, ?, 'github.disconnected', 'github_connection')")
    .bind(crypto.randomUUID(), identity.organizationId, identity.id).run();
  return c.json({ disconnected: true });
});

export default {
  fetch: app.fetch,
  scheduled(_controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
    ctx.waitUntil(Promise.all([
      checkMissedHeartbeats(env).catch((error) => {
        console.error("Heartbeat incident check failed:", error);
      }),
      dispatchIncidentNotifications(env).catch((error) => {
        console.error("Incident email dispatcher failed:", error);
      }),
      pruneFailedDeploymentArtifacts(env).then((result) => {
        if (result.deleted || result.failed) {
          console.info("R2 artifact retention completed:", result);
        }
      }).catch((error) => {
        console.error("R2 artifact retention task failed:", error);
      }),
      runBackupSchedules(env).catch((error) => {
        console.error("Backup scheduler failed:", error);
      }),
      expireDueSubscriptions(env.DB).then((changed) => {
        if (changed > 0) console.info(`Subscription expiry sweep: ${changed} subscription(s) expired or cancelled.`);
      }).catch((error) => {
        console.error("Subscription expiry sweep failed:", error);
      }),
    ]));
  },
};

// addMonthsClamped returns the date exactly `months` calendar months after
// `from`, with end-of-month clamping. For example, Jan 31 + 1 month = Feb 28
// (or Feb 29 in a leap year), not March 3. This is the correct behavior for
// monthly recurrence — JavaScript's built-in setUTCMonth overflows past
// short months, so we clamp manually.
//
// The clamp is computed in UTC to avoid daylight-saving drift: a monthly
// schedule that fires at 02:00 UTC on Jan 31 should next fire at 02:00 UTC
// on Feb 28, not at 03:00 UTC because DST kicked in. UTC has no DST, so
// the hour stays stable.
export function addMonthsClamped(from: Date, months: number): Date {
  const result = new Date(Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate(), from.getUTCHours(), from.getUTCMinutes(), from.getUTCSeconds(), from.getUTCMilliseconds()));
  const targetMonth = result.getUTCMonth() + months;
  // First, set the year/month. We deliberately use Date.UTC(year, month+delta, 0)
  // to compute the last day of the target month, then clamp the day.
  const targetYear = result.getUTCFullYear() + Math.floor(targetMonth / 12);
  const targetMonthIndex = ((targetMonth % 12) + 12) % 12;
  // Days in the target month (0 = last day of previous month = day count).
  const lastDayOfTargetMonth = new Date(Date.UTC(targetYear, targetMonthIndex + 1, 0)).getUTCDate();
  const clampedDay = Math.min(result.getUTCDate(), lastDayOfTargetMonth);
  return new Date(Date.UTC(targetYear, targetMonthIndex, clampedDay, result.getUTCHours(), result.getUTCMinutes(), result.getUTCSeconds(), result.getUTCMilliseconds()));
}

// nextMonthlyRunFromAnchor computes the next monthly run date from a stable
// anchor day, NOT from the execution date. This prevents permanent schedule
// drift: a schedule anchored on day 31 fires Jan 31 → Feb 28 (clamped) →
// March 31 (re-expanded) → April 30 → ... The anchor day is preserved across
// short months so the schedule always targets the original intended day.
//
// Parameters:
//   anchorDay: the original intended day-of-month (1-31).
//   from: the reference date (typically the current execution time).
//   months: how many months to advance (usually 1).
//
// The hour/minute/second are preserved from `from` (UTC). If from is the
// execution time, the next run inherits the same time-of-day, which is
// correct for schedules that should fire at a specific UTC hour.
//
// If anchorDay is null or invalid, falls back to addMonthsClamped(from, months)
// — this is the backward-compatibility path for schedules created before the
// anchor_day_of_month migration.
export function nextMonthlyRunFromAnchor(anchorDay: number | null, from: Date, months: number = 1): Date {
  if (!anchorDay || anchorDay < 1 || anchorDay > 31) {
    return addMonthsClamped(from, months);
  }
  const targetMonth = from.getUTCMonth() + months;
  const targetYear = from.getUTCFullYear() + Math.floor(targetMonth / 12);
  const targetMonthIndex = ((targetMonth % 12) + 12) % 12;
  const lastDayOfTargetMonth = new Date(Date.UTC(targetYear, targetMonthIndex + 1, 0)).getUTCDate();
  const clampedDay = Math.min(anchorDay, lastDayOfTargetMonth);
  return new Date(Date.UTC(targetYear, targetMonthIndex, clampedDay, from.getUTCHours(), from.getUTCMinutes(), from.getUTCSeconds(), from.getUTCMilliseconds()));
}

export async function runBackupSchedules(env: Bindings): Promise<void> {
  if (!env.DB) return;
  const now = new Date();
  const nowIso = now.toISOString();
  // Lease window: 10 minutes. If the scheduler crashes mid-run, the lease
  // expires and a later invocation can reclaim the schedule. The lease is
  // also cleared on backup completion (success or failure) in the result
  // handler, so the next scheduled run is not blocked.
  const leaseExpiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString();

  // Atomic claim: UPDATE backup_schedules SET lease_expires_at = ? WHERE
  // the schedule is due AND no active lease exists, RETURNING the claimed
  // row (including the anchor_day_of_month for stable recurrence).
  const claimed = await env.DB.prepare(
    "UPDATE backup_schedules SET lease_expires_at = ? " +
    "WHERE frequency != 'disabled' AND (next_run_at IS NULL OR next_run_at <= ?) " +
    "AND (lease_expires_at IS NULL OR lease_expires_at < ?) " +
    "AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE status = 'ACTIVE') " +
    "RETURNING hosting_account_id AS accountId, frequency, retention_count AS retentionCount, organization_id AS organizationId, anchor_day_of_month AS anchorDayOfMonth, next_run_at AS nextRunAt, " +
    "(SELECT server_id FROM hosting_accounts WHERE id = backup_schedules.hosting_account_id) AS serverId",
  ).bind(leaseExpiresAt, nowIso, nowIso).all<{ accountId: string; frequency: string; retentionCount: number; organizationId: string; anchorDayOfMonth: number | null; nextRunAt: string | null; serverId: string }>();

  for (const schedule of claimed.results ?? []) {
    // releaseLeaseAndOrphan cleans up a half-created backup: it removes the
    // queued row (so the exclusion is released) and clears the schedule
    // lease. Cleanup failures are swallowed (best-effort) so they cannot
    // mask the original error, and the next scheduler tick — or lease
    // expiry — recovers the state.
    const releaseLeaseAndOrphan = async (backupId: string) => {
      try {
        await env.DB.prepare("DELETE FROM hosting_backups WHERE id = ? AND status = 'QUEUED'").bind(backupId).run();
      } catch { /* best-effort: lease expiry covers it */ }
      try {
        await env.DB.prepare("UPDATE backup_schedules SET lease_expires_at = NULL WHERE hosting_account_id = ?").bind(schedule.accountId).run();
      } catch { /* best-effort: lease expiry covers it */ }
    };

    // Compute the next run time. For monthly schedules, use the stable
    // anchor day (anchorDayOfMonth) to prevent drift. If the anchor is
    // NULL (pre-migration schedule), infer it from the current next_run_at
    // day, or fall back to today's day. The inferred anchor is persisted
    // below so subsequent ticks use the stable value.
    let nextRun: Date;
    let inferredAnchor: number | null = null;
    switch (schedule.frequency) {
      case "daily": nextRun = new Date(now.getTime() + 24 * 60 * 60 * 1000); break;
      case "weekly": nextRun = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); break;
      case "monthly": {
        let anchor = schedule.anchorDayOfMonth;
        if (!anchor || anchor < 1 || anchor > 31) {
          // Backward-compatibility: infer the anchor from the current
          // next_run_at (the originally intended day), or from today if
          // next_run_at is NULL (first-ever tick for this schedule).
          const refDate = schedule.nextRunAt ? new Date(schedule.nextRunAt) : now;
          anchor = refDate.getUTCDate();
          inferredAnchor = anchor;
        }
        // Compute the next run from the ORIGINAL next_run_at (if it
        // exists), not from the execution date. This prevents drift when
        // the scheduler fires late: if the schedule was supposed to run
        // on Jan 31 but actually fired on Feb 2, the next run is computed
        // from Jan 31 → Feb 28 (correct), NOT from Feb 2 → March 31
        // (wrong — skips February entirely). For the first-ever tick
        // (next_run_at is NULL), use `now` as the reference.
        const monthlyRefDate = schedule.nextRunAt ? new Date(schedule.nextRunAt) : now;
        nextRun = nextMonthlyRunFromAnchor(anchor, monthlyRefDate, 1);
        break;
      }
      default: continue;
    }

    // Atomic exclusion: conditional INSERT (NOT EXISTS) checks for an
    // active backup AND inserts in a single SQL statement. The partial
    // unique index idx_hosting_backups_active_exclusion is the DB backstop.
    //
    // Conflicts surface in two ways and both take the same conflict path:
    //   1. changes() = 0 — the NOT EXISTS check saw an active backup.
    //   2. UNIQUE constraint error — the index rejected a racing insert.
    // The conflict path releases the lease and does NOT advance
    // next_run_at or last_run_at — the scheduled backup was not created.
    // Unrelated database errors are NOT swallowed: they clean up the
    // half-created state and rethrow so the caller (cron handler) logs them.
    const backupId = crypto.randomUUID();
    let insertResult: { meta?: { changes?: number } };
    try {
      insertResult = await env.DB.prepare(
        "INSERT INTO hosting_backups (id, hosting_account_id, organization_id, server_id, status, created_at) " +
        "SELECT ?, ?, ?, ?, 'QUEUED', ? " +
        "WHERE NOT EXISTS (SELECT 1 FROM hosting_backups WHERE hosting_account_id = ? AND status IN ('QUEUED', 'RUNNING'))",
      ).bind(backupId, schedule.accountId, schedule.organizationId, schedule.serverId, nowIso, schedule.accountId).run();
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        // Lost the race at the index level. Same handling as changes() = 0.
        await releaseLeaseAndOrphan(backupId);
        continue;
      }
      // Unrelated database error: clean up half-created state and rethrow
      // so the failure is visible to the cron handler, not silently swallowed.
      await releaseLeaseAndOrphan(backupId);
      throw error;
    }
    if ((insertResult.meta?.changes ?? 0) !== 1) {
      // Another backup won the race. Release the lease, do NOT advance
      // next_run_at or last_run_at — the scheduled backup was not created.
      await releaseLeaseAndOrphan(backupId);
      continue;
    }

    // Backup row inserted. The databases query, provisioning job, schedule
    // update, and audit log are ALL inside this try block: any failure —
    // including the databases-list query — cleans up the orphan queued
    // backup (releasing the exclusion) and the lease, and does NOT advance
    // next_run_at. Unrelated errors rethrow so they are visible upstream.
    const jobId = crypto.randomUUID();
    const scheduleUpdate = inferredAnchor !== null
      ? env.DB.prepare("UPDATE backup_schedules SET last_run_at = ?, next_run_at = ?, anchor_day_of_month = ? WHERE hosting_account_id = ?").bind(nowIso, nextRun.toISOString(), inferredAnchor, schedule.accountId)
      : env.DB.prepare("UPDATE backup_schedules SET last_run_at = ?, next_run_at = ? WHERE hosting_account_id = ?").bind(nowIso, nextRun.toISOString(), schedule.accountId);
    try {
      const databases = await env.DB.prepare("SELECT name FROM hosting_databases WHERE hosting_account_id = ? AND organization_id = ? AND status = 'ACTIVE'").bind(schedule.accountId, schedule.organizationId).all<{ name: string }>();
      const databaseNames = (databases.results ?? []).map((db) => db.name);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'CREATE_BACKUP', 'QUEUED', ?, ?)").bind(jobId, schedule.accountId, `backup-create:${backupId}`, JSON.stringify({ backupId, databaseNames })),
        scheduleUpdate,
        env.DB.prepare("INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, 'backup.scheduled_run', 'hosting_backup', ?, ?)").bind(crypto.randomUUID(), schedule.organizationId, backupId, JSON.stringify({ frequency: schedule.frequency, jobId, nextRunAt: nextRun.toISOString(), anchorDayOfMonth: schedule.anchorDayOfMonth ?? inferredAnchor })),
      ]);
    } catch (error) {
      // The scheduled backup was not created. Release the exclusion and
      // the lease; do NOT advance next_run_at — retry on the next tick.
      await releaseLeaseAndOrphan(backupId);
      throw error;
    }
  }
}
