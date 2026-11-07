import { Hono } from "hono";
import { ensureSaasDnsRecord } from "./cloudflare-dns";
import { createDnsRecord, deleteDnsRecord, listDnsRecords, updateDnsRecord } from "./dns-records";
import { pruneFailedDeploymentArtifacts } from "./artifact-retention";

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
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  GITHUB_OIDC_AUDIENCE?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_PRIVATE_KEY?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_KEY_ID?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_ISSUER?: string;
  GITHUB_DEPLOYMENT_ENVELOPE_AUDIENCE?: string;
  ARTIFACTS?: R2Bucket;
  DASHBOARD_URL?: string;
};

type Role = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";

const app = new Hono<{ Bindings: Bindings }>();
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const PASSWORD_ITERATIONS = 100_000;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function randomHex(length: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(length)));
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
  for (const value of [input.organizationId, input.projectId, input.deploymentId, input.hostingAccountId]) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new Error("Deployment envelope identity is invalid");
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
async function encryptDatabaseSecret(env: Bindings, plaintext: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", databaseSecretKey(env), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: base64(iv), ciphertext: base64(new Uint8Array(ciphertext)) };
}
async function decryptDatabaseSecret(env: Bindings, ciphertext: string, iv: string): Promise<string> {
  const decode = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", databaseSecretKey(env), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(iv) }, key, decode(ciphertext));
  return new TextDecoder().decode(plaintext);
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
  if (!/^\\d{10}$/.test(timestamp) || !/^[a-f0-9]{32,128}$/i.test(nonce)) return false;
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

async function bearerIdentity(request: Request, db: D1Database) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+([a-f0-9]{64})$/i.exec(authorization);
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  return db.prepare(
    `SELECT u.id, u.email, u.display_name AS displayName,
            o.id AS organizationId, o.name AS organizationName, o.slug AS organizationSlug,
            m.role
     FROM auth_sessions s
     JOIN users u ON u.id = s.user_id
     JOIN memberships m ON m.user_id = u.id AND m.organization_id = s.organization_id
     JOIN organizations o ON o.id = s.organization_id
     WHERE s.token_hash = ? AND s.revoked_at IS NULL
       AND s.expires_at > ? AND u.status = 'ACTIVE' AND o.status = 'ACTIVE'
     LIMIT 1`,
  ).bind(tokenHash, new Date().toISOString()).first<{
    id: string; email: string; displayName: string | null;
    organizationId: string; organizationName: string; organizationSlug: string; role: Role;
  }>();
}

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
  const expected = ["users", "organizations", "memberships", "auth_sessions", "login_attempts", "servers", "hosting_plans", "hosting_accounts", "domains", "hosting_databases", "hosting_database_users", "agent_credentials", "agent_nonces", "provisioning_jobs", "audit_logs", "server_service_checks", "server_incidents", "incident_notification_settings", "incident_notification_outbox", "hosting_backups", "github_connections", "github_oauth_states", "github_projects", "github_deployments", "github_deployment_upload_tokens", "application_runtime_profiles", "application_node_pools", "application_nodes", "application_project_settings", "application_releases", "application_release_events", "application_workloads", "application_usage_periods", "application_usage_events", "application_node_request_nonces"];
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

  // Limit workspace creation by source IP to reduce automated public sign-up abuse.
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
    `SELECT m.organization_id AS organizationId, m.role
     FROM memberships m JOIN organizations o ON o.id = m.organization_id
     WHERE m.user_id = ? AND o.status = 'ACTIVE' AND (o.id = ? OR o.slug = ?) LIMIT 1`,
  ).bind(user.id, organizationKey, organizationKey).first<{ organizationId: string; role: Role }>() : null;

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
  const session = await issueSession(c.env.DB, user.id, membership.organizationId, role);
  await c.env.DB.prepare(
    "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, source_ip) VALUES (?, ?, ?, 'auth.login', 'user', ?, ?)",
  ).bind(crypto.randomUUID(), membership.organizationId, user.id, user.id, ip).run();

  return c.json({
    user: { id: user.id, email: user.email, displayName: user.displayName },
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
  return c.json({
    id: identity.id,
    email: identity.email,
    displayName: identity.displayName,
    organization: { id: identity.organizationId, name: identity.organizationName, slug: identity.organizationSlug },
    role: identity.role,
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
      canManage: canManageServers(identity.role),
    });
  } catch (error) {
    return c.json({ message: error instanceof Error ? error.message : "Unable to load DNS records." }, 502);
  }
});

app.post("/v1/dns-records", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) {
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
    canManage: canManageServers(identity.role),
  });
});

app.post("/v1/notification-settings", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) {
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
  if (!canManageServers(identity.role)) {
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
            p.github_repository_id AS repositoryId
     FROM github_deployments d
     JOIN github_projects p ON p.id = d.project_id AND p.organization_id = d.organization_id
     JOIN hosting_accounts h ON h.id = p.hosting_account_id AND h.organization_id = d.organization_id
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
            app_disk_mib, app_process_limit, app_build_minutes_month, active, created_at
     FROM hosting_plans WHERE organization_id = ? ORDER BY created_at DESC`,
  ).bind(identity.organizationId).all<HostingPlanRow>();
  return c.json({ plans: result.results ?? [] });
});

app.post("/v1/hosting-plans", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!name || name.length > 80) return c.json({ message: "Plan name is required (maximum 80 characters)" }, 400);
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
          app_cpu_millis, app_memory_mib, app_disk_mib, app_process_limit, app_build_minutes_month, active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      ).bind(id, identity.organizationId, name, diskGb * 1024 ** 3, bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
        websiteLimit, databaseLimit, mailboxLimit, appCpuMillis, appMemoryMiB, appDiskMiB, appProcessLimit, appBuildMinutesMonth),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'hosting_plan.create', 'hosting_plan', ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
    ]);
    return c.json({ plan: { id, name, disk_limit_bytes: diskGb * 1024 ** 3,
      bandwidth_limit_bytes: bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
      website_limit: websiteLimit, database_limit: databaseLimit, mailbox_limit: mailboxLimit,
      app_cpu_millis: appCpuMillis, app_memory_mib: appMemoryMiB, app_disk_mib: appDiskMiB,
      app_process_limit: appProcessLimit, app_build_minutes_month: appBuildMinutesMonth, active: 1 } }, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_plans.organization_id, hosting_plans.name/i.test(message)) {
      return c.json({ message: "A plan with this name already exists in your workspace" }, 409);
    }
    return c.json({ message: "Unable to create hosting plan" }, 500);
  }
});


app.post("/v1/hosting-plans/:id/website-limit", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!account) return c.json({ message: "Active hosting account not found" }, 404);
  const result = await c.env.DB.prepare("SELECT id, status, archive_name AS archiveName, size_bytes AS sizeBytes, sha256, database_names_json AS databaseNamesJson, error_message AS errorMessage, created_at AS createdAt, completed_at AS completedAt, staged_at AS stagedAt FROM hosting_backups WHERE hosting_account_id = ? AND organization_id = ? ORDER BY created_at DESC LIMIT 100").bind(account.id, identity.organizationId).all<{ id: string; status: string; archiveName: string | null; sizeBytes: number | null; sha256: string | null; databaseNamesJson: string; errorMessage: string | null; createdAt: string; completedAt: string | null; stagedAt: string | null }>();
  const backups = (result.results ?? []).map((row) => ({ ...row, databaseNames: (() => { try { const parsed = JSON.parse(row.databaseNamesJson); return Array.isArray(parsed) ? parsed : []; } catch { return []; } })() }));
  return c.json({ backups });
});

app.post("/v1/hosting-accounts/:id/backups", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
  const account = await c.env.DB.prepare("SELECT id, username, server_id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string; username: string; server_id: string }>();
  if (!account) return c.json({ message: "Active hosting account not found" }, 404);
  const databases = await c.env.DB.prepare("SELECT name FROM hosting_databases WHERE hosting_account_id = ? AND organization_id = ? AND status = 'ACTIVE' ORDER BY name LIMIT 20").bind(account.id, identity.organizationId).all<{ name: string }>();
  const databaseNames = (databases.results ?? []).map((row) => row.name);
  const backupId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();
  const requestPayload = JSON.stringify({ backupId, databaseNames });
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO hosting_backups (id, organization_id, hosting_account_id, server_id, status, database_names_json, requested_by_user_id, created_at) VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, ?)").bind(backupId, identity.organizationId, account.id, account.server_id, JSON.stringify(databaseNames), identity.id, now),
      c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key, request_payload) VALUES (?, ?, 'CREATE_BACKUP', 'QUEUED', ?, ?)").bind(jobId, account.id, "backup-create:" + backupId, requestPayload),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'backup.create_requested', 'hosting_backup', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, backupId, JSON.stringify({ accountId: account.id, username: account.username, databaseCount: databaseNames.length })),
    ]);
  } catch { return c.json({ message: "Unable to queue the hosting backup" }, 500); }
  return c.json({ backup: { id: backupId, status: "QUEUED", databaseNames }, job: { id: jobId, status: "QUEUED" }, message: "Backup queued for the connected Linux agent." }, 202);
});

app.post("/v1/backups/:id/restore", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
    "WHERE a.organization_id = ? ORDER BY d.created_at DESC",
  ).bind(identity.organizationId).all<DomainRecord>();
  return c.json({ domains: result.results ?? [] });
});
app.post("/v1/domains", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
    "WHERE a.server_id = ? AND j.operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER', 'CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE', 'CREATE_BACKUP', 'RESTORE_BACKUP', 'DELETE_BACKUP') AND (j.operation NOT IN ('CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE') OR EXISTS (SELECT 1 FROM hosting_databases d WHERE d.hosting_account_id = j.hosting_account_id AND d.name = json_extract(j.request_payload, '$.databaseName') AND ((j.operation = 'CREATE_DATABASE' AND d.status = 'PENDING') OR (j.operation IN ('CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER') AND d.status = 'ACTIVE') OR (j.operation = 'DELETE_DATABASE' AND d.status = 'DELETING')))) " +
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
    "LEFT JOIN domains d ON d.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = a.id AND d2.id = substr(j.idempotency_key, 12) AND j.operation = 'ADD_DOMAIN' LIMIT 1) " +
    "WHERE a.id = ? AND a.server_id = ? AND a.organization_id = ? " +
    "AND ((? = 'CREATE_HOSTING_ACCOUNT' AND a.status = 'PENDING') OR (? = 'ADD_DOMAIN' AND a.status = 'ACTIVE' AND d.id IS NOT NULL) OR (? = 'FILE_MANAGER' AND a.status = 'ACTIVE') OR (? = 'CREATE_DATABASE' AND a.status = 'ACTIVE') OR (? = 'CREATE_DATABASE_USER' AND a.status = 'ACTIVE') OR (? = 'REVOKE_DATABASE_USER' AND a.status = 'ACTIVE') OR (? = 'DELETE_DATABASE' AND a.status = 'ACTIVE') OR (? = 'CREATE_BACKUP' AND a.status = 'ACTIVE') OR (? = 'RESTORE_BACKUP' AND a.status = 'ACTIVE') OR (? = 'DELETE_BACKUP' AND a.status = 'ACTIVE')) LIMIT 1",
  ).bind(claimed.id, claimed.hostingAccountId, auth.credential.serverId, auth.credential.organizationId, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation, claimed.operation)
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
    "AND operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER', 'CREATE_DATABASE', 'CREATE_DATABASE_USER', 'REVOKE_DATABASE_USER', 'DELETE_DATABASE', 'CREATE_BACKUP', 'RESTORE_BACKUP', 'DELETE_BACKUP') " +
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
  const completedJob = await c.env.DB.prepare("SELECT operation, idempotency_key AS idempotencyKey FROM provisioning_jobs WHERE id = ? AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?) LIMIT 1")
    .bind(jobId, auth.credential.serverId, auth.credential.organizationId).first<{ operation: string; idempotencyKey: string }>();
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
      } else {
        await c.env.DB.prepare("UPDATE hosting_backups SET status = 'FAILED', error_message = ? WHERE id = ? AND organization_id = ?").bind(errorMessage || "The backup could not be created", backupId, auth.credential.organizationId).run();
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
      const credential = incomingResult && typeof incomingResult.username === "string" && typeof incomingResult.password === "string"
        ? { username: incomingResult.username, password: incomingResult.password } : null;
      if (!credential || credential.password.length < 32 || credential.password.length > 128 || !/^[a-z][a-z0-9_]{2,80}$/.test(credential.username)) {
        await c.env.DB.prepare("UPDATE hosting_database_users SET status = 'FAILED' WHERE id = ? AND organization_id = ?").bind(databaseUserId, auth.credential.organizationId).run();
        return c.json({ message: "The agent returned an invalid database credential." }, 422);
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
    }
  }
  if (completedJob?.operation === "CREATE_DATABASE" && completedJob.idempotencyKey?.startsWith("create-database:")) {
    const databaseId = completedJob.idempotencyKey.slice("create-database:".length);
    await c.env.DB.prepare(
      "UPDATE hosting_databases SET status = ?, updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'PENDING'",
    ).bind(input.success ? "ACTIVE" : "FAILED", now, databaseId, auth.credential.organizationId).run();
  }
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'provisioning_job', ?, ?)")
    .bind(crypto.randomUUID(), auth.credential.organizationId,
      input.success ? (completedJob?.operation === "FILE_MANAGER" ? "file_manager.operation_completed" : completedJob?.operation === "ADD_DOMAIN" ? "domain.configured" : completedJob?.operation === "CREATE_DATABASE" ? "database.provisioned" : completedJob?.operation === "CREATE_DATABASE_USER" ? "database_user.provisioned" : completedJob?.operation === "REVOKE_DATABASE_USER" ? "database_user.revoked" : completedJob?.operation === "DELETE_DATABASE" ? "database.deleted" : completedJob?.operation === "CREATE_BACKUP" ? "backup.created" : completedJob?.operation === "RESTORE_BACKUP" ? "backup.restore_staged" : completedJob?.operation === "DELETE_BACKUP" ? "backup.deleted" : "hosting_account.provisioned") : (completedJob?.operation === "FILE_MANAGER" ? "file_manager.operation_failed" : completedJob?.operation === "ADD_DOMAIN" ? "domain.configuration_failed" : completedJob?.operation === "CREATE_DATABASE" ? "database.provisioning_failed" : completedJob?.operation === "CREATE_DATABASE_USER" ? "database_user.provisioning_failed" : completedJob?.operation === "REVOKE_DATABASE_USER" ? "database_user.revocation_failed" : completedJob?.operation === "DELETE_DATABASE" ? "database.deletion_failed" : completedJob?.operation === "CREATE_BACKUP" ? "backup.creation_failed" : completedJob?.operation === "RESTORE_BACKUP" ? "backup.restore_stage_failed" : completedJob?.operation === "DELETE_BACKUP" ? "backup.deletion_failed" : "hosting_account.provisioning_failed"),
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

function githubDashboardRedirect(env: Bindings, status: string): string {
  const base = env.DASHBOARD_URL ?? "";
  let url: URL;
  try { url = new URL(base); } catch { throw new Error("Dashboard URL is not configured"); }
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("Dashboard URL must be an HTTPS origin");
  url.pathname = "/github-deployments";
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  const providerError = c.req.query("error");
  if (providerError) {
    try { return c.redirect(githubDashboardRedirect(c.env, "denied")); }
    catch { return c.text("GitHub connection was not completed.", 503); }
  }
  const code = c.req.query("code") ?? "";
  const state = c.req.query("state") ?? "";
  if (!/^[a-f0-9]{64}$/i.test(state) || !/^[A-Za-z0-9.\-_]{1,200}$/.test(code)) return c.text("Invalid GitHub OAuth callback.", 400);
  if (!c.env.GITHUB_APP_CLIENT_ID || !c.env.GITHUB_APP_CLIENT_SECRET || !c.env.GITHUB_OAUTH_CALLBACK_URL || !c.env.GITHUB_TOKEN_ENCRYPTION_KEY) return c.text("GitHub OAuth is not configured.", 503);
  const stateHash = await sha256(state);
  const pending = await c.env.DB.prepare(
    "SELECT organization_id, user_id FROM github_oauth_states WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1",
  ).bind(stateHash, new Date().toISOString()).first<{ organization_id: string; user_id: string }>();
  if (!pending) return c.text("GitHub authorization state is invalid or expired.", 400);
  const consumed = await c.env.DB.prepare(
    "UPDATE github_oauth_states SET consumed_at = ? WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ?",
  ).bind(new Date().toISOString(), stateHash, new Date().toISOString()).run();
  if ((consumed.meta?.changes ?? 0) !== 1) return c.text("GitHub authorization state has already been used.", 400);
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
    return c.redirect(githubDashboardRedirect(c.env, "connected"));
  } catch {
    try { return c.redirect(githubDashboardRedirect(c.env, "error")); }
    catch { return c.text("GitHub connection failed. Check server configuration and try again.", 502); }
  }
});

app.get("/v1/github/repositories", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
  const connection = await c.env.DB.prepare(
    "SELECT id FROM github_connections WHERE organization_id = ? LIMIT 1",
  ).bind(identity.organizationId).first<{ id: string }>();
  if (!connection) return c.json({ message: "Connect a GitHub account first." }, 409);
  try {
    const token = await githubAccessToken(c.env, c.env.DB, identity.organizationId);
    const installationsResponse = await githubApi(token, "/user/installations?per_page=100");
    if (!installationsResponse.ok) return c.json({ message: "Unable to list GitHub App installations. Reinstall the Nexora GitHub App with repository access." }, 502);
    const installationsData = await installationsResponse.json() as { installations?: Array<{ id: number; account?: { login?: string } }> };
    const repositories: Array<{ id: number; name: string; fullName: string; private: boolean; defaultBranch: string; htmlUrl: string; installationId: number; owner: string }> = [];
    for (const installation of (installationsData.installations ?? []).slice(0, 25)) {
      if (!Number.isSafeInteger(installation.id)) continue;
      const response = await githubApi(token, `/user/installations/${installation.id}/repositories?per_page=100`);
      if (!response.ok) continue;
      const data = await response.json() as { repositories?: Array<{ id: number; name: string; full_name: string; private: boolean; default_branch: string; html_url: string; owner?: { login?: string } }> };
      for (const repo of data.repositories ?? []) {
        if (Number.isSafeInteger(repo.id) && repo.full_name && repo.name && repo.default_branch) repositories.push({
          id: repo.id, name: repo.name, fullName: repo.full_name, private: Boolean(repo.private),
          defaultBranch: repo.default_branch, htmlUrl: repo.html_url, installationId: installation.id, owner: repo.owner?.login ?? installation.account?.login ?? "",
        });
      }
    }
    return c.json({ repositories });
  } catch {
    return c.json({ message: "Unable to read GitHub repositories. Reconnect the GitHub App and try again." }, 502);
  }
});

app.post("/v1/github/projects", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
  const account = await c.env.DB.prepare("SELECT id FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(hostingAccountId, identity.organizationId).first<{ id: string }>();
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
  const result = await c.env.DB.prepare(
    `SELECT id, hosting_account_id AS hostingAccountId, repository_full_name AS repositoryFullName,
            production_branch AS productionBranch, root_directory AS rootDirectory, output_directory AS outputDirectory,
            framework, auto_deploy AS autoDeploy, status, created_at AS createdAt
     FROM github_projects WHERE organization_id = ? ORDER BY created_at DESC`,
  ).bind(identity.organizationId).all();
  return c.json({ projects: result.results ?? [] });
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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

  const capability = randomHex(32);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  try {
    const results = await c.env.DB.batch([
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
    ]);
    if ((results[0]?.meta.changes ?? 0) !== 1 || (results[1]?.meta.changes ?? 0) !== 1) {
      return c.json({ message: "A runner has already claimed this deployment." }, 409);
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
  
    const updated = await c.env.DB.prepare(
      "UPDATE github_deployments SET artifact_key = ?, artifact_bytes = ?, artifact_sha256 = ?, log_excerpt = 'Build artifact received; awaiting archive validation and publication.' WHERE id = ? AND organization_id = ? AND status = 'building' AND artifact_key IS NULL",
    ).bind(objectKey, receivedBytes, artifactSHA256, token.deploymentId, token.organizationId).run();
    if ((updated.meta.changes ?? 0) !== 1) {
      await c.env.ARTIFACTS.delete(objectKey);
      return c.json({ message: "Deployment is no longer accepting an artifact." }, 409);
    }
    return c.json({ received: true, deploymentId: token.deploymentId, bytes: receivedBytes }, 202);
  } catch (error) {
    await c.env.ARTIFACTS.delete(objectKey).catch(() => undefined);
    await c.env.DB.prepare(
      "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), log_excerpt = 'Artifact upload failed.' WHERE id = ? AND organization_id = ? AND status = 'building'",
    ).bind(token.deploymentId, token.organizationId).run().catch(() => undefined);
    console.error("GitHub artifact upload failed:", error instanceof Error ? error.message : "unknown error");
    return c.json({ message: "Artifact upload failed; the one-time capability has been consumed." }, 502);
  }
});

app.post("/v1/github/projects/:projectId/deployments", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
  if (!c.env.GITHUB_APP_ID || !c.env.GITHUB_APP_PRIVATE_KEY) {
    return c.json({ message: "GitHub App ID and private key are required before deployments can be dispatched." }, 503);
  }
  const project = await c.env.DB.prepare(
    `SELECT id, github_repository_id AS repositoryId, repository_full_name AS repositoryFullName,
            github_installation_id AS installationId, production_branch AS productionBranch, trusted_workflow_sha AS trustedWorkflowSha, status
     FROM github_projects WHERE id = ? AND organization_id = ? LIMIT 1`,
  ).bind(c.req.param("projectId"), identity.organizationId).first<{
    id: string; repositoryId: string; repositoryFullName: string; installationId: string | null;
    productionBranch: string; trustedWorkflowSha: string | null; status: string;
  }>();
  if (!project) return c.json({ message: "GitHub project not found." }, 404);
  if (!project.installationId) return c.json({ message: "Reconnect the GitHub App and relink this repository." }, 409);
  if (!project.trustedWorkflowSha || !/^[a-f0-9]{40}$/i.test(project.trustedWorkflowSha)) {
    return c.json({ message: "Review the Nexora workflow and approve its full commit SHA before dispatching deployments." }, 409);
  }
  const active = await c.env.DB.prepare(
    "SELECT id FROM github_deployments WHERE project_id = ? AND status IN ('queued','cloning','installing','building','publishing') LIMIT 1",
  ).bind(project.id).first<{ id: string }>();
  if (active) return c.json({ message: "A deployment is already in progress for this project.", deploymentId: active.id }, 409);

  const deploymentId = crypto.randomUUID();
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

    await c.env.DB.prepare(
      `INSERT INTO github_deployments (id, organization_id, project_id, commit_sha, branch, trigger_type, status, commit_message)
       VALUES (?, ?, ?, ?, ?, 'manual', 'queued', ?)`,
    ).bind(deploymentId, identity.organizationId, project.id, commitData.sha, project.productionBranch,
      (commitData.commit?.message ?? "").slice(0, 500)).run();
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
          inputs: { deployment_id: deploymentId, commit_sha: commitData.sha },
        }),
      },
    );
    if (dispatch.status !== 204) {
      await c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), log_excerpt = ? WHERE id = ? AND organization_id = ? AND status = 'queued'",
      ).bind(`GitHub workflow dispatch rejected (HTTP ${dispatch.status}).`, deploymentId, identity.organizationId).run();
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
      message: "GitHub Actions accepted the workflow dispatch. Build execution is not complete until the isolated runner reports a verified artifact.",
    }, 202);
  } catch (error) {
    if (deploymentCreated && !dispatchAccepted) {
      await c.env.DB.prepare(
        "UPDATE github_deployments SET status = 'failed', finished_at = datetime('now'), log_excerpt = 'GitHub did not accept the workflow dispatch.' WHERE id = ? AND organization_id = ? AND status = 'queued'",
      ).bind(deploymentId, identity.organizationId).run().catch(() => undefined);
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);

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
     WHERE p.id = ? AND p.organization_id = ? LIMIT 1`,
  ).bind(projectId, identity.organizationId).first<{
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
     WHERE p.id = ? AND p.organization_id = ? LIMIT 1`,
  ).bind(periodStart, periodStart, projectId, identity.organizationId).first<{
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
  const result = await c.env.DB.prepare(
    "UPDATE application_nodes SET signing_public_key = ?, enrollment_consumed_at = datetime('now'), " +
    "status = 'online', agent_version = ?, last_heartbeat_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE node_identity = ? AND enrollment_key_hash = ? AND enrollment_consumed_at IS NULL " +
    "AND signing_public_key IS NULL AND status = 'pending' " +
    "AND EXISTS (SELECT 1 FROM application_node_pools p WHERE p.id = application_nodes.node_pool_id AND p.status = 'ready')",
  ).bind(body.publicKey.toLowerCase(), body.agentVersion, body.nodeIdentity, tokenHash).run();
  if (Number(result.meta?.changes ?? 0) !== 1) {
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
    "WHERE n.node_identity = ? AND n.status = 'online' AND p.status = 'ready' " +
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

  const nonceResult = await db.prepare(
    "INSERT OR IGNORE INTO application_node_request_nonces (node_id, nonce, expires_at) " +
    "VALUES (?, ?, datetime('now', '+10 minutes'))",
  ).bind(node.id, nonce).run();
  if (Number(nonceResult.meta?.changes ?? 0) !== 1) return c.json({ message: "Request nonce has already been used." }, 409);

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
     LIMIT 1`,
  ).bind(projectId, identity.organizationId).first<Record<string, unknown>>();
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
    "SELECT id FROM github_projects WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(c.req.param("projectId"), identity.organizationId).first<{ id: string }>();
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
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
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
    ]));
  },
};
