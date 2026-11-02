import { Hono } from "hono";

type Bindings = {
  DB: D1Database;
  ALLOW_PUBLIC_REGISTRATION?: string;
};

type Role = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";

const app = new Hono<{ Bindings: Bindings }>();
const SESSION_SECONDS = 15 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const PASSWORD_ITERATIONS = 310_000;

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
    "INSERT INTO auth_sessions (id, user_id, token_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), userId, crypto.randomUUID(), await sha256(token), expiresAt).run();

  return {
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: SESSION_SECONDS,
    organizationId,
    role,
  };
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
     JOIN memberships m ON m.user_id = u.id
     JOIN organizations o ON o.id = m.organization_id
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
  const expected = ["users", "organizations", "memberships", "auth_sessions", "login_attempts", "servers", "hosting_plans", "hosting_accounts", "domains", "provisioning_jobs", "audit_logs"];
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

app.notFound((c) => c.json({ error: "Not found" }, 404));

export default app;
