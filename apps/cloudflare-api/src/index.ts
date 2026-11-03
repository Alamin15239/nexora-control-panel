import { Hono } from "hono";

type Bindings = {
  DB: D1Database;
  ALLOW_PUBLIC_REGISTRATION?: string;
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
  const expected = ["users", "organizations", "memberships", "auth_sessions", "login_attempts", "servers", "hosting_plans", "hosting_accounts", "domains", "hosting_databases", "hosting_database_users", "agent_credentials", "agent_nonces", "provisioning_jobs", "audit_logs"];
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
    "SELECT secret_hash AS secretHash, server_id AS serverId, organization_id AS organizationId FROM agent_credentials WHERE node_id = ? AND revoked_at IS NULL LIMIT 1",
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
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO server_telemetry (id, server_id, agent_version, cpu_usage_percent, memory_total_bytes, memory_used_bytes, disk_total_bytes, disk_used_bytes, load_average_1m, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(crypto.randomUUID(), credential.serverId, agentVersion, cpu, memoryTotal, memoryUsed, diskTotal, diskUsed, load, collectedAt),
    c.env.DB.prepare("UPDATE servers SET status = 'ONLINE', agent_version = ?, last_heartbeat_at = ?, updated_at = ? WHERE id = ?")
      .bind(agentVersion, now, now, credential.serverId),
    c.env.DB.prepare("UPDATE agent_credentials SET last_seen_at = ? WHERE node_id = ?").bind(now, nodeId),
    c.env.DB.prepare("DELETE FROM agent_nonces WHERE created_at < ?").bind(new Date(Date.now() - 10 * 60 * 1000).toISOString()),
  ]);
  return c.json({ accepted: true, receivedAt: now });
});


type HostingPlanRow = {
  id: string; name: string; disk_limit_bytes: number; bandwidth_limit_bytes: number | null;
  website_limit: number; database_limit: number; mailbox_limit: number; active: number; created_at: string;
};

app.get("/v1/hosting-plans", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT id, name, disk_limit_bytes, bandwidth_limit_bytes, website_limit,
            database_limit, mailbox_limit, active, created_at
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
  if (!name || name.length > 80) return c.json({ message: "Plan name is required (maximum 80 characters)" }, 400);
  if (!Number.isInteger(diskGb) || diskGb < 1 || diskGb > 100000) return c.json({ message: "Disk quota must be between 1 and 100,000 GB" }, 400);
  if (bandwidthGb !== null && (!Number.isInteger(bandwidthGb) || bandwidthGb < 1 || bandwidthGb > 1000000)) return c.json({ message: "Bandwidth must be blank or between 1 and 1,000,000 GB" }, 400);
  if (![websiteLimit, databaseLimit, mailboxLimit].every((v) => Number.isInteger(v) && v >= 0 && v <= 10000)) {
    return c.json({ message: "Resource limits must be whole numbers between 0 and 10,000" }, 400);
  }
  const id = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO hosting_plans
         (id, organization_id, name, disk_limit_bytes, bandwidth_limit_bytes, website_limit, database_limit, mailbox_limit, active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      ).bind(id, identity.organizationId, name, diskGb * 1024 ** 3, bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
        websiteLimit, databaseLimit, mailboxLimit),
      c.env.DB.prepare(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'hosting_plan.create', 'hosting_plan', ?)",
      ).bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
    ]);
    return c.json({ plan: { id, name, disk_limit_bytes: diskGb * 1024 ** 3,
      bandwidth_limit_bytes: bandwidthGb === null ? null : bandwidthGb * 1024 ** 3,
      website_limit: websiteLimit, database_limit: databaseLimit, mailbox_limit: mailboxLimit, active: 1 } }, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_plans.organization_id, hosting_plans.name/i.test(message)) {
      return c.json({ message: "A plan with this name already exists in your workspace" }, 409);
    }
    return c.json({ message: "Unable to create hosting plan" }, 500);
  }
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
    "SELECT id, name, active FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1",
  ).bind(planId, identity.organizationId).first<{ id: string; name: string; active: number }>();
  if (!plan || plan.active !== 1) return c.json({ message: "Select an active hosting plan in your workspace." }, 404);

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
    "SELECT d.id, d.name, d.document_root, d.is_primary, d.created_at, a.id AS hosting_account_id, a.username, a.status AS account_status, s.hostname AS server_hostname, " +
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
  const account = await c.env.DB.prepare("SELECT id, username, status FROM hosting_accounts WHERE id = ? AND organization_id = ? AND status = 'ACTIVE' LIMIT 1").bind(accountId, identity.organizationId).first<{ id: string; username: string; status: string }>();
  if (!account) return c.json({ message: "Select an active hosting account in this workspace before adding a domain." }, 404);
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
};
app.get("/v1/databases", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const result = await c.env.DB.prepare(
    `SELECT d.id, d.name, d.engine, d.status, d.created_at, d.hosting_account_id,
            a.username AS account_username, p.database_limit AS plan_database_limit,
            (SELECT COUNT(*) FROM hosting_database_users u WHERE u.database_id = d.id AND u.status != 'REVOKED') AS users
     FROM hosting_databases d JOIN hosting_accounts a ON a.id = d.hosting_account_id
     JOIN hosting_plans p ON p.id = a.plan_id
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
  const name = typeof input.name === "string" ? input.name.trim().toLowerCase() : "";
  const engine = input.engine === "MARIADB" || input.engine === "POSTGRESQL" ? input.engine : "MYSQL";
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(name)) return c.json({ message: "Database name must be 2–31 lowercase letters, numbers or underscores, and start with a letter." }, 400);
  const account = await c.env.DB.prepare(
    `SELECT a.id, a.username, p.database_limit,
       (SELECT COUNT(*) FROM hosting_databases d WHERE d.hosting_account_id = a.id AND d.status != 'DELETED') AS database_count
     FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id
     WHERE a.id = ? AND a.organization_id = ? AND a.status != 'DELETED' LIMIT 1`,
  ).bind(accountId, identity.organizationId).first<{ id: string; username: string; database_limit: number; database_count: number }>();
  if (!account) return c.json({ message: "Select a hosting account in this workspace." }, 404);
  if (account.database_count >= account.database_limit) return c.json({ message: "This hosting plan has reached its database limit." }, 409);
  const id = crypto.randomUUID(); const jobId = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO hosting_databases (id, organization_id, hosting_account_id, name, engine, status) VALUES (?, ?, ?, ?, ?, 'PENDING')").bind(id, identity.organizationId, account.id, name, engine),
      c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'CREATE_DATABASE', 'QUEUED', ?)").bind(jobId, account.id, "create-database:" + id),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'database.create_requested', 'database', ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, id),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_databases.hosting_account_id, hosting_databases.name/i.test(message)) return c.json({ message: "A database with this name already exists for this account." }, 409);
    return c.json({ message: "Unable to queue database creation." }, 500);
  }
  return c.json({ database: { id, name, engine, status: "PENDING", hosting_account_id: account.id, account_username: account.username }, provisioningJob: { id: jobId, status: "QUEUED" }, message: "Database request queued. A connected Linux agent must create it before it becomes active." }, 201);
});

app.get("/v1/databases/:id/users", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  const database = await c.env.DB.prepare("SELECT id FROM hosting_databases WHERE id = ? AND organization_id = ? LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string }>();
  if (!database) return c.json({ message: "Database not found" }, 404);
  const result = await c.env.DB.prepare("SELECT id, username, privileges, status, created_at FROM hosting_database_users WHERE database_id = ? ORDER BY created_at DESC").bind(database.id).all<{ id: string; username: string; privileges: string; status: string; created_at: string }>();
  return c.json({ users: result.results ?? [] });
});

app.post("/v1/databases/:id/users", async (c) => {
  const identity = await bearerIdentity(c.req.raw, c.env.DB);
  if (!identity) return c.json({ message: "Not authenticated" }, 401);
  if (!canManageServers(identity.role)) return c.json({ message: "Administrator access required" }, 403);
  const database = await c.env.DB.prepare("SELECT id, hosting_account_id FROM hosting_databases WHERE id = ? AND organization_id = ? AND status != 'DELETED' LIMIT 1").bind(c.req.param("id"), identity.organizationId).first<{ id: string; hosting_account_id: string }>();
  if (!database) return c.json({ message: "Database not found" }, 404);
  let input: Record<string, unknown>;
  try { input = await c.req.json<Record<string, unknown>>(); }
  catch { return c.json({ message: "Invalid JSON request" }, 400); }
  const username = typeof input.username === "string" ? input.username.trim().toLowerCase() : "";
  const allowed = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "INDEX"];
  const requested = Array.isArray(input.privileges) ? input.privileges.filter((v): v is string => typeof v === "string") : [];
  const privileges = [...new Set(requested)].filter(v => allowed.includes(v));
  if (!/^[a-z][a-z0-9_]{1,30}$/.test(username)) return c.json({ message: "Database username must be 2–31 lowercase letters, numbers or underscores." }, 400);
  if (!privileges.length || privileges.length !== new Set(requested).size) return c.json({ message: "Choose one or more valid database privileges." }, 400);
  const id = crypto.randomUUID(); const jobId = crypto.randomUUID();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO hosting_database_users (id, organization_id, database_id, username, privileges, status) VALUES (?, ?, ?, ?, ?, 'PENDING')").bind(id, identity.organizationId, database.id, username, JSON.stringify(privileges)),
      c.env.DB.prepare("INSERT INTO provisioning_jobs (id, hosting_account_id, operation, status, idempotency_key) VALUES (?, ?, 'CREATE_DATABASE_USER', 'QUEUED', ?)").bind(jobId, database.hosting_account_id, "create-database-user:" + id),
      c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'database_user.create_requested', 'database_user', ?, ?)").bind(crypto.randomUUID(), identity.organizationId, identity.id, id, JSON.stringify({ databaseId: database.id, privileges })),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/UNIQUE constraint failed: hosting_database_users.database_id, hosting_database_users.username/i.test(message)) return c.json({ message: "This username already exists for the database." }, 409);
    return c.json({ message: "Unable to queue database user creation." }, 500);
  }
  return c.json({ user: { id, username, privileges, status: "PENDING" }, provisioningJob: { id: jobId, status: "QUEUED" }, message: "Database user request queued. No password is stored in Nexora; credential creation is delegated to the hosting agent." }, 201);
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
    "SELECT secret_hash AS secretHash, server_id AS serverId, organization_id AS organizationId FROM agent_credentials WHERE node_id = ? AND revoked_at IS NULL LIMIT 1",
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
  await db.prepare("UPDATE agent_credentials SET last_seen_at = ? WHERE node_id = ?")
    .bind(new Date().toISOString(), nodeId).run();
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
    "WHERE a.server_id = ? AND j.operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER') " +
    "AND (j.status = 'QUEUED' OR (j.status = 'RUNNING' AND j.lease_expires_at < ?)) " +
    "ORDER BY j.requested_at ASC LIMIT 1) " +
    "AND (status = 'QUEUED' OR (status = 'RUNNING' AND lease_expires_at < ?)) " +
    "RETURNING id, hosting_account_id AS hostingAccountId, operation, attempts, request_payload AS requestPayload",
  ).bind(now, leaseUntil, auth.credential.nodeId, auth.credential.serverId, now, now)
    .first<{ id: string; hostingAccountId: string; operation: string; attempts: number; requestPayload: string | null }>();
  if (!claimed) return c.json({ job: null });
  const account = await c.env.DB.prepare(
    "SELECT a.id AS accountId, a.username, a.primary_domain AS primaryDomain, p.disk_limit_bytes AS diskLimitBytes, " +
    "d.name AS domain, d.document_root AS documentRoot " +
    "FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id " +
    "JOIN provisioning_jobs j ON j.id = ? AND j.hosting_account_id = a.id " +
    "LEFT JOIN domains d ON d.id = (SELECT d2.id FROM domains d2 WHERE d2.hosting_account_id = a.id AND d2.id = substr(j.idempotency_key, 12) AND j.operation = 'ADD_DOMAIN' LIMIT 1) " +
    "WHERE a.id = ? AND a.server_id = ? AND a.organization_id = ? " +
    "AND ((? = 'CREATE_HOSTING_ACCOUNT' AND a.status = 'PENDING') OR (? = 'ADD_DOMAIN' AND a.status = 'ACTIVE' AND d.id IS NOT NULL) OR (? = 'FILE_MANAGER' AND a.status = 'ACTIVE')) LIMIT 1",
  ).bind(claimed.id, claimed.hostingAccountId, auth.credential.serverId, auth.credential.organizationId, claimed.operation, claimed.operation, claimed.operation)
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
  const resultPayload = input.result && typeof input.result === "object" ? JSON.stringify(input.result) : null;
  const jobId = c.req.param("id");
  const now = new Date().toISOString();
  const status = input.success ? "SUCCEEDED" : "FAILED";
  const update = await c.env.DB.prepare(
    "UPDATE provisioning_jobs SET status = ?, finished_at = ?, error_code = ?, error_message = ?, request_payload = NULL, result_payload = ?, lease_expires_at = NULL " +
    "WHERE id = ? AND status = 'RUNNING' AND claimed_by_node_id = ? AND lease_expires_at > ? " +
    "AND operation IN ('CREATE_HOSTING_ACCOUNT', 'ADD_DOMAIN', 'FILE_MANAGER') " +
    "AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?)",
  ).bind(status, now, input.success ? null : errorCode || "PROVISIONING_FAILED",
    input.success ? null : errorMessage || "The Linux agent could not provision this account", resultPayload,
    jobId, auth.credential.nodeId, now, auth.credential.serverId, auth.credential.organizationId).run();
  if ((update.meta?.changes ?? 0) !== 1) return c.json({ message: "Job lease is missing, expired, or belongs to another server" }, 409);
  const completedJob = await c.env.DB.prepare("SELECT operation FROM provisioning_jobs WHERE id = ? AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE server_id = ? AND organization_id = ?) LIMIT 1")
    .bind(jobId, auth.credential.serverId, auth.credential.organizationId).first<{ operation: string }>();
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
  await c.env.DB.prepare("INSERT INTO audit_logs (id, organization_id, action, resource_type, resource_id, metadata) VALUES (?, ?, ?, 'provisioning_job', ?, ?)")
    .bind(crypto.randomUUID(), auth.credential.organizationId,
      input.success ? (completedJob?.operation === "FILE_MANAGER" ? "file_manager.operation_completed" : completedJob?.operation === "ADD_DOMAIN" ? "domain.configured" : "hosting_account.provisioned") : (completedJob?.operation === "FILE_MANAGER" ? "file_manager.operation_failed" : completedJob?.operation === "ADD_DOMAIN" ? "domain.configuration_failed" : "hosting_account.provisioning_failed"),
      jobId, JSON.stringify({ serverId: auth.credential.serverId, operation: completedJob?.operation ?? null, errorCode: input.success ? null : errorCode })).run();
  return c.json({ accepted: true, jobId, status });
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export default app;
