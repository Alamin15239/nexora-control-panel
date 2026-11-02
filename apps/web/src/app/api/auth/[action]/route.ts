import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COOKIE_NAME = "nexora_session";
const COOKIE_MAX_AGE = 15 * 60;
const SESSION_SECONDS = 15 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const PASSWORD_ITERATIONS = 100_000;

interface D1StatementLike {
  bind(...values: unknown[]): D1StatementLike;
  run(): Promise<unknown>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}
interface D1DatabaseLike {
  prepare(sql: string): D1StatementLike;
  batch(statements: D1StatementLike[]): Promise<unknown>;
}
type AuthRole = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";

async function getDatabase(): Promise<D1DatabaseLike> {
  const { env } = await getCloudflareContext({ async: true });
  const db = (env as typeof env & { DB?: D1DatabaseLike }).DB;
  if (!db) throw new Error("The dashboard DB binding is missing");
  return db;
}

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
  if (algorithm !== "pbkdf2-sha256" || !Number.isInteger(iterations) || iterations < 100_000 || iterations > 1_000_000 ||
      !/^[a-f0-9]{32}$/.test(saltHex ?? "") || !/^[a-f0-9]{64}$/.test(expectedHex ?? "")) return false;
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
async function issueSession(db: D1DatabaseLike, userId: string, organizationId: string, role: AuthRole) {
  const token = randomHex(32);
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1000).toISOString();
  await db.prepare(
    "INSERT INTO auth_sessions (id, user_id, token_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), userId, crypto.randomUUID(), await sha256(token), expiresAt).run();
  return { accessToken: token, tokenType: "Bearer", expiresIn: SESSION_SECONDS, organizationId, role };
}
function sessionCookie(response: NextResponse, token: string) {
  response.cookies.set(COOKIE_NAME, token, {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: COOKIE_MAX_AGE,
  });
}
function clearSessionCookie(response: NextResponse) {
  response.cookies.set(COOKIE_NAME, "", {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0,
  });
}

export async function POST(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;
  if (!["login", "register", "logout"].includes(action)) {
    return NextResponse.json({ message: "Not found" }, { status: 404 });
  }

  if (action === "logout") {
    const token = request.cookies.get(COOKIE_NAME)?.value;
    if (token) {
      try {
        const db = await getDatabase();
        await db.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
          .bind(new Date().toISOString(), await sha256(token)).run();
      } catch (error) {
        console.error("[Nexora auth] Logout failed:", error);
      }
    }
    const response = NextResponse.json({ success: true });
    clearSessionCookie(response);
    return response;
  }

  let input: Record<string, unknown>;
  try {
    const parsed: unknown = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid body");
    input = parsed as Record<string, unknown>;
  } catch {
    return NextResponse.json({ message: "Invalid request body" }, { status: 400 });
  }

  try {
    const db = await getDatabase();
    const email = normalizeEmail(input.email);
    const password = typeof input.password === "string" ? input.password : "";

    if (action === "register") {
      const name = typeof input.name === "string" ? input.name.trim() : "";
      const organizationName = typeof input.organizationName === "string" ? input.organizationName.trim() : "";
      if (!validEmail(email)) return NextResponse.json({ message: "Enter a valid email address" }, { status: 400 });
      if (!name || name.length > 100 || !organizationName || organizationName.length > 120) {
        return NextResponse.json({ message: "Name and organization name are required" }, { status: 400 });
      }
      if (password.length < 12 || password.length > 128) {
        return NextResponse.json({ message: "Password must be between 12 and 128 characters" }, { status: 400 });
      }

      const userId = crypto.randomUUID();
      const organizationId = crypto.randomUUID();
      const slug = `${slugBase(organizationName)}-${randomHex(4)}`;
      const passwordHash = await hashPassword(password);
      await db.batch([
        db.prepare("INSERT INTO users (id, email, password_hash, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
          .bind(userId, email, passwordHash, name),
        db.prepare("INSERT INTO organizations (id, name, slug, status) VALUES (?, ?, ?, 'ACTIVE')")
          .bind(organizationId, organizationName, slug),
        db.prepare("INSERT INTO memberships (id, user_id, organization_id, role) VALUES (?, ?, ?, 'OWNER')")
          .bind(crypto.randomUUID(), userId, organizationId),
        db.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.register', 'organization', ?)")
          .bind(crypto.randomUUID(), organizationId, userId, organizationId),
      ]);
      const session = await issueSession(db, userId, organizationId, "OWNER");
      const { accessToken, ...safeSession } = session;
      const response = NextResponse.json({
        user: { id: userId, email, displayName: name },
        organization: { id: organizationId, name: organizationName, slug },
        ...safeSession,
      }, { status: 201 });
      sessionCookie(response, accessToken);
      return response;
    }

    if (!validEmail(email) || !password) {
      return NextResponse.json({ message: "Email and password are required" }, { status: 400 });
    }
    const organizationKey = typeof input.organizationId === "string" ? input.organizationId.trim() : "";
    if (!organizationKey) return NextResponse.json({ message: "Workspace ID or slug is required" }, { status: 400 });

    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const bucketKey = await sha256(`${email}| ${ip}`);
    const limiter = await db.prepare(
      "SELECT attempts, window_start AS windowStart, blocked_until AS blockedUntil FROM login_attempts WHERE bucket_key = ?",
    ).bind(bucketKey).first<{ attempts: number; windowStart: string; blockedUntil: string | null }>();
    const now = Date.now();
    if (limiter?.blockedUntil && Date.parse(limiter.blockedUntil) > now) {
      return NextResponse.json({ message: "Too many sign-in attempts. Try again later." }, { status: 429 });
    }

    const user = await db.prepare(
      "SELECT id, email, password_hash AS passwordHash, display_name AS displayName, status FROM users WHERE email = ? COLLATE NOCASE LIMIT 1",
    ).bind(email).first<{ id: string; email: string; passwordHash: string | null; displayName: string | null; status: string }>();
    const membership = user?.status === "ACTIVE" ? await db.prepare(
      `SELECT m.organization_id AS organizationId, m.role
       FROM memberships m JOIN organizations o ON o.id = m.organization_id
       WHERE m.user_id = ? AND o.status = 'ACTIVE' AND (o.id = ? OR o.slug = ?) LIMIT 1`,
    ).bind(user.id, organizationKey, organizationKey).first<{ organizationId: string; role: AuthRole }>() : null;
    const passwordValid = await verifyPassword(password, user?.passwordHash ?? null);
    if (!user || user.status !== "ACTIVE" || !membership || !passwordValid) {
      const expiredWindow = !limiter || now - Date.parse(limiter.windowStart) >= LOGIN_WINDOW_MS;
      const attempts = expiredWindow ? 1 : limiter.attempts + 1;
      const blockedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(now + LOGIN_WINDOW_MS).toISOString() : null;
      await db.prepare(
        `INSERT INTO login_attempts (id, bucket_key, user_id, attempts, window_start, blocked_until, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(bucket_key) DO UPDATE SET user_id = excluded.user_id, attempts = excluded.attempts,
         window_start = excluded.window_start, blocked_until = excluded.blocked_until, updated_at = excluded.updated_at`,
      ).bind(crypto.randomUUID(), bucketKey, user?.id ?? null, attempts,
        expiredWindow ? new Date(now).toISOString() : limiter.windowStart, blockedUntil, new Date(now).toISOString()).run();
      return NextResponse.json({ message: "Invalid email, password or workspace" }, { status: 401 });
    }

    await db.prepare("DELETE FROM login_attempts WHERE bucket_key = ?").bind(bucketKey).run();
    const role = membership.role;
    const session = await issueSession(db, user.id, membership.organizationId, role);
    await db.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, source_ip) VALUES (?, ?, ?, 'auth.login', 'user', ?, ?)",
    ).bind(crypto.randomUUID(), membership.organizationId, user.id, user.id, ip).run();
    const { accessToken, ...safeSession } = session;
    const response = NextResponse.json({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      ...safeSession,
    });
    sessionCookie(response, accessToken);
    return response;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.error("[Nexora auth] Direct D1 authentication failed:", reason);
    if (action === "register" && /UNIQUE constraint failed: users\.email/i.test(reason)) {
      return NextResponse.json({ message: "An account with this email already exists" }, { status: 409 });
    }
    return NextResponse.json({ message: `Authentication failed: ${reason}` }, { status: 503 });
  }
}

export async function GET(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;
  if (action !== "me") return NextResponse.json({ message: "Not found" }, { status: 404 });
  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  try {
    const db = await getDatabase();
    const identity = await db.prepare(
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
    ).bind(await sha256(token), new Date().toISOString()).first<{
      id: string; email: string; displayName: string | null;
      organizationId: string; organizationName: string; organizationSlug: string; role: AuthRole;
    }>();
    if (!identity) {
      const response = NextResponse.json({ message: "Not authenticated" }, { status: 401 });
      clearSessionCookie(response);
      return response;
    }
    return NextResponse.json({
      id: identity.id,
      email: identity.email,
      displayName: identity.displayName,
      organization: { id: identity.organizationId, name: identity.organizationName, slug: identity.organizationSlug },
      role: identity.role,
    });
  } catch (error) {
    console.error("[Nexora auth] Session lookup failed:", error);
    return NextResponse.json({ message: "Authentication service is temporarily unavailable" }, { status: 503 });
  }
}
