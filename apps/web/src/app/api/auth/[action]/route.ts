import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COOKIE_NAME = "nexora_session";
const SESSION_SECONDS = 12 * 60 * 60;
const COOKIE_MAX_AGE = SESSION_SECONDS;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const PASSWORD_ITERATIONS = 100_000;

interface D1StatementLike {
  bind(...values: unknown[]): D1StatementLike;
  run(): Promise<unknown>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] }>;
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
  if (algorithm !== "pbkdf2-sha256" || !Number.isInteger(iterations) || iterations < 100_000 || iterations > PASSWORD_ITERATIONS ||
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
    "INSERT INTO auth_sessions (id, user_id, organization_id, token_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), userId, organizationId, crypto.randomUUID(), await sha256(token), expiresAt).run();
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
  const origin = request.headers.get("origin");
  let sameOrigin = false;
  try { sameOrigin = !!origin && new URL(origin).origin === request.nextUrl.origin; }
  catch { sameOrigin = false; }
  if (!sameOrigin) return NextResponse.json({ message: "Cross-origin request rejected" }, { status: 403 });

  const { action } = await context.params;
  if (!["login", "register", "logout", "forgot-password", "reset-password"].includes(action)) {
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

    if (action === "forgot-password") {
      const generic = { message: "If the account exists, a password reset link will be sent." };
      if (!validEmail(email)) return NextResponse.json(generic);
      const user = await db.prepare(
        "SELECT id, email, display_name AS displayName FROM users WHERE email = ? COLLATE NOCASE AND status = 'ACTIVE' LIMIT 1",
      ).bind(email).first<{ id: string; email: string; displayName: string | null }>();
      if (!user) return NextResponse.json(generic);

      const now = new Date();
      const nowIso = now.toISOString();
      const recent = await db.prepare(
        "SELECT created_at AS createdAt FROM password_reset_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
      ).bind(user.id).first<{ createdAt: string }>();
      if (recent && now.getTime() - Date.parse(recent.createdAt) < 60_000) return NextResponse.json(generic);

      const token = randomHex(32);
      const tokenHash = await sha256(token);
      const expiresAt = new Date(now.getTime() + 30 * 60 * 1000).toISOString();
      await db.batch([
        db.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL").bind(nowIso, user.id),
        db.prepare("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
          .bind(crypto.randomUUID(), user.id, tokenHash, expiresAt, nowIso),
      ]);

      const { env } = await getCloudflareContext({ async: true });
      const mail = env as typeof env & { RESEND_API_KEY?: string; EMAIL_FROM?: string; DASHBOARD_URL?: string };
      if (!mail.RESEND_API_KEY || !mail.EMAIL_FROM) {
        console.error("[Nexora auth] Password reset email is not configured on the dashboard Worker");
        return NextResponse.json({ message: "Password recovery email is temporarily unavailable. Contact your platform administrator." }, { status: 503 });
      }
      const baseUrl = (mail.DASHBOARD_URL || request.nextUrl.origin).replace(/\\/$/, "");
      const resetUrl = baseUrl + "/reset-password?token=" + encodeURIComponent(token);
      const safeName = (user.displayName || "there").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char);
      const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#172033">
        <h2>Reset your Nexora password</h2><p>Hello ${safeName},</p>
        <p>We received a request to reset your Nexora Control password. This link expires in 30 minutes and can only be used once.</p>
        <p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;text-decoration:none;border-radius:8px">Reset password</a></p>
        <p>If you did not request this, ignore this email. Your password will not change.</p>
      </div>`;
      try {
        const response = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: { Authorization: `Bearer ${mail.RESEND_API_KEY}`, "Content-Type": "application/json" },
          body: JSON.stringify({ from: mail.EMAIL_FROM, to: [user.email], subject: "Reset your Nexora password", html }),
        });
        if (!response.ok) {
          console.error("[Nexora auth] Resend rejected password reset:", response.status, (await response.text()).slice(0, 500));
          return NextResponse.json({ message: "Password recovery email could not be sent. Please try again later." }, { status: 503 });
        }
      } catch (error) {
        console.error("[Nexora auth] Password reset delivery failed:", error);
        return NextResponse.json({ message: "Password recovery email could not be sent. Please try again later." }, { status: 503 });
      }
      return NextResponse.json(generic);
    }

    if (action === "reset-password") {
      const token = typeof input.token === "string" ? input.token.trim() : "";
      if (!/^[a-f0-9]{64}$/i.test(token)) {
        return NextResponse.json({ message: "This reset link is invalid or has expired. Request a new one." }, { status: 400 });
      }
      if (password.length < 12 || password.length > 128) {
        return NextResponse.json({ message: "Password must be between 12 and 128 characters" }, { status: 400 });
      }
      const tokenHash = await sha256(token);
      const now = new Date().toISOString();
      const reset = await db.prepare(
        "SELECT id, user_id AS userId FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? LIMIT 1",
      ).bind(tokenHash, now).first<{ id: string; userId: string }>();
      if (!reset) return NextResponse.json({ message: "This reset link is invalid or has expired. Request a new one." }, { status: 400 });
      const claimed = await db.prepare(
        "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
      ).bind(now, reset.id, now).run() as { meta?: { changes?: number } };
      if ((claimed.meta?.changes ?? 0) !== 1) {
        return NextResponse.json({ message: "This reset link is invalid or has expired. Request a new one." }, { status: 400 });
      }
      const passwordHash = await hashPassword(password);
      await db.batch([
        db.prepare("UPDATE users SET password_hash = ? WHERE id = ? AND status = 'ACTIVE'").bind(passwordHash, reset.userId),
        db.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, reset.userId),
        db.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL").bind(now, reset.userId),
      ]);
      const response = NextResponse.json({ success: true, message: "Your password has been reset. Sign in with your new password." });
      clearSessionCookie(response);
      return response;
    }

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

      const registrationIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const registrationBucket = await sha256("register|" + registrationIp);
      const registrationLimit = await db.prepare(
        "SELECT attempts, window_start AS windowStart, blocked_until AS blockedUntil FROM login_attempts WHERE bucket_key = ?",
      ).bind(registrationBucket).first<{ attempts: number; windowStart: string; blockedUntil: string | null }>();
      const registrationNow = Date.now();
      if (registrationLimit?.blockedUntil && Date.parse(registrationLimit.blockedUntil) > registrationNow) {
        return NextResponse.json({ message: "Too many workspace registrations from this network. Try again later." }, { status: 429 });
      }
      const registrationWindowExpired = !registrationLimit || registrationNow - Date.parse(registrationLimit.windowStart) >= 60 * 60 * 1000;
      const registrationAttempts = registrationWindowExpired ? 1 : registrationLimit.attempts + 1;
      const registrationBlockedUntil = registrationAttempts >= 5
        ? new Date(registrationNow + 60 * 60 * 1000).toISOString()
        : null;
      await db.prepare(
        `INSERT INTO login_attempts (id, bucket_key, attempts, window_start, blocked_until, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(bucket_key) DO UPDATE SET attempts = excluded.attempts,
         window_start = excluded.window_start, blocked_until = excluded.blocked_until, updated_at = excluded.updated_at`,
      ).bind(crypto.randomUUID(), registrationBucket, registrationAttempts,
        registrationWindowExpired ? new Date(registrationNow).toISOString() : registrationLimit.windowStart,
        registrationBlockedUntil, new Date(registrationNow).toISOString()).run();

      const userId = crypto.randomUUID();
      const organizationId = crypto.randomUUID();
      const slug = `${slugBase(organizationName)}-${randomHex(4)}`;
      const passwordHash = await hashPassword(password);
      await db.batch([
        db.prepare("INSERT INTO users (id, email, password_hash, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
          .bind(userId, email, passwordHash, name),
        db.prepare("INSERT INTO organizations (id, name, slug, status) VALUES (?, ?, ?, 'ACTIVE')")
          .bind(organizationId, organizationName, slug),
        db.prepare("INSERT INTO memberships (id, user_id, organization_id, role) VALUES (?, ?, ?, 'MEMBER')")
          .bind(crypto.randomUUID(), userId, organizationId),
        db.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'auth.register', 'organization', ?)")
          .bind(crypto.randomUUID(), organizationId, userId, organizationId),
      ]);
      const session = await issueSession(db, userId, organizationId, "MEMBER");
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
    // Workspace is optional for accounts with a single active membership.
    // Existing clients may still send an organization ID or slug.
    const organizationKey = typeof input.organizationId === "string" ? input.organizationId.trim() : "";

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
    const membershipsResult = user?.status === "ACTIVE" ? await db.prepare(
      `SELECT m.organization_id AS organizationId, o.name AS organizationName,
              o.slug AS organizationSlug, m.role
       FROM memberships m JOIN organizations o ON o.id = m.organization_id
       WHERE m.user_id = ? AND o.status = 'ACTIVE'
       ORDER BY m.created_at ASC`,
    ).bind(user.id).all<{ organizationId: string; organizationName: string; organizationSlug: string; role: AuthRole }>() : { results: [] };
    const memberships = membershipsResult.results ?? [];
    const passwordValid = await verifyPassword(password, user?.passwordHash ?? null);
    if (!user || user.status !== "ACTIVE" || !passwordValid) {
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
      return NextResponse.json({ message: "Invalid email or password" }, { status: 401 });
    }

    if (!organizationKey && memberships.length > 1) {
      return NextResponse.json({
        message: "Choose the workspace you want to open.",
        requiresOrganization: true,
        organizations: memberships.map(({ organizationId, organizationName, organizationSlug, role }) => ({
          id: organizationId, name: organizationName, slug: organizationSlug, role,
        })),
      }, { status: 409 });
    }
    const membership = organizationKey
      ? memberships.find(item => item.organizationId === organizationKey || item.organizationSlug === organizationKey)
      : memberships[0];
    if (!membership) return NextResponse.json({ message: "Invalid email, password or workspace" }, { status: 401 });

    await db.prepare("DELETE FROM login_attempts WHERE bucket_key = ?").bind(bucketKey).run();
    const role = membership.role;
    const customerAccess = await db.prepare(
      "SELECT 1 AS active FROM hosting_account_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
    ).bind(user.id).first<{ active: number }>();
    const session = await issueSession(db, user.id, membership.organizationId, role);
    await db.prepare(
      "INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, source_ip) VALUES (?, ?, ?, 'auth.login', 'user', ?, ?)",
    ).bind(crypto.randomUUID(), membership.organizationId, user.id, user.id, ip).run();
    const { accessToken, ...safeSession } = session;
    const response = NextResponse.json({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      customerAccess: Boolean(customerAccess),
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
       JOIN memberships m ON m.user_id = u.id AND m.organization_id = s.organization_id
       JOIN organizations o ON o.id = s.organization_id
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
    const customerAccess = await db.prepare(
      "SELECT 1 AS active FROM hosting_account_memberships WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
    ).bind(identity.id).first<{ active: number }>();
    return NextResponse.json({
      id: identity.id,
      email: identity.email,
      displayName: identity.displayName,
      organization: { id: identity.organizationId, name: identity.organizationName, slug: identity.organizationSlug },
      role: identity.role,
      customerAccess: Boolean(customerAccess),
    });
  } catch (error) {
    console.error("[Nexora auth] Session lookup failed:", error);
    return NextResponse.json({ message: "Authentication service is temporarily unavailable" }, { status: 503 });
  }
}
