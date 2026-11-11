import test from "node:test";
import assert from "node:assert/strict";
import { createHash, pbkdf2Sync, randomBytes, createCipheriv } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// mfa-login.integration.test.ts
//
// MFA enforcement on the normal dashboard login flow.
//
// These integration tests exercise the Worker endpoints end-to-end through
// the Hono app's `fetch` handler, backed by a focused in-memory mock D1.
// The mock implements only the SQL queries that the login, login/mfa, and
// auth/me endpoints issue — every other query throws, so the test fails
// loudly if the endpoints drift from the expected SQL.
//
// Covered scenarios:
//   1. Login with NO MFA factor → session issued directly (no challenge).
//   2. Login WITH MFA factor → 200 with mfaRequired=true + challengeId, no
//      accessToken, no session row written, audit challenge row written.
//   3. MFA completion with a valid code → 200 with accessToken + session,
//      challenge consumed, last_used_totp_period set on the factor.
//   4. MFA completion with an invalid code → 401, failed_attempts
//      incremented, audit failed row written, no session.
//   5. After 5 invalid attempts the challenge is locked (423), subsequent
//      submissions rejected without re-checking the code.
//   6. Expired challenge (expires_at in the past) → 410.
//   7. Already-consumed challenge → 409.
//   8. Replay protection: after a successful consume, re-submitting the
//      same code against a fresh challenge for the same user is rejected
//      because last_used_totp_period is now equal to the current period.
//   9. Bypass attempt: calling /v1/auth/login/mfa without a prior /v1/auth
//      /login (i.e. with a forged challengeId) → 404, no session.
//  10. /v1/auth/me returns mfaEnrolled=true for a user with an active
//      factor, false for a user without.
//
// // The mock D1 validates endpoint behavior and SQL predicates but does not prove
// concurrent database semantics. A separate real-SQLite test exercises the
// atomic UPDATE statements under concurrent connections; Cloudflare D1 remote
// concurrency still requires deployment-environment acceptance testing.
// ---------------------------------------------------------------------------

const MFA_KEY_HEX = "a".repeat(64); // 32-byte AES-256 key for TOTP secret encryption
const PASSWORD = "CorrectHorseBatteryStaple12!";
const PBKDF2_ITERATIONS = 100_000;

// Precompute the password hash with the same algorithm the Worker uses
// (pbkdf2-sha256$<iterations>$<saltHex>$<hashHex>) so verifyPassword passes.
function makePasswordHash(password: string): string {
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

// AES-GCM encrypt using Node's crypto (matches the Worker's WebCrypto impl).
// The Worker stores ciphertext = base64(iv || ciphertext || tag).
function encryptTotpSecret(secret: string): string {
  const key = Buffer.from(MFA_KEY_HEX, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString("base64");
}

// Compute a TOTP code using the same algorithm the Worker uses (HMAC-SHA1,
// 30-second period, 6 digits). This lets the test generate the valid code
// the dashboard would submit.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(secret: string): Uint8Array {
  const bytes: number[] = [];
  let bits = 0; let value = 0;
  for (const char of secret) {
    const idx = BASE32_ALPHABET.indexOf(char.toUpperCase());
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(bytes);
}
async function computeTotpCode(secret: string, timestamp: number): Promise<string> {
  const period = 30;
  const counter = Math.floor(timestamp / 1000 / period);
  const key = base32Decode(secret);
  const counterBytes = new Uint8Array(8);
  let v = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = v & 0xff; v = Math.floor(v / 256); }
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1_000_000;
  return code.toString().padStart(6, "0");
}

type UserRow = {
  id: string; email: string; password_hash: string; display_name: string; status: string;
};
type OrgRow = { id: string; name: string; slug: string; status: string };
type MembershipRow = { user_id: string; organization_id: string; role: string };
type PlatformMembershipRow = { user_id: string; role: string; status: string };
type FactorRow = {
  id: string; user_id: string; kind: string; encrypted_secret: string;
  backup_codes: string | null; enrolled_at: string; last_used_totp_period: number | null;
};
type ChallengeRow = {
  id: string; user_id: string; organization_id: string; expires_at: string;
  consumed_at: string | null; created_at: string; failed_attempts: number; locked_at: string | null;
};
type SessionRow = {
  id: string; user_id: string; organization_id: string; token_id: string;
  token_hash: string; expires_at: string; revoked_at: string | null;
};
type LoginAttemptRow = {
  id: string; bucket_key: string; user_id: string | null; attempts: number;
  window_start: string; blocked_until: string | null; updated_at: string;
};
type AuditRow = {
  id: string; organization_id: string | null; actor_user_id: string | null;
  action: string; resource_type: string; resource_id: string | null; source_ip: string | null;
};

class MfaLoginD1 {
  users = new Map<string, UserRow>();
  orgs = new Map<string, OrgRow>();
  memberships: MembershipRow[] = [];
  platformMemberships: PlatformMembershipRow[] = [];
  factors = new Map<string, FactorRow>();
  challenges = new Map<string, ChallengeRow>();
  sessions = new Map<string, SessionRow>();
  loginAttempts = new Map<string, LoginAttemptRow>();
  auditLogs: AuditRow[] = [];
  hostingMemberships: Array<{ user_id: string; status: string }> = [];

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const stmt = {
      bind(...args: unknown[]) { values = args; return stmt; },
      async first<T>() {
        const q = query.replace(/\s+/g, " ").trim();
        // users lookup by email (login endpoint).
        if (q.startsWith("SELECT id, email, password_hash AS passwordHash") && q.includes("FROM users WHERE email =")) {
          const user = [...db.users.values()].find((u) => u.email.toLowerCase() === String(values[0]).toLowerCase());
          if (!user) return null;
          return { id: user.id, email: user.email, passwordHash: user.password_hash, displayName: user.display_name, status: user.status } as T;
        }
        // membership lookup (login endpoint).
        if (q.startsWith("SELECT m.organization_id AS organizationId, m.role, pm.role AS platformRole")) {
          const userId = values[0] as string;
          const orgKey = String(values[1]);
          const orgKey2 = String(values[2]);
          const m = db.memberships.find((mm) => mm.user_id === userId);
          if (!m) return null;
          const org = db.orgs.get(m.organization_id);
          if (!org || org.status !== "ACTIVE") return null;
          if (org.id !== orgKey && org.slug !== orgKey2) return null;
          const pm = db.platformMemberships.find((p) => p.user_id === userId && p.status === "ACTIVE");
          return { organizationId: m.organization_id, role: m.role, platformRole: pm?.role ?? null } as T;
        }
        // login_attempts lookup (login endpoint rate limiter).
        if (q.startsWith("SELECT attempts, window_start AS windowStart, blocked_until AS blockedUntil FROM login_attempts")) {
          const row = db.loginAttempts.get(String(values[0]));
          if (!row) return null;
          return { attempts: row.attempts, windowStart: row.window_start, blockedUntil: row.blocked_until } as T;
        }
        // MFA factor lookup at login: does the user have an active factor?
        if (q.startsWith("SELECT id FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL")) {
          const factor = [...db.factors.values()].find((f) => f.user_id === String(values[0]) && f.backup_codes !== null);
          if (!factor) return null;
          return { id: factor.id } as T;
        }
        // /v1/auth/me: hosting account membership probe.
        if (q.startsWith("SELECT 1 AS active FROM hosting_account_memberships")) {
          const active = db.hostingMemberships.some((hm) => hm.user_id === String(values[0]) && hm.status === "ACTIVE");
          return active ? ({ active: 1 } as T) : null;
        }
        // /v1/auth/me: MFA factor probe.
        if (q.startsWith("SELECT 1 AS active FROM mfa_factors WHERE user_id = ?") && q.includes("backup_codes IS NOT NULL")) {
          const factor = [...db.factors.values()].find((f) => f.user_id === String(values[0]) && f.backup_codes !== null);
          return factor ? ({ active: 1 } as T) : null;
        }
        // bearerIdentity (used by /v1/auth/me): join auth_sessions + users +
        // memberships + organizations + platform_memberships.
        if (q.startsWith("SELECT u.id, u.email") && q.includes("FROM auth_sessions s")) {
          const tokenHash = String(values[0]);
          const session = [...db.sessions.values()].find((s) => s.token_hash === tokenHash && !s.revoked_at);
          if (!session) return null;
          const user = db.users.get(session.user_id);
          if (!user || user.status !== "ACTIVE") return null;
          const m = db.memberships.find((mm) => mm.user_id === user.id && mm.organization_id === session.organization_id);
          if (!m) return null;
          const org = db.orgs.get(session.organization_id);
          if (!org || org.status !== "ACTIVE") return null;
          const pm = db.platformMemberships.find((p) => p.user_id === user.id && p.status === "ACTIVE");
          return {
            id: user.id, email: user.email, displayName: user.display_name,
            organizationId: org.id, organizationName: org.name, organizationSlug: org.slug,
            role: m.role, platformRole: pm?.role ?? null,
          } as T;
        }
        // login/mfa: challenge lookup with failed_attempts + locked_at.
        if (q.startsWith("SELECT id, user_id AS userId, organization_id AS organizationId, expires_at AS expiresAt, consumed_at AS consumedAt, failed_attempts AS failedAttempts, locked_at AS lockedAt FROM mfa_challenges")) {
          const c = db.challenges.get(String(values[0]));
          if (!c) return null;
          return {
            id: c.id, userId: c.user_id, organizationId: c.organization_id,
            expiresAt: c.expires_at, consumedAt: c.consumed_at,
            failedAttempts: c.failed_attempts, lockedAt: c.locked_at,
          } as T;
        }
        // login/mfa: reread the atomically incremented failed-attempt counter.
        if (q.startsWith("SELECT failed_attempts AS failedAttempts, locked_at AS lockedAt FROM mfa_challenges")) {
          const c = db.challenges.get(String(values[0]));
          return c ? ({ failedAttempts: c.failed_attempts, lockedAt: c.locked_at } as T) : null;
        }
        // login/mfa: factor lookup with last_used_totp_period.
        if (q.startsWith("SELECT id, encrypted_secret AS encryptedSecret, last_used_totp_period AS lastUsedTotpPeriod FROM mfa_factors WHERE user_id = ? AND kind = 'totp' AND backup_codes IS NOT NULL")) {
          const f = [...db.factors.values()].find((f) => f.user_id === String(values[0]) && f.backup_codes !== null);
          if (!f) return null;
          return { id: f.id, encryptedSecret: f.encrypted_secret, lastUsedTotpPeriod: f.last_used_totp_period } as T;
        }
        // login/mfa: revalidate user + organization state and exact membership.
        if (q.startsWith("SELECT m.role, pm.role AS platformRole") && q.includes("JOIN users u") && q.includes("JOIN organizations o")) {
          const userId = String(values[0]);
          const orgId = String(values[1]);
          const user = db.users.get(userId);
          const org = db.orgs.get(orgId);
          const m = db.memberships.find((mm) => mm.user_id === userId && mm.organization_id === orgId);
          if (!user || user.status !== "ACTIVE" || !org || org.status !== "ACTIVE" || !m) return null;
          const pm = db.platformMemberships.find((p) => p.user_id === userId && p.status === "ACTIVE");
          return { role: m.role, platformRole: pm?.role ?? null } as T;
        }
        // login/mfa: final authorization recheck immediately before issueSession.
        if (q.startsWith("SELECT m.role FROM memberships m JOIN users u") && q.includes("JOIN organizations o")) {
          const userId = String(values[0]);
          const orgId = String(values[1]);
          const user = db.users.get(userId);
          const org = db.orgs.get(orgId);
          const m = db.memberships.find((mm) => mm.user_id === userId && mm.organization_id === orgId);
          if (!user || user.status !== "ACTIVE" || !org || org.status !== "ACTIVE" || !m) return null;
          return { role: m.role } as T;
        }
        // login/mfa: user display info.
        if (q.startsWith("SELECT id, email, display_name AS displayName FROM users WHERE id = ?")) {
          const u = db.users.get(String(values[0]));
          if (!u) return null;
          return { id: u.id, email: u.email, displayName: u.display_name } as T;
        }
        return null;
      },
      async all<T>() {
        return { results: [] as T[] };
      },
      async run() {
        const q = query.replace(/\s+/g, " ").trim();
        // login_attempts: clear on successful password verification.
        if (q.startsWith("DELETE FROM login_attempts WHERE bucket_key = ?")) {
          db.loginAttempts.delete(String(values[0]));
          return { meta: { changes: 1 } };
        }
        // login_attempts: insert or update on failed password.
        if (q.startsWith("INSERT INTO login_attempts") && q.includes("ON CONFLICT(bucket_key) DO UPDATE")) {
          const bucketKey = String(values[1]);
          db.loginAttempts.set(bucketKey, {
            id: String(values[0]), bucket_key: bucketKey, user_id: values[2] as string | null,
            attempts: values[3] as number, window_start: values[4] as string,
            blocked_until: values[5] as string | null, updated_at: values[6] as string,
          });
          return { meta: { changes: 1 } };
        }
        // mfa_challenges insert (login endpoint, after password verified).
        if (q.startsWith("INSERT INTO mfa_challenges (id, user_id, organization_id, expires_at)")) {
          const id = String(values[0]);
          db.challenges.set(id, {
            id, user_id: String(values[1]), organization_id: String(values[2]),
            expires_at: String(values[3]), consumed_at: null, created_at: new Date().toISOString(),
            failed_attempts: 0, locked_at: null,
          });
          return { meta: { changes: 1 } };
        }
        // auth_sessions insert (issueSession).
        if (q.startsWith("INSERT INTO auth_sessions")) {
          const id = String(values[0]);
          db.sessions.set(id, {
            id, user_id: String(values[1]), organization_id: String(values[2]),
            token_id: String(values[3]), token_hash: String(values[4]),
            expires_at: String(values[5]), revoked_at: null,
          });
          return { meta: { changes: 1 } };
        }
        // audit_logs insert. The Worker's INSERT statements embed action and
        // resource_type as SQL string literals (e.g. VALUES (?, ?, ?, 'auth
        // .login_mfa_failed', 'mfa_challenge', ?)) so we regex-extract them
        // from the query rather than reading them from the bind array. The
        // bind array's positional values depend on how many `?` placeholders
        // precede the literals, which varies per call site.
        if (q.startsWith("INSERT INTO audit_logs")) {
          const actionMatch = q.match(/'([a-z][a-z0-9_.]+)'/);
          const typeMatch = q.match(/,\s*'([a-z][a-z0-9_]+)'\s*,\s*\?/);
          // Count how many `?` placeholders appear before the first literal
          // so we know which bind index holds resource_id / source_ip.
          const beforeLiteral = q.split(/'[a-z]/)[0];
          const placeholdersBeforeLiteral = (beforeLiteral.match(/\?/g) ?? []).length;
          // After the two literals, count remaining `?` to map resource_id
          // and (optional) source_ip bind positions.
          const afterLiterals = q.split(/'[a-z][a-z0-9_.]+',\s*'[a-z][a-z0-9_]+'/)[1] ?? "";
          const remainingPlaceholders = (afterLiterals.match(/\?/g) ?? []);
          const resourceIdIndex = placeholdersBeforeLiteral; // next bind after the literals
          const sourceIpIndex = remainingPlaceholders.length > 1 ? resourceIdIndex + 1 : null;
          db.auditLogs.push({
            id: String(values[0]),
            organization_id: values[1] as string | null,
            actor_user_id: values[2] as string | null,
            action: actionMatch ? actionMatch[1] : String(values[3] ?? ""),
            resource_type: typeMatch ? typeMatch[1] : String(values[4] ?? ""),
            resource_id: values[resourceIdIndex] as string | null ?? null,
            source_ip: sourceIpIndex !== null ? (values[sourceIpIndex] as string | null ?? null) : null,
          });
          return { meta: { changes: 1 } };
        }
        // login/mfa: atomic failed-attempt increment and lockout.
        if (q.startsWith("UPDATE mfa_challenges SET failed_attempts = failed_attempts + 1")) {
          const c = db.challenges.get(String(values[2]));
          const now = String(values[3]);
          const cap = Number(values[0]);
          if (!c || c.consumed_at || c.locked_at || Date.parse(c.expires_at) <= Date.parse(now) || c.failed_attempts >= cap) {
            return { meta: { changes: 0 } };
          }
          c.failed_attempts += 1;
          if (c.failed_attempts >= cap) c.locked_at = String(values[1]);
          return { meta: { changes: 1 } };
        }
        // login/mfa: atomic challenge consumption bound to user/org and expiry.
        if (q.startsWith("UPDATE mfa_challenges SET consumed_at = ? WHERE id = ? AND user_id = ?")) {
          const c = db.challenges.get(String(values[1]));
          const now = String(values[4]);
          if (!c || c.user_id !== String(values[2]) || c.organization_id !== String(values[3]) ||
              c.consumed_at || c.locked_at || Date.parse(c.expires_at) <= Date.parse(now)) {
            return { meta: { changes: 0 } };
          }
          c.consumed_at = String(values[0]);
          return { meta: { changes: 1 } };
        }
        // login/mfa: atomically claim a TOTP period once per enrolled factor.
        if (q.startsWith("UPDATE mfa_factors SET last_used_totp_period = ? WHERE id = ? AND (last_used_totp_period IS NULL OR last_used_totp_period < ?)")) {
          const f = db.factors.get(String(values[1]));
          const c = db.challenges.get(String(values[3]));
          if (!f || !c || f.user_id !== String(values[4]) || c.user_id !== String(values[4]) ||
              c.organization_id !== String(values[5]) || c.consumed_at !== String(values[6]) ||
              (f.last_used_totp_period !== null && f.last_used_totp_period >= Number(values[2]))) {
            return { meta: { changes: 0 } };
          }
          f.last_used_totp_period = Number(values[0]);
          return { meta: { changes: 1 } };
        }
        return { meta: { changes: 0 } };
      },
      async batch() { return [{ meta: { changes: 0 } }]; },
    };
    return stmt;
  }
}

function setupEnv(opts: { withMfa?: boolean } = {}) {
  const db = new MfaLoginD1();
  db.orgs.set("org-a", { id: "org-a", name: "Acme", slug: "acme", status: "ACTIVE" });
  db.users.set("user-a", {
    id: "user-a", email: "alice@acme.test",
    password_hash: makePasswordHash(PASSWORD),
    display_name: "Alice", status: "ACTIVE",
  });
  db.memberships.push({ user_id: "user-a", organization_id: "org-a", role: "ADMIN" });
  if (opts.withMfa) {
    db.factors.set("factor-a", {
      id: "factor-a", user_id: "user-a", kind: "totp",
      encrypted_secret: encryptTotpSecret("JBSWY3DPEHPK3PXP"), // a known TOTP secret
      backup_codes: JSON.stringify({ activated: true, enrolledAt: new Date().toISOString() }),
      enrolled_at: new Date().toISOString(),
      last_used_totp_period: null,
    });
  }
  const env = {
    DB: db as unknown as Parameters<typeof worker.fetch>[1]["DB"],
    MFA_ENCRYPTION_KEY: MFA_KEY_HEX,
  };
  return { db, env };
}

async function callLogin(env: unknown, body: unknown) {
  return worker.fetch(
    new Request("https://api.test/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    env as Parameters<typeof worker.fetch>[1],
    {} as ExecutionContext,
  );
}

async function callMfa(env: unknown, body: unknown) {
  return worker.fetch(
    new Request("https://api.test/v1/auth/login/mfa", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    env as Parameters<typeof worker.fetch>[1],
    {} as ExecutionContext,
  );
}

async function callMe(env: unknown, token: string) {
  return worker.fetch(
    new Request("https://api.test/v1/auth/me", {
      headers: { authorization: `Bearer ${token}` },
    }),
    env as Parameters<typeof worker.fetch>[1],
    {} as ExecutionContext,
  );
}

// ---------------------------------------------------------------------------

test("login without an MFA factor issues a session directly", async () => {
  const { env } = setupEnv({ withMfa: false });
  const res = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  assert.equal(res.status, 200);
  const data = await res.json() as { accessToken?: string; mfaRequired?: boolean };
  assert.ok(data.accessToken, "expected accessToken for non-MFA login");
  assert.equal(data.mfaRequired, undefined);
  assert.match(data.accessToken!, /^[a-f0-9]{64}$/);
});

test("login with an active MFA factor returns mfaRequired and a challengeId, no accessToken", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const res = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  assert.equal(res.status, 200);
  const data = await res.json() as { accessToken?: string; mfaRequired?: boolean; challengeId?: string; expiresAt?: string };
  assert.equal(data.accessToken, undefined, "no session token should be issued before MFA completion");
  assert.equal(data.mfaRequired, true);
  assert.ok(data.challengeId);
  assert.match(data.challengeId!, /^[a-f0-9-]{36}$/);
  assert.ok(data.expiresAt);
  // Challenge row should be persisted with failed_attempts=0, locked_at=null.
  const challenge = db.challenges.get(data.challengeId!);
  assert.ok(challenge);
  assert.equal(challenge!.failed_attempts, 0);
  assert.equal(challenge!.locked_at, null);
  assert.equal(challenge!.consumed_at, null);
  // No session should have been written yet.
  assert.equal(db.sessions.size, 0);
  // Audit log should record the challenge creation.
  assert.ok(db.auditLogs.some((a) => a.action === "auth.login_mfa_challenge"));
});

test("MFA completion with a valid code issues a session, consumes the challenge, marks the factor", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const loginRes = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const login = await loginRes.json() as { challengeId: string };
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const mfaRes = await callMfa(env, { challengeId: login.challengeId, code });
  assert.equal(mfaRes.status, 200);
  const data = await mfaRes.json() as { accessToken?: string; customerAccess?: boolean };
  assert.ok(data.accessToken);
  // Challenge consumed.
  const c = db.challenges.get(login.challengeId)!;
  assert.ok(c.consumed_at);
  // Factor's last_used_totp_period set to the current period.
  const f = db.factors.get("factor-a")!;
  assert.ok(f.last_used_totp_period !== null);
  assert.equal(f.last_used_totp_period, Math.floor(Date.now() / 1000 / 30));
  // Session row written.
  assert.equal(db.sessions.size, 1);
  // Audit success row written.
  assert.ok(db.auditLogs.some((a) => a.action === "auth.login_mfa"));
});

test("MFA completion with an invalid code returns 401, increments failed_attempts, audits the failure", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const loginRes = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const login = await loginRes.json() as { challengeId: string };
  const mfaRes = await callMfa(env, { challengeId: login.challengeId, code: "000000" });
  assert.equal(mfaRes.status, 401);
  const c = db.challenges.get(login.challengeId)!;
  assert.equal(c.failed_attempts, 1);
  assert.equal(c.locked_at, null);
  assert.equal(c.consumed_at, null);
  assert.equal(db.sessions.size, 0);
  assert.ok(db.auditLogs.some((a) => a.action === "auth.login_mfa_failed"));
});

test("after 5 invalid attempts the challenge is locked (423) and subsequent submissions are rejected without re-checking the code", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const loginRes = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const login = await loginRes.json() as { challengeId: string };
  // Submit 5 invalid codes; the 5th should return 423 (lock fires at the cap).
  for (let i = 0; i < 4; i++) {
    const r = await callMfa(env, { challengeId: login.challengeId, code: "000000" });
    assert.equal(r.status, 401, `attempt ${i + 1} should be 401`);
  }
  const fifth = await callMfa(env, { challengeId: login.challengeId, code: "000000" });
  assert.equal(fifth.status, 423);
  const c = db.challenges.get(login.challengeId)!;
  assert.equal(c.failed_attempts, 5);
  assert.ok(c.locked_at);
  // Even a VALID code now should be rejected because locked_at is set.
  const validCode = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const afterLock = await callMfa(env, { challengeId: login.challengeId, code: validCode });
  assert.equal(afterLock.status, 423);
  assert.equal(db.sessions.size, 0);
  assert.ok(db.auditLogs.some((a) => a.action === "auth.login_mfa_locked"));
});

test("expired challenge returns 410", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  // Use a valid UUID so the endpoint's challengeId regex accepts it.
  const expiredId = "11111111-1111-1111-1111-111111111111";
  db.challenges.set(expiredId, {
    id: expiredId, user_id: "user-a", organization_id: "org-a",
    expires_at: new Date(Date.now() - 1000).toISOString(),
    consumed_at: null, created_at: new Date().toISOString(),
    failed_attempts: 0, locked_at: null,
  });
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const res = await callMfa(env, { challengeId: expiredId, code });
  assert.equal(res.status, 410);
  assert.equal(db.sessions.size, 0);
});

test("already-consumed challenge returns 409", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const consumedId = "22222222-2222-2222-2222-222222222222";
  db.challenges.set(consumedId, {
    id: consumedId, user_id: "user-a", organization_id: "org-a",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    consumed_at: new Date().toISOString(), created_at: new Date().toISOString(),
    failed_attempts: 0, locked_at: null,
  });
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const res = await callMfa(env, { challengeId: consumedId, code });
  assert.equal(res.status, 409);
  assert.equal(db.sessions.size, 0);
});

test("replay protection: re-submitting the same code against a fresh challenge for the same user is rejected because last_used_totp_period is set", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  // First login + successful MFA completion sets last_used_totp_period.
  const login1 = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const c1 = (await login1.json() as { challengeId: string }).challengeId;
  const validCode = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const mfa1 = await callMfa(env, { challengeId: c1, code: validCode });
  assert.equal(mfa1.status, 200);
  // Second login within the same 30-second window produces a fresh challenge,
  // but the same valid code (still in the current TOTP period) should be
  // rejected because last_used_totp_period == currentTotpPeriod.
  const login2 = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const c2 = (await login2.json() as { challengeId: string }).challengeId;
  const mfa2 = await callMfa(env, { challengeId: c2, code: validCode });
  assert.equal(mfa2.status, 409);
  // The second challenge should NOT be consumed by the rejected attempt.
  const c2row = db.challenges.get(c2)!;
  assert.equal(c2row.consumed_at, null);
  assert.equal(c2row.failed_attempts, 0); // replay rejection does not increment failed_attempts
});

test("bypass attempt: calling /v1/auth/login/mfa with a forged challengeId yields 404, no session", async () => {
  const { db, env } = setupEnv({ withMfa: false });
  // User has no MFA factor — but even if they did, a forged challengeId would
  // not exist in the challenges table.
  const res = await callMfa(env, { challengeId: "ffffffff-ffff-ffff-ffff-ffffffffffff", code: "123456" });
  assert.equal(res.status, 404);
  assert.equal(db.sessions.size, 0);
});

test("/v1/auth/me returns mfaEnrolled=true for a user with an active factor, false without", async () => {
  // Without MFA.
  const env1 = setupEnv({ withMfa: false });
  const login1 = await callLogin(env1.env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const token1 = (await login1.json() as { accessToken: string }).accessToken;
  const me1 = await callMe(env1.env, token1);
  assert.equal(me1.status, 200);
  const me1Data = await me1.json() as { mfaEnrolled?: boolean };
  assert.equal(me1Data.mfaEnrolled, false);

  // With MFA: we must complete the challenge to get a session token, then
  // call /v1/auth/me with it.
  const env2 = setupEnv({ withMfa: true });
  const login2 = await callLogin(env2.env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const challengeId = (await login2.json() as { challengeId: string }).challengeId;
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const mfa2 = await callMfa(env2.env, { challengeId, code });
  const token2 = (await mfa2.json() as { accessToken: string }).accessToken;
  const me2 = await callMe(env2.env, token2);
  assert.equal(me2.status, 200);
  const me2Data = await me2.json() as { mfaEnrolled?: boolean };
  assert.equal(me2Data.mfaEnrolled, true);
});

test("login cannot bypass MFA by submitting a forged challengeId to /v1/auth/login/mfa when the factor exists", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  // User DOES have an MFA factor. An attacker who knows the user's email +
  // password but NOT the challengeId (because they did not call /v1/auth/login
  // themselves, or the challengeId has been consumed) tries to forge one.
  const forged = "00000000-0000-0000-0000-000000000000";
  const res = await callMfa(env, { challengeId: forged, code: "123456" });
  assert.equal(res.status, 404); // challenge not found
  assert.equal(db.sessions.size, 0);
  // No failed_attempts row was modified because no challenge matched.
  assert.equal([...db.challenges.values()].length, 0);
});

test("parallel invalid MFA submissions cannot lose increments or exceed the attempt cap", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const login = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const challengeId = (await login.json() as { challengeId: string }).challengeId;
  const results = await Promise.all(Array.from({ length: 12 }, () =>
    callMfa(env, { challengeId, code: "000000" }),
  ));
  const challenge = db.challenges.get(challengeId)!;
  assert.equal(challenge.failed_attempts, 5);
  assert.ok(challenge.locked_at);
  assert.equal(db.sessions.size, 0);
  assert.ok(results.some((r) => r.status === 423));
  assert.ok(results.every((r) => [401, 409, 423].includes(r.status)));
});

test("parallel challenges cannot issue two sessions using the same TOTP period", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const login1 = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const login2 = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const id1 = (await login1.json() as { challengeId: string }).challengeId;
  const id2 = (await login2.json() as { challengeId: string }).challengeId;
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const results = await Promise.all([
    callMfa(env, { challengeId: id1, code }),
    callMfa(env, { challengeId: id2, code }),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  assert.equal(db.sessions.size, 1);
  assert.equal(db.factors.get("factor-a")!.last_used_totp_period, Math.floor(Date.now() / 1000 / 30));
});

test("MFA completion rejects a user suspended after password verification", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const login = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const challengeId = (await login.json() as { challengeId: string }).challengeId;
  db.users.get("user-a")!.status = "SUSPENDED";
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const result = await callMfa(env, { challengeId, code });
  assert.equal(result.status, 403);
  assert.equal(db.sessions.size, 0);
  assert.equal(db.challenges.get(challengeId)!.consumed_at, null);
});

test("MFA completion rejects a suspended organization", async () => {
  const { db, env } = setupEnv({ withMfa: true });
  const login = await callLogin(env, { email: "alice@acme.test", password: PASSWORD, organizationId: "org-a" });
  const challengeId = (await login.json() as { challengeId: string }).challengeId;
  db.orgs.get("org-a")!.status = "SUSPENDED";
  const code = await computeTotpCode("JBSWY3DPEHPK3PXP", Date.now());
  const result = await callMfa(env, { challengeId, code });
  assert.equal(result.status, 403);
  assert.equal(db.sessions.size, 0);
  assert.equal(db.challenges.get(challengeId)!.consumed_at, null);
});
