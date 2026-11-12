import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// application-integration-fix5.test.ts
//
// 21 integration tests covering the new administrator and customer surface:
// PHP-FPM pool settings, per-account backup schedules, organization rename,
// organization-scoped audit logs, session management, hosting-account
// lifecycle (suspend/reactivate), and TOTP MFA enrollment.
//
// The IntegrationD1 mock simulates the subset of the schema the routes
// touch: auth_sessions, hosting_accounts, hosting_plans,
// hosting_account_php_settings, backup_schedules, audit_logs,
// provisioning_jobs, mfa_factors, users, and memberships. State mutates in
// memory so the tests can assert end-to-end transitions without a real D1.
// ---------------------------------------------------------------------------

const MFA_ENCRYPTION_KEY = "a".repeat(64);
const SESSION_TOKEN = "a".repeat(64); // bearerIdentity requires 64-hex

type Role = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";
type PlatformRole = "PLATFORM_OWNER" | "PLATFORM_ADMIN" | null;

type Identity = {
  id: string;
  email: string;
  displayName: string | null;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: Role;
  platformRole: PlatformRole;
};

type SessionRow = {
  id: string;
  userId: string;
  organizationId: string;
  tokenHash: string;
  revokedAt: string | null;
  expiresAt: string;
  createdAt: string;
  userAgent: string | null;
  sourceIp: string | null;
};

type AccountRow = {
  id: string;
  organizationId: string;
  username: string;
  status: string;
  serverId: string;
  planId: string;
};

type PhpSettingsRow = {
  phpVersion: string;
  memoryLimitMib: number;
  maxExecutionTimeSeconds: number;
  uploadMaxFilesizeMib: number;
  maxInputVars: number;
  displayErrors: number;
  updatedAt: string;
};

type BackupScheduleRow = {
  frequency: string;
  retentionCount: number;
  nextRunAt: string | null;
  lastRunAt: string | null;
  updatedAt: string;
};

type AuditRow = {
  id: string;
  organizationId: string;
  actorUserId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  sourceIp: string | null;
  metadata: string | null;
  createdAt: string;
};

type JobRow = {
  id: string;
  hostingAccountId: string;
  operation: string;
  status: string;
};

type MfaFactorRow = {
  id: string;
  userId: string;
  kind: string;
  encryptedSecret: string;
  backupCodes: string | null;
};

class IntegrationD1 {
  user = {
    id: "user-a",
    email: "owner@example.test",
    displayName: "Owner",
    status: "ACTIVE",
  };
  sessions = new Map<string, SessionRow>();
  accounts = new Map<string, AccountRow>();
  plans = new Map<string, { id: string; cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number }>();
  phpSettings = new Map<string, PhpSettingsRow>();
  backupSchedules = new Map<string, BackupScheduleRow>();
  auditRows: AuditRow[] = [];
  jobs: JobRow[] = [];
  mfaFactors = new Map<string, MfaFactorRow>();
  identity: Identity | null = null;
  currentTokenHash = "";

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      getValues() { return values; },
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        // auth_sessions s lookup (bearerIdentity). Bind order:
        // (tokenHash, currentIsoTimestamp). The session must exist, be
        // unrevoked, and belong to the active identity.
        if (query.includes("FROM auth_sessions s")) {
          if (!db.identity) return null as T;
          const tokenHash = String(values[0]);
          const session = db.sessions.get(tokenHash);
          if (!session || session.revokedAt) return null as T;
          if (Date.parse(session.expiresAt) <= Date.now()) return null as T;
          return ({
            id: db.identity.id,
            email: db.identity.email,
            displayName: db.identity.displayName,
            organizationId: db.identity.organizationId,
            organizationName: db.identity.organizationName,
            organizationSlug: db.identity.organizationSlug,
            role: db.identity.role,
            platformRole: db.identity.platformRole,
          } as T);
        }
        // hosting_accounts WHERE id = ? (account existence / status lookup).
        if (query.includes("FROM hosting_accounts WHERE id = ?")) {
          const accountId = String(values[0]);
          const orgId = String(values[1]);
          const account = db.accounts.get(accountId);
          if (!account || account.organizationId !== orgId) return null as T;
          if (query.includes("username")) {
            return ({
              id: account.id,
              username: account.username,
              status: account.status,
            } as T);
          }
          return ({ id: account.id } as T);
        }
        // hosting_plans WHERE id = ? (defensive — not exercised by these
        // routes but the mock must handle the shape).
        if (query.includes("FROM hosting_plans WHERE id = ?")) {
          const plan = db.plans.get(String(values[0]));
          if (!plan) return null as T;
          return ({
            id: plan.id,
            cpuMillis: plan.cpuMillis,
            memoryMiB: plan.memoryMiB,
            diskMiB: plan.diskMiB,
            processLimit: plan.processLimit,
          } as T);
        }
        // hosting_account_php_settings lookup.
        if (query.includes("FROM hosting_account_php_settings")) {
          const accountId = String(values[0]);
          const settings = db.phpSettings.get(accountId);
          if (!settings) return null as T;
          return ({
            phpVersion: settings.phpVersion,
            memoryLimitMib: settings.memoryLimitMib,
            maxExecutionTimeSeconds: settings.maxExecutionTimeSeconds,
            uploadMaxFilesizeMib: settings.uploadMaxFilesizeMib,
            maxInputVars: settings.maxInputVars,
            displayErrors: settings.displayErrors,
            updatedAt: settings.updatedAt,
          } as T);
        }
        // backup_schedules lookup.
        if (query.includes("FROM backup_schedules")) {
          const accountId = String(values[0]);
          const schedule = db.backupSchedules.get(accountId);
          if (!schedule) return null as T;
          return ({
            frequency: schedule.frequency,
            retentionCount: schedule.retentionCount,
            nextRunAt: schedule.nextRunAt,
            lastRunAt: schedule.lastRunAt,
            updatedAt: schedule.updatedAt,
          } as T);
        }
        // auth_sessions WHERE token_hash = ? (current session lookup).
        if (query.includes("FROM auth_sessions WHERE token_hash = ?")) {
          const tokenHash = String(values[0]);
          const session = db.sessions.get(tokenHash);
          if (!session) return null as T;
          return ({ id: session.id } as T);
        }
        // auth_sessions WHERE id = ? (target session for revocation).
        if (query.includes("FROM auth_sessions WHERE id = ?")) {
          const sessionId = String(values[0]);
          for (const session of db.sessions.values()) {
            if (session.id === sessionId) {
              return ({ id: session.id, userId: session.userId } as T);
            }
          }
          return null as T;
        }
        // users WHERE id = ? (defensive).
        if (query.includes("FROM users WHERE id = ?")) {
          if (String(values[0]) !== db.user.id) return null as T;
          return ({
            id: db.user.id,
            email: db.user.email,
            displayName: db.user.displayName,
            status: db.user.status,
          } as T);
        }
        // memberships (defensive).
        if (query.includes("FROM memberships")) {
          return ({ role: db.identity?.role ?? "MEMBER" } as T);
        }
        // mfa_factors lookup (enrollment verification path).
        if (query.includes("FROM mfa_factors")) {
          const userId = String(values[0]);
          for (const factor of db.mfaFactors.values()) {
            if (factor.userId === userId) {
              return ({ id: factor.id, encryptedSecret: factor.encryptedSecret } as T);
            }
          }
          return null as T;
        }
        return null as T;
      },
      async all<T>() {
        // audit_logs (organization-scoped). Bind order: organizationFilter
        // first, optional filters, then pageLimit last.
        if (query.includes("FROM audit_logs")) {
          const orgId = String(values[0]);
          const filtered = db.auditRows.filter((r) => r.organizationId === orgId);
          return ({
            results: filtered.map((r) => ({
              id: r.id,
              organizationId: r.organizationId,
              actorUserId: r.actorUserId,
              action: r.action,
              resourceType: r.resourceType,
              resourceId: r.resourceId,
              sourceIp: r.sourceIp,
              metadata: r.metadata,
              createdAt: r.createdAt,
            })) as T[],
          });
        }
        // auth_sessions WHERE user_id = ? (sessions listing).
        if (query.includes("FROM auth_sessions WHERE user_id = ?")) {
          const userId = String(values[0]);
          const userSessions = Array.from(db.sessions.values())
            .filter((s) => s.userId === userId);
          return ({
            results: userSessions.map((s) => ({
              id: s.id,
              organizationId: s.organizationId,
              issuedAt: s.createdAt,
              expiresAt: s.expiresAt,
              revokedAt: s.revokedAt,
              userAgent: s.userAgent,
              sourceIp: s.sourceIp,
            })) as T[],
          });
        }
        return { results: [] as T[] };
      },
      async run() {
        // Nonce replay protection (defensive — not exercised by these routes).
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces") ||
            query.includes("INSERT OR IGNORE INTO agent_nonces")) {
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE hosting_accounts SET status. Check the SET clause for
        // SUSPENDED vs ACTIVE. Bind order: (accountId, organizationId).
        if (query.includes("UPDATE hosting_accounts SET status")) {
          const acctId = String(values[0]);
          const account = db.accounts.get(acctId);
          if (account) {
            if (query.includes("SET status = 'SUSPENDED'")) {
              account.status = "SUSPENDED";
            } else if (query.includes("SET status = 'ACTIVE'")) {
              account.status = "ACTIVE";
            }
          }
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE domains (defensive — surface area only).
        if (query.includes("UPDATE domains")) {
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE hosting_plans (defensive).
        if (query.includes("UPDATE hosting_plans")) {
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT hosting_account_php_settings. Bind order:
        // (accountId, phpVersion, memoryLimitMib, maxExecutionTimeSeconds,
        //  uploadMaxFilesizeMib, maxInputVars, displayErrors).
        if (query.includes("INSERT INTO hosting_account_php_settings")) {
          const accountId = String(values[0]);
          db.phpSettings.set(accountId, {
            phpVersion: String(values[1]),
            memoryLimitMib: Number(values[2]),
            maxExecutionTimeSeconds: Number(values[3]),
            uploadMaxFilesizeMib: Number(values[4]),
            maxInputVars: Number(values[5]),
            displayErrors: Number(values[6]),
            updatedAt: new Date().toISOString(),
          });
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT backup_schedules. Bind order:
        // (accountId, frequency, retentionCount).
        if (query.includes("INSERT INTO backup_schedules")) {
          const accountId = String(values[0]);
          db.backupSchedules.set(accountId, {
            frequency: String(values[1]),
            retentionCount: Number(values[2]),
            nextRunAt: null,
            lastRunAt: null,
            updatedAt: new Date().toISOString(),
          });
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT provisioning_jobs. Extract operation from the query
        // literals. Bind order varies slightly between the VALUES and
        // SELECT ... WHERE changes() = 1 forms; only id and hosting_account_id
        // are needed for assertions.
        if (query.includes("INSERT INTO provisioning_jobs")) {
          let operation = "UNKNOWN";
          if (query.includes("'UPDATE_PHP_POOL'")) operation = "UPDATE_PHP_POOL";
          else if (query.includes("'SUSPEND_HOSTING_ACCOUNT'")) operation = "SUSPEND_HOSTING_ACCOUNT";
          else if (query.includes("'REACTIVATE_HOSTING_ACCOUNT'")) operation = "REACTIVATE_HOSTING_ACCOUNT";
          else if (query.includes("'RESTORE_BACKUP'")) operation = "RESTORE_BACKUP";
          else if (query.includes("'DELETE_BACKUP'")) operation = "DELETE_BACKUP";
          db.jobs.push({
            id: String(values[0]),
            hostingAccountId: String(values[1]),
            operation,
            status: "QUEUED",
          });
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT audit_logs. Extract action from the query literals.
        // Bind order: (id, organizationId, actorUserId, resourceId, metadata)
        // (metadata omitted on some queries).
        if (query.includes("INSERT INTO audit_logs")) {
          let action = "unknown";
          if (query.includes("'hosting_account.php_updated'")) action = "hosting_account.php_updated";
          else if (query.includes("'backup_schedule.updated'")) action = "backup_schedule.updated";
          else if (query.includes("'organization.updated'")) action = "organization.updated";
          else if (query.includes("'hosting_account.suspended'")) action = "hosting_account.suspended";
          else if (query.includes("'hosting_account.reactivated'")) action = "hosting_account.reactivated";
          else if (query.includes("'auth.session_revoked'")) action = "auth.session_revoked";
          else if (query.includes("'auth.mfa_enrolled'")) action = "auth.mfa_enrolled";
          let resourceType = "unknown";
          if (query.includes("'hosting_account'")) resourceType = "hosting_account";
          else if (query.includes("'organization'")) resourceType = "organization";
          else if (query.includes("'auth_session'")) resourceType = "auth_session";
          else if (query.includes("'mfa_factor'")) resourceType = "mfa_factor";
          db.auditRows.push({
            id: String(values[0]),
            organizationId: String(values[1]),
            actorUserId: String(values[2]),
            action,
            resourceType,
            resourceId: String(values[3] ?? ""),
            sourceIp: null,
            metadata: values[4] !== undefined ? String(values[4]) : null,
            createdAt: new Date().toISOString(),
          });
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE auth_sessions SET revoked_at. Bind order:
        // (revokedAtIso, sessionId).
        if (query.includes("UPDATE auth_sessions SET revoked_at")) {
          const sessionId = String(values[1]);
          for (const session of db.sessions.values()) {
            if (session.id === sessionId) {
              session.revokedAt = String(values[0]);
            }
          }
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE organizations SET name = ?. Bind order: (name, orgId).
        if (query.includes("UPDATE organizations SET name = ?")) {
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT mfa_factors. Bind order:
        // (id, userId, encryptedSecret) — kind is the literal 'totp'.
        if (query.includes("INSERT INTO mfa_factors")) {
          const id = String(values[0]);
          const userId = String(values[1]);
          const encryptedSecret = String(values[3]);
          db.mfaFactors.set(userId, {
            id,
            userId,
            kind: "totp",
            encryptedSecret,
            backupCodes: null,
          });
          return { success: true, meta: { changes: 1 } };
        }
        // UPDATE mfa_factors (verify/disable path — defensive).
        if (query.includes("UPDATE mfa_factors")) {
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>) {
    // Each statement was prepared with its own closure-bound run(); batch()
    // invokes each run() directly and collects results.
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const stmt of statements) {
      const result = await (stmt as unknown as {
        run(): Promise<{ success: boolean; meta: { changes: number } }>;
      }).run();
      results.push(result);
    }
    return results;
  }
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function setup(
  platformRole: PlatformRole = null,
  role: Role = "OWNER",
) {
  const db = new IntegrationD1();
  const tokenHash = await sha256Hex(SESSION_TOKEN);
  const sessionId = "session-a";
  db.identity = {
    id: "user-a",
    email: "owner@example.test",
    displayName: "Owner",
    organizationId: "org-a",
    organizationName: "Acme",
    organizationSlug: "acme",
    role,
    platformRole,
  };
  db.currentTokenHash = tokenHash;
  db.sessions.set(tokenHash, {
    id: sessionId,
    userId: "user-a",
    organizationId: "org-a",
    tokenHash,
    revokedAt: null,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    createdAt: "2026-01-01T00:00:00.000Z",
    userAgent: "test-agent",
    sourceIp: "127.0.0.1",
  });
  db.accounts.set("account-a", {
    id: "account-a",
    organizationId: "org-a",
    username: "acme",
    status: "ACTIVE",
    serverId: "server-a",
    planId: "plan-a",
  });
  db.plans.set("plan-a", {
    id: "plan-a",
    cpuMillis: 1000,
    memoryMiB: 512,
    diskMiB: 2048,
    processLimit: 128,
  });
  const env: Record<string, unknown> = {
    DB: db as unknown as D1Database,
    MFA_ENCRYPTION_KEY,
  };
  return { db, token: SESSION_TOKEN, env };
}

function authedRequest(
  token: string | null,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
) {
  const headers: Record<string, string> = {};
  if (token) {
    headers["authorization"] = `Bearer ${token}`;
  }
  if (body !== undefined) {
    headers["content-type"] = "application/json";
  }
  return new Request("https://api.test" + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

const validPhpBody = {
  phpVersion: "8.3",
  memoryLimitMib: 256,
  maxExecutionTimeSeconds: 30,
  uploadMaxFilesizeMib: 64,
  maxInputVars: 1000,
  displayErrors: false,
};

// ---------------------------------------------------------------------------
// PHP settings
// ---------------------------------------------------------------------------

test("GET /v1/hosting-accounts/:id/php returns defaults when no row exists", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "GET", "/v1/hosting-accounts/account-a/php"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    phpVersion: string; memoryLimitMib: number; maxExecutionTimeSeconds: number;
    uploadMaxFilesizeMib: number; maxInputVars: number; displayErrors: number;
    updatedAt: string | null;
  };
  assert.equal(body.phpVersion, "8.3");
  assert.equal(body.memoryLimitMib, 256);
  assert.equal(body.maxExecutionTimeSeconds, 30);
  assert.equal(body.uploadMaxFilesizeMib, 64);
  assert.equal(body.maxInputVars, 1000);
  assert.equal(body.displayErrors, 0);
  assert.equal(body.updatedAt, null);
  assert.equal(db.phpSettings.size, 0);
});

test("PUT /v1/hosting-accounts/:id/php rejects an unsupported PHP version", async () => {
  const { token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/php", {
      ...validPhpBody,
      phpVersion: "7.4",
    }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});

test("PUT /v1/hosting-accounts/:id/php accepts a supported version and queues an UPDATE_PHP_POOL job", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/php", validPhpBody),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  assert.ok(db.phpSettings.has("account-a"));
  const saved = db.phpSettings.get("account-a");
  assert.equal(saved?.phpVersion, "8.3");
  assert.equal(saved?.memoryLimitMib, 256);
  assert.equal(saved?.displayErrors, 0);
  const phpJob = db.jobs.find((j) => j.operation === "UPDATE_PHP_POOL");
  assert.ok(phpJob, "expected an UPDATE_PHP_POOL provisioning job to be queued");
  assert.equal(phpJob.hostingAccountId, "account-a");
});

test("PUT /v1/hosting-accounts/:id/php rejects an out-of-range memory limit", async () => {
  const { token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/php", {
      ...validPhpBody,
      memoryLimitMib: 32, // below the 64 MiB minimum
    }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});

test("PUT /v1/hosting-accounts/:id/php rejects a non-existent account", async () => {
  const { token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/does-not-exist/php", validPhpBody),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 404);
});

test("PUT /v1/hosting-accounts/:id/php requires platform admin", async () => {
  const { token, env } = await setup(); // no platformRole
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/php", validPhpBody),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 403);
});

// ---------------------------------------------------------------------------
// Backup schedule
// ---------------------------------------------------------------------------

test("GET /v1/hosting-accounts/:id/backup-schedule returns defaults when no row exists", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "GET", "/v1/hosting-accounts/account-a/backup-schedule"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    frequency: string; retentionCount: number;
    nextRunAt: string | null; lastRunAt: string | null; updatedAt: string | null;
  };
  assert.equal(body.frequency, "weekly");
  assert.equal(body.retentionCount, 4);
  assert.equal(body.nextRunAt, null);
  assert.equal(body.lastRunAt, null);
  assert.equal(body.updatedAt, null);
  assert.equal(db.backupSchedules.size, 0);
});

test("PUT /v1/hosting-accounts/:id/backup-schedule updates frequency and retention", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/backup-schedule", {
      frequency: "daily",
      retentionCount: 7,
    }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const saved = db.backupSchedules.get("account-a");
  assert.ok(saved);
  assert.equal(saved?.frequency, "daily");
  assert.equal(saved?.retentionCount, 7);
});

test("PUT /v1/hosting-accounts/:id/backup-schedule accepts an unknown frequency and defaults to weekly", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/backup-schedule", {
      frequency: "hourly", // not in the allowed set
      retentionCount: 3,
    }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const saved = db.backupSchedules.get("account-a");
  assert.ok(saved);
  assert.equal(saved?.frequency, "weekly");
  assert.equal(saved?.retentionCount, 3);
});

test("PUT /v1/hosting-accounts/:id/backup-schedule rejects an out-of-range retention count", async () => {
  const { token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/hosting-accounts/account-a/backup-schedule", {
      frequency: "weekly",
      retentionCount: 100, // above the 52 maximum
    }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});

// ---------------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------------

test("PUT /v1/organizations/:id updates the name for the workspace owner", async () => {
  const { token, env } = await setup(); // orgs bypass the /v1/* middleware
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/organizations/org-a", { name: "Renamed Org" }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { success: boolean };
  assert.equal(body.success, true);
});

test("PUT /v1/organizations/:id rejects a non-owner", async () => {
  const { token, env } = await setup(null, "MEMBER");
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/organizations/org-a", { name: "Renamed Org" }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 403);
});

test("PUT /v1/organizations/:id rejects an empty name", async () => {
  const { token, env } = await setup();
  const response = await worker.fetch(
    authedRequest(token, "PUT", "/v1/organizations/org-a", { name: "   " }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

test("GET /v1/audit-logs returns organization-scoped entries (cross-org isolation)", async () => {
  const { db, token, env } = await setup();
  db.auditRows.push({
    id: "audit-1",
    organizationId: "org-a",
    actorUserId: "user-a",
    action: "hosting_account.php_updated",
    resourceType: "hosting_account",
    resourceId: "account-a",
    sourceIp: null,
    metadata: null,
    createdAt: "2026-01-01T00:00:00.000Z",
  });
  db.auditRows.push({
    id: "audit-2",
    organizationId: "org-b",
    actorUserId: "user-b",
    action: "hosting_account.php_updated",
    resourceType: "hosting_account",
    resourceId: "account-b",
    sourceIp: null,
    metadata: null,
    createdAt: "2026-01-01T00:00:00.000Z",
  });

  const response = await worker.fetch(
    authedRequest(token, "GET", "/v1/audit-logs"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    entries: Array<{ id: string; organizationId: string }>;
    count: number;
  };
  assert.equal(body.count, 1);
  assert.equal(body.entries[0].id, "audit-1");
  assert.equal(body.entries[0].organizationId, "org-a");
});

test("GET /v1/audit-logs rejects unauthenticated requests", async () => {
  const { env } = await setup();
  const response = await worker.fetch(
    authedRequest(null, "GET", "/v1/audit-logs"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 401);
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

test("GET /v1/sessions returns the user's active sessions", async () => {
  const { db, token, env } = await setup();
  // Add a second session for the same user.
  db.sessions.set("second-token-hash", {
    id: "session-b",
    userId: "user-a",
    organizationId: "org-a",
    tokenHash: "second-token-hash",
    revokedAt: null,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    createdAt: "2026-01-02T00:00:00.000Z",
    userAgent: "test-agent-b",
    sourceIp: "127.0.0.2",
  });

  const response = await worker.fetch(
    authedRequest(token, "GET", "/v1/sessions"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    sessions: Array<{ id: string; current: boolean }>;
  };
  assert.equal(body.sessions.length, 2);
  const current = body.sessions.find((s) => s.current);
  assert.ok(current);
  assert.equal(current?.id, "session-a");
});

test("DELETE /v1/sessions/:id rejects self-revocation", async () => {
  const { token, env } = await setup();
  // The current session is "session-a" (from setup()).
  const response = await worker.fetch(
    authedRequest(token, "DELETE", "/v1/sessions/session-a"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
});

// ---------------------------------------------------------------------------
// Hosting account lifecycle
// ---------------------------------------------------------------------------

test("PATCH /v1/hosting-accounts/:id/suspend transitions the account to SUSPENDED", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  const response = await worker.fetch(
    authedRequest(token, "PATCH", "/v1/hosting-accounts/account-a/suspend"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { success: boolean; status: string; jobId: string };
  assert.equal(body.success, true);
  assert.equal(body.status, "SUSPENDED");
  assert.equal(db.accounts.get("account-a")?.status, "SUSPENDED");
  const suspendJob = db.jobs.find((j) => j.operation === "SUSPEND_HOSTING_ACCOUNT");
  assert.ok(suspendJob);
});

test("PATCH /v1/hosting-accounts/:id/reactivate transitions the account back to ACTIVE", async () => {
  const { db, token, env } = await setup("PLATFORM_ADMIN");
  // First suspend the account so reactivate has work to do.
  db.accounts.get("account-a")!.status = "SUSPENDED";

  const response = await worker.fetch(
    authedRequest(token, "PATCH", "/v1/hosting-accounts/account-a/reactivate"),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { success: boolean; status: string };
  assert.equal(body.success, true);
  assert.equal(body.status, "ACTIVE");
  assert.equal(db.accounts.get("account-a")?.status, "ACTIVE");
  const reactivateJob = db.jobs.find((j) => j.operation === "REACTIVATE_HOSTING_ACCOUNT");
  assert.ok(reactivateJob);
});

// ---------------------------------------------------------------------------
// MFA
// ---------------------------------------------------------------------------

test("POST /v1/auth/mfa/enroll generates a TOTP secret and otpauth URI", async () => {
  const { db, token, env } = await setup();
  const response = await worker.fetch(
    authedRequest(token, "POST", "/v1/auth/mfa/enroll", { accountName: "owner@example.test" }),
    env as unknown as typeof env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { otpauthUri: string; secret: string; message: string };
  assert.match(body.otpauthUri, /^otpauth:\/\/totp\/Nexora:/);
  assert.ok(body.secret.length > 0);
  assert.ok(db.mfaFactors.has("user-a"));
  const factor = db.mfaFactors.get("user-a");
  assert.equal(factor?.kind, "totp");
  assert.ok(factor?.encryptedSecret.length > 0);
});

test("POST /v1/auth/mfa/enroll fails without MFA_ENCRYPTION_KEY", async () => {
  const { token, env } = await setup();
  // Remove the encryption key to simulate a misconfigured deployment.
  const envWithoutKey = { ...env, MFA_ENCRYPTION_KEY: undefined } as unknown as Record<string, unknown>;
  const response = await worker.fetch(
    authedRequest(token, "POST", "/v1/auth/mfa/enroll", { accountName: "owner@example.test" }),
    envWithoutKey, {} as ExecutionContext,
  );
  assert.equal(response.status, 503);
});
