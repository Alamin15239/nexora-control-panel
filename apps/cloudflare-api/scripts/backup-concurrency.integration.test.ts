import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// backup-concurrency.integration.test.ts
//
// Regression tests for the atomic backup exclusion mechanism.
//
// Defect: The scheduler used a non-atomic SELECT-COUNT-then-INSERT. The
// manual backup endpoint did no check at all. A manual backup could be
// inserted between the scheduler's count check and its insert.
//
// Fix: Both manual and scheduled creation use a conditional INSERT (NOT
// EXISTS) backed by a partial unique index
// (idx_hosting_backups_active_exclusion). At most one QUEUED or RUNNING
// backup per hosting account at the database level.
//
// Tests:
//   1. Two sequential manual backups → first 202, second 409.
//   2. Completed backup allows another.
//   3. Failed backup allows another.
//   4. Different accounts independent.
//   5. No orphan job/audit after 409.
//   6. RUNNING backup blocks manual.
// ---------------------------------------------------------------------------

class BackupConcurrencyD1 {
  backups = new Map<string, { id: string; hosting_account_id: string; organization_id: string; status: string; created_at: string }>();
  jobs: Array<{ id: string; hosting_account_id: string; operation: string; status: string }> = [];
  auditLogs: Array<{ action: string; resource_id: string }> = [];
  accounts = new Map<string, { id: string; organization_id: string; server_id: string; username: string; status: string }>();
  servers = new Map<string, { id: string; organization_id: string }>();
  databases = new Map<string, { id: string; name: string; hosting_account_id: string; organization_id: string; status: string }>();
  sessions = new Map<string, { token_hash: string; user_id: string; organization_id: string; expires_at: string; revoked_at: string | null }>();
  users = new Map<string, { id: string; email: string; display_name: string | null; status: string }>();
  orgs = new Map<string, { id: string; name: string; slug: string; status: string }>();
  memberships = new Map<string, { user_id: string; organization_id: string; role: string }>();
  platformMemberships = new Map<string, { user_id: string; role: number; status: string }>();

  hasActiveBackup(accountId: string): boolean {
    for (const b of this.backups.values()) {
      if (b.hosting_account_id === accountId && (b.status === "QUEUED" || b.status === "RUNNING")) return true;
    }
    return false;
  }

  async batch(stmts: Array<{ run: () => Promise<{ meta: { changes: number } }> }>) {
    const results: Array<{ meta: { changes: number } }> = [];
    for (const s of stmts) {
      const r = await s.run();
      results.push(r);
    }
    return results;
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const stmt = {
      bind(...args: unknown[]) { values = args; return stmt; },
      async first<T>() {
        const q = query.replace(/\s+/g, " ").trim();
        if (q.startsWith("SELECT u.id") && q.includes("auth_sessions")) {
          const session = [...db.sessions.values()].find((s) => s.token_hash === values[0] && !s.revoked_at && s.expires_at > (values[1] as string));
          if (!session) return null;
          const user = db.users.get(session.user_id);
          if (!user || user.status !== "ACTIVE") return null;
          const org = db.orgs.get(session.organization_id);
          if (!org || org.status !== "ACTIVE") return null;
          const membership = [...db.memberships.values()].find((m) => m.user_id === user.id && m.organization_id === org.id);
          const pm = [...db.platformMemberships.values()].find((p) => p.user_id === user.id && p.status === "ACTIVE");
          return { id: user.id, email: user.email, displayName: user.display_name, organizationId: org.id, organizationName: org.name, organizationSlug: org.slug, role: membership?.role ?? "MEMBER", platformRole: pm?.role ?? null } as T;
        }
        if (q.startsWith("SELECT id") && q.includes("FROM hosting_accounts") && q.includes("status = 'ACTIVE'")) {
          const account = [...db.accounts.values()].find((a) => a.id === values[0] && a.organization_id === values[1] && a.status === "ACTIVE");
          if (!account) return null;
          return { id: account.id, username: account.username, server_id: account.server_id } as T;
        }
        if (q.startsWith("SELECT id") && q.includes("FROM hosting_accounts")) {
          const account = [...db.accounts.values()].find((a) => a.id === values[0] && a.organization_id === values[1]);
          if (!account) return null;
          return { id: account.id } as T;
        }
        return null;
      },
      async all<T>() {
        const q = query.replace(/\s+/g, " ").trim();
        if (q.startsWith("SELECT") && q.includes("hosting_databases")) {
          const dbs = [...db.databases.values()].filter((d) => d.hosting_account_id === values[0] && d.organization_id === values[1] && d.status === "ACTIVE");
          return { results: dbs.map((d) => ({ name: d.name })) as T[] } as { results: T[] };
        }
        if (q.startsWith("SELECT") && q.includes("FROM hosting_backups")) {
          const backups = [...db.backups.values()].filter((b) => b.hosting_account_id === values[0] && b.organization_id === values[1]);
          return { results: backups.map((b) => ({ id: b.id, status: b.status, databaseNamesJson: "[]" })) as T[] } as { results: T[] };
        }
        return { results: [] as T[] } as { results: T[] };
      },
      async run() {
        const q = query.replace(/\s+/g, " ").trim();
        if (q.startsWith("INSERT INTO hosting_backups") && q.includes("WHERE NOT EXISTS")) {
          const accountId = values[2] as string;
          if (db.hasActiveBackup(accountId)) return { meta: { changes: 0 } };
          const backupId = values[0] as string;
          db.backups.set(backupId, { id: backupId, hosting_account_id: accountId, organization_id: values[1] as string, status: "QUEUED", created_at: values[6] as string });
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("INSERT INTO hosting_backups") && !q.includes("WHERE NOT EXISTS")) {
          const backupId = values[0] as string;
          db.backups.set(backupId, { id: backupId, hosting_account_id: values[2] as string, organization_id: values[1] as string, status: "QUEUED", created_at: values[4] as string });
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("INSERT INTO provisioning_jobs")) {
          const operationMatch = q.match(/'([A-Z_]+)'/);
          db.jobs.push({ id: values[0] as string, hosting_account_id: values[1] as string, operation: operationMatch ? operationMatch[1] : "UNKNOWN", status: "QUEUED" });
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("INSERT INTO audit_logs")) {
          db.auditLogs.push({ action: values[2] as string, resource_id: values[4] as string });
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("DELETE FROM hosting_backups")) {
          const backupId = values[0] as string;
          if (db.backups.has(backupId)) { db.backups.delete(backupId); return { meta: { changes: 1 } }; }
          return { meta: { changes: 0 } };
        }
        if (q.startsWith("UPDATE hosting_backups SET status")) {
          const backupId = values[1] as string;
          const backup = db.backups.get(backupId);
          if (backup) { backup.status = values[0] as string; return { meta: { changes: 1 } }; }
          return { meta: { changes: 0 } };
        }
        return { meta: { changes: 0 } };
      },
    };
    return stmt;
  }
}

function setupEnv() {
  const db = new BackupConcurrencyD1();
  db.servers.set("server-a", { id: "server-a", organization_id: "org-a" });
  db.accounts.set("acct-a", { id: "acct-a", organization_id: "org-a", server_id: "server-a", username: "client01", status: "ACTIVE" });
  db.accounts.set("acct-b", { id: "acct-b", organization_id: "org-a", server_id: "server-a", username: "client02", status: "ACTIVE" });
  db.databases.set("db-a", { id: "db-a", name: "client01_db", hosting_account_id: "acct-a", organization_id: "org-a", status: "ACTIVE" });
  db.orgs.set("org-a", { id: "org-a", name: "Org A", slug: "org-a", status: "ACTIVE" });
  db.users.set("user-admin", { id: "user-admin", email: "admin@example.test", display_name: "Admin", status: "ACTIVE" });
  db.memberships.set("m1", { user_id: "user-admin", organization_id: "org-a", role: "OWNER" });
  db.platformMemberships.set("pm1", { user_id: "user-admin", role: 1, status: "ACTIVE" });
  const rawToken = "a".repeat(64);
  const tokenHash = createHash("sha256").update(rawToken).digest("hex");
  db.sessions.set("sess-admin", { token_hash: tokenHash, user_id: "user-admin", organization_id: "org-a", expires_at: new Date(Date.now() + 3600 * 1000).toISOString(), revoked_at: null });
  const env = { DB: db as unknown as Parameters<typeof worker.fetch>[1]["DB"], DATABASE_SECRET_ENCRYPTION_KEY: "a".repeat(64) };
  return { db, env, token: rawToken };
}

function manualBackup(env: { DB: unknown }, accountId: string, token: string) {
  return worker.fetch(
    new Request(`https://api.test/v1/hosting-accounts/${accountId}/backups`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
    env as unknown as Parameters<typeof worker.fetch>[1], {} as ExecutionContext,
  );
}

test("two sequential manual backup requests: first 202, second 409", async () => {
  const { db, env, token } = setupEnv();
  const r1 = await manualBackup(env, "acct-a", token);
  assert.equal(r1.status, 202, "first should succeed");
  const r2 = await manualBackup(env, "acct-a", token);
  assert.equal(r2.status, 409, "second should conflict");
  assert.equal([...db.backups.values()].filter((b) => b.hosting_account_id === "acct-a").length, 1, "exactly one backup");
  assert.equal(db.jobs.filter((j) => j.hosting_account_id === "acct-a" && j.operation === "CREATE_BACKUP").length, 1, "exactly one job");
});

test("completed backup allows another (exclusion released)", async () => {
  const { db, env, token } = setupEnv();
  const r1 = await manualBackup(env, "acct-a", token);
  assert.equal(r1.status, 202);
  const first = [...db.backups.values()].find((b) => b.hosting_account_id === "acct-a");
  assert.ok(first);
  first.status = "AVAILABLE";
  const r2 = await manualBackup(env, "acct-a", token);
  assert.equal(r2.status, 202, "second should succeed after first completes");
  assert.equal([...db.backups.values()].filter((b) => b.hosting_account_id === "acct-a").length, 2);
});

test("failed backup releases exclusion (next succeeds)", async () => {
  const { db, env, token } = setupEnv();
  const r1 = await manualBackup(env, "acct-a", token);
  assert.equal(r1.status, 202);
  const first = [...db.backups.values()].find((b) => b.hosting_account_id === "acct-a");
  first.status = "FAILED";
  const r2 = await manualBackup(env, "acct-a", token);
  assert.equal(r2.status, 202, "second should succeed after first fails");
});

test("different hosting accounts remain independent", async () => {
  const { db, env, token } = setupEnv();
  const r1 = await manualBackup(env, "acct-a", token);
  const r2 = await manualBackup(env, "acct-b", token);
  assert.equal(r1.status, 202);
  assert.equal(r2.status, 202, "different account, no conflict");
  assert.equal([...db.backups.values()].filter((b) => b.hosting_account_id === "acct-a").length, 1);
  assert.equal([...db.backups.values()].filter((b) => b.hosting_account_id === "acct-b").length, 1);
});

test("no orphan job or audit record after 409 rejection", async () => {
  const { db, env, token } = setupEnv();
  await manualBackup(env, "acct-a", token);
  const jobsBefore = db.jobs.length;
  const auditsBefore = db.auditLogs.length;
  const r2 = await manualBackup(env, "acct-a", token);
  assert.equal(r2.status, 409);
  assert.equal(db.jobs.length, jobsBefore, "no orphan job");
  assert.equal(db.auditLogs.length, auditsBefore, "no orphan audit");
});

test("manual backup returns 409 when a RUNNING backup exists", async () => {
  const { db, env, token } = setupEnv();
  db.backups.set("existing-running", { id: "existing-running", hosting_account_id: "acct-a", organization_id: "org-a", status: "RUNNING", created_at: new Date().toISOString() });
  const r = await manualBackup(env, "acct-a", token);
  assert.equal(r.status, 409);
  assert.ok(db.backups.has("existing-running"), "existing backup untouched");
});
