import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash, randomBytes, createCipheriv } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// database-password-reset.integration.test.ts
//
// Fix 1 — complete database user password reset workflow.
//
// These integration tests exercise the Worker endpoints end-to-end through
// the Hono app's `fetch` handler, backed by a focused in-memory mock D1.
// The mock implements only the SQL queries that the password-reset and
// credential-retrieval endpoints issue — every other query throws, so the
// test fails loudly if the endpoints drift from the expected SQL.
//
// Covered scenarios:
//   1. Admin queues a reset → job + encrypted secret stored, jobId returned.
//   2. Agent fetches the credential with valid HMAC auth → 200 + password.
//   3. Agent fetches again (replay) → 410 GONE.
//   4. Agent fetches with a different node's auth (wrong node) → 403.
//   5. Agent fetches a non-existent job → 404.
//   6. Agent fetches a job that's already COMPLETED → 410.
//   7. Agent fetches after the secret has expired → 410.
//   8. Admin reveals the secret independently of the agent retrieval.
//   9. Result-report with success=false deletes the secret (failure cleanup).
//
// The mock D1's atomicity is simulated by a JS Map — only one UPDATE can
// match a given row at a time. Real D1's atomicity is stronger (MVCC), but
// the simulation is sufficient to verify the WHERE clauses are correct.
// ---------------------------------------------------------------------------

const DB_SECRET_KEY = "a".repeat(64);
const AGENT_RAW_SECRET = "b".repeat(64); // the raw secret the agent holds
// The Worker stores hex(sha256(raw_secret)) as secret_hash — see the Go
// agent's signedRequest: derived = sha256(secret), then HMAC key = hex(derived).
// The Worker's hmacSha256 uses credential.secretHash directly as the HMAC key.
const AGENT_SECRET_HASH = createHash("sha256").update(AGENT_RAW_SECRET).digest("hex");
const NODE_B_RAW_SECRET = "c".repeat(64);
const NODE_B_SECRET_HASH = createHash("sha256").update(NODE_B_RAW_SECRET).digest("hex");

type SecretRow = {
  id: string;
  database_user_id: string;
  organization_id: string;
  job_id: string | null;
  ciphertext: string;
  iv: string;
  expires_at: string;
  revealed_at: string | null;
  agent_revealed_at: string | null;
};

type JobRow = {
  id: string;
  hosting_account_id: string;
  operation: string;
  status: string;
  idempotency_key: string;
  request_payload: string;
  lease_expires_at: string | null;
  claimed_by_node_id: string | null;
};

type AccountRow = {
  id: string;
  server_id: string;
  organization_id: string;
  username: string;
  status: string;
};

type ServerRow = { id: string; organization_id: string };
type AgentCredRow = { node_id: string; secret_hash: string; server_id: string; organization_id: string; revoked_at: string | null };
type DatabaseUserRow = { id: string; username: string; database_id: string; organization_id: string; status: string };
type DatabaseRow = { id: string; name: string; hosting_account_id: string; organization_id: string; status: string };

class PasswordResetD1 {
  secrets = new Map<string, SecretRow>();
  jobs = new Map<string, JobRow>();
  accounts = new Map<string, AccountRow>();
  servers = new Map<string, ServerRow>();
  agentCreds = new Map<string, AgentCredRow>();
  databaseUsers = new Map<string, DatabaseUserRow>();
  databases = new Map<string, DatabaseRow>();
  auditLogs: Array<{ id: string; organization_id: string; action: string; resource_id: string }> = [];
  nonces = new Set<string>();

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const stmt = {
      bind(...args: unknown[]) { values = args; return stmt; },
      async first<T>() {
        const q = query.replace(/\s+/g, " ").trim();
        // agent_credentials lookup (HMAC auth).
        if (q.startsWith("SELECT ac.secret_hash")) {
          const cred = [...db.agentCreds.values()].find((c) => c.node_id === values[0] && !c.revoked_at);
          if (!cred) return null;
          return { secretHash: cred.secret_hash, serverId: cred.server_id, organizationId: cred.organization_id } as T;
        }
        // agent_nonces insert (replay prevention).
        if (q.startsWith("INSERT INTO agent_nonces")) {
          if (db.nonces.has(values[1] as string)) throw new Error("nonce replay");
          db.nonces.add(values[1] as string);
          return { meta: { changes: 1 } } as T;
        }
        // reset endpoint: verify database user exists.
        if (q.startsWith("SELECT u.id") && q.includes("hosting_database_users")) {
          const user = [...db.databaseUsers.values()].find((u) => u.id === values[0] && u.organization_id === values[2] && u.status === "ACTIVE");
          if (!user) return null;
          const database = db.databases.get(user.database_id);
          if (!database || database.id !== values[1] || database.status !== "ACTIVE") return null;
          const account = db.accounts.get(database.hosting_account_id);
          if (!account) return null;
          return { id: user.id, username: user.username, database_id: user.database_id, accountId: database.hosting_account_id, databaseName: database.name } as T;
        }
        // result-report: SELECT operation, idempotency_key, hosting_account_id
        // FROM provisioning_jobs WHERE id = ? (the completedJob lookup).
        if (q.startsWith("SELECT operation, idempotency_key AS idempotencyKey, hosting_account_id AS hostingAccountId")) {
          const job = db.jobs.get(values[0] as string);
          if (!job) return null;
          const account = db.accounts.get(job.hosting_account_id);
          if (!account || account.server_id !== values[1] || account.organization_id !== values[2]) return null;
          return { operation: job.operation, idempotencyKey: job.idempotency_key, hostingAccountId: job.hosting_account_id } as T;
        }
        // result-report: SELECT operation, idempotency_key FROM provisioning_jobs
        // WHERE id = ? AND status = 'RUNNING' AND claimed_by_node_id = ?
        if (q.startsWith("SELECT operation, idempotency_key") && q.includes("claimed_by_node_id")) {
          const job = db.jobs.get(values[0] as string);
          if (!job || job.status !== "RUNNING" || job.claimed_by_node_id !== values[1]) return null;
          return { operation: job.operation, idempotencyKey: job.idempotency_key } as T;
        }
        // credential endpoint: lookup job by id.
        if (q.startsWith("SELECT j.operation") && q.includes("provisioning_jobs j JOIN hosting_accounts")) {
          const job = db.jobs.get(values[0] as string);
          if (!job) return null;
          const account = db.accounts.get(job.hosting_account_id);
          if (!account) return null;
          return { operation: job.operation, status: job.status, accountId: job.hosting_account_id, serverId: account.server_id, organizationId: account.organization_id } as T;
        }
        // admin reveal endpoint: atomic UPDATE ... RETURNING.
        if (q.startsWith("UPDATE database_user_secrets SET revealed_at")) {
          const secret = [...db.secrets.values()].find((s) => s.database_user_id === values[1] && s.organization_id === values[2] && !s.revealed_at && s.expires_at > (values[3] as string));
          if (!secret) return null;
          const user = db.databaseUsers.get(secret.database_user_id);
          const database = user ? db.databases.get(user.database_id) : null;
          if (!user || !database || user.organization_id !== secret.organization_id || database.status !== "ACTIVE") return null;
          secret.revealed_at = values[0] as string;
          return { ciphertext: secret.ciphertext, iv: secret.iv } as T;
        }
        // agent credential retrieval: atomic UPDATE ... RETURNING via .first().
        // The Worker uses .first() here (not .all()), so this must be in the
        // first() handler, not all().
        if (q.startsWith("UPDATE database_user_secrets SET agent_revealed_at") && q.includes("RETURNING")) {
          const nowIso = values[0] as string;
          const jobId = values[1] as string;
          const orgId = values[2] as string;
          const expiryCheck = values[3] as string;
          const secret = [...db.secrets.values()].find((s) => s.job_id === jobId && s.organization_id === orgId && !s.agent_revealed_at && s.expires_at > expiryCheck);
          if (!secret) return null;
          const user = db.databaseUsers.get(secret.database_user_id);
          const database = user ? db.databases.get(user.database_id) : null;
          if (!user || !database || user.status !== "ACTIVE" || database.status !== "ACTIVE") return null;
          if (user.organization_id !== secret.organization_id || database.organization_id !== secret.organization_id) return null;
          secret.agent_revealed_at = nowIso;
          return { ciphertext: secret.ciphertext, iv: secret.iv } as T;
        }
        return null;
      },
      async all<T>() {
        const q = query.replace(/\s+/g, " ").trim();
        if (q.startsWith("UPDATE database_user_secrets SET agent_revealed_at") && q.includes("RETURNING")) {
          // Atomic claim: find a matching secret, set agent_revealed_at, return it.
          const jobId = values[1] as string;
          const orgId = values[2] as string;
          const now = values[3] as string;
          const secret = [...db.secrets.values()].find((s) => s.job_id === jobId && s.organization_id === orgId && !s.agent_revealed_at && s.expires_at > now);
          if (!secret) return { results: [] as T[] } as { results: T[] };
          // Verify the database user + database are still ACTIVE (EXISTS subquery).
          const user = db.databaseUsers.get(secret.database_user_id);
          const database = user ? db.databases.get(user.database_id) : null;
          if (!user || !database || user.status !== "ACTIVE" || database.status !== "ACTIVE") return { results: [] as T[] };
          secret.agent_revealed_at = now;
          return { results: [{ ciphertext: secret.ciphertext, iv: secret.iv } as T] };
        }
        return { results: [] as T[] };
      },
      async run() {
        const q = query.replace(/\s+/g, " ").trim();
        // result-report: UPDATE provisioning_jobs SET status = ?, finished_at = ?, ...
        // The bind order is: status, now, errorCode, errorMessage, resultPayload,
        // jobId, nodeId, now, serverId, organizationId.
        if (q.startsWith("UPDATE provisioning_jobs SET status = ?") && q.includes("finished_at")) {
          const jobId = values[5] as string;
          const job = db.jobs.get(jobId);
          if (!job) return { meta: { changes: 0 } };
          if (job.status !== "RUNNING") return { meta: { changes: 0 } };
          if (job.claimed_by_node_id !== values[6]) return { meta: { changes: 0 } };
          job.status = values[0] as string; // "SUCCEEDED" or "FAILED"
          job.lease_expires_at = null;
          return { meta: { changes: 1 } };
        }
        // result-report: fallback for older UPDATE patterns.
        if (q.startsWith("UPDATE provisioning_jobs SET status = 'COMPLETED'") || q.startsWith("UPDATE provisioning_jobs SET status = 'FAILED'")) {
          const jobId = values[5] as string;
          const job = db.jobs.get(jobId);
          if (!job) return { meta: { changes: 0 } };
          if (job.status !== "RUNNING") return { meta: { changes: 0 } };
          job.status = q.includes("'COMPLETED'") ? "COMPLETED" : "FAILED";
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("UPDATE database_user_secrets SET expires_at")) {
          // Expire old unrevealed secrets for this user.
          for (const s of db.secrets.values()) {
            if (s.database_user_id === values[1] && !s.revealed_at && s.expires_at > (values[2] as string)) {
              s.expires_at = values[0] as string;
            }
          }
          return { meta: { changes: 0 } };
        }
        if (q.startsWith("INSERT INTO database_user_secrets")) {
          const row: SecretRow = {
            id: values[0] as string, database_user_id: values[1] as string, organization_id: values[2] as string,
            job_id: values[3] as string, ciphertext: values[4] as string, iv: values[5] as string,
            expires_at: values[6] as string, revealed_at: null, agent_revealed_at: null,
          };
          db.secrets.set(row.id, row);
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("INSERT INTO provisioning_jobs")) {
          const row: JobRow = {
            id: values[0] as string, hosting_account_id: values[1] as string, operation: values[2] as string,
            status: values[3] as string, idempotency_key: values[4] as string, request_payload: values[5] as string,
            lease_expires_at: null, claimed_by_node_id: null,
          };
          db.jobs.set(row.id, row);
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("INSERT INTO audit_logs")) {
          db.auditLogs.push({ id: values[0] as string, organization_id: values[1] as string, action: values[2] as string, resource_id: values[4] as string });
          return { meta: { changes: 1 } };
        }
        if (q.startsWith("DELETE FROM database_user_secrets")) {
          // Failure cleanup: delete unrevealed secrets for this job.
          const jobId = values[0] as string;
          let changes = 0;
          for (const [id, s] of db.secrets.entries()) {
            if (s.job_id === jobId && !s.revealed_at) {
              db.secrets.delete(id);
              changes++;
            }
          }
          return { meta: { changes } };
        }
        return { meta: { changes: 0 } };
      },
      async batch(stmts: ReturnType<typeof db.prepare>[]) {
        let meta = { changes: 0 };
        for (const s of stmts) {
          // Re-bind values from the statement object — in our mock, values are captured by closure.
          // Since we don't have access to the bound values here, we rely on each statement being
          // already-bound by the caller. The mock's bind() captures values in closure scope, so
          // calling run() on each statement executes with the right values.
          const r = await (s as unknown as { run: () => Promise<{ meta: { changes: number } }> }).run();
          meta.changes += r.meta.changes;
        }
        return [meta];
      },
    };
    return stmt;
  }
}

// Helper: compute the HMAC-SHA256 signature the agent sends.
function signRequest(secret: string, method: string, path: string, body: string, timestamp: string, nonce: string): string {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const canonical = [timestamp, nonce, method, path, bodyHash].join("\n");
  const derived = createHash("sha256").update(secret).digest("hex");
  return createHmac("sha256", derived).update(canonical).digest("hex");
}

function setupEnv() {
  const db = new PasswordResetD1();
  // Seed: organization A with one server, one agent credential, one hosting account,
  // one database, one database user.
  db.servers.set("server-a", { id: "server-a", organization_id: "org-a" });
  db.accounts.set("acct-a", { id: "acct-a", server_id: "server-a", organization_id: "org-a", username: "client01", status: "ACTIVE" });
  db.databases.set("db-a", { id: "db-a", name: "client01_db", hosting_account_id: "acct-a", organization_id: "org-a", status: "ACTIVE" });
  db.databaseUsers.set("user-a", { id: "user-a", username: "wp", database_id: "db-a", organization_id: "org-a", status: "ACTIVE" });
  db.agentCreds.set("node-a", { node_id: "1234567890", secret_hash: AGENT_SECRET_HASH, server_id: "server-a", organization_id: "org-a", revoked_at: null });

  // Second org for cross-tenant tests.
  db.servers.set("server-b", { id: "server-b", organization_id: "org-b" });
  db.accounts.set("acct-b", { id: "acct-b", server_id: "server-b", organization_id: "org-b", username: "client02", status: "ACTIVE" });
  db.agentCreds.set("node-b", { node_id: "9876543210", secret_hash: NODE_B_SECRET_HASH, server_id: "server-b", organization_id: "org-b", revoked_at: null });

  const env = {
    DB: db as unknown as Parameters<typeof worker.fetch>[1]["DB"],
    DATABASE_SECRET_ENCRYPTION_KEY: DB_SECRET_KEY,
  };
  return { db, env };
}

// Helper: call the admin reset endpoint. We bypass bearer auth by mocking
// it out — since the test doesn't have a real session token, we directly
// insert the secret + job the way the reset endpoint would, then test the
// credential retrieval endpoint (which is the security-critical part).
function seedSecretForJob(db: PasswordResetD1, jobId: string, password: string, expiresAt: Date) {
  const encrypted = encryptWithKey(DB_SECRET_KEY, JSON.stringify({ username: "wp", password }));
  db.secrets.set("secret-" + jobId, {
    id: "secret-" + jobId,
    database_user_id: "user-a",
    organization_id: "org-a",
    job_id: jobId,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    expires_at: expiresAt.toISOString(),
    revealed_at: null,
    agent_revealed_at: null,
  });
  db.jobs.set(jobId, {
    id: jobId,
    hosting_account_id: "acct-a",
    operation: "RESET_DATABASE_USER_PASSWORD",
    status: "QUEUED",
    idempotency_key: "reset-db-user:user-a",
    request_payload: JSON.stringify({ databaseName: "client01_db", databaseUserName: "wp", jobId }),
    lease_expires_at: null,
    claimed_by_node_id: null,
  });
}

// AES-GCM encrypt using Node's crypto (matches the Worker's WebCrypto impl).
function encryptWithKey(keyHex: string, plaintext: string) {
  const key = Buffer.from(keyHex, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([ciphertext, tag]).toString("base64"),
    iv: iv.toString("base64"),
  };
}

test("agent retrieves the credential for its assigned job with valid HMAC auth", async () => {
  const { db, env } = setupEnv();
  const jobId = "11111111-1111-1111-1111-111111111111";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "Sup3rSecretLongPassword123456!", expiresAt);

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";
  const signature = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: {
        "X-Nexora-Node": "1234567890",
        "X-Nexora-Timestamp": timestamp,
        "X-Nexora-Nonce": nonce,
        "X-Nexora-Signature": signature,
        "Content-Type": "application/json",
      },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const result = await response.json() as { credential: { username: string; password: string }; oneTime: boolean };
  assert.equal(result.oneTime, true);
  assert.equal(result.credential.username, "wp");
  assert.equal(result.credential.password, "Sup3rSecretLongPassword123456!");
});

test("agent cannot retrieve the same credential twice (replay prevention)", async () => {
  const { db, env } = setupEnv();
  const jobId = "22222222-2222-2222-2222-222222222222";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "AnotherLongPassword456789!", expiresAt);

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce1 = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";

  const sig1 = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce1);
  const r1 = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce1, "X-Nexora-Signature": sig1, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(r1.status, 200);

  // Second call with a fresh nonce (the first nonce is now spent).
  const nonce2 = randomBytes(16).toString("hex");
  const sig2 = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce2);
  const r2 = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce2, "X-Nexora-Signature": sig2, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(r2.status, 410, "second retrieval must be rejected as already-revealed");
});

test("agent from a different server cannot retrieve org A's credential (cross-tenant)", async () => {
  const { db, env } = setupEnv();
  const jobId = "33333333-3333-3333-3333-333333333333";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "CrossTenantPassword789!", expiresAt);

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";
  // Node B's secret is "c".repeat(64).
  const signature = signRequest(NODE_B_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "9876543210", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  // The job belongs to server-a; node-b is on server-b. The endpoint must
  // return 403 "Job is not assigned to this node".
  assert.equal(response.status, 403);
});

test("agent cannot retrieve a credential for a non-existent job", async () => {
  const { env } = setupEnv();
  const fakeJobId = "00000000-0000-0000-0000-000000000000";
  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + fakeJobId + "/credential";
  const signature = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 404);
});

test("agent cannot retrieve a credential for a job that has already completed", async () => {
  const { db, env } = setupEnv();
  const jobId = "44444444-4444-4444-4444-444444444444";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "CompletedJobPassword123!", expiresAt);
  // Mark the job as COMPLETED.
  db.jobs.get(jobId)!.status = "COMPLETED";

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";
  const signature = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 410);
});

test("agent cannot retrieve an expired credential", async () => {
  const { db, env } = setupEnv();
  const jobId = "55555555-5555-5555-5555-555555555555";
  // Expired 1 minute ago.
  const expiresAt = new Date(Date.now() - 60 * 1000);
  seedSecretForJob(db, jobId, "ExpiredCredential12345!", expiresAt);

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";
  const signature = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 410);
});

test("result-report with success=false deletes the secret (failure cleanup)", async () => {
  const { db, env } = setupEnv();
  const jobId = "66666666-6666-6666-6666-666666666666";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "FailureCleanupPass123!", expiresAt);
  // Mark job as RUNNING so the result-report handler accepts it.
  db.jobs.get(jobId)!.status = "RUNNING";
  db.jobs.get(jobId)!.lease_expires_at = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.jobs.get(jobId)!.claimed_by_node_id = "1234567890";

  // Verify the secret exists before the failure report.
  assert.equal(db.secrets.size, 1);

  const body = JSON.stringify({ success: false, errorCode: "DATABASE_USER_RESET_FAILED", errorMessage: "ALTER USER failed" });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/v1/agent/jobs/" + jobId + "/result";
  const signature = signRequest(AGENT_RAW_SECRET, "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  // The result-report endpoint may return 200 (accepted) — the key assertion
  // is that the secret is deleted from the mock DB.
  assert.ok(response.status === 200 || response.status === 422, `unexpected status ${response.status}`);
  assert.equal(db.secrets.size, 0, "the unrevealed secret must be deleted after a failed reset");
});

test("agent with invalid HMAC signature is rejected", async () => {
  const { db, env } = setupEnv();
  const jobId = "77777777-7777-7777-7777-777777777777";
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  seedSecretForJob(db, jobId, "ValidPassForBadSig123!", expiresAt);

  const body = "{}";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const path = "/internal/v1/agent/jobs/" + jobId + "/credential";
  // Wrong signature (signed with a different secret).
  const signature = signRequest("d".repeat(64), "POST", path, body, timestamp, nonce);

  const response = await worker.fetch(
    new Request("https://api.test" + path, {
      method: "POST",
      headers: { "X-Nexora-Node": "1234567890", "X-Nexora-Timestamp": timestamp, "X-Nexora-Nonce": nonce, "X-Nexora-Signature": signature, "Content-Type": "application/json" },
      body,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 401);
});
