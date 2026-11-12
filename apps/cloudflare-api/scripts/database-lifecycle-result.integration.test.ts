import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import worker from "../src/index.ts";

const ORG = "11111111-1111-4111-8111-111111111111";
const SERVER = "22222222-2222-4222-8222-222222222222";
const ACCOUNT = "33333333-3333-4333-8333-333333333333";
const JOB = "44444444-4444-4444-8444-444444444444";
const DB_ID = "55555555-5555-4555-8555-555555555555";
const USER_ID = "66666666-6666-4666-8666-666666666666";
const NODE = "nexora-test-node";
const SECRET_HASH = "test-agent-secret-hash";
const EXPECTED_USERNAME = "acme01_wpuser";

type Job = { operation: string; idempotencyKey: string; status: string; hostingAccountId: string };
type User = { username: string; status: string };

class AgentResultD1 {
  job: Job;
  databaseStatus: string;
  user: User;
  nonceCount = 0;
  credentialSecretWrites = 0;
  auditWrites = 0;

  constructor(operation: string, idempotencyKey: string) {
    this.job = { operation, idempotencyKey, status: "RUNNING", hostingAccountId: ACCOUNT };
    this.databaseStatus = "DELETING";
    this.user = { username: EXPECTED_USERNAME, status: "PENDING" };
  }

  prepare(query: string) {
    let values: unknown[] = [];
    const db = this;
    return {
      bind(...args: unknown[]) { values = args; return this; },
      async first<T>() {
        if (query.includes("FROM agent_credentials ac JOIN servers")) {
          return { secretHash: SECRET_HASH, serverId: SERVER, organizationId: ORG } as T;
        }
        if (query.includes("SELECT operation, idempotency_key AS idempotencyKey FROM provisioning_jobs")) {
          if (String(values[0]) !== JOB || thisJobStatus(db) !== "RUNNING") return null;
          return { operation: db.job.operation, idempotencyKey: db.job.idempotencyKey } as T;
        }
        if (query.includes("SELECT operation, idempotency_key AS idempotencyKey, hosting_account_id AS hostingAccountId")) {
          return { operation: db.job.operation, idempotencyKey: db.job.idempotencyKey, hostingAccountId: ACCOUNT } as T;
        }
        if (query.includes("SELECT u.username") && query.includes("FROM hosting_database_users u")) {
          if (db.user.status !== "PENDING" || String(values[0]) !== USER_ID ||
              String(values[1]) !== ORG || String(values[2]) !== ACCOUNT || db.databaseStatus !== "ACTIVE") return null;
          return { username: db.user.username } as T;
        }
        throw new Error("Unmocked first() SQL: " + query);
      },
      async run() {
        if (query.startsWith("INSERT INTO agent_nonces")) {
          db.nonceCount++;
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("UPDATE provisioning_jobs SET status = ?")) {
          db.job.status = String(values[0]);
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE hosting_database_users SET status = 'FAILED'")) {
          if (db.user.status === "PENDING") db.user.status = "FAILED";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE hosting_databases SET status = 'FAILED'")) {
          if (db.databaseStatus === "DELETING") db.databaseStatus = "FAILED";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("INSERT INTO audit_logs")) {
          db.auditWrites++;
          return { success: true, meta: { changes: 1 } };
        }
        throw new Error("Unmocked run() SQL: " + query);
      },
    };
  }

  async batch() {
    throw new Error("Unexpected batch() in agent-result regression test");
  }
}

function thisJobStatus(db: AgentResultD1): string {
  return db.job.status;
}

async function signedResult(db: AgentResultD1, payload: Record<string, unknown>) {
  const rawBody = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = "a".repeat(32);
  const path = `/v1/agent/jobs/${JOB}/result`;
  const bodyHash = createHash("sha256").update(rawBody).digest("hex");
  const canonical = [timestamp, nonce, "POST", path, bodyHash].join("\n");
  const signature = createHmac("sha256", SECRET_HASH).update(canonical).digest("hex");
  const request = new Request("https://worker.test" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Nexora-Node": NODE,
      "X-Nexora-Timestamp": timestamp,
      "X-Nexora-Nonce": nonce,
      "X-Nexora-Signature": signature,
    },
    body: rawBody,
  });
  const response = await worker.fetch(request, {
    DB: db as unknown as D1Database,
    DATABASE_SECRET_ENCRYPTION_KEY: "c".repeat(64),
  } as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* no body */ }
  return { status: response.status, json };
}

test("agent CREATE_DATABASE_USER rejects a credential username that differs from the pending user", async () => {
  const db = new AgentResultD1("CREATE_DATABASE_USER", `create-database-user:${USER_ID}`);
  const response = await signedResult(db, {
    success: true,
    result: { username: "acme01_attacker", password: "x".repeat(48) },
  });

  assert.equal(response.status, 422);
  assert.match(String(response.json.message), /does not match the pending user/);
  assert.equal(db.job.status, "SUCCEEDED", "agent job result is recorded before credential validation");
  assert.equal(db.user.status, "FAILED");
  assert.equal(db.credentialSecretWrites, 0);
  assert.equal(db.nonceCount, 1);
});

test("agent DELETE_DATABASE failure moves DELETING database to FAILED for retry", async () => {
  const db = new AgentResultD1("DELETE_DATABASE", `delete-database:${DB_ID}`);
  const response = await signedResult(db, {
    success: false,
    errorCode: "DROP_DATABASE_FAILED",
    errorMessage: "MariaDB returned an error while dropping the database",
  });

  assert.equal(response.status, 200);
  assert.equal(response.json.accepted, true);
  assert.equal(response.json.status, "FAILED");
  assert.equal(db.job.status, "FAILED");
  assert.equal(db.databaseStatus, "FAILED");
  assert.equal(db.auditWrites, 1);
});
