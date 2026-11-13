import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformCompletionD1, call, makeEnv,
  SESSION_TOKEN, PRIMARY_TOKEN_HASH, ORG_A, ORG_B, OWNER_A, MEMBER_A, PLATFORM_ADMIN,
  PLAN_BASIC, ACCOUNT_1, SERVER_1,
} from "./platform-completion-harness.ts";

// ---------------------------------------------------------------------------
// hosting-account-lifecycle.integration.test.ts
//
// Regression tests for the failed-provisioning lifecycle:
//   1. The hosting-account inventory surfaces the latest CREATE_HOSTING_ACCOUNT
//      job's failure reason (error_code + error_message + attempts) so the
//      dashboard can show WHY an account is FAILED.
//   2. FAILED accounts can be deleted (bugfix: the delete route previously
//      treated a FAILED job as "finished" and blocked deletion forever).
//   3. Deleting a failed account tombstones the username, freeing the
//      UNIQUE(server_id, username) slot for immediate reuse.
//   4. Deletion is still blocked while a job is RUNNING and for ACTIVE
//      accounts (agent-backed deprovisioning required).
//   5. Retrying a FAILED CREATE_HOSTING_ACCOUNT queues a new job with a
//      unique retry idempotency key and moves the account back to PENDING.
// ---------------------------------------------------------------------------

function freshDb(): PlatformCompletionD1 {
  const db = new PlatformCompletionD1();
  db.seed();
  return db;
}

function loginAs(db: PlatformCompletionD1, userId: string): void {
  db.addSession(userId, ORG_A, PRIMARY_TOKEN_HASH);
  db.identity = db.asIdentity(userId);
}

// WHM hosting-account routes sit behind the platform-staff middleware AND
// internally require organization OWNER/ADMIN — the same combination the
// production platform administrator holds. Give the platform admin an OWNER
// membership so the full route stack is exercised.
function loginAsPlatformOwner(db: PlatformCompletionD1): void {
  db.memberships.set(`${PLATFORM_ADMIN}:${ORG_A}`, { userId: PLATFORM_ADMIN, organizationId: ORG_A, role: "OWNER" });
  // asIdentity's membership lookup targets ORG_B for non-"aaaa" user ids;
  // mirror the OWNER role there so identity.role resolves to OWNER.
  db.memberships.set(`${PLATFORM_ADMIN}:${ORG_B}`, { userId: PLATFORM_ADMIN, organizationId: ORG_A, role: "OWNER" });
  loginAs(db, PLATFORM_ADMIN);
}

function seedJob(
  db: PlatformCompletionD1,
  jobId: string,
  accountId: string,
  status: string,
  attempts = 0,
): void {
  db.jobs.set(jobId, {
    id: jobId, hostingAccountId: accountId, operation: "CREATE_HOSTING_ACCOUNT",
    status, idempotencyKey: `create-account:${accountId}`, attempts,
    requestPayload: null, requestedAt: new Date().toISOString(),
    errorCode: status === "FAILED" ? "PROVISIONER_FAILED" : null,
    errorMessage: status === "FAILED" ? "useradd: existing group acme01 conflicts" : null,
  });
}

// ---------------------------------------------------------------------------
// 1. Inventory exposes the failure reason
// ---------------------------------------------------------------------------

test("the hosting-account inventory surfaces the failed provisioning reason", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  seedJob(db, "job-fail-1", ACCOUNT_1, "FAILED", 1);
  loginAsPlatformOwner(db);
  const { status, json } = await call(db, "GET", "/v1/hosting-accounts", makeEnv());
  assert.equal(status, 200);
  const account = (json.accounts as Array<Record<string, unknown>>).find((a) => a.id === ACCOUNT_1)!;
  assert.ok(account, "the failed account must be listed");
  assert.equal(account.job_status, "FAILED");
  assert.equal(account.job_id, "job-fail-1");
  assert.equal(account.error_code, "PROVISIONER_FAILED");
  assert.equal(account.error_message, "useradd: existing group acme01 conflicts");
  assert.equal(account.job_attempts, 1);
});

test("succeeded accounts report no failure reason", async () => {
  const db = freshDb();
  seedJob(db, "job-ok-1", ACCOUNT_1, "SUCCEEDED");
  loginAsPlatformOwner(db);
  const { status, json } = await call(db, "GET", "/v1/hosting-accounts", makeEnv());
  assert.equal(status, 200);
  const account = (json.accounts as Array<Record<string, unknown>>).find((a) => a.id === ACCOUNT_1)!;
  assert.equal(account.job_status, "SUCCEEDED");
  assert.equal(account.error_code, null);
  assert.equal(account.error_message, null);
});

// ---------------------------------------------------------------------------
// 2. FAILED accounts are deletable
// ---------------------------------------------------------------------------

test("a FAILED account can be deleted and the job is preserved for audit", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  seedJob(db, "job-fail-1", ACCOUNT_1, "FAILED", 2);
  loginAsPlatformOwner(db);
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 200);
  assert.equal(del.json.deleted, true);
  const account = db.accounts.get(ACCOUNT_1)!;
  assert.equal(account.status, "DELETED");
  // The username is tombstoned so UNIQUE(server_id, username) frees the slot.
  assert.match(account.username, /^acme01-deleted-/);
  // FAILED job stays as-is for the audit trail; only QUEUED jobs are cancelled.
  assert.equal(db.jobs.get("job-fail-1")!.status, "FAILED");
  const audit = db.auditRows.find((row) => row.action === "hosting_account.failed_provisioning_deleted");
  assert.ok(audit, "a failed-provisioning deletion must be audited");
});

test("a plain pending account keeps the legacy pre-provisioning deletion flow", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "PENDING";
  loginAsPlatformOwner(db);
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 200);
  assert.equal(db.accounts.get(ACCOUNT_1)!.status, "DELETED");
});

// ---------------------------------------------------------------------------
// 3. The username is reusable after a failed-account delete
// ---------------------------------------------------------------------------

test("the username freed by a failed-account delete can be re-created on the same server", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  seedJob(db, "job-fail-1", ACCOUNT_1, "FAILED", 1);
  loginAsPlatformOwner(db); // account creation + deletion are platform-admin scoped
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 200);
  const create = await call(db, "POST", "/v1/hosting-accounts", makeEnv(), {
    serverId: SERVER_1, planId: PLAN_BASIC, username: "acme01", primaryDomain: "",
  });
  assert.equal(create.status, 201);
  const account = create.json.account as { username: string; status: string };
  assert.equal(account.username, "acme01");
  assert.equal(account.status, "PENDING");
  const recreated = [...db.accounts.values()].find((a) => a.username === "acme01");
  assert.ok(recreated, "the recreated account row must exist");
});

test("creating a duplicate username while the failed account still exists is refused", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  loginAsPlatformOwner(db);
  const create = await call(db, "POST", "/v1/hosting-accounts", makeEnv(), {
    serverId: SERVER_1, planId: PLAN_BASIC, username: "acme01", primaryDomain: "",
  });
  assert.equal(create.status, 409);
});

// ---------------------------------------------------------------------------
// 4. Deletion guards that must stay
// ---------------------------------------------------------------------------

test("deletion is blocked while the provisioning job is running", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "PENDING";
  seedJob(db, "job-run-1", ACCOUNT_1, "RUNNING");
  loginAsPlatformOwner(db);
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 409);
  assert.match(String(del.json.message), /running/i);
});

test("deletion of an ACTIVE account still requires the agent-backed workflow", async () => {
  const db = freshDb();
  seedJob(db, "job-ok-1", ACCOUNT_1, "SUCCEEDED");
  loginAsPlatformOwner(db);
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 409);
  assert.match(String(del.json.message), /agent-backed deprovisioning/);
});

test("non-admin members cannot delete hosting accounts", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  loginAs(db, MEMBER_A);
  const del = await call(db, "DELETE", `/v1/hosting-accounts/${ACCOUNT_1}`, makeEnv());
  assert.equal(del.status, 403);
});

// ---------------------------------------------------------------------------
// 5. Retry moves a FAILED account back to PENDING
// ---------------------------------------------------------------------------

test("retrying a failed CREATE_HOSTING_ACCOUNT queues a fresh job and resets the account", async () => {
  const db = freshDb();
  db.accounts.get(ACCOUNT_1)!.status = "FAILED";
  seedJob(db, "job-fail-1", ACCOUNT_1, "FAILED", 1);
  loginAsPlatformOwner(db); // the inspector retry route is platform-admin scoped
  const retried = await call(db, "POST", "/v1/provisioning-jobs/job-fail-1/retry", makeEnv());
  assert.equal(retried.status, 201);
  const newJobId = retried.json.jobId as string;
  assert.notEqual(newJobId, "job-fail-1");
  const newJob = db.jobs.get(newJobId)!;
  assert.equal(newJob.status, "QUEUED");
  assert.match(newJob.idempotencyKey, /create-account:.*:retry-2/);
  // The original FAILED job is preserved; the account returns to PENDING.
  assert.equal(db.jobs.get("job-fail-1")!.status, "FAILED");
  assert.equal(db.accounts.get(ACCOUNT_1)!.status, "PENDING");
  const audit = db.auditRows.find((row) => row.action === "provisioning_job.retried");
  assert.ok(audit, "the retry must be audited");
});

test("an anonymous request cannot list hosting accounts", async () => {
  const db = freshDb();
  db.identity = null;
  const request = new Request("https://worker.test/v1/hosting-accounts", {
    method: "GET", headers: { authorization: `Bearer ${SESSION_TOKEN}` },
  });
  const response = await import("../src/index.ts").then((mod) =>
    mod.default.fetch(request, { DB: db as never, ...makeEnv() } as never, { waitUntil: () => {} } as never));
  assert.equal(response.status, 401);
});
