import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

// These tests cover the outstanding Phase 2 deployment-lifecycle items from
// PROJECT_STATUS.md:
//   3. Make health-report retries idempotent when probe duration changes.
//   4. Reject retries that conflict with the original health result.
//   5. Add regression tests for these recovery and retry scenarios.
//
// The mock D1 simulates the subset of schema the health-check endpoint touches:
// application_nodes, application_releases, application_release_events,
// application_workloads, github_deployments, application_project_settings,
// application_node_request_nonces, and application_rollback_acknowledgements.
// State mutates in memory so the test can assert transitions end-to-end.

const HEALTH_PATH = "/internal/v1/application-nodes/releases/health-check";

const baseReport = {
  deploymentId: "deployment-a",
  artifactSha256: "a".repeat(64),
  probePath: "/ready",
  healthStatus: "healthy",
  httpStatus: 200,
  durationMs: 12,
};

type ReleaseState = "health_checking" | "succeeded" | "failed";

class HealthCheckD1 {
  node = {
    id: "runtime-node-id",
    nodeIdentity: "runtime-a",
    nodePoolId: "pool-static",
    signingPublicKey: "",
  };
  nonces = new Set<string>();
  release = {
    rowId: "release-row-1",
    state: "health_checking" as ReleaseState,
    artifactDigest: "a".repeat(64),
    deploymentArtifactDigest: "a".repeat(64),
    projectId: "project-a",
    organizationId: "org-a",
    healthCheckPath: "/ready",
    previousActiveReleaseId: null as string | null,
    previousDeploymentId: null as string | null,
    previousArtifactDigest: null as string | null,
    previousActiveNodeId: null as string | null,
    previousActiveNodeIdentity: null as string | null,
  };
  // Track inserted health-check events keyed by (releaseId, eventCode).
  events: Array<{ releaseId: string; eventCode: string }> = [];
  batches = 0;
  nonceReplays = 0;

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      getValues() { return values; },
      async first<T>() {
        if (query.includes("FROM application_nodes n")) {
          return values[0] === db.node.nodeIdentity
            ? ({
                id: db.node.id,
                nodePoolId: db.node.nodePoolId,
                signingPublicKey: db.node.signingPublicKey,
              } as T)
            : null;
        }
        if (query.includes("FROM application_releases r ")) {
          return ({
            releaseRowId: db.release.rowId,
            state: db.release.state,
            artifactDigest: db.release.artifactDigest,
            deploymentArtifactDigest: db.release.deploymentArtifactDigest,
            projectId: db.release.projectId,
            organizationId: db.release.organizationId,
            healthCheckPath: db.release.healthCheckPath,
            previousActiveReleaseId: db.release.previousActiveReleaseId,
            previousDeploymentId: db.release.previousDeploymentId,
            previousArtifactDigest: db.release.previousArtifactDigest,
            previousActiveNodeId: db.release.previousActiveNodeId,
            previousActiveNodeIdentity: db.release.previousActiveNodeIdentity,
          } as T);
        }
        if (query.includes("FROM application_rollback_acknowledgements")) {
          return null;
        }
        if (query.includes("FROM application_release_events WHERE release_id = ?")) {
          // values: [releaseId, eventCode]
          const releaseId = String(values[0]);
          const eventCode = String(values[1]);
          const found = db.events.find(
            (e) => e.releaseId === releaseId && e.eventCode === eventCode,
          );
          return (found ? { id: "event-" + found.eventCode } : null) as T;
        }
        return null;
      },
      async run() {
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          const nonce = String(values[1]);
          if (db.nonces.has(nonce)) {
            db.nonceReplays += 1;
            return { success: true, meta: { changes: 0 } };
          }
          db.nonces.add(nonce);
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>) {
    this.batches += 1;
    // Inspect the first statement to determine the target state. The Worker
    // emits UPDATE application_releases SET state = 'succeeded'|'failed' ...
    // as the first statement of the batch.
    const firstQuery = statements[0].query;
    const targetState: ReleaseState = firstQuery.includes("state = 'succeeded'")
      ? "succeeded"
      : firstQuery.includes("state = 'failed'")
        ? "failed"
        : (() => { throw new Error("unexpected batch lead statement: " + firstQuery); })();

    // The second statement is the INSERT INTO application_release_events
    // SELECT ... 'health_check_succeeded'|'health_check_failed', details.
    // Find it and record the event row.
    const insertStmt = statements.find((s) =>
      s.query.includes("INSERT INTO application_release_events"));
    if (insertStmt) {
      const eventCode = insertStmt.query.includes("'health_check_succeeded'")
        ? "health_check_succeeded"
        : insertStmt.query.includes("'health_check_failed'")
          ? "health_check_failed"
          : "unknown";
      // Don't duplicate-event on replay within the same mock.
      if (!this.events.find(
        (e) => e.releaseId === this.release.rowId && e.eventCode === eventCode,
      )) {
        this.events.push({ releaseId: this.release.rowId, eventCode });
      }
    }
    this.release.state = targetState;
    return statements.map(() => ({ success: true, meta: { changes: 1 } }));
  }
}

async function setup() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const db = new HealthCheckD1();
  db.node.signingPublicKey = Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { db, privateKey: pair.privateKey, env: { DB: db as unknown as D1Database } };
}

async function signedRequest(
  privateKey: CryptoKey,
  body: unknown,
  nonce: string,
  nodeIdentity = "runtime-a",
) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const rawBody = JSON.stringify(body);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", nodeIdentity, timestamp, nonce, "POST", HEALTH_PATH, digestHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, privateKey, new TextEncoder().encode(message),
  ));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test" + HEALTH_PATH, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-node-identity": nodeIdentity,
      "x-nexora-node-timestamp": timestamp,
      "x-nexora-node-nonce": nonce,
      "x-nexora-node-signature": signatureHex,
    },
    body: rawBody,
  });
}

test("first healthy report transitions the release from health_checking to succeeded", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(
    await signedRequest(privateKey, baseReport, "1".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; duplicate: boolean; releaseState: string };
  assert.equal(body.accepted, true);
  assert.equal(body.duplicate, false);
  assert.equal(body.releaseState, "succeeded");
  assert.equal(db.release.state, "succeeded");
  assert.equal(db.batches, 1);
  assert.equal(db.events.length, 1);
  assert.equal(db.events[0].eventCode, "health_check_succeeded");
});

test("healthy retry with different probe duration is idempotent and does not insert a duplicate event", async () => {
  // PROJECT_STATUS item 3: retries must be idempotent when probe duration changes.
  const { db, privateKey, env } = await setup();
  const first = await worker.fetch(
    await signedRequest(privateKey, baseReport, "2".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  const firstBody = await first.json() as { duplicate: boolean };
  assert.equal(firstBody.duplicate, false);

  // Retry with a different durationMs (simulating network jitter or a probe
  // restart after agent recovery). Same outcome, different probe details.
  const retry = await worker.fetch(
    await signedRequest(privateKey, { ...baseReport, durationMs: 187 }, "3".repeat(32)),
    env, {} as ExecutionContext,
  );
  assert.equal(retry.status, 200);
  const retryBody = await retry.json() as { accepted: boolean; duplicate: boolean; releaseState: string };
  assert.equal(retryBody.accepted, true);
  assert.equal(retryBody.duplicate, true);
  assert.equal(retryBody.releaseState, "succeeded");
  // The terminal transition must not be re-issued: only the first batch ran.
  assert.equal(db.batches, 1);
  // No duplicate event was inserted for the same (release, event_code).
  assert.equal(db.events.filter((e) => e.eventCode === "health_check_succeeded").length, 1);
});

test("retry that disagrees with the terminal outcome is rejected as a conflict", async () => {
  // PROJECT_STATUS item 4: reject retries that conflict with the original
  // health result. The release already succeeded; a later unhealthy report
  // for the same deployment must not flip the durable state.
  const { db, privateKey, env } = await setup();
  const first = await worker.fetch(
    await signedRequest(privateKey, baseReport, "4".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  const conflicting = await worker.fetch(
    await signedRequest(
      privateKey,
      {
        ...baseReport,
        healthStatus: "unhealthy",
        httpStatus: 503,
        durationMs: 9,
        failureCode: "http_5xx",
      },
      "5".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(conflicting.status, 409);
  // The release state and event history remain unchanged.
  assert.equal(db.release.state, "succeeded");
  assert.equal(db.events.length, 1);
});

test("terminal release with no matching health-check event is rejected as a data-integrity failure", async () => {
  // If a release somehow reached a terminal state without a recorded
  // health-check event, a later report must not be accepted as a duplicate
  // (otherwise a stale or replayed report could silently agree with a state
  // reached by a different path).
  const { db, privateKey, env } = await setup();
  db.release.state = "succeeded";
  db.events = [];
  const response = await worker.fetch(
    await signedRequest(privateKey, baseReport, "6".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.equal(db.batches, 0);
});

test("release left in health_checking after a simulated agent restart still accepts a fresh report", async () => {
  // PROJECT_STATUS item 5 regression: recovery after agent restart. The
  // publisher restarts, polls pending-static-releases, finds the same release
  // still in health_checking (control plane retained the state across the
  // restart), re-runs the probe, and reports again with a fresh nonce. The
  // Worker must accept the report and transition the release to succeeded.
  const { db, privateKey, env } = await setup();
  // Simulate the post-restart state: release still awaiting health check.
  assert.equal(db.release.state, "health_checking");
  const response = await worker.fetch(
    await signedRequest(privateKey, { ...baseReport, durationMs: 240 }, "7".repeat(32)),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; duplicate: boolean; releaseState: string };
  assert.equal(body.accepted, true);
  assert.equal(body.duplicate, false);
  assert.equal(body.releaseState, "succeeded");
  assert.equal(db.release.state, "succeeded");
  assert.equal(db.events.length, 1);
});

test("replayed nonce is rejected even when the outcome agrees with the terminal state", async () => {
  // Replay protection is independent of idempotency: the same nonce can never
  // authorize two requests, even if the second would have been a duplicate.
  const { db, privateKey, env } = await setup();
  const first = await worker.fetch(
    await signedRequest(privateKey, baseReport, "8".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  const replay = await worker.fetch(
    await signedRequest(privateKey, { ...baseReport, durationMs: 67 }, "8".repeat(32)),
    env, {} as ExecutionContext,
  );
  assert.equal(replay.status, 409);
  assert.equal(db.batches, 1);
  assert.equal(db.nonceReplays, 1);
});

test("unhealthy report transitions the release to failed and records a health_check_failed event", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(
    await signedRequest(
      privateKey,
      {
        ...baseReport,
        healthStatus: "unhealthy",
        httpStatus: 503,
        durationMs: 9,
        failureCode: "http_5xx",
      },
      "9".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; duplicate: boolean; releaseState: string };
  assert.equal(body.accepted, true);
  assert.equal(body.duplicate, false);
  assert.equal(body.releaseState, "failed");
  assert.equal(db.release.state, "failed");
  assert.equal(db.events[0].eventCode, "health_check_failed");
});

test("unhealthy retry with different failure duration is idempotent", async () => {
  // Mirror of item 3 for the unhealthy branch: a retried unhealthy report
  // after a failed terminal state must be a duplicate, not a conflict.
  const { db, privateKey, env } = await setup();
  const first = await worker.fetch(
    await signedRequest(
      privateKey,
      {
        ...baseReport,
        healthStatus: "unhealthy",
        httpStatus: 503,
        durationMs: 9,
        failureCode: "http_5xx",
      },
      "a".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  const retry = await worker.fetch(
    await signedRequest(
      privateKey,
      {
        ...baseReport,
        healthStatus: "unhealthy",
        httpStatus: 502,
        durationMs: 41,
        failureCode: "http_5xx",
      },
      "b".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(retry.status, 200);
  const retryBody = await retry.json() as { accepted: boolean; duplicate: boolean };
  assert.equal(retryBody.accepted, true);
  assert.equal(retryBody.duplicate, true);
  assert.equal(db.batches, 1);
  assert.equal(db.events.filter((e) => e.eventCode === "health_check_failed").length, 1);
});

test("report with mismatched artifact digest is rejected before any state change", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(
    await signedRequest(
      privateKey,
      { ...baseReport, artifactSha256: "b".repeat(64) },
      "c".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.equal(db.release.state, "health_checking");
  assert.equal(db.batches, 0);
});

test("report with probe path disagreeing with project runtime settings is rejected", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(
    await signedRequest(
      privateKey,
      { ...baseReport, probePath: "/healthz" },
      "d".repeat(32),
    ),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.equal(db.batches, 0);
});

test("request with a tampered signature is rejected as unauthorized", async () => {
  const { db, privateKey, env } = await setup();
  // Sign with the wrong path so the Worker's signature verification fails.
  const timestamp = String(Math.floor(Date.now() / 1000));
  const rawBody = JSON.stringify(baseReport);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", "runtime-a", timestamp, "e".repeat(32), "POST",
    "/internal/v1/application-nodes/releases/activated", digestHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, privateKey, new TextEncoder().encode(message),
  ));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await worker.fetch(
    new Request("https://api.test" + HEALTH_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nexora-node-identity": "runtime-a",
        "x-nexora-node-timestamp": timestamp,
        "x-nexora-node-nonce": "e".repeat(32),
        "x-nexora-node-signature": signatureHex,
      },
      body: rawBody,
    }),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 401);
  assert.equal(db.batches, 0);
});
