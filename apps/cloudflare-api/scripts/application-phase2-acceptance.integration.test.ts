import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// application-phase2-acceptance.integration.test.ts
//
// Five end-to-end acceptance tests covering the Phase 2 deployment-lifecycle
// acceptance criteria. The mock D1 (TwoNodeD1) simulates two independently
// authenticated application nodes so we can verify per-node release isolation,
// authenticated health reporting, terminal-state transitions, and conflict
// rejection. State mutates in memory so the tests can assert transitions
// end-to-end without a real D1 binding.
// ---------------------------------------------------------------------------

const HEALTH_PATH = "/internal/v1/application-nodes/releases/health-check";
const PENDING_PATH = "/internal/v1/application-nodes/pending-static-releases";

const healthyReport = {
  deploymentId: "deployment-recovery-001",
  artifactSha256: "b".repeat(64),
  probePath: "/ready",
  healthStatus: "healthy",
  httpStatus: 200,
  durationMs: 42,
};

const unhealthyReport = {
  deploymentId: "deployment-recovery-001",
  artifactSha256: "b".repeat(64),
  probePath: "/ready",
  healthStatus: "unhealthy",
  httpStatus: 503,
  durationMs: 9,
  failureCode: "http_5xx",
};

type ReleaseState = "health_checking" | "succeeded" | "failed";

type NodeRow = {
  id: string;
  nodeIdentity: string;
  nodePoolId: string;
  signingPublicKey: string;
};

type ReleaseRow = {
  rowId: string;
  state: ReleaseState;
  artifactDigest: string;
  deploymentArtifactDigest: string;
  projectId: string;
  organizationId: string;
  deploymentId: string;
  healthCheckPath: string;
  assignedNodeIdentity: string;
  assignedNodeId: string;
  previousActiveReleaseId: string | null;
  previousDeploymentId: string | null;
  previousArtifactDigest: string | null;
  previousActiveNodeId: string | null;
  previousActiveNodeIdentity: string | null;
};

class TwoNodeD1 {
  nodes = new Map<string, NodeRow>();
  releases: ReleaseRow[] = [];
  events: Array<{ releaseId: string; eventCode: string }> = [];
  nonces = new Set<string>();

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      getValues() { return values; },
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        // Defensive: bearer-token identity lookup. The application-node
        // routes do not call bearerIdentity, but the mock must handle the
        // query shape if any middleware touches it.
        if (query.includes("FROM auth_sessions s")) return null as T;
        // Runtime node auth lookup: SELECT n.id, n.node_pool_id AS nodePoolId,
        // n.signing_public_key AS signingPublicKey FROM application_nodes n ...
        if (query.includes("FROM application_nodes n")) {
          const identity = String(values[0]);
          const node = db.nodes.get(identity);
          if (!node) return null as T;
          return ({
            id: node.id,
            nodePoolId: node.nodePoolId,
            signingPublicKey: node.signingPublicKey,
          } as T);
        }
        // Health-check release lookup. The discriminator MUST be
        // `r.assigned_node_id = ?` — NOT `healthCheckPath`, which appears as
        // a SELECT alias in the pending-poll query that runs through all().
        // Bind order: (deploymentId, nodePoolId, nodeId) — values[0] and
        // values[2] identify the release uniquely.
        if (query.includes("r.assigned_node_id = ?")) {
          const deploymentId = String(values[0]);
          const nodeId = String(values[2]);
          const release = db.releases.find(
            (r) => r.deploymentId === deploymentId && r.assignedNodeId === nodeId,
          );
          if (!release) return null as T;
          return ({
            releaseRowId: release.rowId,
            state: release.state,
            artifactDigest: release.artifactDigest,
            deploymentArtifactDigest: release.deploymentArtifactDigest,
            projectId: release.projectId,
            organizationId: release.organizationId,
            healthCheckPath: release.healthCheckPath,
            previousActiveReleaseId: release.previousActiveReleaseId,
            previousDeploymentId: release.previousDeploymentId,
            previousArtifactDigest: release.previousArtifactDigest,
            previousActiveNodeId: release.previousActiveNodeId,
            previousActiveNodeIdentity: release.previousActiveNodeIdentity,
          } as T);
        }
        // Prior health-check event lookup (terminal duplicate / conflict check).
        if (query.includes("FROM application_release_events WHERE release_id = ?")) {
          const releaseId = String(values[0]);
          const eventCode = String(values[1]);
          const found = db.events.find(
            (e) => e.releaseId === releaseId && e.eventCode === eventCode,
          );
          return (found ? { id: "event-" + found.eventCode } : null) as T;
        }
        // Rollback acknowledgement lookup — always fresh in these tests.
        if (query.includes("FROM application_rollback_acknowledgements")) {
          return null as T;
        }
        return null as T;
      },
      async all<T>() {
        // Pending releases query. Discriminator: JOIN github_projects p
        // (the pending-poll query joins through github_projects; the rollback
        // query joins through application_workloads first). Bind order:
        // (node.id, node.nodePoolId, nodeIdentity) — values[2] is the node
        // identity we filter releases by.
        if (query.includes("JOIN github_projects p")) {
          const nodeIdentity = String(values[2]);
          const filtered = db.releases.filter(
            (r) => r.assignedNodeIdentity === nodeIdentity,
          );
          return ({
            results: filtered.map((r) => ({
              releaseId: r.rowId,
              state: r.state,
              artifactSha256: r.artifactDigest,
              deploymentId: r.deploymentId,
              organizationId: r.organizationId,
              projectId: r.projectId,
              hostingAccountId: "hosting-a",
              domainId: "domain-a",
              hostname: "www.example.test",
              repositoryId: "123456789",
              commitSha: "0123456789abcdef0123456789abcdef01234567",
              healthCheckPath: r.healthCheckPath,
              previousDeploymentId: r.previousDeploymentId ?? "",
            })) as T[],
          });
        }
        return { results: [] as T[] };
      },
      async run() {
        // Nonce replay protection (INSERT OR IGNORE).
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          const nonce = String(values[1]);
          if (db.nonces.has(nonce)) {
            return { success: true, meta: { changes: 0 } };
          }
          db.nonces.add(nonce);
          return { success: true, meta: { changes: 1 } };
        }
        // Healthy terminal transition. Bind order:
        // (release.releaseRowId, body.artifactSha256, node.id, nodeIdentity, signingPublicKey)
        // values[0] is the rowId.
        if (query.includes("UPDATE application_releases SET state = 'succeeded'")) {
          const rowId = String(values[0]);
          const release = db.releases.find((r) => r.rowId === rowId);
          if (release) release.state = "succeeded";
          return { success: true, meta: { changes: 1 } };
        }
        // Unhealthy terminal transition. Bind order:
        // (failureCode, release.releaseRowId, body.artifactSha256, ...)
        // values[0] is failureCode, values[1] is the rowId.
        if (query.includes("UPDATE application_releases SET state = 'failed'")) {
          const rowId = String(values[1]);
          const release = db.releases.find((r) => r.rowId === rowId);
          if (release) release.state = "failed";
          return { success: true, meta: { changes: 1 } };
        }
        // INSERT INTO application_release_events. Bind order for both healthy
        // and unhealthy branches:
        // (crypto.randomUUID(), node.id, details, release.releaseRowId, body.artifactSha256, ...)
        // values[3] is release.releaseRowId. The event_code is a query literal.
        if (query.includes("INSERT INTO application_release_events")) {
          const eventCode = query.includes("'health_check_succeeded'")
            ? "health_check_succeeded"
            : query.includes("'health_check_failed'")
              ? "health_check_failed"
              : "unknown";
          const releaseId = String(values[3]);
          if (!db.events.find(
            (e) => e.releaseId === releaseId && e.eventCode === eventCode,
          )) {
            db.events.push({ releaseId, eventCode });
          }
          return { success: true, meta: { changes: 1 } };
        }
        // All other writes (workload upsert, deployment status update, node
        // last_signature_at refresh) report a single successful change.
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>) {
    // Each statement was prepared with its own closure-bound run() that
    // already records events for INSERT INTO application_release_events, so
    // batch() only needs to invoke each run() in order and collect results.
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

async function setupTwoNodes() {
  const pairA = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pairB = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubA = new Uint8Array(await crypto.subtle.exportKey("raw", pairA.publicKey));
  const pubB = new Uint8Array(await crypto.subtle.exportKey("raw", pairB.publicKey));
  const toHex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const db = new TwoNodeD1();
  db.nodes.set("runtime-a", {
    id: "node-runtime-a",
    nodeIdentity: "runtime-a",
    nodePoolId: "pool-static",
    signingPublicKey: toHex(pubA),
  });
  db.nodes.set("runtime-b", {
    id: "node-runtime-b",
    nodeIdentity: "runtime-b",
    nodePoolId: "pool-static",
    signingPublicKey: toHex(pubB),
  });
  return {
    db,
    privateKeyA: pairA.privateKey,
    privateKeyB: pairB.privateKey,
    env: { DB: db as unknown as D1Database },
  };
}

async function signedNodeRequest(
  privateKey: CryptoKey,
  method: "POST" | "GET",
  path: string,
  body: unknown,
  nonce: string,
  nodeIdentity: string,
) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const rawBody = method === "POST" ? JSON.stringify(body) : "";
  const bodyBytes = new TextEncoder().encode(rawBody);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bodyBytes));
  const digestHex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", nodeIdentity, timestamp, nonce, method, path, digestHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, privateKey, new TextEncoder().encode(message),
  ));
  const signatureHex = Array.from(signature, (b) => b.toString(16).padStart(2, "0")).join("");
  const headers: Record<string, string> = {
    "x-nexora-node-identity": nodeIdentity,
    "x-nexora-node-timestamp": timestamp,
    "x-nexora-node-nonce": nonce,
    "x-nexora-node-signature": signatureHex,
  };
  if (method === "POST") {
    headers["content-type"] = "application/json";
  }
  return new Request("https://api.test" + path, {
    method,
    headers,
    body: method === "POST" ? rawBody : undefined,
  });
}

function makeRelease(overrides: Partial<ReleaseRow> & { assignedNodeIdentity: string; assignedNodeId: string; deploymentId: string; rowId: string; artifactDigest: string }): ReleaseRow {
  return {
    state: "health_checking",
    deploymentArtifactDigest: overrides.artifactDigest,
    projectId: "project-a",
    organizationId: "org-a",
    healthCheckPath: "/ready",
    previousActiveReleaseId: null,
    previousDeploymentId: null,
    previousArtifactDigest: null,
    previousActiveNodeId: null,
    previousActiveNodeIdentity: null,
    ...overrides,
  } as ReleaseRow;
}

test("health_checking release completes a successful authenticated health report and transitions to succeeded", async () => {
  const { db, privateKeyA, env } = await setupTwoNodes();
  db.releases.push(makeRelease({
    rowId: "release-recovery-001",
    deploymentId: "deployment-recovery-001",
    artifactDigest: "b".repeat(64),
    assignedNodeIdentity: "runtime-a",
    assignedNodeId: "node-runtime-a",
  }));

  const response = await worker.fetch(
    await signedNodeRequest(privateKeyA, "POST", HEALTH_PATH, healthyReport, "1".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releaseState: string };
  assert.equal(body.releaseState, "succeeded");
});

test("two independently authenticated nodes see only their own assigned releases", async () => {
  const { db, privateKeyA, privateKeyB, env } = await setupTwoNodes();
  db.releases.push(makeRelease({
    rowId: "release-a",
    deploymentId: "deployment-a",
    artifactDigest: "a".repeat(64),
    assignedNodeIdentity: "runtime-a",
    assignedNodeId: "node-runtime-a",
    projectId: "project-a",
    organizationId: "org-a",
  }));
  db.releases.push(makeRelease({
    rowId: "release-b",
    deploymentId: "deployment-b",
    artifactDigest: "c".repeat(64),
    assignedNodeIdentity: "runtime-b",
    assignedNodeId: "node-runtime-b",
    projectId: "project-b",
    organizationId: "org-b",
  }));

  const pollA = await worker.fetch(
    await signedNodeRequest(privateKeyA, "GET", PENDING_PATH, null, "2".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(pollA.status, 200);
  const bodyA = await pollA.json() as { releases: Array<{ releaseId: string }> };
  assert.equal(bodyA.releases.length, 1);
  assert.equal(bodyA.releases[0].releaseId, "release-a");

  const pollB = await worker.fetch(
    await signedNodeRequest(privateKeyB, "GET", PENDING_PATH, null, "3".repeat(32), "runtime-b"),
    env, {} as ExecutionContext,
  );
  assert.equal(pollB.status, 200);
  const bodyB = await pollB.json() as { releases: Array<{ releaseId: string }> };
  assert.equal(bodyB.releases.length, 1);
  assert.equal(bodyB.releases[0].releaseId, "release-b");
});

test("health report from the wrong node is rejected", async () => {
  const { db, privateKeyA, env } = await setupTwoNodes();
  // Release is assigned to runtime-b.
  db.releases.push(makeRelease({
    rowId: "release-b",
    deploymentId: "deployment-b",
    artifactDigest: "b".repeat(64),
    assignedNodeIdentity: "runtime-b",
    assignedNodeId: "node-runtime-b",
  }));
  // Node A attempts to report health for node B's release. The mock's
  // health-check lookup requires both deploymentId AND assignedNodeId to
  // match, so the release is not found and the Worker responds 404.
  const response = await worker.fetch(
    await signedNodeRequest(privateKeyA, "POST", HEALTH_PATH, {
      ...healthyReport,
      deploymentId: "deployment-b",
    }, "4".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 404);
});

test("unhealthy health report transitions release to failed", async () => {
  const { db, privateKeyA, env } = await setupTwoNodes();
  db.releases.push(makeRelease({
    rowId: "release-recovery-001",
    deploymentId: "deployment-recovery-001",
    artifactDigest: "b".repeat(64),
    assignedNodeIdentity: "runtime-a",
    assignedNodeId: "node-runtime-a",
  }));

  const response = await worker.fetch(
    await signedNodeRequest(privateKeyA, "POST", HEALTH_PATH, unhealthyReport, "5".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releaseState: string };
  assert.equal(body.releaseState, "failed");
});

test("conflicting health outcome is rejected", async () => {
  const { db, privateKeyA, env } = await setupTwoNodes();
  db.releases.push(makeRelease({
    rowId: "release-recovery-001",
    deploymentId: "deployment-recovery-001",
    artifactDigest: "b".repeat(64),
    assignedNodeIdentity: "runtime-a",
    assignedNodeId: "node-runtime-a",
  }));

  // First: healthy report transitions the release to succeeded.
  const first = await worker.fetch(
    await signedNodeRequest(privateKeyA, "POST", HEALTH_PATH, healthyReport, "6".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);

  // Then: an unhealthy report disagrees with the terminal outcome. The
  // Worker must reject the conflicting retry with 409 and leave the
  // durable state untouched.
  const conflicting = await worker.fetch(
    await signedNodeRequest(privateKeyA, "POST", HEALTH_PATH, unhealthyReport, "7".repeat(32), "runtime-a"),
    env, {} as ExecutionContext,
  );
  assert.equal(conflicting.status, 409);
});
