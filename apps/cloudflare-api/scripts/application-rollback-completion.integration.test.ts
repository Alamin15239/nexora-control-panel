import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const rollbackBody = {
  operationId: "rollback-deployment-failed-001",
  failedDeploymentId: "deployment-failed",
  targetDeploymentId: "deployment-previous",
  targetArtifactSha256: "a".repeat(64),
  httpStatus: 200,
  durationMs: 12,
};

class RollbackCompletionD1 {
  node = {
    id: "runtime-node-id",
    nodePoolId: "pool-a",
    nodeIdentity: "runtime-a",
    signingPublicKey: "",
  };
  bindingAllowed = true;
  nonces = new Set<string>();
  acknowledgement: {
    nodeId: string;
    failedDeploymentId: string;
    targetDeploymentId: string;
    failedReleaseId: string;
    targetReleaseId: string;
    targetArtifactSha256: string;
    httpStatus: number;
    durationMs: number;
  } | null = null;
  workload = {
    id: "workload-a",
    status: "unhealthy",
    activeReleaseId: "release-previous",
    nodeId: "runtime-node-id",
  };
  batches = 0;

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
        if (query.includes("FROM application_rollback_acknowledgements")) {
          if (!db.acknowledgement) return null;
          if (query.includes("failed_deployment_id AS failedDeploymentId")) {
            return ({
              nodeId: db.acknowledgement.nodeId,
              failedDeploymentId: db.acknowledgement.failedDeploymentId,
              targetDeploymentId: db.acknowledgement.targetDeploymentId,
              targetArtifactSha256: db.acknowledgement.targetArtifactSha256,
              httpStatus: db.acknowledgement.httpStatus,
              durationMs: db.acknowledgement.durationMs,
            } as T);
          }
          return ({
            nodeId: db.acknowledgement.nodeId,
            failedReleaseId: db.acknowledgement.failedReleaseId,
            targetReleaseId: db.acknowledgement.targetReleaseId,
            targetArtifactSha256: db.acknowledgement.targetArtifactSha256,
            httpStatus: db.acknowledgement.httpStatus,
            durationMs: db.acknowledgement.durationMs,
          } as T);
        }
        if (query.includes("FROM application_releases failed")) {
          if (!db.bindingAllowed) return null;
          return ({
            failedReleaseId: "release-failed",
            organizationId: "org-a",
            projectId: "project-a",
            targetReleaseId: "release-previous",
            targetArtifactDigest: rollbackBody.targetArtifactSha256,
            workloadId: db.workload.id,
          } as T);
        }
        if (query.includes("FROM application_workloads WHERE id = ?")) {
          return ({ ...db.workload } as T);
        }
        return null;
      },
      async run() {
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          const nonce = String(values[1]);
          if (db.nonces.has(nonce)) return { success: true, meta: { changes: 0 } };
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
    const ack = statements[0].getValues();
    this.acknowledgement = {
      nodeId: String(ack[3]),
      failedReleaseId: String(ack[4]),
      targetReleaseId: String(ack[5]),
      failedDeploymentId: String(ack[6]),
      targetDeploymentId: String(ack[7]),
      targetArtifactSha256: String(ack[8]),
      httpStatus: Number(ack[9]),
      durationMs: Number(ack[10]),
    };
    this.workload.status = "healthy";
    return statements.map(() => ({ success: true, meta: { changes: 1 } }));
  }
}

async function setup() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const db = new RollbackCompletionD1();
  db.node.signingPublicKey = Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { db, privateKey: pair.privateKey, env: { DB: db as unknown as D1Database } };
}

async function signedRequest(privateKey: CryptoKey, body: unknown, nonce: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const path = "/internal/v1/application-nodes/releases/rollback-completed";
  const rawBody = JSON.stringify(body);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", "runtime-a", timestamp, nonce, "POST", path, digestHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, privateKey, new TextEncoder().encode(message),
  ));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-node-identity": "runtime-a",
      "x-nexora-node-timestamp": timestamp,
      "x-nexora-node-nonce": nonce,
      "x-nexora-node-signature": signatureHex,
    },
    body: rawBody,
  });
}

test("rollback completion accepts a verified same-node rollback and restores workload health", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(
    await signedRequest(privateKey, rollbackBody, "a".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; duplicate: boolean; state: string };
  assert.equal(body.accepted, true);
  assert.equal(body.duplicate, false);
  assert.equal(body.state, "reported");
  assert.equal(db.acknowledgement?.failedReleaseId, "release-failed");
  assert.equal(db.acknowledgement?.targetReleaseId, "release-previous");
  assert.equal(db.workload.status, "healthy");
  assert.equal(db.batches, 1);
});

test("rollback completion is idempotent for an exact operation retry", async () => {
  const { db, privateKey, env } = await setup();
  const first = await worker.fetch(
    await signedRequest(privateKey, rollbackBody, "b".repeat(32)), env, {} as ExecutionContext,
  );
  const retry = await worker.fetch(
    await signedRequest(privateKey, rollbackBody, "c".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  assert.equal(retry.status, 200);
  const body = await retry.json() as { accepted: boolean; duplicate: boolean; state: string };
  assert.equal(body.accepted, true);
  assert.equal(body.duplicate, true);
  assert.equal(body.state, "reported");
  assert.equal(db.batches, 1);
});

test("rollback completion rejects stale or cross-node assignments without writing an acknowledgement", async () => {
  const { db, privateKey, env } = await setup();
  db.bindingAllowed = false;
  const response = await worker.fetch(
    await signedRequest(privateKey, rollbackBody, "d".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.equal(db.acknowledgement, null);
  assert.equal(db.batches, 0);
});

test("rollback completion rejects a replayed request nonce", async () => {
  const { db, privateKey, env } = await setup();
  const request = await signedRequest(privateKey, rollbackBody, "e".repeat(32));
  const first = await worker.fetch(request, env, {} as ExecutionContext);
  const replay = await worker.fetch(
    await signedRequest(privateKey, rollbackBody, "e".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(first.status, 200);
  assert.equal(replay.status, 409);
  assert.equal(db.batches, 1);
});
