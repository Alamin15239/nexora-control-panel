import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const path = "/internal/v1/application-nodes/releases/rollback-completed";
const nodeIdentity = "runtime-node-test";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

class RevokedDuringBatchD1 {
  batchStatements: string[] = [];
  nonceInserted = false;

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_nodes n JOIN application_node_pools p")) {
          return {
            id: "node-row-1",
            nodePoolId: "pool-1",
            signingPublicKey: db.publicKeyHex,
          } as T;
        }
        if (query.includes("FROM application_rollback_acknowledgements WHERE operation_id")) return null;
        if (query.includes("FROM application_releases failed")) {
          return {
            failedReleaseId: "failed-release-row",
            organizationId: "org-1",
            projectId: "project-1",
            targetReleaseId: "target-release-row",
            targetArtifactDigest: "a".repeat(64),
            workloadId: "workload-1",
          } as T;
        }
        return null;
      },
      async run() {
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          db.nonceInserted = true;
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 0 } };
      },
    };
    return statement;
  }

  publicKeyHex = "";

  async batch(statements: Array<{ query: string }>) {
    this.batchStatements = statements.map((statement) => statement.query);
    // Simulate the node being revoked immediately before the atomic batch claims it.
    // The first guarded UPDATE affects zero rows; later writes must also be guarded.
    return statements.map(() => ({ success: true, meta: { changes: 0 } }));
  }
}

test("rollback acknowledgement claims the live node before any durable writes", async () => {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const db = new RevokedDuringBatchD1();
  db.publicKeyHex = hex(publicKey);

  const body = JSON.stringify({
    operationId: "rollback-deploy-failed-1",
    failedDeploymentId: "deploy-failed-1",
    targetDeploymentId: "deploy-good-1",
    targetArtifactSha256: "a".repeat(64),
    httpStatus: 200,
    durationMs: 24,
  });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef0123456789abcdef";
  const bodyHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))));
  const canonical = [
    "NEXORA-APPLICATION-NODE-V1", nodeIdentity, timestamp, nonce, "POST", path, bodyHash,
  ].join("\n");
  const signature = hex(new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, keyPair.privateKey, new TextEncoder().encode(canonical),
  )));

  const response = await worker.fetch(new Request("https://api.test" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-node-identity": nodeIdentity,
      "x-nexora-node-timestamp": timestamp,
      "x-nexora-node-nonce": nonce,
      "x-nexora-node-signature": signature,
    },
    body,
  }), { DB: db as unknown as D1Database }, {} as ExecutionContext);

  assert.equal(response.status, 409);
  assert.equal(db.nonceInserted, true);
  assert.equal(db.batchStatements.length, 4);
  assert.match(db.batchStatements[0], /^UPDATE application_nodes SET/);
  assert.match(db.batchStatements[1], /EXISTS \(SELECT 1 FROM application_nodes n/);
  assert.match(db.batchStatements[2], /EXISTS \(SELECT 1 FROM application_nodes n/);
  assert.match(db.batchStatements[3], /EXISTS \(SELECT 1 FROM application_nodes n/);
});
