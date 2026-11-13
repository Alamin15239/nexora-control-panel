import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const validRelease = {
  deploymentId: "deployment-a",
  organizationId: "org-a",
  projectId: "project-a",
  hostingAccountId: "hosting-a",
  domainId: "domain-a",
  hostname: "www.example.test",
  repositoryId: "123456789",
  commitSha: "0123456789abcdef0123456789abcdef01234567",
  healthCheckPath: "/ready",
};

const validRollback = {
  failedDeploymentId: "deployment-failed",
  targetDeploymentId: "deployment-previous",
  failedReleaseId: "release-failed",
  targetReleaseId: "release-previous",
  organizationId: "org-a",
  projectId: "project-a",
  hostingAccountId: "hosting-a",
  hostname: "www.example.test",
  healthCheckPath: "/ready",
  targetArtifactSha256: "a".repeat(64),
};

class StaticPendingD1 {
  node = {
    id: "runtime-node-id",
    nodeIdentity: "runtime-a",
    nodePoolId: "pool-static",
    signingPublicKey: "",
  };
  nonces = new Set<string>();
  releaseRows: Array<Record<string, unknown>> = [{ ...validRelease }];
  rollbackRows: Array<Record<string, unknown>> = [{ ...validRollback }];
  queries: string[] = [];
  heartbeatUpdated = false;
  heartbeatUpdatedAfterNonce = false;

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        db.queries.push(query);
        if (query.includes("FROM application_nodes n")) {
          return values[0] === db.node.nodeIdentity
            ? ({
                id: db.node.id,
                nodePoolId: db.node.nodePoolId,
                signingPublicKey: db.node.signingPublicKey,
              } as T)
            : null;
        }
        return null;
      },
      async all<T>() {
        db.queries.push(query);
        if (query.includes("FROM application_releases failed")) {
          return { results: db.rollbackRows as T[] };
        }
        if (query.includes("FROM application_releases r")) {
          return { results: db.releaseRows as T[] };
        }
        return { results: [] as T[] };
      },
      async run() {
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          const nonce = String(values[1]);
          if (db.nonces.has(nonce)) return { success: true, meta: { changes: 0 } };
          db.nonces.add(nonce);
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_nodes SET last_heartbeat_at")) {
          db.heartbeatUpdated = true;
          db.heartbeatUpdatedAfterNonce = db.nonces.size === 1;
        }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }
}

async function setup() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const db = new StaticPendingD1();
  db.node.signingPublicKey = Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { db, privateKey: pair.privateKey, env: { DB: db as unknown as D1Database } };
}

async function signedPoll(privateKey: CryptoKey, nonce: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const path = "/internal/v1/application-nodes/pending-static-releases";
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array()));
  const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", "runtime-a", timestamp, nonce, "GET", path, digestHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, privateKey, new TextEncoder().encode(message),
  ));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test" + path, {
    method: "GET",
    headers: {
      "x-nexora-node-identity": "runtime-a",
      "x-nexora-node-timestamp": timestamp,
      "x-nexora-node-nonce": nonce,
      "x-nexora-node-signature": signatureHex,
    },
  });
}

test("static pending poll returns only well-formed assigned releases and same-node rollback intents", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.push({ ...validRelease, deploymentId: "bad-path", healthCheckPath: "/../private" });
  db.releaseRows.push({ ...validRelease, deploymentId: "bad-sha", commitSha: "not-a-commit" });
  db.rollbackRows.push({ ...validRollback, failedDeploymentId: "bad-digest", targetArtifactSha256: "invalid" });
  db.rollbackRows.push({ ...validRollback, failedDeploymentId: "bad-host", hostname: "invalid host" });

  const response = await worker.fetch(
    await signedPoll(privateKey, "1".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json() as {
    nodeIdentity: string;
    releases: Array<Record<string, unknown>>;
    rollbacks: Array<Record<string, unknown>>;
  };
  assert.equal(body.nodeIdentity, "runtime-a");
  assert.deepEqual(body.releases, [validRelease]);
  assert.deepEqual(body.rollbacks, [validRollback]);
  const nodeQuery = db.queries.find((query) => query.includes("FROM application_nodes n"));
  assert.ok(nodeQuery);
  assert.match(nodeQuery, /p\\.runtime_engine = 'static'/);
  assert.match(nodeQuery, /p\\.isolation_level = 'untrusted'/);
  assert.equal(db.heartbeatUpdated, true);
  assert.equal(db.heartbeatUpdatedAfterNonce, true);
  const heartbeatQuery = db.queries.find((query) => query.includes("UPDATE application_nodes SET last_heartbeat_at"));
  assert.ok(heartbeatQuery);
  assert.match(heartbeatQuery, /signing_public_key = \\?/);

  const releaseQuery = db.queries.find((query) => query.includes("FROM application_releases r"));
  const rollbackQuery = db.queries.find((query) => query.includes("FROM application_releases failed"));
  assert.ok(releaseQuery);
  assert.match(releaseQuery, /r\.state = 'artifact_uploaded'/);
  assert.match(releaseQuery, /rp\.enabled = 1/);
  assert.match(releaseQuery, /r\.assigned_node_id = \?/);
  assert.ok(rollbackQuery);
  assert.match(rollbackQuery, /failed\.state = 'failed'/);
  assert.match(rollbackQuery, /target\.state = 'succeeded'/);
  assert.match(rollbackQuery, /target\.assigned_node_id = \?/);
  assert.match(rollbackQuery, /NOT EXISTS \(SELECT 1 FROM application_rollback_acknowledgements/);
});

test("static pending poll rejects nonce replay", async () => {
  const { db, privateKey, env } = await setup();
  const nonce = "2".repeat(32);
  const first = await worker.fetch(await signedPoll(privateKey, nonce), env, {} as ExecutionContext);
  const replay = await worker.fetch(await signedPoll(privateKey, nonce), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  assert.equal(replay.status, 409);
  assert.equal(db.nonces.size, 1);
});
