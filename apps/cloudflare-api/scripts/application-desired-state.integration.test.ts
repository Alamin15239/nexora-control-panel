import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

class DesiredStateD1 {
  node = {
    id: "runtime-node-a", identity: "runtime-a", status: "online", role: "runtime",
    revokedAt: null as string | null, isolation: "microvm", poolStatus: "ready",
    publicKey: "",
  };
  nonces = new Set<string>();
  rows: Array<Record<string, unknown>> = [{
    workloadId: "workload-a", projectId: "project-a", workloadKind: "web",
    workloadStatus: "healthy", desiredReplicas: 1, observedReplicas: 1,
    releaseId: "release-a", releaseState: "succeeded", releaseSpecVersion: 2,
    imageDigest: "sha256:" + "a".repeat(64), artifactDigest: "b".repeat(64),
    settingsSpecVersion: 2, runtimeProfileId: "runtime-nodejs-v1",
    runtimeProfileKey: "nodejs-v1", runtimeFamily: "nodejs", executionKind: "oci",
    listenPort: 3000, cpuMillis: 500, memoryMiB: 512, diskMiB: 2048, processLimit: 128,
  }];

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_nodes n")) {
          const eligible = db.node.identity === values[0] && db.node.status === "online" &&
            db.node.role === "runtime" && db.node.revokedAt === null &&
            db.node.isolation === "microvm" && db.node.poolStatus === "ready" && db.node.publicKey;
          return eligible ? ({ id: db.node.id, signingPublicKey: db.node.publicKey } as T) : null;
        }
        return null;
      },
      async all<T>() {
        if (!query.includes("FROM application_workloads w") || values[0] !== db.node.id) {
          return { results: [] as T[] };
        }
        return { results: db.rows as T[] };
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
}

async function makeRequest(privateKey: CryptoKey, nonce = crypto.randomUUID().replaceAll("-", "")) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const path = "/internal/v1/application-nodes/desired-state";
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

async function setup() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const db = new DesiredStateD1();
  db.node.publicKey = Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { db, privateKey: pair.privateKey, env: { DB: db as unknown as D1Database } };
}

test("desired-state polling returns only assigned workload metadata and never enables execution", async () => {
  const { db, privateKey, env } = await setup();
  const response = await worker.fetch(await makeRequest(privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json() as {
    executionEnabled: boolean; commandsIncluded: boolean; secretsIncluded: boolean;
    workloads: Array<Record<string, unknown>>;
  };
  assert.equal(body.executionEnabled, false);
  assert.equal(body.commandsIncluded, false);
  assert.equal(body.secretsIncluded, false);
  assert.equal(body.workloads.length, 1);
  assert.equal(body.workloads[0].workloadId, "workload-a");
  assert.equal(body.workloads[0].desiredState, "running");
  assert.equal("startCommand" in body.workloads[0], false);
  assert.equal("buildCommand" in body.workloads[0], false);
  assert.equal("specJson" in body.workloads[0], false);
  assert.equal(db.nonces.size, 1);
});

test("desired-state polling rejects builder, revoked and untrusted nodes", async () => {
  for (const change of [
    (db: DesiredStateD1) => { db.node.role = "builder"; },
    (db: DesiredStateD1) => { db.node.revokedAt = "2026-11-07 00:00:00"; },
    (db: DesiredStateD1) => { db.node.isolation = "untrusted"; },
    (db: DesiredStateD1) => { db.node.poolStatus = "disabled"; },
  ]) {
    const { db, privateKey, env } = await setup();
    change(db);
    const response = await worker.fetch(await makeRequest(privateKey), env, {} as ExecutionContext);
    assert.equal(response.status, 401);
    assert.equal(db.nonces.size, 0);
  }
});

test("desired-state polling rejects nonce replay", async () => {
  const { db, privateKey, env } = await setup();
  const nonce = "c".repeat(32);
  const first = await worker.fetch(await makeRequest(privateKey, nonce), env, {} as ExecutionContext);
  const replay = await worker.fetch(await makeRequest(privateKey, nonce), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  assert.equal(replay.status, 409);
});

test("desired-state polling rejects invalid signatures", async () => {
  const { privateKey, env } = await setup();
  const request = await makeRequest(privateKey);
  request.headers.set("x-nexora-node-signature", "0".repeat(128));
  const response = await worker.fetch(request, env, {} as ExecutionContext);
  assert.equal(response.status, 401);
});

test("desired-state polling returns an empty snapshot when no workloads are assigned", async () => {
  const { db, privateKey, env } = await setup();
  db.rows = [];
  const response = await worker.fetch(await makeRequest(privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as { workloads: unknown[]; executionEnabled: boolean };
  assert.deepEqual(body.workloads, []);
  assert.equal(body.executionEnabled, false);
});
