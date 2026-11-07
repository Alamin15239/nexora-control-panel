import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const artifactBytes = new TextEncoder().encode("synthetic-application-artifact");
const artifactDigestPromise = crypto.subtle.digest("SHA-256", artifactBytes).then((value) =>
  Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join(""));

class ArtifactD1 {
  node = {
    id: "runtime-node-id",
    nodeIdentity: "runtime-a",
    nodePoolId: "pool-prod-a",
    signingPublicKey: "",
    status: "online",
    role: "runtime",
    poolStatus: "ready",
    isolationLevel: "rootless",
    revokedAt: null as string | null,
  };
  release = {
    releaseId: "release-a",
    organizationId: "org-a",
    projectId: "project-a",
    deploymentId: "deployment-a",
    nodePoolId: "pool-prod-a",
    state: "ready_to_publish",
    releaseArtifactDigest: "",
    releaseArtifactBytes: artifactBytes.byteLength,
    commitSha: "0123456789abcdef0123456789abcdef01234567",
    artifactKey: "private/org-a/project-a/deployment-a.tar.gz",
    artifactBytes: artifactBytes.byteLength,
    artifactSha256: "",
    hostingAccountId: "hosting-a",
    repositoryId: "123456789",
  };
  nonces = new Set<string>();
  lastSignatureUpdated = false;

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_nodes n")) {
          const [identity] = values;
          const valid = identity === db.node.nodeIdentity &&
            db.node.status === "online" && db.node.role === "runtime" &&
            db.node.revokedAt === null && db.node.poolStatus === "ready" &&
            ["rootless", "microvm"].includes(db.node.isolationLevel) &&
            Boolean(db.node.signingPublicKey);
          return valid ? ({
            id: db.node.id,
            nodePoolId: db.node.nodePoolId,
            signingPublicKey: db.node.signingPublicKey,
          } as T) : null;
        }
        if (query.includes("FROM application_releases r")) {
          const [deploymentId, nodePoolId] = values;
          return deploymentId === db.release.deploymentId && nodePoolId === db.release.nodePoolId
            ? ({ ...db.release } as T) : null;
        }
        if (query.includes("SELECT state FROM application_releases")) {
          return ({ state: db.release.state } as T);
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
        if (query.includes("UPDATE application_releases SET state = 'publishing'")) {
          if (db.release.state !== "ready_to_publish") return { success: true, meta: { changes: 0 } };
          db.release.state = "publishing";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_nodes SET last_signature_at")) {
          db.lastSignatureUpdated = true;
        }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }
}

async function keyPair(name: "Ed25519" | "RSASSA-PKCS1-v1_5") {
  if (name === "Ed25519") {
    const pair = await crypto.subtle.generateKey({ name }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return {
      publicKey: Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join(""),
      privateKey: pair.privateKey,
    };
  }
  const pair = await crypto.subtle.generateKey({
    name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256",
  }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const pem = "-----BEGIN PRIVATE KEY-----\n" +
    btoa(String.fromCharCode(...der)).match(/.{1,64}/g)!.join("\n") +
    "\n-----END PRIVATE KEY-----";
  return { publicKey: pair.publicKey, privateKeyPEM: pem, privateKey: pair.privateKey };
}

async function signedArtifactRequest(
  privateKey: CryptoKey,
  nonce = "a".repeat(32),
  timestamp = String(Math.floor(Date.now() / 1000)),
  nodeIdentity = "runtime-a",
  deploymentId = "deployment-a",
) {
  const path = "/internal/v1/application-nodes/artifact";
  const rawBody = JSON.stringify({ deploymentId });
  const bodyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const bodyHashHex = Array.from(bodyHash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const message = [
    "NEXORA-APPLICATION-NODE-V1", nodeIdentity, timestamp, nonce, "POST", path, bodyHashHex,
  ].join("\n");
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(message)));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test" + path, {
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

async function environment(db: ArtifactD1, privateKeyPEM: string, includeArtifacts = true) {
  const artifactDigest = await artifactDigestPromise;
  db.release.releaseArtifactDigest = artifactDigest;
  db.release.artifactSha256 = artifactDigest;
  const artifacts = includeArtifacts ? {
    get: async (key: string) => key === db.release.artifactKey ? ({
      size: artifactBytes.byteLength,
      customMetadata: {
        organizationId: db.release.organizationId,
        projectId: db.release.projectId,
        deploymentId: db.release.deploymentId,
        commitSha: db.release.commitSha,
        artifactSha256: artifactDigest,
      },
      body: new Response(artifactBytes).body,
    }) : null,
  } : undefined;
  return {
    DB: db as unknown as D1Database,
    ARTIFACTS: artifacts as unknown as R2Bucket,
    GITHUB_DEPLOYMENT_ENVELOPE_PRIVATE_KEY: privateKeyPEM,
    GITHUB_DEPLOYMENT_ENVELOPE_KEY_ID: "nexora-test-key",
    GITHUB_DEPLOYMENT_ENVELOPE_ISSUER: "https://api.nexoraedge.digital",
    GITHUB_DEPLOYMENT_ENVELOPE_AUDIENCE: "nexora-runtime",
  };
}

test("artifact delivery rejects non-JSON content types before database access", async () => {
  const db = new ArtifactD1();
  const response = await worker.fetch(new Request("https://api.test/internal/v1/application-nodes/artifact", {
    method: "POST",
    headers: {
      "content-type": "text/plain",
      "x-nexora-node-identity": "runtime-a",
      "x-nexora-node-timestamp": String(Math.floor(Date.now() / 1000)),
      "x-nexora-node-nonce": "f".repeat(32),
      "x-nexora-node-signature": "0".repeat(128),
    },
    body: "{}",
  }), { DB: db as unknown as D1Database, ARTIFACTS: {} as R2Bucket }, {} as ExecutionContext);
  assert.equal(response.status, 415);
});

test("artifact delivery enforces the request body limit while streaming", async () => {
  const db = new ArtifactD1();
  const body = '{"deploymentId":"' + "x".repeat(1100) + '"}';
  const response = await worker.fetch(new Request("https://api.test/internal/v1/application-nodes/artifact", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-node-identity": "runtime-a",
      "x-nexora-node-timestamp": String(Math.floor(Date.now() / 1000)),
      "x-nexora-node-nonce": "a".repeat(32),
      "x-nexora-node-signature": "0".repeat(128),
    },
    body,
  }), { DB: db as unknown as D1Database, ARTIFACTS: {} as R2Bucket }, {} as ExecutionContext);
  assert.equal(response.status, 413);
});

test("runtime node receives a signed artifact for a release assigned to its pool", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  const response = await worker.fetch(await signedArtifactRequest(node.privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/gzip");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-nexora-artifact-sha256"), await artifactDigestPromise);
  assert.ok(response.headers.get("x-nexora-deployment-envelope"));
  assert.equal(response.headers.get("x-nexora-release-id"), "release-a");
  assert.equal(db.release.state, "publishing");
  assert.equal(db.lastSignatureUpdated, true);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), artifactBytes);
});

test("artifact delivery rejects builder nodes and untrusted runtime pools", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  db.node.role = "builder";
  const builder = await worker.fetch(await signedArtifactRequest(node.privateKey, "b".repeat(32)), env, {} as ExecutionContext);
  assert.equal(builder.status, 401);
  db.node.role = "runtime";
  db.node.isolationLevel = "untrusted";
  const untrusted = await worker.fetch(await signedArtifactRequest(node.privateKey, "c".repeat(32)), env, {} as ExecutionContext);
  assert.equal(untrusted.status, 401);
});

test("artifact delivery is scoped to the assigned node pool", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  db.release.nodePoolId = "another-pool";
  const response = await worker.fetch(await signedArtifactRequest(node.privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 404);
});

test("artifact delivery rejects a replayed request nonce", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  const nonce = "d".repeat(32);
  const first = await worker.fetch(await signedArtifactRequest(node.privateKey, nonce), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  const replay = await worker.fetch(await signedArtifactRequest(node.privateKey, nonce), env, {} as ExecutionContext);
  assert.equal(replay.status, 409);
});

test("artifact delivery rejects inconsistent release and R2 digest metadata", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  db.release.releaseArtifactDigest = "f".repeat(64);
  const response = await worker.fetch(await signedArtifactRequest(node.privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 409);
});

test("artifact delivery does not follow a request signed by a different node identity", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  const response = await worker.fetch(await signedArtifactRequest(node.privateKey, "e".repeat(32), undefined, "other-runtime"), env, {} as ExecutionContext);
  assert.equal(response.status, 401);
});

test("artifact delivery fails closed when R2 is unavailable", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM, false);
  const response = await worker.fetch(await signedArtifactRequest(node.privateKey), env, {} as ExecutionContext);
  assert.equal(response.status, 503);
});
