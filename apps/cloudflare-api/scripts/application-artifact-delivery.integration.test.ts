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
    assignedNodeId: "runtime-node-id",
    state: "ready_to_publish",
    releaseArtifactDigest: "",
    releaseArtifactBytes: artifactBytes.byteLength,
    commitSha: "0123456789abcdef0123456789abcdef01234567",
    artifactKey: "private/org-a/project-a/deployment-a.tar.gz",
    artifactBytes: artifactBytes.byteLength,
    artifactSha256: "",
    hostingAccountId: "hosting-a",
    domainId: "domain-a",
    hostname: "www.example.test",
    repositoryId: "123456789",
    healthCheckPath: "/ready",
    previousActiveReleaseId: "previous-release",
    previousDeploymentId: "previous-deployment",
    previousArtifactDigest: "b".repeat(64),
    previousActiveNodeId: "previous-runtime-node",
    previousActiveNodeIdentity: "runtime-a",
  };
  nonces = new Set<string>();
  lastSignatureUpdated = false;
  validationEventDetails: string | null = null;
  activationEventDetails: string | null = null;
  healthEventDetails: string | null = null;
  workloadStatus: string | null = null;
  githubDeploymentStatus = "building";

  async batch(statements: Array<{ run: () => Promise<{ success: boolean; meta: { changes: number } }> }>) {
    const results = [];
    for (const statement of statements) results.push(await statement.run());
    return results;
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_nodes n")) {
          const identity = query.includes("n.id = ? AND n.node_identity = ?")
            ? values[1] : values[0];
          const idMatches = !query.includes("n.id = ? AND n.node_identity = ?") || values[0] === db.node.id;
          const valid = idMatches && identity === db.node.nodeIdentity &&
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
        if (query.includes("SELECT id FROM application_release_events")) {
          if (query.includes("release_files_activated")) {
            return db.activationEventDetails === values[1] ? ({ id: "activation-event" } as T) : null;
          }
          if (values[1] === "health_check_succeeded" || values[1] === "health_check_failed") {
            return db.healthEventDetails === values[2] ? ({ id: "health-event" } as T) : null;
          }
          return db.validationEventDetails === values[1] ? ({ id: "validation-event" } as T) : null;
        }
        if (query.includes("FROM application_releases r") && query.includes("healthCheckPath")) {
          const [deploymentId, nodePoolId, assignedNodeId] = values;
          return deploymentId === db.release.deploymentId && nodePoolId === db.release.nodePoolId &&
            assignedNodeId === db.node.id && assignedNodeId === db.release.assignedNodeId
            ? ({
                releaseRowId: db.release.releaseId,
                state: db.release.state,
                artifactDigest: db.release.releaseArtifactDigest,
                deploymentArtifactDigest: db.release.artifactSha256,
                projectId: db.release.projectId,
                organizationId: db.release.organizationId,
                healthCheckPath: db.release.healthCheckPath,
                previousActiveReleaseId: db.release.previousActiveReleaseId,
                previousDeploymentId: db.release.previousDeploymentId,
                previousArtifactDigest: db.release.previousArtifactDigest,
                previousActiveNodeId: db.release.previousActiveNodeId,
                previousActiveNodeIdentity: db.release.previousActiveNodeIdentity,
              } as T) : null;
        }
        if (query.includes("FROM application_releases r") && query.includes("deploymentArtifactDigest")) {
          const [deploymentId, nodePoolId, assignedNodeId] = values;
          if (deploymentId !== db.release.deploymentId || nodePoolId !== db.release.nodePoolId ||
              assignedNodeId !== db.node.id || assignedNodeId !== db.release.assignedNodeId) return null;
          if (query.includes("releaseArtifactBytes")) {
            return ({
              releaseId: db.release.releaseId,
              state: db.release.state,
              artifactDigest: db.release.releaseArtifactDigest,
              releaseArtifactBytes: db.release.releaseArtifactBytes,
              deploymentArtifactDigest: db.release.artifactSha256,
              deploymentArtifactBytes: db.release.artifactBytes,
            } as T);
          }
          return ({
            releaseId: db.release.releaseId,
            state: db.release.state,
            artifactDigest: db.release.releaseArtifactDigest,
            deploymentArtifactDigest: db.release.artifactSha256,
            nodePoolId: db.release.nodePoolId,
          } as T);
        }
        if (query.includes("FROM application_releases r")) {
          const [deploymentId, nodePoolId, assignedNodeId] = values;
          const purpose = values[3];
          const stateAllowed = purpose === "validate"
            ? ["artifact_uploaded", "validating", "publishing"].includes(db.release.state)
            : ["ready_to_publish", "publishing"].includes(db.release.state);
          return deploymentId === db.release.deploymentId && nodePoolId === db.release.nodePoolId &&
            assignedNodeId === db.node.id && assignedNodeId === db.release.assignedNodeId &&
            stateAllowed ? ({ ...db.release } as T) : null;
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
        if (query.includes("UPDATE application_releases SET state = 'validating'")) {
          if (db.release.state !== "artifact_uploaded") return { success: true, meta: { changes: 0 } };
          db.release.state = "validating";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_releases SET state = 'ready_to_publish'")) {
          if (db.release.state !== "validating") return { success: true, meta: { changes: 0 } };
          db.release.state = "ready_to_publish";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_releases SET state = 'publishing'")) {
          if (db.release.state !== "ready_to_publish") return { success: true, meta: { changes: 0 } };
          db.release.state = "publishing";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_releases SET state = 'health_checking'")) {
          if (db.release.state !== "publishing") return { success: true, meta: { changes: 0 } };
          db.release.state = "health_checking";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_releases SET state = 'succeeded'")) {
          if (db.release.state !== "health_checking") return { success: true, meta: { changes: 0 } };
          db.release.state = "succeeded";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_releases SET state = 'failed'")) {
          if (db.release.state !== "health_checking") return { success: true, meta: { changes: 0 } };
          db.release.state = "failed";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("INSERT INTO application_release_events") &&
            (query.includes("health_check_succeeded") || query.includes("health_check_failed"))) {
          db.healthEventDetails = String(values[2]);
        }
        if (query.includes("INSERT INTO application_workloads")) {
          db.workloadStatus = query.includes("'healthy'") ? "healthy" : "unhealthy";
        }
        if (query.includes("INSERT INTO application_release_events") && query.includes("archive_validated_for_publish")) {
          db.validationEventDetails = String(values[2]);
        }
        if (query.includes("INSERT INTO application_release_events") && query.includes("release_files_activated")) {
          db.activationEventDetails = String(values[2]);
        }
        if (query.includes("UPDATE github_deployments SET status = 'succeeded'")) {
          if (db.githubDeploymentStatus !== "building") return { success: true, meta: { changes: 0 } };
          db.githubDeploymentStatus = "succeeded";
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE github_deployments SET status = 'failed'")) {
          if (db.githubDeploymentStatus !== "building") return { success: true, meta: { changes: 0 } };
          db.githubDeploymentStatus = "failed";
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

async function signedValidationReportRequest(
  privateKey: CryptoKey,
  report: {
    deploymentId: string; artifactSha256: string;
    archiveEntries: number; archiveFiles: number; archiveBytes: number;
  },
  nonce = "9".repeat(32),
  nodeIdentity = "runtime-a",
) {
  const path = "/internal/v1/application-nodes/releases/validated";
  const rawBody = JSON.stringify(report);
  const bodyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const bodyHashHex = Array.from(bodyHash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const timestamp = String(Math.floor(Date.now() / 1000));
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

async function signedActivationRequest(
  privateKey: CryptoKey,
  report: { deploymentId: string; releaseId: string; artifactSha256: string },
  nonce = "8".repeat(32),
  nodeIdentity = "runtime-a",
) {
  const path = "/internal/v1/application-nodes/releases/activated";
  const rawBody = JSON.stringify(report);
  const bodyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const bodyHashHex = Array.from(bodyHash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const timestamp = String(Math.floor(Date.now() / 1000));
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

async function signedHealthCheckRequest(
  privateKey: CryptoKey,
  report: {
    deploymentId: string; artifactSha256: string; probePath: string;
    healthStatus: "healthy" | "unhealthy"; httpStatus: number; durationMs: number; failureCode?: string;
  },
  nonce = "7".repeat(32),
  nodeIdentity = "runtime-a",
) {
  const path = "/internal/v1/application-nodes/releases/health-check";
  const rawBody = JSON.stringify(report);
  const bodyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
  const bodyHashHex = Array.from(bodyHash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const timestamp = String(Math.floor(Date.now() / 1000));
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
  const envelope = response.headers.get("x-nexora-deployment-envelope");
  assert.ok(envelope);
  const claims = JSON.parse(atob(envelope!.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
  assert.equal(claims.domain_id, "domain-a");
  assert.equal(claims.hostname, "www.example.test");
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

test("runtime node cannot fetch another node's assigned release in the same pool", async () => {
  const db = new ArtifactD1();
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  const signer = await keyPair("RSASSA-PKCS1-v1_5");
  const env = await environment(db, signer.privateKeyPEM);
  db.release.assignedNodeId = "another-runtime-node";
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

test("signed runtime archive validation advances release to publishing", async () => {
  const db = new ArtifactD1();
  db.release.state = "artifact_uploaded";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a",
    artifactSha256: await artifactDigestPromise,
    archiveEntries: 3,
    archiveFiles: 2,
    archiveBytes: 4096,
  };
  const env = { DB: db as unknown as D1Database };
  const response = await worker.fetch(await signedValidationReportRequest(node.privateKey, report), env, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; releaseState: string; duplicate: boolean };
  assert.equal(body.accepted, true);
  assert.equal(body.releaseState, "publishing");
  assert.equal(body.duplicate, false);
  assert.equal(db.release.state, "publishing");
  assert.ok(db.validationEventDetails);
});

test("signed runtime archive validation is idempotent only for the same report", async () => {
  const db = new ArtifactD1();
  db.release.state = "artifact_uploaded";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a",
    artifactSha256: await artifactDigestPromise,
    archiveEntries: 3,
    archiveFiles: 2,
    archiveBytes: 4096,
  };
  const env = { DB: db as unknown as D1Database };
  const first = await worker.fetch(await signedValidationReportRequest(node.privateKey, report, "1".repeat(32)), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  const duplicate = await worker.fetch(await signedValidationReportRequest(node.privateKey, report, "2".repeat(32)), env, {} as ExecutionContext);
  assert.equal(duplicate.status, 200);
  const duplicateBody = await duplicate.json() as { duplicate: boolean };
  assert.equal(duplicateBody.duplicate, true);
  const changed = await worker.fetch(await signedValidationReportRequest(node.privateKey, { ...report, archiveBytes: 4097 }, "3".repeat(32)), env, {} as ExecutionContext);
  assert.equal(changed.status, 409);
});

test("archive validation report rejects digest mismatch and unsafe node identity", async () => {
  const db = new ArtifactD1();
  db.release.state = "artifact_uploaded";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a",
    artifactSha256: "f".repeat(64),
    archiveEntries: 3,
    archiveFiles: 2,
    archiveBytes: 4096,
  };
  const env = { DB: db as unknown as D1Database };
  const mismatch = await worker.fetch(await signedValidationReportRequest(node.privateKey, report), env, {} as ExecutionContext);
  assert.equal(mismatch.status, 409);
  const wrongNode = await worker.fetch(await signedValidationReportRequest(node.privateKey, {
    ...report, artifactSha256: await artifactDigestPromise,
  }, "4".repeat(32), "another-runtime"), env, {} as ExecutionContext);
  assert.equal(wrongNode.status, 401);
  assert.equal(db.release.state, "artifact_uploaded");
});



test("signed release activation advances publishing to health_checking, not succeeded", async () => {
  const db = new ArtifactD1();
  db.release.state = "publishing";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a",
    releaseId: "deployment-a",
    artifactSha256: await artifactDigestPromise,
  };
  const response = await worker.fetch(await signedActivationRequest(node.privateKey, report),
    { DB: db as unknown as D1Database }, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; releaseState: string; workloadHealth: string };
  assert.equal(body.accepted, true);
  assert.equal(body.releaseState, "health_checking");
  assert.equal(body.workloadHealth, "pending");
  assert.equal(db.release.state, "health_checking");
  assert.ok(db.activationEventDetails);
});

test("release activation acknowledgement is idempotent for an exact report", async () => {
  const db = new ArtifactD1();
  db.release.state = "publishing";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a",
    releaseId: "deployment-a",
    artifactSha256: await artifactDigestPromise,
  };
  const env = { DB: db as unknown as D1Database };
  const first = await worker.fetch(await signedActivationRequest(node.privateKey, report, "5".repeat(32)), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  const duplicate = await worker.fetch(await signedActivationRequest(node.privateKey, report, "6".repeat(32)), env, {} as ExecutionContext);
  assert.equal(duplicate.status, 200);
  const body = await duplicate.json() as { duplicate: boolean; releaseState: string };
  assert.equal(body.duplicate, true);
  assert.equal(body.releaseState, "health_checking");
});

test("release activation rejects digest mismatch, unassigned node, and replayed nonce", async () => {
  const db = new ArtifactD1();
  db.release.state = "publishing";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const env = { DB: db as unknown as D1Database };
  const mismatch = await worker.fetch(await signedActivationRequest(node.privateKey, {
    deploymentId: "deployment-a", releaseId: "deployment-a", artifactSha256: "f".repeat(64),
  }, "7".repeat(32)), env, {} as ExecutionContext);
  assert.equal(mismatch.status, 409);
  const wrongNode = await worker.fetch(await signedActivationRequest(node.privateKey, {
    deploymentId: "deployment-a", releaseId: "deployment-a", artifactSha256: await artifactDigestPromise,
  }, "8".repeat(32), "another-runtime"), env, {} as ExecutionContext);
  assert.equal(wrongNode.status, 401);
  const nonce = "9".repeat(32);
  const valid = await worker.fetch(await signedActivationRequest(node.privateKey, {
    deploymentId: "deployment-a", releaseId: "deployment-a", artifactSha256: await artifactDigestPromise,
  }, nonce), env, {} as ExecutionContext);
  assert.equal(valid.status, 200);
  const replay = await worker.fetch(await signedActivationRequest(node.privateKey, {
    deploymentId: "deployment-a", releaseId: "deployment-a", artifactSha256: await artifactDigestPromise,
  }, nonce), env, {} as ExecutionContext);
  assert.equal(replay.status, 409);
});


test("signed successful health check marks the release succeeded and workload healthy", async () => {
  const db = new ArtifactD1();
  db.release.state = "health_checking";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a", artifactSha256: await artifactDigestPromise,
    probePath: "/ready", healthStatus: "healthy" as const, httpStatus: 200, durationMs: 37,
  };
  const response = await worker.fetch(await signedHealthCheckRequest(node.privateKey, report),
    { DB: db as unknown as D1Database }, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as { accepted: boolean; releaseState: string; workloadHealth: string };
  assert.equal(body.accepted, true);
  assert.equal(body.releaseState, "succeeded");
  assert.equal(body.workloadHealth, "healthy");
  assert.equal(db.release.state, "succeeded");
  assert.equal(db.workloadStatus, "healthy");
  assert.equal(db.githubDeploymentStatus, "succeeded");
  assert.ok(db.healthEventDetails);
});

test("signed failed health check records failure and returns the prior rollback target", async () => {
  const db = new ArtifactD1();
  db.release.state = "health_checking";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a", artifactSha256: await artifactDigestPromise,
    probePath: "/ready", healthStatus: "unhealthy" as const, httpStatus: 503,
    durationMs: 30000, failureCode: "http_5xx",
  };
  const response = await worker.fetch(await signedHealthCheckRequest(node.privateKey, report),
    { DB: db as unknown as D1Database }, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as {
    releaseState: string; rollbackRequired: boolean; rollbackTargetDeploymentId: string | null;
    rollbackTargetNodeIdentity: string | null;
  };
  assert.equal(body.releaseState, "failed");
  assert.equal(body.rollbackRequired, true);
  assert.equal(body.rollbackTargetDeploymentId, "previous-deployment");
  assert.equal(body.rollbackTargetNodeIdentity, "runtime-a");
  assert.equal(db.release.state, "failed");
  assert.equal(db.workloadStatus, "unhealthy");
  assert.equal(db.githubDeploymentStatus, "failed");
});

test("failed health check on another node preserves the previous workload without requesting a local rollback", async () => {
  const db = new ArtifactD1();
  db.release.state = "health_checking";
  db.release.previousActiveNodeIdentity = "previous-runtime-node";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a", artifactSha256: await artifactDigestPromise,
    probePath: "/ready", healthStatus: "unhealthy" as const, httpStatus: 503,
    durationMs: 30, failureCode: "http_5xx",
  };
  const response = await worker.fetch(await signedHealthCheckRequest(node.privateKey, report),
    { DB: db as unknown as D1Database }, {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as {
    releaseState: string; rollbackRequired: boolean;
    rollbackTargetDeploymentId: string | null; rollbackTargetNodeIdentity: string | null;
  };
  assert.equal(body.releaseState, "failed");
  assert.equal(body.rollbackRequired, false);
  assert.equal(body.rollbackTargetDeploymentId, null);
  assert.equal(body.rollbackTargetNodeIdentity, null);
});

test("health-check report rejects mismatched configured path and digest", async () => {
  const db = new ArtifactD1();
  db.release.state = "health_checking";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const env = { DB: db as unknown as D1Database };
  const wrongPath = await worker.fetch(await signedHealthCheckRequest(node.privateKey, {
    deploymentId: "deployment-a", artifactSha256: await artifactDigestPromise,
    probePath: "/wrong", healthStatus: "healthy", httpStatus: 200, durationMs: 1,
  }), env, {} as ExecutionContext);
  assert.equal(wrongPath.status, 409);
  const wrongDigest = await worker.fetch(await signedHealthCheckRequest(node.privateKey, {
    deploymentId: "deployment-a", artifactSha256: "f".repeat(64),
    probePath: "/ready", healthStatus: "healthy", httpStatus: 200, durationMs: 1,
  }, "6".repeat(32)), env, {} as ExecutionContext);
  assert.equal(wrongDigest.status, 409);
  assert.equal(db.release.state, "health_checking");
});

test("successful health-check report is idempotent only for an exact duplicate", async () => {
  const db = new ArtifactD1();
  db.release.state = "health_checking";
  const node = await keyPair("Ed25519");
  db.node.signingPublicKey = node.publicKey;
  db.release.releaseArtifactDigest = await artifactDigestPromise;
  db.release.artifactSha256 = await artifactDigestPromise;
  const report = {
    deploymentId: "deployment-a", artifactSha256: await artifactDigestPromise,
    probePath: "/ready", healthStatus: "healthy" as const, httpStatus: 200, durationMs: 37,
  };
  const env = { DB: db as unknown as D1Database };
  const first = await worker.fetch(await signedHealthCheckRequest(node.privateKey, report, "1".repeat(32)), env, {} as ExecutionContext);
  assert.equal(first.status, 200);
  const duplicate = await worker.fetch(await signedHealthCheckRequest(node.privateKey, report, "2".repeat(32)), env, {} as ExecutionContext);
  assert.equal(duplicate.status, 200);
  const body = await duplicate.json() as { duplicate: boolean; releaseState: string };
  assert.equal(body.duplicate, true);
  assert.equal(body.releaseState, "succeeded");
});
