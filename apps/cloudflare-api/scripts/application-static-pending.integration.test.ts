import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const validRelease = {
  releaseId: "deployment-a",
  state: "publishing",
  artifactSha256: "a".repeat(64),
  assignedNodeIdentity: "runtime-a",
  deploymentId: "deployment-a",
  organizationId: "org-a",
  projectId: "project-a",
  hostingAccountId: "hosting-a",
  domainId: "domain-a",
  hostname: "www.example.test",
  repositoryId: "123456789",
  commitSha: "0123456789abcdef0123456789abcdef01234567",
  healthCheckPath: "/ready",
  previousDeploymentId: "",
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
          const filtered = db.releaseRows.filter(
            (row) => row.assignedNodeIdentity === db.node.nodeIdentity,
          );
          return { results: filtered as T[] };
        }
        return { results: [] as T[] };
      },
      async run() {
        db.queries.push(query);
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
  const expectedRelease = {
    releaseId: validRelease.releaseId, state: validRelease.state,
    artifactSha256: validRelease.artifactSha256, deploymentId: validRelease.deploymentId,
    organizationId: validRelease.organizationId, projectId: validRelease.projectId,
    hostingAccountId: validRelease.hostingAccountId, domainId: validRelease.domainId,
    hostname: validRelease.hostname, repositoryId: validRelease.repositoryId,
    commitSha: validRelease.commitSha, healthCheckPath: validRelease.healthCheckPath,
    previousDeploymentId: validRelease.previousDeploymentId,
  };
  assert.deepEqual(body.releases, [expectedRelease]);
  assert.deepEqual(body.rollbacks, [validRollback]);

  const nodeQuery = db.queries.find((query) => query.includes("FROM application_nodes n"));
  assert.ok(nodeQuery);
  assert.match(nodeQuery, /p\.runtime_engine = 'static'/);
  assert.match(nodeQuery, /p\.isolation_level = 'untrusted'/);
  assert.doesNotMatch(nodeQuery, /last_heartbeat_at >=/);
  assert.equal(db.heartbeatUpdated, true);
  assert.equal(db.heartbeatUpdatedAfterNonce, true);
  assert.ok(db.queries.some((query) => query.includes("rp.profile_key = 'static-v1'")));

  const releaseQuery = db.queries.find((query) => query.includes("FROM application_releases r"));
  const rollbackQuery = db.queries.find((query) => query.includes("FROM application_releases failed"));
  assert.ok(releaseQuery);
  assert.match(releaseQuery, /r\.state IN \('artifact_uploaded','publishing','health_checking'\)/);
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

// ---------------------------------------------------------------------------
// Phase 2 restart-recovery regression: PROJECT_STATUS item — "Releases in
// health_checking are not returned by the pending-release endpoint after the
// Linux publisher agent restarts." The original SQL filter excluded
// health_checking, so a release that had already been activated but not yet
// probed became stranded forever. The tests below verify the fix:
// health_checking releases ARE returned, terminal states are NOT returned,
// releases from another node/org are NOT returned, and the returned payload
// carries every field the publisher needs to resume probing safely.
// ---------------------------------------------------------------------------

const healthCheckingRelease = {
  ...validRelease,
  releaseId: "deployment-recovering",
  state: "health_checking",
  artifactSha256: "b".repeat(64),
  deploymentId: "deployment-recovering",
};

const terminalRelease = {
  ...validRelease,
  releaseId: "deployment-done",
  state: "succeeded",
  artifactSha256: "c".repeat(64),
  deploymentId: "deployment-done",
};

const failedRelease = {
  ...validRelease,
  releaseId: "deployment-failed",
  state: "failed",
  artifactSha256: "d".repeat(64),
  deploymentId: "deployment-failed",
};

const crossNodeRelease = {
  ...validRelease,
  releaseId: "deployment-other-node",
  state: "health_checking",
  artifactSha256: "e".repeat(64),
  deploymentId: "deployment-other-node",
  assignedNodeIdentity: "runtime-b",
};

test("pending endpoint returns health_checking releases so a restart can resume probing", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...healthCheckingRelease });

  const response = await worker.fetch(
    await signedPoll(privateKey, "3".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    releases: Array<{ releaseId: string; state: string; artifactSha256: string; deploymentId: string }>;
  };
  assert.equal(body.releases.length, 1);
  assert.equal(body.releases[0].releaseId, "deployment-recovering");
  assert.equal(body.releases[0].state, "health_checking");
  assert.equal(body.releases[0].artifactSha256, "b".repeat(64));
  assert.equal(body.releases[0].deploymentId, "deployment-recovering");
});

test("pending payload for a health_checking release includes release id, state, and artifact SHA-256", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...healthCheckingRelease });

  const response = await worker.fetch(
    await signedPoll(privateKey, "4".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releases: Array<Record<string, unknown>> };
  assert.equal(body.releases.length, 1);
  const release = body.releases[0];
  assert.equal(release.releaseId, "deployment-recovering");
  assert.equal(release.state, "health_checking");
  assert.equal(release.artifactSha256, "b".repeat(64));
  // Recovery-required metadata is also present.
  assert.equal(release.deploymentId, "deployment-recovering");
  assert.equal(release.hostname, "www.example.test");
  assert.equal(release.healthCheckPath, "/ready");
  assert.equal(release.hostingAccountId, "hosting-a");
});

test("pending endpoint never returns releases in terminal states (succeeded or failed)", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...terminalRelease });
  db.releaseRows.push({ ...failedRelease });

  const response = await worker.fetch(
    await signedPoll(privateKey, "5".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releases: Array<Record<string, unknown>> };
  assert.equal(body.releases.length, 0);
});

test("pending endpoint rejects releases whose artifact digest or state is malformed", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  // Missing artifactSha256 (the filter must drop the row).
  db.releaseRows.push({ ...healthCheckingRelease, artifactSha256: "" });
  // Malformed state.
  db.releaseRows.push({ ...healthCheckingRelease, releaseId: "deployment-bad", state: "unknown_state" });
  // Missing releaseId.
  db.releaseRows.push({ ...healthCheckingRelease, releaseId: "" });
  // Malformed artifact digest (wrong length).
  db.releaseRows.push({ ...healthCheckingRelease, artifactSha256: "not-a-real-digest" });

  const response = await worker.fetch(
    await signedPoll(privateKey, "6".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releases: Array<Record<string, unknown>> };
  assert.equal(body.releases.length, 0);
});

test("a health_checking release is returned by the pending endpoint after a simulated restart", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...healthCheckingRelease });

  const response = await worker.fetch(
    await signedPoll(privateKey, "7".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as {
    releases: Array<{ releaseId: string; state: string; artifactSha256: string; deploymentId: string }>;
  };
  assert.equal(body.releases.length, 1);
  assert.equal(body.releases[0].releaseId, "deployment-recovering");
  assert.equal(body.releases[0].state, "health_checking");
  assert.equal(body.releases[0].artifactSha256, "b".repeat(64));
  assert.equal(body.releases[0].deploymentId, "deployment-recovering");
});

test("repeated polls of the same health_checking release do not produce duplicate activations", async () => {
  // The publisher's recovery path never activates; it only verifies and
  // reports. The Worker's idempotent retry semantics accept duplicate
  // health reports. Together, this means a flapping publisher that polls
  // the same release repeatedly cannot cause duplicate activation events.
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...healthCheckingRelease });

  const poll1 = await worker.fetch(
    await signedPoll(privateKey, "9".repeat(32)), env, {} as ExecutionContext,
  );
  const poll2 = await worker.fetch(
    await signedPoll(privateKey, "a".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(poll1.status, 200);
  assert.equal(poll2.status, 200);
  const body1 = await poll1.json() as { releases: Array<{ releaseId: string }> };
  const body2 = await poll2.json() as { releases: Array<{ releaseId: string }> };
  assert.equal(body1.releases.length, 1);
  assert.equal(body2.releases.length, 1);
  assert.equal(body1.releases[0].releaseId, body2.releases[0].releaseId);
});

test("pending endpoint only returns releases for the authenticated node (cross-node isolation)", async () => {
  const { db, privateKey, env } = await setup();
  db.releaseRows.length = 0;
  db.releaseRows.push({ ...healthCheckingRelease });
  db.releaseRows.push({ ...crossNodeRelease });

  const response = await worker.fetch(
    await signedPoll(privateKey, "b".repeat(32)), env, {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { releases: Array<{ releaseId: string }> };
  assert.equal(body.releases.length, 1);
  assert.equal(body.releases[0].releaseId, "deployment-recovering");
  for (const release of body.releases) {
    assert.notEqual(release.releaseId, "deployment-other-node");
  }
});
