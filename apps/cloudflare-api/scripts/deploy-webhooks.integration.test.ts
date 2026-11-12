import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// deploy-webhooks.integration.test.ts
//
// Regression tests for the Nexora Deploy batch-4 routes:
//
//   * POST /v1/github/webhooks — HMAC-verified push/PR receiver, idempotent
//     by delivery id, with an auditable outcome for every decision.
//   * PUT  /v1/github/projects/:id/webhook-secret — one-time secret rotation.
//   * POST /v1/github/projects/:id/deployments/:deploymentId/promote —
//     alias re-point (no rebuild).
//   * POST /v1/github/projects/:id/deployments — manual dispatch through the
//     shared dispatcher (same gates as webhooks).
//
// The GitHub REST surface (App installation tokens, commit resolution,
// workflow dispatch) is stubbed at the network boundary. The D1 mock
// implements only the SQL these routes issue; every other query throws so
// endpoint drift fails loudly.
//
// Scenarios:
//   1.  Valid push webhook dispatches a production deployment (verified
//       signature, recorded outcome, deployment kind/trigger persisted).
//   2.  Invalid or missing signature is a uniform 401 with no ledger row
//       and no deployment — untracked repositories leak nothing either.
//   3.  Replayed delivery id returns skipped_replay without double records.
//   4.  auto_deploy disabled / deleted branch / branch mismatch / ignored
//       paths / [skip deploy] commit message / in-flight deployments each
//       produce their specific recorded outcome without dispatching.
//   5.  Pull requests dispatch preview deployments only when previews are
//       enabled; closed PRs and disabled previews are recorded skips.
//   6.  A rejected workflow dispatch is recorded as an error outcome, the
//       deployment is marked failed, and GitHub still gets a 200.
//   7.  Webhook secret rotation returns the raw secret once and stores it
//       encrypted; each rotation produces a different secret.
//   8.  Promotion re-points the production alias at the preview release
//       without rebuilding; non-preview, unhealthy, or alias-less targets
//       are refused; cross-tenant projects are 404.
//   9.  Manual dispatch through the shared dispatcher still honors every
//       prerequisite (runtime admission) and returns 202 on success.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "c".repeat(64);
const SESSION_HASH = createHash("sha256").update(SESSION_TOKEN).digest("hex");
const ORG_A = "11111111-1111-4111-8111-111111111111";
const OWNER_A = "aaaaaaa1-0000-4000-8000-000000000001";
const ACCOUNT_1 = "eeeeeee1-0000-4000-8000-000000000008";
const PROJECT_1 = "b1000000-0000-4000-8000-000000000001";
const REPO_ID = 98765432;
const REPO_FULL = "acme/landing";
const TOKEN_KEY = "f".repeat(64);
const WEBHOOK_SECRET = "whsec_" + "3".repeat(40);

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function encryptWithKey(hexKey: string, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const keyBytes = Uint8Array.from(hexKey.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)));
  return { ciphertext: base64(encrypted), iv: base64(iv) };
}

function signPayload(secret: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

const COMMIT_SHA = "a".repeat(40);

type ProjectRow = {
  id: string; organization_id: string; repositoryFullName: string; repositoryId: string;
  installationId: string | null; productionBranch: string; trustedWorkflowSha: string | null;
  status: string; auto_deploy: number; preview_enabled: number; ignored_build_paths: string;
  outputDirectory: string; webhookSecretEncrypted: string | null; webhookSecretIv: string | null;
};

type DeploymentRow = {
  id: string; project_id: string; organization_id: string; commit_sha: string; branch: string;
  trigger_type: string; status: string; deployment_kind: string;
};

class WebhookD1 {
  project: ProjectRow;
  deployments = new Map<string, DeploymentRow>();
  releases = new Map<string, { id: string; deployment_id: string; state: string; artifactDigest: string | null }>();
  releaseEvents: Array<{ releaseId: string; eventCode: string }> = [];
  deliveries = new Map<string, { outcome: string; detail: string; eventType: string; branch: string | null; commitSha: string | null }>();
  aliases = new Map<string, { id: string; alias: string; kind: string; releaseId: string | null; deploymentId: string | null; status: string }>();
  auditActions: string[] = [];
  runtimeAssignment: Record<string, unknown> | null = {
    runtimeProfileId: "rp-1", specVersion: 1, nodePoolId: "pool-1",
    runtimeEnabled: 1, profileKey: "static-v1", runtimeFamily: "static",
    buildMethod: "static", poolStatus: "ready", isolationLevel: "rootless",
    assignedNodeId: "node-1",
  };
  dispatchStatus = 204;
  commitStatus = 200;
  identity: { id: string; email: string; displayName: string | null; organizationId: string; organizationName: string; organizationSlug: string; role: string; platformRole: string | null } | null = null;

  constructor() {
    this.project = {
      id: PROJECT_1,
      organization_id: ORG_A,
      repositoryFullName: REPO_FULL,
      repositoryId: String(REPO_ID),
      installationId: "12345",
      productionBranch: "main",
      trustedWorkflowSha: "e".repeat(40),
      status: "configured",
      auto_deploy: 1,
      preview_enabled: 1,
      ignored_build_paths: "[]",
      outputDirectory: "dist",
      webhookSecretEncrypted: null,
      webhookSecretIv: null,
    };
  }

  async seedWebhookSecret(secret: string) {
    const encrypted = await encryptWithKey(TOKEN_KEY, secret);
    this.project.webhookSecretEncrypted = encrypted.ciphertext;
    this.project.webhookSecretIv = encrypted.iv;
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      getValues() { return values; },
      async first<T>(): Promise<T | null> {
        if (query.includes("FROM auth_sessions")) {
          return db.identity ? { ...db.identity } as T : null;
        }
        if (query.includes("WHERE github_repository_id = ?") && !query.includes("SELECT id, organization_id FROM github_projects")) {
          throw new Error("candidates query must use all(): " + query.slice(0, 100));
        }
        if (query.startsWith("SELECT id, organization_id FROM github_projects")) {
          const [projectId, orgId] = values as [string, string];
          if (projectId === db.project.id && orgId === db.project.organization_id) {
            return { id: db.project.id, organization_id: db.project.organization_id } as T;
          }
          return null;
        }
        if (query.includes("FROM application_project_settings s") && query.includes("application_runtime_profiles")) {
          return db.runtimeAssignment ? { ...db.runtimeAssignment } as T : null;
        }
        if (query.includes("FROM github_projects p") && query.includes("LEFT JOIN application_project_settings s")) {
          const [projectId, orgId] = values as [string, string];
          if (projectId === db.project.id && orgId === db.project.organization_id) {
            return {
              id: db.project.id, repositoryId: db.project.repositoryId,
              repositoryFullName: db.project.repositoryFullName, installationId: db.project.installationId,
              productionBranch: db.project.productionBranch, trustedWorkflowSha: db.project.trustedWorkflowSha,
              status: db.project.status, outputDirectory: db.project.outputDirectory,
            } as T;
          }
          return null;
        }
        if (query.startsWith("SELECT auto_deploy, preview_enabled, ignored_build_paths FROM github_projects")) {
          const [projectId, orgId] = values as [string, string];
          if (projectId === db.project.id && orgId === db.project.organization_id) {
            return {
              auto_deploy: db.project.auto_deploy,
              preview_enabled: db.project.preview_enabled,
              ignored_build_paths: db.project.ignored_build_paths,
            } as T;
          }
          return null;
        }
        if (query.startsWith("SELECT id FROM github_deployments WHERE project_id")) {
          const [projectId] = values as [string];
          for (const row of db.deployments.values()) {
            if (row.project_id === projectId && ["queued", "cloning", "installing", "building", "publishing"].includes(row.status)) {
              return { id: row.id } as T;
            }
          }
          return null;
        }
        if (query.startsWith("SELECT id FROM github_webhook_deliveries WHERE delivery_id")) {
          const [deliveryId] = values as [string];
          return db.deliveries.has(deliveryId) ? { id: deliveryId } as T : null;
        }
        if (query.includes("FROM github_deployments d") && query.includes("LEFT JOIN application_releases r")) {
          const [deploymentId, projectId, orgId] = values as [string, string, string];
          const deployment = db.deployments.get(deploymentId);
          if (!deployment || deployment.project_id !== projectId || deployment.organization_id !== orgId) return null;
          const release = [...db.releases.values()].find((row) => row.deployment_id === deploymentId) ?? null;
          return {
            id: deployment.id,
            deploymentKind: deployment.deployment_kind,
            status: deployment.status,
            branch: deployment.branch,
            releaseId: release?.id ?? null,
            releaseState: release?.state ?? null,
            artifactDigest: release?.artifactDigest ?? null,
          } as T;
        }
        if (query.includes("FROM application_deployment_aliases") && query.includes("kind = 'production'")) {
          for (const row of db.aliases.values()) {
            if (row.kind === "production" && row.alias.startsWith("prod-")) return { id: row.id, alias: row.alias } as T;
          }
          return null;
        }
        if (query.includes("application_node_request_nonces")) {
          throw new Error("Unexpected nonce query in webhook tests: " + query.slice(0, 100));
        }
        throw new Error(`Unexpected first() query: ${query.slice(0, 140)}`);
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (query.includes("FROM github_projects WHERE github_repository_id = ?")) {
          const [repositoryId] = values as [string];
          if (repositoryId !== db.project.repositoryId) return { results: [] };
          return { results: [{ ...db.project }] as T[] };
        }
        throw new Error(`Unexpected all() query: ${query.slice(0, 140)}`);
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        if (query.startsWith("INSERT INTO github_webhook_deliveries")) {
          const [id, orgId, repoId, deliveryId, eventType, branch, commitSha, outcome, detail] = values as [string, string, string, string, string, string | null, string | null, string, string];
          if (db.deliveries.has(deliveryId)) {
            throw new Error("UNIQUE constraint failed: github_webhook_deliveries.delivery_id");
          }
          db.deliveries.set(deliveryId, { outcome, detail, eventType, branch, commitSha });
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("UPDATE github_deployments SET status = 'failed'")) {
          const [logExcerpt, deploymentId, orgId] = values as [string, string, string];
          const row = db.deployments.get(deploymentId);
          if (row && row.organization_id === orgId && row.status === "queued") {
            row.status = "failed";
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (query.startsWith("UPDATE github_projects SET webhook_secret_encrypted")) {
          const [ciphertext, iv, projectId, orgId] = values as [string, string, string, string];
          if (projectId === db.project.id && orgId === db.project.organization_id) {
            db.project.webhookSecretEncrypted = ciphertext;
            db.project.webhookSecretIv = iv;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (query.startsWith("UPDATE github_projects SET auto_deploy")) {
          const [autoDeploy, previewEnabled, ignoredPaths, projectId, orgId] = values as [number, number, string, string, string];
          if (projectId === db.project.id && orgId === db.project.organization_id) {
            db.project.auto_deploy = autoDeploy;
            db.project.preview_enabled = previewEnabled;
            db.project.ignored_build_paths = ignoredPaths;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (query.startsWith("INSERT INTO audit_logs")) {
          const action = /'([a-z_.]+)'/.exec(query)?.[1] ?? "unknown";
          db.auditActions.push(action);
          return { success: true, meta: { changes: 1 } };
        }
        throw new Error(`Unexpected run() query: ${query.slice(0, 140)}`);
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>): Promise<Array<{ success: boolean; meta: { changes: number } }>> {
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const stmt of statements) {
      const q = stmt.query;
      const v = stmt.getValues();
      if (q.startsWith("INSERT INTO github_deployments")) {
        const [id, orgId, projectId, sha, branch, trigger, , kind] = v as [string, string, string, string, string, string, string, string];
        this.deployments.set(id, {
          id, project_id: projectId, organization_id: orgId, commit_sha: sha, branch,
          trigger_type: trigger, status: "queued", deployment_kind: kind,
        });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_releases") && !q.includes("SELECT")) {
        const [id, orgId, projectId, deploymentId, , , , , , sha] = v as [string, string, string, string, string, string, string, number, string, string];
        this.releases.set(id, { id, deployment_id: deploymentId, state: "queued", artifactDigest: null });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_release_events")) {
        const eventCode = /'(deployment_queued|promoted_to_production|workflow_dispatch_rejected|workflow_dispatch_error|health_check_succeeded|health_check_failed)'/.exec(q)?.[1] ?? "unknown";
        // INSERT ... VALUES binds: [id, org, releaseId, ...]; INSERT ... SELECT binds end with releaseId, orgId.
        const releaseId = q.includes("SELECT") ? String(v[v.length - 2]) : String(v[2]);
        this.releaseEvents.push({ releaseId, eventCode });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_releases SET state = 'failed'")) {
        const releaseId = String(v[0]);
        const release = this.releases.get(releaseId);
        if (release && release.state === "queued") {
          release.state = "failed";
          results.push({ success: true, meta: { changes: 1 } });
        } else {
          results.push({ success: true, meta: { changes: 0 } });
        }
        continue;
      }
      if (q.startsWith("UPDATE github_projects SET status = 'building'")) {
        this.project.status = "building";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_deployment_aliases SET release_id")) {
        const [releaseId, deploymentId, aliasId] = v as [string, string, string];
        const alias = this.aliases.get(aliasId);
        if (alias) {
          alias.releaseId = releaseId;
          alias.deploymentId = deploymentId;
          alias.status = "active";
          results.push({ success: true, meta: { changes: 1 } });
        } else {
          results.push({ success: true, meta: { changes: 0 } });
        }
        continue;
      }
      if (q.startsWith("INSERT INTO audit_logs")) {
        const action = /'([a-z_.]+)'/.exec(q)?.[1] ?? "unknown";
        this.auditActions.push(action);
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      throw new Error("Unexpected batch statement: " + q.slice(0, 140));
    }
    return results;
  }
}

type StubRoute = {
  match: (url: URL, init: { method?: string }) => boolean;
  respond: () => { status: number; body?: unknown; headers?: Record<string, string> };
};

let restoreFetch: (() => void) | null = null;

function withFetchStub(routes: StubRoute[]): { calls: string[] } {
  const calls: string[] = [];
  const original = globalThis.fetch;
  restoreFetch = () => { globalThis.fetch = original; };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(method + " " + url.pathname);
    for (const route of routes) {
      if (route.match(url, { method })) {
        const result = route.respond();
        const headers = new Headers(result.headers ?? {});
        headers.set("content-type", "application/json");
        // 204 responses must have a null body for Node's Response constructor.
        const body = result.status === 204 || result.body === undefined ? null : JSON.stringify(result.body);
        return new Response(body, { status: result.status, headers });
      }
    }
    return new Response(JSON.stringify({ message: `stubbed route missing for ${method} ${url.pathname}` }), { status: 599, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls };
}

const githubStubRoutes: StubRoute[] = [
  {
    match: (url, init) => url.pathname.startsWith("/app/installations/") && url.pathname.endsWith("/access_tokens") && init.method === "POST",
    respond: () => ({ status: 201, body: { token: "ghs_installation_token", expires_at: new Date(Date.now() + 3600_000).toISOString() } }),
  },
  {
    match: (url) => url.pathname.startsWith(`/repos/${REPO_FULL}/commits/`),
    respond: () => ({ status: 200, body: { sha: COMMIT_SHA, commit: { message: "feat: update landing page" } } }),
  },
  {
    match: (url, init) => url.pathname === `/repos/${REPO_FULL}/actions/workflows/.github%2Fworkflows%2Fnexora-deploy.yml/dispatches` && init.method === "POST",
    respond: () => ({ status: 204 }),
  },
];

function dispatchRoutes(dispatchStatus = 204): StubRoute[] {
  const routes = githubStubRoutes.map((route) => ({ ...route }));
  routes[2].respond = () => ({ status: dispatchStatus });
  return routes;
}

type WebhookCall = {
  body: string;
  event: string;
  deliveryId: string;
  signature?: string;
  env?: Record<string, string | undefined>;
};

async function callWebhook(db: WebhookD1, call: WebhookCall): Promise<{ status: number; json: Record<string, unknown> }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-github-event": call.event,
    "x-github-delivery": call.deliveryId,
  };
  if (call.signature !== undefined) headers["x-hub-signature-256"] = call.signature;
  const request = new Request("https://worker.test/v1/github/webhooks", {
    method: "POST",
    headers,
    body: call.body,
  });
  const env = {
    DB: db as unknown as D1Database,
    GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY,
    GITHUB_APP_ID: "12345678",
    GITHUB_APP_PRIVATE_KEY: privateKey,
  };
  const response = await worker.fetch(request, env as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* empty */ }
  return { status: response.status, json };
}

function pushPayload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ref: "refs/heads/main",
    after: COMMIT_SHA,
    deleted: false,
    repository: { id: REPO_ID, full_name: REPO_FULL },
    head_commit: { id: COMMIT_SHA, message: "feat: update landing page" },
    commits: [{ added: ["src/index.html"], modified: [], removed: [] }],
    ...overrides,
  });
}

function prPayload(action: string, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    action,
    repository: { id: REPO_ID, full_name: REPO_FULL },
    pull_request: { head: { ref: "feature/redesign", sha: COMMIT_SHA } },
    ...overrides,
  });
}

const ALREADY_UUID = /^[0-9a-fA-F-]{36}$/;

test("valid push webhook dispatches a production deployment and records the outcome", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  const body = pushPayload();
  withFetchStub(dispatchRoutes());
  const result = await callWebhook(db, { body, event: "push", deliveryId: "dpl-1", signature: signPayload(WEBHOOK_SECRET, body) });
  assert.equal(result.status, 200);
  assert.equal(result.json.outcome, "dispatched");
  const deployment = [...db.deployments.values()][0];
  assert.ok(deployment);
  assert.equal(deployment.deployment_kind, "production");
  assert.equal(deployment.trigger_type, "push");
  assert.equal(deployment.commit_sha, COMMIT_SHA);
  assert.equal(deployment.branch, "main");
  assert.equal(db.deliveries.get("dpl-1")?.outcome, "dispatched");
  assert.deepEqual(db.releaseEvents.filter((event) => event.eventCode === "deployment_queued").length, 1);
  assert.ok(db.auditActions.includes("github.deployment_dispatched"));
});

test("invalid, missing, or unattributed signatures are uniform 401 with no ledger row", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  const body = pushPayload();
  withFetchStub(dispatchRoutes());

  const badSignature = await callWebhook(db, { body, event: "push", deliveryId: "dpl-bad", signature: "sha256=" + "0".repeat(64) });
  assert.equal(badSignature.status, 401);

  const missingSignature = await callWebhook(db, { body, event: "push", deliveryId: "dpl-none" });
  assert.equal(missingSignature.status, 401);

  // A repository not linked to any project gets the same uniform 401 — no
  // information leak about which repositories are tracked.
  const untrackedBody = pushPayload({ repository: { id: 1, full_name: "other/repo" } });
  const untracked = await callWebhook(db, { body: untrackedBody, event: "push", deliveryId: "dpl-untracked", signature: signPayload("attacker-secret", untrackedBody) });
  assert.equal(untracked.status, 401);

  assert.equal(db.deliveries.size, 0);
  assert.equal(db.deployments.size, 0);
});

test("replayed delivery id returns skipped_replay without double records", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  db.project.auto_deploy = 0;
  const body = pushPayload();
  withFetchStub(dispatchRoutes());
  const signature = signPayload(WEBHOOK_SECRET, body);
  const first = await callWebhook(db, { body, event: "push", deliveryId: "dpl-replay", signature });
  assert.equal(first.json.outcome, "skipped_auto_deploy_disabled");
  const second = await callWebhook(db, { body, event: "push", deliveryId: "dpl-replay", signature });
  assert.equal(second.json.outcome, "skipped_replay");
  assert.equal(db.deliveries.size, 1);
  assert.equal(db.deployments.size, 0);
});

test("push skips are recorded with their specific outcomes", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  withFetchStub(dispatchRoutes());
  const call = (body: string, deliveryId: string) =>
    callWebhook(db, { body, event: "push", deliveryId, signature: signPayload(WEBHOOK_SECRET, body) });

  // Branch mismatch.
  const mismatch = await call(pushPayload({ ref: "refs/heads/dev" }), "dpl-mismatch");
  assert.equal(mismatch.json.outcome, "skipped_branch_mismatch");

  // Branch deletion.
  const deleted = await call(pushPayload({ after: "0".repeat(40), deleted: true }), "dpl-deleted");
  assert.equal(deleted.json.outcome, "skipped_branch_deleted");

  // Ignored paths only (docs/ is in the ignore list).
  db.project.ignored_build_paths = JSON.stringify(["docs/", "README.md"]);
  const ignored = await call(pushPayload({
    commits: [{ added: ["docs/guide.md"], modified: ["README.md"], removed: [] }],
  }), "dpl-ignored");
  assert.equal(ignored.json.outcome, "skipped_ignored_paths");

  // Mixed changes are NOT ignored — the push continues to dispatch.
  const mixed = await call(pushPayload({
    commits: [{ added: ["docs/guide.md"], modified: ["src/app.js"], removed: [] }],
  }), "dpl-mixed");
  assert.equal(mixed.json.outcome, "dispatched");
  db.project.ignored_build_paths = "[]";

  // [skip deploy] commit message.
  const skipMessage = await call(pushPayload({ head_commit: { id: COMMIT_SHA, message: "docs: tweak [skip deploy]" } }), "dpl-skipmsg");
  assert.equal(skipMessage.json.outcome, "skipped_commit_message");

  // In-flight deployment.
  db.deployments.set("running-1", {
    id: "running-1", project_id: PROJECT_1, organization_id: ORG_A,
    commit_sha: COMMIT_SHA, branch: "main", trigger_type: "manual", status: "building", deployment_kind: "production",
  });
  const inFlight = await call(pushPayload(), "dpl-inflight");
  assert.equal(inFlight.json.outcome, "skipped_in_flight");
  db.deployments.delete("running-1");

  const outcomes = [...db.deliveries.values()].map((row) => row.outcome);
  assert.deepEqual(outcomes.sort(), [
    "dispatched", "skipped_branch_deleted", "skipped_branch_mismatch",
    "skipped_commit_message", "skipped_ignored_paths", "skipped_in_flight",
  ]);
  assert.equal(db.deployments.size, 1, "only the mixed-change push dispatched");
});

test("pull requests dispatch preview deployments only when previews are enabled", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  withFetchStub(dispatchRoutes());
  const call = (body: string, deliveryId: string) =>
    callWebhook(db, { body, event: "pull_request", deliveryId, signature: signPayload(WEBHOOK_SECRET, body) });

  const opened = await call(prPayload("opened"), "dpl-pr-open");
  assert.equal(opened.json.outcome, "dispatched");
  assert.equal(opened.json.deploymentKind, "preview");
  const preview = [...db.deployments.values()].find((row) => row.id !== undefined && row.deployment_kind === "preview");
  assert.ok(preview);
  assert.equal(preview.branch, "feature/redesign");
  assert.equal(preview.trigger_type, "push");
  // Settle the running preview so later deliveries reach their own checks.
  preview.status = "succeeded";

  db.project.preview_enabled = 0;
  const disabled = await call(prPayload("synchronize"), "dpl-pr-disabled");
  assert.equal(disabled.json.outcome, "skipped_preview_disabled");
  db.project.preview_enabled = 1;

  const closed = await call(prPayload("closed"), "dpl-pr-closed");
  assert.equal(closed.json.outcome, "skipped_pull_request_closed");

  const outcomes = [...db.deliveries.values()].map((row) => row.outcome).sort();
  assert.deepEqual(outcomes, ["dispatched", "skipped_preview_disabled", "skipped_pull_request_closed"]);
});

test("a rejected workflow dispatch is recorded as an error outcome and marks the deployment failed", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  withFetchStub(dispatchRoutes(404));
  const body = pushPayload();
  const result = await callWebhook(db, { body, event: "push", deliveryId: "dpl-reject", signature: signPayload(WEBHOOK_SECRET, body) });
  assert.equal(result.status, 200);
  assert.equal(result.json.outcome, "error");
  const deployment = [...db.deployments.values()][0];
  assert.ok(deployment);
  assert.equal(deployment.status, "failed");
  const release = [...db.releases.values()][0];
  assert.ok(release);
  assert.equal(release.state, "failed");
  assert.equal(db.deliveries.get("dpl-reject")?.outcome, "error");
});

test("webhook secret rotation returns the raw secret once and stores it encrypted", async () => {
  const db = new WebhookD1();
  db.identity = {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
  withFetchStub([]);
  const request = (deliveryNote: string) => new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/webhook-secret`, {
    method: "PUT",
    headers: { authorization: `Bearer ${SESSION_TOKEN}` },
  });
  const env = { DB: db as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY };
  const first = await worker.fetch(request("first"), env as never, { waitUntil: () => {} } as never);
  const firstJson = await first.json() as { webhookSecret?: string };
  assert.equal(first.status, 200);
  assert.ok(firstJson.webhookSecret);
  assert.equal(db.project.webhookSecretEncrypted?.includes(firstJson.webhookSecret), false);
  const second = await worker.fetch(request("second"), env as never, { waitUntil: () => {} } as never);
  const secondJson = await second.json() as { webhookSecret?: string };
  assert.notEqual(firstJson.webhookSecret, secondJson.webhookSecret);
  // The rotated secret verifies a webhook.
  const body = pushPayload();
  withFetchStub(dispatchRoutes());
  const verified = await callWebhook(db, { body, event: "push", deliveryId: "dpl-rotated", signature: signPayload(secondJson.webhookSecret!, body) });
  assert.equal(verified.json.outcome, "dispatched");
  assert.ok(db.auditActions.includes("deploy.webhook_secret_rotated"));
});

async function seedPromotableState(db: WebhookD1, options: { previewStatus?: string; releaseState?: string; withProductionAlias?: boolean } = {}) {
  const previewDeploymentId = "d2000000-0000-4000-8000-000000000001";
  const releaseId = "r2000000-0000-4000-8000-000000000001";
  db.deployments.set(previewDeploymentId, {
    id: previewDeploymentId, project_id: PROJECT_1, organization_id: ORG_A,
    commit_sha: COMMIT_SHA, branch: "feature/redesign", trigger_type: "push",
    status: options.previewStatus ?? "succeeded", deployment_kind: "preview",
  });
  db.releases.set(releaseId, {
    id: releaseId, deployment_id: previewDeploymentId,
    state: options.releaseState ?? "succeeded",
    artifactDigest: options.releaseState === undefined || options.releaseState === "succeeded" ? "d".repeat(64) : null,
  });
  if (options.withProductionAlias !== false) {
    db.aliases.set("alias-prod-1", {
      id: "alias-prod-1", alias: "prod-b10000000000.nexoraedge.digital",
      kind: "production", releaseId: "r0000000-0000-4000-8000-000000000009",
      deploymentId: "d0000000-0000-4000-8000-000000000009", status: "active",
    });
  }
  return { previewDeploymentId, releaseId };
}

function promotionRequest(db: WebhookD1, projectId: string, deploymentId: string) {
  return new Request(`https://worker.test/v1/github/projects/${projectId}/deployments/${deploymentId}/promote`, {
    method: "POST",
    headers: { authorization: `Bearer ${SESSION_TOKEN}` },
  });
}

async function callPromotion(db: WebhookD1, projectId = PROJECT_1, deploymentId: string) {
  const env = { DB: db as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY };
  const response = await worker.fetch(promotionRequest(db, projectId, deploymentId), env as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* empty */ }
  return { status: response.status, json };
}

test("promotion re-points the production alias at the preview release without rebuilding", async () => {
  const db = new WebhookD1();
  db.identity = {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
  const { previewDeploymentId, releaseId } = await seedPromotableState(db);
  withFetchStub([]);
  const result = await callPromotion(db, PROJECT_1, previewDeploymentId);
  assert.equal(result.status, 200);
  assert.equal(result.json.promoted, true);
  const alias = db.aliases.get("alias-prod-1")!;
  assert.equal(alias.releaseId, releaseId);
  assert.equal(alias.deploymentId, previewDeploymentId);
  assert.equal(alias.status, "active");
  assert.ok(db.releaseEvents.some((event) => event.releaseId === releaseId && event.eventCode === "promoted_to_production"));
  assert.ok(db.auditActions.includes("deploy.preview_promoted"));
});

test("promotion refuses non-preview, unhealthy, or alias-less targets", async () => {
  const db = new WebhookD1();
  db.identity = {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
  withFetchStub([]);

  // Production deployments are not promotable.
  db.deployments.set("d4000000-0000-4000-8000-000000000004", {
    id: "d4000000-0000-4000-8000-000000000004", project_id: PROJECT_1, organization_id: ORG_A,
    commit_sha: COMMIT_SHA, branch: "main", trigger_type: "push", status: "succeeded", deployment_kind: "production",
  });
  const production = await callPromotion(db, PROJECT_1, "d4000000-0000-4000-8000-000000000004");
  assert.equal(production.status, 409);
  assert.match(String(production.json.message), /Only preview deployments/);

  // Unhealthy preview.
  const unhealthy = await seedPromotableState(db, { previewStatus: "failed", releaseState: "failed" });
  const refused = await callPromotion(db, PROJECT_1, unhealthy.previewDeploymentId);
  assert.equal(refused.status, 409);
  assert.match(String(refused.json.message), /healthy preview/);

  // No production alias yet (fresh project state).
  db.aliases.clear();
  const { previewDeploymentId } = await seedPromotableState(db, { withProductionAlias: false });
  const noAlias = await callPromotion(db, PROJECT_1, previewDeploymentId);
  assert.equal(noAlias.status, 409);
  assert.match(String(noAlias.json.message), /No production deployment/);

  // Cross-tenant project id is 404.
  const crossTenant = await callPromotion(db, "b9999999-0000-4000-8000-000000000009", "d3000000-0000-4000-8000-000000000003");
  assert.equal(crossTenant.status, 404);
});

test("deploy settings update preview, auto-deploy, and ignored paths", async () => {
  const db = new WebhookD1();
  await db.seedWebhookSecret(WEBHOOK_SECRET);
  db.identity = {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
  withFetchStub([]);
  const call = (body: Record<string, unknown>) =>
    new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/deploy-settings`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${SESSION_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const env = { DB: db as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY };
  const first = await worker.fetch(call({ previewEnabled: false, autoDeploy: true, ignoredBuildPaths: ["docs/", "README.md"] }), env as never, { waitUntil: () => {} } as never);
  assert.equal(first.status, 200);
  const settings = (await first.json() as { settings: { previewEnabled: boolean; autoDeploy: boolean; ignoredBuildPaths: string[] } }).settings;
  assert.equal(settings.previewEnabled, false);
  assert.equal(settings.autoDeploy, true);
  assert.deepEqual(settings.ignoredBuildPaths, ["docs/", "README.md"]);
  // The persisted ignore list drives the webhook decision immediately.
  const body = pushPayload({ commits: [{ added: ["docs/new.md"], modified: [], removed: [] }] });
  const webhook = await callWebhook(db, { body, event: "push", deliveryId: "dpl-settings-ignored", signature: signPayload(WEBHOOK_SECRET, body) });
  // Signature must match after settings change: seed the secret again is unnecessary (unchanged).
  assert.equal(webhook.json.outcome, "skipped_ignored_paths");

  // Invalid ignored paths are rejected without persisting.
  const invalid = await worker.fetch(call({ ignoredBuildPaths: ["../escape"] }), env as never, { waitUntil: () => {} } as never);
  assert.equal(invalid.status, 400);

  // Unauthenticated is 401.
  const anonymous = new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/deploy-settings`, {
    method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ previewEnabled: true }),
  });
  const anonymousResponse = await worker.fetch(anonymous, env as never, { waitUntil: () => {} } as never);
  assert.equal(anonymousResponse.status, 401);
});

test("manual dispatch through the shared dispatcher honors prerequisites and returns 202", async () => {
  const db = new WebhookD1();
  db.identity = {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
  withFetchStub(dispatchRoutes());
  const env = { DB: db as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY, GITHUB_APP_ID: "12345678", GITHUB_APP_PRIVATE_KEY: privateKey };
  const request = new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/deployments`, {
    method: "POST",
    headers: { authorization: `Bearer ${SESSION_TOKEN}`, "content-type": "application/json" },
    body: "{}",
  });
  const response = await worker.fetch(request, env as never, { waitUntil: () => {} } as never);
  assert.equal(response.status, 202);
  const body = await response.json() as { deployment?: { deploymentKind?: string } };
  assert.equal(body.deployment?.deploymentKind, "production");
  const deployment = [...db.deployments.values()][0];
  assert.ok(deployment);
  assert.equal(deployment.trigger_type, "manual");
  assert.equal(deployment.deployment_kind, "production");

  // Without admitted runtime settings the same dispatch is refused 409.
  const db2 = new WebhookD1();
  db2.identity = db.identity;
  db2.runtimeAssignment = null;
  withFetchStub([]);
  const request2 = new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/deployments`, {
    method: "POST",
    headers: { authorization: `Bearer ${SESSION_TOKEN}`, "content-type": "application/json" },
    body: "{}",
  });
  const response2 = await worker.fetch(request2, { DB: db2 as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY, GITHUB_APP_ID: "12345678", GITHUB_APP_PRIVATE_KEY: privateKey } as never, { waitUntil: () => {} } as never);
  assert.equal(response2.status, 409);
});
