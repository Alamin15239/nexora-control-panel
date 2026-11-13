import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// github-deploy-selfheal.integration.test.ts
//
// "Connect once, deploy automatically" regression tests:
//
//   1. A dispatch for a project without runtime settings self-heals: static
//      runtime settings are bootstrapped from the framework contract saved at
//      link time, an eligible pool is bound, and the deployment dispatches.
//   2. Without any eligible pool the dispatch still fails closed (409) but the
//      settings row is created so a later admission pass only needs the pool.
//   3. Once a pool becomes eligible, the next dispatch assigns it and succeeds.
//   4. A non-static pool with untrusted isolation remains rejected.
//   5. Enrolling a runtime node sweeps the admission backlog: projects bound
//      to that pool with zero deployments dispatch automatically, projects
//      that already deployed do not.
//
// The GitHub REST surface is stubbed at the network boundary; the D1 mock
// implements only the SQL these flows issue and throws on anything else.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "9".repeat(64);
const ORG_A = "22222222-2222-4222-8222-222222222222";
const OWNER_A = "aaaaaaa2-0000-4000-8000-000000000002";
const ACCOUNT_1 = "eeeeeee2-0000-4000-8000-000000000002";
const PROJECT_1 = "b2000000-0000-4000-8000-000000000001";
const POOL_STATIC = "pool_static_publish_01";
const NODE_ID = "nexora-server-static-01";
const REPO_ID = 55555555;
const REPO_FULL = "acme/site";
const TOKEN_KEY = "e".repeat(64);
const COMMIT_SHA = "b".repeat(40);
const WORKFLOW_SHA = "c".repeat(40);
const ENROLLMENT_TOKEN = "d".repeat(64);
const NODE_PUBLIC_KEY = "a".repeat(64);

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

type DispatchRow = { id: string; project_id: string; organization_id: string; trigger_type: string; deployment_kind: string; status: string };

class SelfHealD1 {
  identity: { id: string; email: string; displayName: null; organizationId: string; organizationName: string; organizationSlug: string; role: string; platformRole: string | null } | null = null;
  pool = { id: POOL_STATIC, ready: true, engine: "static", isolation: "untrusted", onlineNode: true };
  runtimeProfile = { id: "runtime-static-v1", enabled: 1 };
  plan = { cpuMillis: 1000, memoryMiB: 1024, diskMiB: 4096, processLimit: 256 };
  projectRow = {
    id: PROJECT_1, organizationId: ORG_A, framework: "vite", outputDirectory: "dist",
    hostingAccountId: ACCOUNT_1, auto_deploy: 1, repositoryFullName: REPO_FULL,
    repositoryId: String(REPO_ID), installationId: "77777", productionBranch: "main",
    trustedWorkflowSha: WORKFLOW_SHA, status: "configured",
  };
  settingsRow: { id: string; nodePoolId: string | null } | null = null;
  settingsInserts: Array<{ nodePoolId: string | null; buildMethod: string; outputDirectory: string; cpuMillis: number }> = [];
  poolAssignments: string[] = [];
  deployments = new Map<string, DispatchRow>();
  releases = new Map<string, { id: string; deployment_id: string; node_pool_id: string | null; state: string }>();
  releaseEvents: Array<{ eventCode: string }> = [];
  auditActions: string[] = [];
  node = {
    id: "node-1", identity: NODE_ID, poolId: POOL_STATIC, status: "pending",
    enrollmentKeyHash: sha256(ENROLLMENT_TOKEN), signingPublicKey: null as string | null,
  };

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>): Promise<Array<{ success: boolean; meta: { changes: number } }>> {
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const stmt of statements) {
      const q = stmt.query;
      const v = stmt.getValues();
      if (q.startsWith("INSERT INTO github_deployments")) {
        const [id, organizationId, projectId, , branch, triggerType, , deploymentKind] = v as [string, string, string, string, string, string, string, string];
        this.deployments.set(String(id), {
          id: String(id), project_id: String(projectId), organization_id: String(organizationId),
          trigger_type: String(triggerType), deployment_kind: String(deploymentKind),
          branch: String(branch), status: "queued",
        });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_releases")) {
        const [id, organizationId, projectId, deploymentId, nodePoolId, , assignedNodeId] = v as [string, string, string, string, string | null, string, string | null];
        this.releases.set(String(id), {
          id: String(id), deployment_id: String(deploymentId),
          node_pool_id: nodePoolId == null ? null : String(nodePoolId),
          assigned_node_id: assignedNodeId == null ? null : String(assignedNodeId),
          project_id: String(projectId), organization_id: String(organizationId), state: "queued",
        });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_release_events")) {
        this.releaseEvents.push({ eventCode: "deployment_queued" });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_nodes SET signing_public_key")) {
        const [publicKey] = v as [string];
        this.node.signingPublicKey = String(publicKey);
        this.node.status = "online";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_node_signing_key_history")) {
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE github_projects SET status = 'building'")) {
        this.projectRow.status = "building";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO audit_logs")) {
        this.auditActions.push(/'([a-z_.]+)'/.exec(q)?.[1] ?? "unknown");
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_releases SET state = 'failed'") ||
          q.startsWith("INSERT INTO application_release_events") === false && q.includes("SELECT ?, organization_id, id, 'queued', 'failed'")) {
        results.push({ success: true, meta: { changes: 0 } });
        continue;
      }
      throw new Error("Unexpected batch statement: " + q.slice(0, 160));
    }
    return results;
  }

  // Mirror of isRuntimeAssignmentAdmitted inputs as persisted rows would join.
  private assignmentRow() {
    const settings = this.settingsRow;
    if (!settings) return null;
    const poolBound = settings.nodePoolId === this.pool.id && this.pool.ready;
    return {
      runtimeProfileId: this.runtimeProfile.id,
      specVersion: 1,
      nodePoolId: settings.nodePoolId,
      runtimeEnabled: this.runtimeProfile.enabled,
      profileKey: "static-v1",
      runtimeFamily: "static",
      buildMethod: "static",
      poolStatus: poolBound ? "ready" : null,
      isolationLevel: poolBound ? this.pool.isolation : null,
      runtimeEngine: poolBound ? this.pool.engine : null,
      assignedNodeId: poolBound && this.pool.onlineNode ? this.node.id : null,
    };
  }

  private poolEligible() {
    return this.pool.ready && this.pool.onlineNode &&
      (["rootless", "microvm"].includes(this.pool.isolation) ||
       (this.pool.engine === "static" && this.pool.isolation === "untrusted"));
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      getValues() { return values; },
      async first<T>(): Promise<T | null> {
        if (query.includes("FROM auth_sessions")) return db.identity ? { ...db.identity } as T : null;
        if (query.includes("FROM github_projects p") && query.includes("LEFT JOIN application_project_settings s")) {
          const [projectId, organizationId] = values as [string, string];
          if (projectId !== db.projectRow.id || organizationId !== db.projectRow.organizationId) return null;
          return {
            id: db.projectRow.id,
            repositoryId: db.projectRow.repositoryId,
            repositoryFullName: db.projectRow.repositoryFullName,
            installationId: db.projectRow.installationId,
            productionBranch: db.projectRow.productionBranch,
            trustedWorkflowSha: db.projectRow.trustedWorkflowSha,
            status: db.projectRow.status,
            outputDirectory: db.projectRow.outputDirectory,
          } as T;
        }
        if (query.startsWith("SELECT id FROM application_runtime_profiles WHERE profile_key")) {
          return db.runtimeProfile.enabled === 1 ? { id: db.runtimeProfile.id } as T : null;
        }
        if (query.includes("FROM application_project_settings s") && query.includes("application_runtime_profiles")) {
          return db.assignmentRow() ? { ...db.assignmentRow()! } as T : null;
        }
        if (query.includes("FROM github_projects p") && query.includes("hostingAccountId")) {
          return db.projectRow ? {
            framework: db.projectRow.framework,
            outputDirectory: db.projectRow.outputDirectory,
            hostingAccountId: db.projectRow.hostingAccountId,
          } as T : null;
        }
        if (query.includes("FROM application_project_settings") && query.includes("node_pool_id AS nodePoolId")) {
          return db.settingsRow ? { ...db.settingsRow } as T : null;
        }
        if (query.includes("FROM hosting_accounts h JOIN hosting_plans hp")) {
          return { ...db.plan } as T;
        }
        if (query.includes("FROM application_node_pools p") && query.includes("CASE WHEN p.runtime_engine = 'static'")) {
          return db.poolEligible() ? { id: db.pool.id } as T : null;
        }
        if (query.startsWith("SELECT id FROM github_deployments WHERE project_id")) {
          for (const row of db.deployments.values()) {
            if (row.project_id === values[0] && ["queued", "cloning", "installing", "building", "publishing"].includes(row.status)) {
              return { id: row.id } as T;
            }
          }
          return null;
        }
        if (query.includes("FROM application_nodes WHERE node_identity")) {
          if (values[0] !== db.node.identity) return null;
          return { id: db.node.id, nodePoolId: db.node.poolId, nodeIdentity: db.node.identity, status: db.node.status, agentVersion: "0.8.0" } as T;
        }
        throw new Error(`Unexpected first() query: ${query.slice(0, 160)}`);
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (query.includes("FROM github_projects p JOIN application_project_settings s") &&
            query.includes("NOT EXISTS (SELECT 1 FROM github_deployments d WHERE d.project_id = p.id)")) {
          const [nodePoolId] = values as [string];
          if (nodePoolId !== db.settingsRow?.nodePoolId) return { results: [] };
          if (db.deployments.size > 0) return { results: [] };
          if (db.projectRow.auto_deploy !== 1 || db.projectRow.status === "paused") return { results: [] };
          if (!db.projectRow.trustedWorkflowSha || !db.projectRow.installationId) return { results: [] };
          return { results: [{
            id: db.projectRow.id,
            organizationId: db.projectRow.organizationId,
            repositoryId: db.projectRow.repositoryId,
            repositoryFullName: db.projectRow.repositoryFullName,
            installationId: db.projectRow.installationId,
            productionBranch: db.projectRow.productionBranch,
            trustedWorkflowSha: db.projectRow.trustedWorkflowSha,
            status: db.projectRow.status,
            outputDirectory: db.projectRow.outputDirectory,
          }] as T[] };
        }
        throw new Error(`Unexpected all() query: ${query.slice(0, 160)}`);
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        if (query.startsWith("INSERT INTO application_project_settings")) {
          const withPool = query.includes(", node_pool_id");
          // Binds: [id, orgId, projectId, profileId, buildCommand, outputDirectory,
          //        cpuMillis, memoryMiB, diskMiB, processLimit, (nodePoolId)]
          const [id, , , , , outputDirectory, cpuMillis] = values as unknown[];
          const buildMethod = /'static'/.test(query) ? "static" : "managed";
          const nodePoolId = withPool ? String(values[values.length - 1]) : null;
          db.settingsRow = { id: String(id), nodePoolId };
          db.settingsInserts.push({
            nodePoolId,
            buildMethod,
            outputDirectory: String(outputDirectory),
            cpuMillis: Number(cpuMillis),
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("UPDATE application_project_settings SET node_pool_id")) {
          const [poolId] = values as [string];
          if (!db.settingsRow) return { success: true, meta: { changes: 0 } };
          db.settingsRow.nodePoolId = String(poolId);
          db.poolAssignments.push(String(poolId));
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("UPDATE github_deployments SET status = 'failed'")) {
          return { success: true, meta: { changes: 0 } };
        }
        throw new Error(`Unexpected run() query: ${query.slice(0, 160)}`);
      },
    };
    return statement;
  }
}

type StubRoute = {
  match: (url: URL, init: { method?: string }) => boolean;
  respond: () => { status: number; body?: unknown };
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
        const headers = new Headers();
        headers.set("content-type", "application/json");
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
    respond: () => ({ status: 200, body: { sha: COMMIT_SHA, commit: { message: "feat: landing page" } } }),
  },
  {
    match: (url, init) => url.pathname === `/repos/${REPO_FULL}/actions/workflows/.github%2Fworkflows%2Fnexora-deploy.yml/dispatches` && init.method === "POST",
    respond: () => ({ status: 204 }),
  },
];

function adminIdentity() {
  return {
    id: OWNER_A, email: "owner@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "OWNER", platformRole: "PLATFORM_ADMIN",
  };
}

function baseEnv(db: SelfHealD1) {
  return { DB: db as unknown as D1Database, GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY, GITHUB_APP_ID: "12345678", GITHUB_APP_PRIVATE_KEY: privateKey };
}

function manualDispatchRequest(): Request {
  return new Request(`https://worker.test/v1/github/projects/${PROJECT_1}/deployments`, {
    method: "POST",
    headers: { authorization: `Bearer ${SESSION_TOKEN}`, "content-type": "application/json" },
    body: "{}",
  });
}

test("dispatch self-heals missing runtime settings and deploys through a static pool", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  withFetchStub(githubStubRoutes);
  const response = await worker.fetch(manualDispatchRequest(), baseEnv(db) as never, { waitUntil: () => {} } as never);
  assert.equal(response.status, 202);
  const body = await response.json() as { deployment?: { id?: string }; applicationRelease?: { nodePoolId?: string; assignedNodeId?: string } };
  assert.ok(body.deployment?.id);
  assert.equal(body.applicationRelease?.nodePoolId, POOL_STATIC);
  assert.equal(body.applicationRelease?.assignedNodeId, "node-1");
  // Settings were bootstrapped from the vite preset with plan-clamped resources.
  assert.equal(db.settingsInserts.length, 1);
  assert.equal(db.settingsInserts[0].buildMethod, "static");
  assert.equal(db.settingsInserts[0].outputDirectory, "dist");
  assert.equal(db.settingsInserts[0].cpuMillis, 500);
  assert.equal(db.settingsInserts[0].nodePoolId, POOL_STATIC);
  assert.equal(db.deployments.size, 1);
  assert.equal([...db.deployments.values()][0].trigger_type, "manual");
  assert.equal(db.auditActions.includes("github.deployment_dispatched"), true);
});

test("dispatch without an eligible pool fails closed but still bootstraps settings", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  db.pool.onlineNode = false;
  withFetchStub(githubStubRoutes);
  const response = await worker.fetch(manualDispatchRequest(), baseEnv(db) as never, { waitUntil: () => {} } as never);
  assert.equal(response.status, 409);
  const body = await response.json() as { message?: string };
  assert.match(body.message ?? "", /not admitted yet/);
  assert.equal(db.settingsInserts.length, 1);
  assert.equal(db.settingsInserts[0].nodePoolId, null);
  assert.equal(db.deployments.size, 0);
});

test("a later dispatch assigns the pool once it becomes eligible", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  db.pool.onlineNode = false;
  withFetchStub(githubStubRoutes);
  const refused = await worker.fetch(manualDispatchRequest(), baseEnv(db) as never, { waitUntil: () => {} } as never);
  assert.equal(refused.status, 409);
  db.pool.onlineNode = true;
  const accepted = await worker.fetch(manualDispatchRequest(), baseEnv(db) as never, { waitUntil: () => {} } as never);
  assert.equal(accepted.status, 202);
  assert.deepEqual(db.poolAssignments, [POOL_STATIC]);
  assert.equal(db.deployments.size, 1);
});

test("a non-static pool with untrusted isolation stays rejected", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  db.pool.engine = "containerd";
  db.settingsRow = { id: "settings-1", nodePoolId: POOL_STATIC };
  withFetchStub(githubStubRoutes);
  const response = await worker.fetch(manualDispatchRequest(), baseEnv(db) as never, { waitUntil: () => {} } as never);
  assert.equal(response.status, 409);
  assert.equal(db.deployments.size, 0);
});

test("enrolling a runtime node dispatches the backlog for never-deployed projects", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  db.settingsRow = { id: "settings-1", nodePoolId: POOL_STATIC };
  const waitUntilPromises: Array<Promise<unknown>> = [];
  withFetchStub(githubStubRoutes);
  const response = await worker.fetch(
    new Request("https://worker.test/internal/v1/application-nodes/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nodeIdentity: NODE_ID,
        enrollmentToken: ENROLLMENT_TOKEN,
        publicKey: NODE_PUBLIC_KEY,
        agentVersion: "0.8.0",
      }),
    }),
    baseEnv(db) as never,
    { waitUntil: (promise: Promise<unknown>) => { waitUntilPromises.push(promise); } } as never,
  );
  assert.equal(response.status, 200);
  const body = await response.json() as { enrolled?: boolean; node?: { status?: string } };
  assert.equal(body.enrolled, true);
  assert.equal(body.node?.status, "online");
  await Promise.all(waitUntilPromises);
  assert.equal(db.deployments.size, 1);
  const deployment = [...db.deployments.values()][0];
  assert.equal(deployment.trigger_type, "manual");
  assert.equal(deployment.deployment_kind, "production");
  assert.equal(db.projectRow.status, "building");
});

test("the backlog sweep skips projects that already have deployments", async () => {
  const db = new SelfHealD1();
  db.identity = adminIdentity();
  db.settingsRow = { id: "settings-1", nodePoolId: POOL_STATIC };
  db.deployments.set("existing-deployment", {
    id: "existing-deployment", project_id: PROJECT_1, organization_id: ORG_A,
    trigger_type: "push", deployment_kind: "production", status: "succeeded",
  });
  const waitUntilPromises: Array<Promise<unknown>> = [];
  withFetchStub(githubStubRoutes);
  const response = await worker.fetch(
    new Request("https://worker.test/internal/v1/application-nodes/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nodeIdentity: NODE_ID,
        enrollmentToken: ENROLLMENT_TOKEN,
        publicKey: NODE_PUBLIC_KEY,
        agentVersion: "0.8.0",
      }),
    }),
    baseEnv(db) as never,
    { waitUntil: (promise: Promise<unknown>) => { waitUntilPromises.push(promise); } } as never,
  );
  assert.equal(response.status, 200);
  await Promise.all(waitUntilPromises);
  assert.equal(db.deployments.size, 1);
  assert.ok(db.deployments.has("existing-deployment"));
});
