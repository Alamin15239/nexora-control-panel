import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

type TestIdentity = {
  id: string;
  email: string;
  displayName: string | null;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: "OWNER" | "ADMIN" | "MEMBER";
  platformRole?: string | null;
};

type SavedSettings = {
  id: string; organizationId: string; projectId: string; runtimeProfileId: string;
  buildMethod: string; buildContext: string; buildCommand: string | null;
  outputDirectory: string | null; startCommand: string | null; listenPort: number | null;
  healthCheckPath: string | null; cpuMillis: number; memoryMiB: number;
  diskMiB: number; processLimit: number; specVersion: number;
};

class TestD1 {
  identity: TestIdentity | null;
  projectOrganizationId = "org-a";
  profile = { id: "runtime-nodejs-v1", runtimeFamily: "nodejs", enabled: 0 };
  settings: SavedSettings | null = null;
  writes = 0;
  audits = 0;
  usageRow: { id: string; buildMinutesLimit: number; buildSecondsUsed: number } | null = null;
  deploymentRow = { id: "deployment-a", organizationId: "org-a", projectId: "project-a", status: "building" };
  usagePeriod: { organizationId: string; projectId: string; periodStart: string; buildSecondsUsed: number; buildMinutesLimit: number } | null = null;
  usageEvents = new Map<string, { id: string; organizationId: string; projectId: string; deploymentId: string; periodStart: string; buildSeconds: number; buildResult: string; aggregatedAt: string | null; nodeId: string }>();
  node = { id: "node-a", nodeIdentity: "builder-a", enrollmentKeyHash: "", signingPublicKey: null as string | null,
    status: "pending", poolReady: true, agentVersion: null as string | null,
    challengeHash: null as string | null, challengeExpiresAt: null as string | null,
    revokedAt: null as string | null, revokedReason: null as string | null };
  keyHistory: string[] = [];
  nodeNonces = new Set<string>();

  constructor(identity: TestIdentity | null) { this.identity = identity; }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      getValues() { return values; },
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("LEFT JOIN application_usage_periods")) {
          const [periodStart, eventPeriodStart, projectId, organizationId] = values;
          if (projectId !== "project-a" || organizationId !== db.projectOrganizationId) return null;
          return (db.usageRow ?? { id: "project-a", buildMinutesLimit: 300, buildSecondsUsed: 0 }) as T;
        }
        if (query.includes("FROM application_nodes n")) {
          const [nodeIdentity] = values;
          return nodeIdentity === db.node.nodeIdentity && ["online", "draining"].includes(db.node.status) && db.node.poolReady && db.node.signingPublicKey
            ? ({ id: db.node.id, signingPublicKey: db.node.signingPublicKey } as T) : null;
        }
        if (query.includes("FROM application_nodes WHERE node_identity")) {
          if (values[0] !== db.node.nodeIdentity) return null;
          if (query.includes("challengeHash")) {
            return ["online", "draining"].includes(db.node.status) && db.node.signingPublicKey && db.node.challengeHash
              ? ({ id: db.node.id, signingPublicKey: db.node.signingPublicKey,
                  challengeHash: db.node.challengeHash, challengeExpiresAt: db.node.challengeExpiresAt } as T) : null;
          }
          return ({ id: db.node.id, nodeIdentity: db.node.nodeIdentity, status: db.node.status, agentVersion: db.node.agentVersion } as T);
        }
        if (query.includes("FROM github_deployments d")) {
          const [deploymentId] = values;
          return deploymentId === db.deploymentRow.id && ["cloning", "installing", "building"].includes(db.deploymentRow.status)
            ? ({ ...db.deploymentRow } as T) : null;
        }
        if (query.includes("FROM application_usage_events e")) {
          const [deploymentId, nodeId] = values;
          const event = db.usageEvents.get(String(deploymentId));
          return event && event.nodeId === nodeId
            ? ({ id: event.id, periodStart: event.periodStart, organizationId: event.organizationId, projectId: event.projectId, buildSeconds: event.buildSeconds, buildResult: event.buildResult } as T) : null;
        }
        if (query.includes("FROM application_usage_events")) {
          const [organizationId, projectId, deploymentId, nodeId] = values;
          const event = db.usageEvents.get(String(deploymentId));
          return event && event.organizationId === organizationId && event.projectId === projectId && event.nodeId === nodeId
            ? ({ id: event.id, periodStart: event.periodStart } as T) : null;
        }
        if (query.includes("FROM application_usage_periods")) {
          return db.usagePeriod ? ({ buildSecondsUsed: db.usagePeriod.buildSecondsUsed,
            buildMinutesLimit: db.usagePeriod.buildMinutesLimit } as T) : null;
        }
        if (query.includes("FROM auth_sessions s")) return db.identity as T | null;
        if (query.includes("FROM github_projects p") && query.includes("JOIN hosting_accounts h") && !query.includes("LEFT JOIN application_project_settings")) {
          const [projectId, organizationId] = values;
          return projectId === "project-a" && organizationId === db.projectOrganizationId
            ? ({
                id: "project-a",
                appCpuMillis: 1000,
                appMemoryMiB: 512,
                appDiskMiB: 2048,
                appProcessLimit: 128,
                accountDiskLimitBytes: 10 * 1024 * 1024 * 1024,
              } as T) : null;
        }
        if (query.includes("FROM github_projects WHERE id = ? AND organization_id = ?")) {
          const [projectId, organizationId] = values;
          if (projectId !== "project-a" || organizationId !== db.projectOrganizationId) return null;
          if (query.includes("github_repository_id AS repositoryId")) {
            return ({
              id: "project-a",
              repositoryId: "12345",
              repositoryFullName: "Alamin15239/example-app",
              installationId: "installation-a",
              productionBranch: "main",
              trustedWorkflowSha: "a".repeat(40),
              status: "active",
            } as T);
          }
          return ({ id: "project-a" } as T);
        }
        if (query.includes("FROM application_runtime_profiles WHERE id = ?")) {
          return values[0] === db.profile.id ? ({ ...db.profile } as T) : null;
        }
        if (query.includes("FROM github_projects p") && query.includes("LEFT JOIN application_project_settings")) {
          const [projectId, organizationId] = values;
          if (projectId !== "project-a" || organizationId !== db.projectOrganizationId) return null;
          const base = {
            id: "project-a",
            repositoryFullName: "Alamin15239/example-app",
            planCpuMillis: 1000,
            planMemoryMiB: 512,
            planDiskMiB: 2048,
            planProcessLimit: 128,
          };
          if (!db.settings) return { ...base, settingsId: null } as T;
          const s = db.settings;
          return {
            ...base,
            settingsId: s.id,
            runtimeProfileId: s.runtimeProfileId,
            runtimeFamily: db.profile.runtimeFamily,
            runtimeProfileKey: "nodejs-v1",
            runtimeEnabled: db.profile.enabled,
            specVersion: s.specVersion,
            buildMethod: s.buildMethod,
            buildContext: s.buildContext,
            buildCommand: s.buildCommand,
            outputDirectory: s.outputDirectory,
            startCommand: s.startCommand,
            listenPort: s.listenPort,
            healthCheckPath: s.healthCheckPath,
            cpuMillis: s.cpuMillis,
            memoryMiB: s.memoryMiB,
            diskMiB: s.diskMiB,
            processLimit: s.processLimit,
            updatedAt: "2026-11-07 00:00:00",
          } as T;
        }
        return null;
      },
      async all<T>() { return { results: [] as T[] }; },
      async run() {
        if (query.includes("UPDATE application_nodes SET status = 'revoked'")) {
          const [reason, enrollmentHash, nodeId] = values;
          if (nodeId !== db.node.id || db.node.status === "revoked") return { success: true, meta: { changes: 0 } };
          db.node.status = "revoked";
          db.node.revokedAt = "2026-11-07 00:00:00";
          db.node.revokedReason = String(reason);
          db.node.enrollmentKeyHash = String(enrollmentHash);
          db.node.challengeHash = null;
          db.node.challengeExpiresAt = null;
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_nodes SET key_rotation_challenge_hash")) {
          const [hash, nodeId] = values;
          if (nodeId !== db.node.id || !["online", "draining"].includes(db.node.status) || !db.node.signingPublicKey) {
            return { success: true, meta: { changes: 0 } };
          }
          db.node.challengeHash = String(hash);
          db.node.challengeExpiresAt = new Date(Date.now() + 600000).toISOString().replace("T", " ").replace("Z", "");
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("UPDATE application_nodes SET agent_version")) {
          const [agentVersion] = values;
          if (["online", "draining"].includes(db.node.status) && db.node.signingPublicKey) {
            db.node.agentVersion = String(agentVersion);
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (query.includes("UPDATE application_nodes SET signing_public_key")) {
          const [publicKey, agentVersion, nodeIdentity, tokenHash] = values;
          if (nodeIdentity === db.node.nodeIdentity && tokenHash === db.node.enrollmentKeyHash &&
              db.node.status === "pending" && db.node.poolReady && !db.node.signingPublicKey) {
            db.node.signingPublicKey = String(publicKey);
            db.node.agentVersion = String(agentVersion);
            db.node.status = "online";
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (query.includes("INSERT OR IGNORE INTO application_node_request_nonces")) {
          const nonce = String(values[1]);
          if (db.nodeNonces.has(nonce)) return { success: true, meta: { changes: 0 } };
          db.nodeNonces.add(nonce);
          return { success: true, meta: { changes: 1 } };
        }
        if (query.includes("INSERT INTO application_project_settings")) {
          db.writes++;
          const [id, organizationId, projectId, runtimeProfileId, buildMethod, buildContext,
            buildCommand, outputDirectory, startCommand, listenPort, healthCheckPath,
            cpuMillis, memoryMiB, diskMiB, processLimit] = values as [
              string, string, string, string, string, string, string | null,
              string | null, string | null, number | null, string | null,
              number, number, number, number
            ];
          db.settings = {
            id, organizationId, projectId, runtimeProfileId, buildMethod, buildContext,
            buildCommand, outputDirectory, startCommand, listenPort, healthCheckPath,
            cpuMillis, memoryMiB, diskMiB, processLimit,
            specVersion: (db.settings?.specVersion ?? 0) + 1,
          };
        }
        if (query.includes("INSERT INTO audit_logs")) db.audits++;
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }

  async batch(statements: unknown[]) {
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const raw of statements) {
      const statement = raw as { query: string; getValues(): unknown[] };
      const query = statement.query;
      const values = statement.getValues();
      let changes = 0;
      if (query.includes("UPDATE application_nodes SET signing_public_key = ?, enrollment_consumed_at")) {
        const [publicKey, agentVersion, nodeIdentity, tokenHash] = values as string[];
        if (nodeIdentity === this.node.nodeIdentity && tokenHash === this.node.enrollmentKeyHash &&
            this.node.status === "pending" && this.node.poolReady && !this.node.signingPublicKey) {
          this.node.signingPublicKey = publicKey;
          this.node.agentVersion = agentVersion;
          this.node.status = "online";
          changes = 1;
        }
      } else if (query.includes("INSERT INTO application_node_signing_key_history") &&
          query.includes("enrollment_consumed_at IS NOT NULL")) {
        const [keyId, nodeIdentity, publicKey] = values as string[];
        if (nodeIdentity === this.node.nodeIdentity && this.node.signingPublicKey === publicKey &&
            this.node.status === "online" && !this.keyHistory.includes(publicKey)) {
          this.keyHistory.push(publicKey);
          changes = 1;
        }
      } else if (query.includes("UPDATE application_nodes SET signing_public_key = ?, key_rotation_challenge_hash")) {
        const [newKey, nodeId, nodeIdentity, oldKey, challengeHash] = values as string[];
        if (nodeId === this.node.id && nodeIdentity === this.node.nodeIdentity &&
            oldKey === this.node.signingPublicKey && challengeHash === this.node.challengeHash &&
            ["online", "draining"].includes(this.node.status) && this.node.challengeExpiresAt &&
            Date.parse(this.node.challengeExpiresAt + "Z") > Date.now()) {
          this.keyHistory.push(oldKey, newKey);
          this.node.signingPublicKey = newKey;
          this.node.challengeHash = null;
          this.node.challengeExpiresAt = null;
          changes = 1;
        }
      } else if (query.includes("INSERT OR IGNORE INTO application_usage_periods")) {
        const [id, periodStart, projectId, organizationId] = values as [string, string, string, string];
        if (projectId === this.deploymentRow.projectId && organizationId === this.deploymentRow.organizationId &&
            organizationId === this.projectOrganizationId && !this.usagePeriod) {
          this.usagePeriod = { organizationId, projectId, periodStart, buildSecondsUsed: 0, buildMinutesLimit: 300 };
          changes = 1;
        }
      } else if (query.includes("INSERT OR IGNORE INTO application_usage_events")) {
        const [id, periodStart, buildSeconds, buildResult, nodeId, deploymentId, organizationId, projectId] =
          values as [string, string, number, string, string, string, string, string];
        if (!this.usageEvents.has(deploymentId) && this.deploymentRow.id === deploymentId &&
            this.deploymentRow.status !== "queued" && organizationId === this.deploymentRow.organizationId &&
            projectId === this.deploymentRow.projectId && this.usagePeriod?.periodStart === periodStart) {
          this.usageEvents.set(deploymentId, { id, organizationId, projectId, deploymentId, periodStart,
            buildSeconds, buildResult, aggregatedAt: null, nodeId });
          changes = 1;
        }
      } else if (query.includes("UPDATE application_usage_periods")) {
        if (this.usagePeriod) {
          const pending = [...this.usageEvents.values()].filter((event) =>
            event.organizationId === this.usagePeriod?.organizationId &&
            event.projectId === this.usagePeriod?.projectId &&
            event.periodStart === this.usagePeriod?.periodStart && event.aggregatedAt === null);
          this.usagePeriod.buildSecondsUsed += pending.reduce((sum, event) => sum + event.buildSeconds, 0);
          changes = 1;
        }
      } else if (query.includes("UPDATE application_usage_events SET aggregated_at")) {
        for (const event of this.usageEvents.values()) {
          if (event.aggregatedAt === null) { event.aggregatedAt = "2026-11-07 00:00:00"; changes++; }
        }
      }
      results.push({ success: true, meta: { changes } });
    }
    return results;
  }
}

const identity = (role: TestIdentity["role"], organizationId = "org-a"): TestIdentity => ({
  id: "user-a",
  email: "test@example.invalid",
  displayName: "Test User",
  organizationId,
  organizationName: "Test Organization",
  organizationSlug: "test-org",
  role,
  platformRole: null,
});

function environment(db: TestD1, operatorToken?: string) {
  return {
    DB: db as unknown as D1Database,
    APPLICATION_NODE_OPERATOR_TOKEN: operatorToken,
    GITHUB_APP_ID: "test-app",
    GITHUB_APP_PRIVATE_KEY: "test-private-key",
  };
}

async function createNodeKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const privateKey = pair.privateKey;
  const publicKeyHex = Array.from(publicKey, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { publicKeyHex, privateKey };
}

async function signedNodeRequest(body: unknown, privateKey: CryptoKey, nonce = "a".repeat(32), timestamp = String(Math.floor(Date.now() / 1000)), path = "/internal/v1/application-build-usage") {
  const rawBody = JSON.stringify(body);
  const message = new TextEncoder().encode(timestamp + "." + nonce + "." + rawBody);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message));
  const signatureHex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-node-identity": "builder-a",
      "x-nexora-node-timestamp": timestamp,
      "x-nexora-node-nonce": nonce,
      "x-nexora-node-signature": signatureHex,
    },
    body: rawBody,
  });
}

function request(method: string, path: string, body?: unknown, authenticated = true) {
  const headers = new Headers();
  if (authenticated) headers.set("authorization", "Bearer " + "a".repeat(64));
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request("https://api.test" + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const validSettings = {
  runtimeProfileId: "runtime-nodejs-v1",
  buildMethod: "managed",
  buildContext: ".",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  startCommand: "npm run start",
  listenPort: 3000,
  healthCheckPath: "/health",
  cpuMillis: 500,
  memoryMiB: 512,
  diskMiB: 2048,
  processLimit: 128,
};

test("customer MEMBER identity cannot access WHM server inventory", async () => {
  const db = new TestD1(identity("MEMBER"));
  const response = await worker.fetch(request("GET", "/v1/servers"), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { message: "Customer accounts cannot access WHM administration." });
});

test("customer OWNER identity cannot dispatch production deployments before platform enablement", async () => {
  const db = new TestD1(identity("OWNER"));
  const response = await worker.fetch(
    request("POST", "/v1/github/projects/project-a/deployments", {}),
    environment(db),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { message: "Customer accounts cannot access WHM administration." });
  assert.equal(db.writes, 0);
});

test("customer ADMIN identity cannot dispatch production deployments before platform enablement", async () => {
  const db = new TestD1(identity("ADMIN"));
  const response = await worker.fetch(
    request("POST", "/v1/github/projects/project-a/deployments", {}),
    environment(db),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { message: "Customer accounts cannot access WHM administration." });
  assert.equal(db.writes, 0);
});

test("platform deployment dispatch rejects projects with no runtime assignment", async () => {
  const db = new TestD1(identity("OWNER"));
  db.identity!.platformRole = "ADMIN";
  const response = await worker.fetch(
    request("POST", "/v1/github/projects/project-a/deployments", {}),
    environment(db),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    message: "Application deployment is not admitted: configure an enabled runtime assigned to a ready isolated pool with an online runtime node.",
  });
  assert.equal(db.writes, 0);
});

test("settings PUT rejects unauthenticated requests with 401", async () => {
  const db = new TestD1(null);
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", validSettings, false), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 401);
  assert.equal(db.writes, 0);
});

test("settings PUT rejects MEMBER role with 403 before project writes", async () => {
  const db = new TestD1(identity("MEMBER"));
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", validSettings), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 403);
  assert.equal(db.writes, 0);
});

test("settings PUT returns 404 for a project outside the caller organization", async () => {
  const db = new TestD1(identity("OWNER"));
  db.projectOrganizationId = "org-b";
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", validSettings), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 404);
  assert.equal(db.writes, 0);
});

test("settings PUT rejects path traversal without persisting settings", async () => {
  const db = new TestD1(identity("ADMIN"));
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", {
    ...validSettings, buildContext: "../outside",
  }), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 400);
  assert.equal(db.writes, 0);
});

test("settings PUT rejects resource values outside platform bounds", async () => {
  const db = new TestD1(identity("OWNER"));
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", {
    ...validSettings, memoryMiB: 16385,
  }), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 400);
  assert.equal(db.writes, 0);
});

test("settings PUT rejects resources above the assigned hosting plan quota", async () => {
  const db = new TestD1(identity("OWNER"));
  const response = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", {
    ...validSettings, memoryMiB: 513,
  }), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 400);
  const result = await response.json() as { message: string; planResourceLimits: { memoryMiB: number } };
  assert.match(result.message, /hosting plan quotas/i);
  assert.equal(result.planResourceLimits.memoryMiB, 512);
  assert.equal(db.writes, 0);
});

test("OWNER can save settings and read them back as metadata only", async () => {
  const db = new TestD1(identity("OWNER"));
  const put = await worker.fetch(request("PUT", "/v1/applications/projects/project-a/settings", validSettings), environment(db), {} as ExecutionContext);
  assert.equal(put.status, 200);
  const saved = await put.json() as {
    saved: boolean; executionEnabled: boolean; planQuotasEnforced: boolean;
    planResourceLimits: { cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number };
  };
  assert.equal(saved.saved, true);
  assert.equal(saved.executionEnabled, false);
  assert.equal(saved.planQuotasEnforced, true);
  assert.equal(saved.planResourceLimits.memoryMiB, 512);
  assert.equal(db.writes, 1);
  assert.equal(db.audits, 1);

  const get = await worker.fetch(request("GET", "/v1/applications/projects/project-a/settings"), environment(db), {} as ExecutionContext);
  assert.equal(get.status, 200);
  const result = await get.json() as {
    executionEnabled: boolean;
    planLimits: { cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number };
    settings: { runtimeProfileId: string; buildContext: string; resources: { memoryMiB: number } } | null;
  };
  assert.equal(result.executionEnabled, false);
  assert.equal(result.planLimits.memoryMiB, 512);
  assert.equal(result.settings?.runtimeProfileId, "runtime-nodejs-v1");
  assert.equal(result.settings?.buildContext, ".");
  assert.equal(result.settings?.resources.memoryMiB, 512);
});

test("settings GET does not reveal projects from another organization", async () => {
  const db = new TestD1(identity("MEMBER"));
  db.projectOrganizationId = "org-b";
  const response = await worker.fetch(request("GET", "/v1/applications/projects/project-a/settings"), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 404);
});


test("project usage GET requires authentication", async () => {
  const db = new TestD1(null);
  const response = await worker.fetch(request("GET", "/v1/applications/projects/project-a/usage", undefined, false), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 401);
});

test("project usage GET is tenant-scoped and reports current monthly allowance", async () => {
  const db = new TestD1(identity("MEMBER"));
  db.usageRow = { id: "project-a", buildMinutesLimit: 300, buildSecondsUsed: 90 };
  const response = await worker.fetch(request("GET", "/v1/applications/projects/project-a/usage"), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 200);
  const result = await response.json() as {
    buildMinutesLimit: number; buildSecondsUsed: number; buildMinutesUsed: number;
    buildSecondsRemaining: number; quotaExhausted: boolean; executionEnabled: boolean;
    meteringStatus: string; periodStart: string;
  };
  assert.equal(result.buildMinutesLimit, 300);
  assert.equal(result.buildSecondsUsed, 90);
  assert.equal(result.buildMinutesUsed, 1.5);
  assert.equal(result.buildSecondsRemaining, 17910);
  assert.equal(result.quotaExhausted, false);
  assert.equal(result.executionEnabled, false);
  assert.equal(result.meteringStatus, "not_connected");
  assert.match(result.periodStart, /^\d{4}-\d{2}-01$/);
});

test("project usage GET does not expose another organization's project", async () => {
  const db = new TestD1(identity("MEMBER"));
  db.projectOrganizationId = "org-b";
  const response = await worker.fetch(request("GET", "/v1/applications/projects/project-a/usage"), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 404);
});



test("node enrollment consumes a one-time token and stores the Ed25519 public key", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  const enrollmentToken = "e".repeat(64);
  db.node.enrollmentKeyHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(enrollmentToken))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await worker.fetch(new Request("https://api.test/internal/v1/application-nodes/enroll", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ nodeIdentity: "builder-a", enrollmentToken, publicKey: pair.publicKeyHex, agentVersion: "0.1.0" }),
  }), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 200);
  assert.equal(db.node.status, "online");
  assert.equal(db.node.signingPublicKey, pair.publicKeyHex);
  assert.deepEqual(db.keyHistory, [pair.publicKeyHex], "enrollment must record the initial key in the same transaction");
  const replay = await worker.fetch(new Request("https://api.test/internal/v1/application-nodes/enroll", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ nodeIdentity: "builder-a", enrollmentToken, publicKey: pair.publicKeyHex, agentVersion: "0.1.0" }),
  }), environment(db), {} as ExecutionContext);
  assert.equal(replay.status, 409);
});

test("node enrollment rejects enrollment while its pool is not ready", async () => {
  const db = new TestD1(null);
  db.node.poolReady = false;
  const pair = await createNodeKeyPair();
  const token = "e".repeat(64);
  db.node.enrollmentKeyHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await worker.fetch(new Request("https://api.test/internal/v1/application-nodes/enroll", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ nodeIdentity: "builder-a", enrollmentToken: token, publicKey: pair.publicKeyHex, agentVersion: "0.1.0" }),
  }), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 409);
});

test("per-node Ed25519 usage reports are accepted once and duplicate delivery is idempotent", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  const body = { deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" };
  const first = await worker.fetch(await signedNodeRequest(body, pair.privateKey), environment(db), {} as ExecutionContext);
  assert.equal(first.status, 200);
  const firstResult = await first.json() as { accepted: boolean; duplicate: boolean; buildSecondsUsed: number; buildMinutesLimit: number };
  assert.equal(firstResult.accepted, true);
  assert.equal(firstResult.duplicate, false);
  assert.equal(firstResult.buildSecondsUsed, 90);
  assert.equal(firstResult.buildMinutesLimit, 300);

  const replay = await worker.fetch(await signedNodeRequest(body, pair.privateKey, "9".repeat(32)), environment(db), {} as ExecutionContext);
  assert.equal(replay.status, 200);
  const replayResult = await replay.json() as { accepted: boolean; duplicate: boolean; buildSecondsUsed: number };
  assert.equal(replayResult.accepted, true);
  assert.equal(replayResult.duplicate, true);
  assert.equal(replayResult.buildSecondsUsed, 90);
  assert.equal(db.usageEvents.size, 1);
  const conflict = await worker.fetch(await signedNodeRequest(
    { deploymentId: "deployment-a", buildSeconds: 91, buildResult: "succeeded" }, pair.privateKey, "b".repeat(32)),
    environment(db), {} as ExecutionContext);
  assert.equal(conflict.status, 409);
});

test("a previously accepted node request nonce cannot be replayed even for an idempotent usage report", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  const body = { deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" };
  const nonce = "a".repeat(32);
  const first = await worker.fetch(await signedNodeRequest(body, pair.privateKey, nonce), environment(db), {} as ExecutionContext);
  assert.equal(first.status, 200);
  const replay = await worker.fetch(await signedNodeRequest(body, pair.privateKey, nonce), environment(db), {} as ExecutionContext);
  assert.equal(replay.status, 409);
  assert.equal(db.usageEvents.size, 1);
});

test("per-node usage authentication rejects invalid signatures and stale timestamps", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  const bad = new Request("https://api.test/internal/v1/application-build-usage", {
    method: "POST",
    headers: { "content-type": "application/json", "x-nexora-node-identity": "builder-a",
      "x-nexora-node-timestamp": String(Math.floor(Date.now() / 1000)), "x-nexora-node-nonce": "b".repeat(32),
      "x-nexora-node-signature": "0".repeat(128) },
    body: JSON.stringify({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" }),
  });
  const invalid = await worker.fetch(bad, environment(db), {} as ExecutionContext);
  assert.equal(invalid.status, 401);
  const stale = await worker.fetch(await signedNodeRequest({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" },
    pair.privateKey, "c".repeat(32), String(Math.floor(Date.now() / 1000) - 600)), environment(db), {} as ExecutionContext);
  assert.equal(stale.status, 401);
});

test("per-node usage authentication rejects a revoked node and duplicate request nonce", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  db.nodeNonces.add("d".repeat(32));
  const duplicateNonce = await worker.fetch(await signedNodeRequest({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" },
    pair.privateKey, "d".repeat(32)), environment(db), {} as ExecutionContext);
  assert.equal(duplicateNonce.status, 409);
  db.node.status = "revoked";
  const revoked = await worker.fetch(await signedNodeRequest({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" },
    pair.privateKey, "f".repeat(32)), environment(db), {} as ExecutionContext);
  assert.equal(revoked.status, 401);
});

test("per-node usage report rejects queued deployments", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  db.deploymentRow.status = "queued";
  const response = await worker.fetch(await signedNodeRequest({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" },
    pair.privateKey), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 409);
});


test("signed runtime heartbeat updates agent version for eligible online nodes", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  const response = await worker.fetch(
    await signedNodeRequest({ agentVersion: "0.2.0" }, pair.privateKey, "7".repeat(32),
      String(Math.floor(Date.now() / 1000)), "/internal/v1/application-nodes/heartbeat"),
    environment(db), {} as ExecutionContext,
  );
  assert.equal(response.status, 200);
  assert.equal(db.node.agentVersion, "0.2.0");
  assert.equal(db.nodeNonces.has("7".repeat(32)), true);
});

test("signed node heartbeat rejects unexpected fields", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.status = "online";
  const response = await worker.fetch(
    await signedNodeRequest({ agentVersion: "0.2.0", status: "online" }, pair.privateKey, "8".repeat(32),
      String(Math.floor(Date.now() / 1000)), "/internal/v1/application-nodes/heartbeat"),
    environment(db), {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});


const operatorToken = "operator-token-" + "x".repeat(40);

function operatorRequest(path: string, token = operatorToken, body?: unknown) {
  return new Request("https://api.test" + path, {
    method: "POST",
    headers: { authorization: "Bearer " + token, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test("node operator controls fail closed when the operator secret is not configured", async () => {
  const db = new TestD1(null);
  const response = await worker.fetch(operatorRequest("/internal/v1/operator/application-nodes/node-a/revoke"),
    environment(db), {} as ExecutionContext);
  assert.equal(response.status, 503);
  assert.equal(db.node.status, "pending");
});

test("node revocation requires operator authorization and is terminal", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.status = "online";
  db.node.signingPublicKey = pair.publicKeyHex;
  const denied = await worker.fetch(operatorRequest("/internal/v1/operator/application-nodes/node-a/revoke", "wrong-token"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(denied.status, 401);
  const revoked = await worker.fetch(operatorRequest("/internal/v1/operator/application-nodes/node-a/revoke", operatorToken,
    { reason: "operator security test" }), environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(revoked.status, 200);
  assert.equal(db.node.status, "revoked");
  const heartbeat = await worker.fetch(await signedNodeRequest({ agentVersion: "0.3.0" }, pair.privateKey,
    "1".repeat(32), String(Math.floor(Date.now() / 1000)), "/internal/v1/application-nodes/heartbeat"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(heartbeat.status, 401);
  const repeat = await worker.fetch(operatorRequest("/internal/v1/operator/application-nodes/node-a/revoke"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(repeat.status, 404);
});

test("operator challenge and old-key proof rotate a node signing key exactly once", async () => {
  const db = new TestD1(null);
  const oldPair = await createNodeKeyPair();
  const newPair = await createNodeKeyPair();
  db.node.status = "online";
  db.node.signingPublicKey = oldPair.publicKeyHex;
  const challengeResponse = await worker.fetch(
    operatorRequest("/internal/v1/operator/application-nodes/node-a/key-rotation-challenge"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(challengeResponse.status, 200);
  const challengeResult = await challengeResponse.json() as { challenge: string };
  const rotate = await worker.fetch(
    await signedNodeRequest({ newPublicKey: newPair.publicKeyHex, challenge: challengeResult.challenge },
      oldPair.privateKey, "2".repeat(32), String(Math.floor(Date.now() / 1000)), "/internal/v1/application-nodes/rotate-key"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(rotate.status, 200);
  assert.equal(db.node.signingPublicKey, newPair.publicKeyHex);
  assert.deepEqual(db.keyHistory, [oldPair.publicKeyHex, newPair.publicKeyHex]);
  const replay = await worker.fetch(
    await signedNodeRequest({ newPublicKey: oldPair.publicKeyHex, challenge: challengeResult.challenge },
      oldPair.privateKey, "3".repeat(32), String(Math.floor(Date.now() / 1000)), "/internal/v1/application-nodes/rotate-key"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(replay.status, 401);
});

test("revoked nodes cannot request or complete signing-key rotation", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  const replacement = await createNodeKeyPair();
  db.node.status = "revoked";
  db.node.revokedAt = "2026-11-07 00:00:00";
  db.node.signingPublicKey = pair.publicKeyHex;
  db.node.challengeHash = "a".repeat(64);
  db.node.challengeExpiresAt = "2026-11-07 00:10:00";

  const challenge = await worker.fetch(
    operatorRequest("/internal/v1/operator/application-nodes/node-a/key-rotation-challenge"),
    environment(db, operatorToken), {} as ExecutionContext,
  );
  assert.equal(challenge.status, 404);

  const rotation = await worker.fetch(
    await signedNodeRequest({ newPublicKey: replacement.publicKeyHex, challenge: "a".repeat(64) },
      pair.privateKey, "5".repeat(32), String(Math.floor(Date.now() / 1000)),
      "/internal/v1/application-nodes/rotate-key"),
    environment(db, operatorToken), {} as ExecutionContext,
  );
  assert.equal(rotation.status, 401);
  assert.equal(db.node.signingPublicKey, pair.publicKeyHex);
});

test("revoked nodes cannot submit signed builder usage reports", async () => {
  const db = new TestD1(null);
  const pair = await createNodeKeyPair();
  db.node.status = "revoked";
  db.node.signingPublicKey = pair.publicKeyHex;
  const response = await worker.fetch(await signedNodeRequest(
    { deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" }, pair.privateKey, "4".repeat(32)),
    environment(db), {} as ExecutionContext);
  assert.equal(response.status, 401);
  assert.equal(db.usageEvents.size, 0);
});
