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
  usageEvents = new Map<string, { id: string; organizationId: string; projectId: string; deploymentId: string; periodStart: string; buildSeconds: number; buildResult: string; aggregatedAt: string | null }>();

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
        if (query.includes("FROM github_deployments d")) {
          const [deploymentId] = values;
          return deploymentId === db.deploymentRow.id && ["cloning", "installing", "building"].includes(db.deploymentRow.status)
            ? ({ ...db.deploymentRow } as T) : null;
        }
        if (query.includes("FROM application_usage_events")) {
          const [organizationId, projectId, deploymentId] = values;
          const event = db.usageEvents.get(String(deploymentId));
          return event && event.organizationId === organizationId && event.projectId === projectId
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
          return projectId === "project-a" && organizationId === db.projectOrganizationId
            ? ({ id: "project-a" } as T) : null;
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
      if (query.includes("INSERT OR IGNORE INTO application_usage_periods")) {
        const [id, periodStart, projectId, organizationId] = values as [string, string, string, string];
        if (projectId === this.deploymentRow.projectId && organizationId === this.deploymentRow.organizationId &&
            organizationId === this.projectOrganizationId && !this.usagePeriod) {
          this.usagePeriod = { organizationId, projectId, periodStart, buildSecondsUsed: 0, buildMinutesLimit: 300 };
          changes = 1;
        }
      } else if (query.includes("INSERT OR IGNORE INTO application_usage_events")) {
        const [id, periodStart, buildSeconds, buildResult, deploymentId, organizationId, projectId] =
          values as [string, string, number, string, string, string, string];
        if (!this.usageEvents.has(deploymentId) && this.deploymentRow.id === deploymentId &&
            this.deploymentRow.status !== "queued" && organizationId === this.deploymentRow.organizationId &&
            projectId === this.deploymentRow.projectId && this.usagePeriod?.periodStart === periodStart) {
          this.usageEvents.set(deploymentId, { id, organizationId, projectId, deploymentId, periodStart,
            buildSeconds, buildResult, aggregatedAt: null });
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
});

function environment(db: TestD1, meteringSecret?: string) {
  return { DB: db as unknown as D1Database, APPLICATION_BUILDER_METERING_SECRET: meteringSecret };
}

async function signedBuilderRequest(body: unknown, secret: string, timestamp = String(Math.floor(Date.now() / 1000))) {
  const rawBody = JSON.stringify(body);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key,
    new TextEncoder().encode(timestamp + "." + rawBody)));
  const signature = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request("https://api.test/internal/v1/application-build-usage", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexora-builder-timestamp": timestamp,
      "x-nexora-builder-signature": "sha256=" + signature,
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


test("builder usage ingestion is disabled when the signing secret is not configured", async () => {
  const db = new TestD1(null);
  const response = await worker.fetch(
    request("POST", "/internal/v1/application-build-usage", { deploymentId: "deployment-a", buildSeconds: 60, buildResult: "succeeded" }),
    environment(db),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 503);
});

test("builder usage ingestion rejects an invalid HMAC signature", async () => {
  const db = new TestD1(null);
  const body = { deploymentId: "deployment-a", buildSeconds: 60, buildResult: "succeeded" };
  const rawBody = JSON.stringify(body);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const response = await worker.fetch(new Request("https://api.test/internal/v1/application-build-usage", {
    method: "POST",
    headers: { "content-type": "application/json", "x-nexora-builder-timestamp": timestamp, "x-nexora-builder-signature": "sha256=" + "0".repeat(64) },
    body: rawBody,
  }), environment(db, "s".repeat(48)), {} as ExecutionContext);
  assert.equal(response.status, 401);
});

test("builder usage ingestion verifies HMAC before validating payload", async () => {
  const db = new TestD1(null);
  const secret = "s".repeat(48);
  const response = await worker.fetch(
    await signedBuilderRequest({ deploymentId: "deployment-a", buildSeconds: 0, buildResult: "succeeded" }, secret),
    environment(db, secret),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 400);
});

test("builder usage ingestion rejects stale signed reports", async () => {
  const db = new TestD1(null);
  const secret = "s".repeat(48);
  const staleTimestamp = String(Math.floor(Date.now() / 1000) - 600);
  const response = await worker.fetch(
    await signedBuilderRequest({ deploymentId: "deployment-a", buildSeconds: 60, buildResult: "succeeded" }, secret, staleTimestamp),
    environment(db, secret),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 401);
});


test("authenticated builder usage report is recorded once and replay is idempotent", async () => {
  const db = new TestD1(null);
  const secret = "s".repeat(48);
  const body = { deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" };
  const first = await worker.fetch(await signedBuilderRequest(body, secret), environment(db, secret), {} as ExecutionContext);
  assert.equal(first.status, 200);
  const firstResult = await first.json() as { accepted: boolean; duplicate: boolean; buildSecondsUsed: number; buildMinutesLimit: number };
  assert.equal(firstResult.accepted, true);
  assert.equal(firstResult.duplicate, false);
  assert.equal(firstResult.buildSecondsUsed, 90);
  assert.equal(firstResult.buildMinutesLimit, 300);

  const replay = await worker.fetch(await signedBuilderRequest(body, secret), environment(db, secret), {} as ExecutionContext);
  assert.equal(replay.status, 200);
  const replayResult = await replay.json() as { accepted: boolean; duplicate: boolean; buildSecondsUsed: number };
  assert.equal(replayResult.accepted, true);
  assert.equal(replayResult.duplicate, true);
  assert.equal(replayResult.buildSecondsUsed, 90);
  assert.equal(db.usageEvents.size, 1);
});

test("builder usage report cannot be submitted for a queued deployment", async () => {
  const db = new TestD1(null);
  db.deploymentRow.status = "queued";
  const secret = "s".repeat(48);
  const response = await worker.fetch(
    await signedBuilderRequest({ deploymentId: "deployment-a", buildSeconds: 90, buildResult: "succeeded" }, secret),
    environment(db, secret),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 409);
  assert.equal(db.usageEvents.size, 0);
});
