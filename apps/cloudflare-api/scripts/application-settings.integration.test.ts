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

  constructor(identity: TestIdentity | null) { this.identity = identity; }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_usage_periods")) {
          const [periodStart, projectId, organizationId] = values;
          if (projectId !== "project-a" || organizationId !== db.projectOrganizationId) return null;
          return (db.usageRow ?? { id: "project-a", buildMinutesLimit: 300, buildSecondsUsed: 0 }) as T;
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

function environment(db: TestD1) {
  return { DB: db as unknown as D1Database };
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
  assert.match(result.periodStart, /^\\d{4}-\\d{2}-01$/);
});

test("project usage GET does not expose another organization's project", async () => {
  const db = new TestD1(identity("MEMBER"));
  db.projectOrganizationId = "org-b";
  const response = await worker.fetch(request("GET", "/v1/applications/projects/project-a/usage"), environment(db), {} as ExecutionContext);
  assert.equal(response.status, 404);
});
