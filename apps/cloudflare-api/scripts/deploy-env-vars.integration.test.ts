import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// deploy-env-vars.integration.test.ts
//
// Regression tests for the Nexora Deploy batch-3 routes:
//
//   * GET  /v1/deploy/framework-presets           (catalog, authenticated)
//   * POST /v1/github/projects/detect-framework   (trees + package.json)
//   * CRUD /v1/github/projects/:id/env-vars       (AES-GCM at rest, masked)
//
// The D1 mock implements only the SQL these routes issue; every other query
// throws so endpoint drift fails loudly. GitHub REST traffic is stubbed at
// the network boundary. The tests assert that values are encrypted at rest,
// never returned by any response, that tenant isolation holds at the query
// level, and that detection is honest about its evidence.
//
// Scenarios:
//   1.  Framework presets catalog requires authentication and lists the
//       six supported presets with build/output contract.
//   2.  Env var create stores AES-GCM ciphertext (never plaintext) and
//       returns metadata only.
//   3.  Listing never exposes values or ciphertext; JSON body contains no
//       plaintext.
//   4.  Unauthenticated create/list is 401.
//   5.  Customer developer membership can access env vars (middleware
//       exemption works — no WHM platform gate).
//   6.  READONLY account membership is denied (404, no existence leak).
//   7.  Cross-tenant project access is 404.
//   8.  Invalid key names, environments, targets, and value sizes are 400.
//   9.  Duplicate (key, environment) is 409; same key in another
//       environment succeeds.
//   10. Missing DEPLOY_ENV_ENCRYPTION_KEY is 503 with exact requirements.
//   11. PATCH rotates ciphertext and IV; metadata-only PATCH leaves the
//       stored value untouched (IV unchanged).
//   12. PATCH/DELETE unknown variable is 404; delete then list is empty.
//   13. 128-variable per-project limit returns 409.
//   14. Detection: Next.js via dependencies; Astro via config file only;
//       plain HTML falls back to static with honest evidence.
//   15. Detection errors are honest: 404 repository/branch, 429 rate limit
//       with reset passthrough, 409 without a GitHub connection.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "d".repeat(64);
const SESSION_HASH = createHash("sha256").update(SESSION_TOKEN).digest("hex");
const ORG_A = "11111111-1111-4111-8111-111111111111";
const ORG_B = "22222222-2222-4222-8222-222222222222";
const OWNER_A = "aaaaaaa1-0000-4000-8000-000000000001"; // org A OWNER
const DEV_A = "aaaaaaa2-0000-4000-8000-000000000002"; // org A MEMBER + account developer
const READONLY_A = "aaaaaaa3-0000-4000-8000-000000000003"; // org A MEMBER + account readonly
const OUTSIDER = "bbbbbbb1-0000-4000-8000-000000000004"; // org B MEMBER
const ACCOUNT_1 = "eeeeeee1-0000-4000-8000-000000000008";
const PROJECT_1 = "a1000000-0000-4000-8000-000000000001"; // linked to ACCOUNT_1 (hex UUID)
const PROJECT_B = "a2000000-0000-4000-8000-000000000002"; // org B project (hex UUID)
const TOKEN_KEY = "f".repeat(64);
const ENV_KEY = "a".repeat(64);
const REPO_FULL = "acme/landing";
const GITHUB_TOKEN = "ghus_test_token_1234567890";

type Identity = {
  id: string;
  email: string;
  displayName: string | null;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: string;
  platformRole: string | null;
};

const OWNER_IDENTITY: Identity = {
  id: OWNER_A,
  email: "owner@acme.test",
  displayName: "Acme Owner",
  organizationId: ORG_A,
  organizationName: "Acme Hosting",
  organizationSlug: "acme-hosting",
  role: "OWNER",
  platformRole: null,
};

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

type EnvVarRow = {
  id: string;
  organization_id: string;
  project_id: string;
  key_name: string;
  environment: string;
  target: string;
  encrypted_value: string;
  value_iv: string;
  is_secret: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

class DeployEnvD1 {
  identity: Identity | null;
  vars = new Map<string, EnvVarRow>(); // key: `${project_id}:${id}`
  membershipRole: string | null = "ACCOUNT_DEVELOPER"; // role for the active identity on ACCOUNT_1
  activeAccount = ACCOUNT_1;
  connection: { encrypted_access_token: string; access_token_iv: string; encrypted_refresh_token: string | null; refresh_token_iv: string | null; token_expires_at: string | null; refresh_token_expires_at: string | null } | null = null;
  auditActions: string[] = [];

  constructor(identity: Identity | null) {
    this.identity = identity;
  }

  async encryptGithubTokenForTest(token: string) {
    const encrypted = await encryptWithKey(TOKEN_KEY, token);
    this.connection = {
      encrypted_access_token: encrypted.ciphertext,
      access_token_iv: encrypted.iv,
      encrypted_refresh_token: null,
      refresh_token_iv: null,
      token_expires_at: new Date(Date.now() + 3600_000).toISOString(),
      refresh_token_expires_at: null,
    };
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>(): Promise<T | null> {
        if (query.includes("FROM auth_sessions")) {
          if (!db.identity) return null;
          return { ...db.identity } as T;
        }
        if (query.includes("encrypted_access_token")) {
          if (!db.connection) return null;
          return { ...db.connection } as T;
        }
        if (query.startsWith("SELECT id, organization_id FROM github_projects")) {
          const [projectId, orgId] = values as [string, string];
          if (projectId === PROJECT_1 && orgId === ORG_A) return { id: PROJECT_1, organization_id: ORG_A } as T;
          if (projectId === PROJECT_B && orgId === ORG_B) return { id: PROJECT_B, organization_id: ORG_B } as T;
          return null;
        }
        if (query.includes("FROM github_projects p") && query.includes("hosting_account_memberships")) {
          const [projectId, orgId, userId] = values as [string, string, string];
          if (orgId !== ORG_A && orgId !== ORG_B) return null;
          if (projectId === PROJECT_1 && orgId === ORG_A) {
            const linkedAccount = db.activeAccount === ACCOUNT_1 ? PROJECT_1 : "";
            if (!linkedAccount) return null;
            if (userId !== db.identity?.id) return null;
            if (!db.membershipRole) return null;
            if (db.membershipRole !== "ACCOUNT_OWNER" && db.membershipRole !== "ACCOUNT_ADMIN" && db.membershipRole !== "ACCOUNT_DEVELOPER") return null;
            return { id: PROJECT_1, organization_id: ORG_A } as T;
          }
          if (projectId === PROJECT_B && orgId === ORG_B && db.identity?.organizationId === ORG_B) {
            // Org B project: the outsider has no membership rows in this mock.
            return null;
          }
          return null;
        }
        if (query.includes("COUNT(*) AS total") && query.includes("application_env_vars")) {
          const [projectId, orgId] = values as [string, string];
          let total = 0;
          for (const row of db.vars.values()) {
            if (row.project_id === projectId && row.organization_id === orgId) total += 1;
          }
          return { total } as T;
        }
        if (query.startsWith("SELECT id, environment, target, is_secret FROM application_env_vars")) {
          const [envVarId, projectId, orgId] = values as [string, string, string];
          const row = db.vars.get(`${projectId}:${envVarId}`);
          if (!row || row.organization_id !== orgId) return null;
          return { id: row.id, environment: row.environment, target: row.target, is_secret: row.is_secret } as T;
        }
        throw new Error(`Unexpected first() query: ${query.slice(0, 140)}`);
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (query.startsWith("SELECT id, key_name, environment, target, is_secret, created_at, updated_at")) {
          const [projectId, orgId] = values as [string, string];
          const rows = [...db.vars.values()]
            .filter((row) => row.project_id === projectId && row.organization_id === orgId)
            .sort((a, b) => a.key_name.localeCompare(b.key_name) || a.environment.localeCompare(b.environment))
            .map((row) => ({
              id: row.id, key_name: row.key_name, environment: row.environment,
              target: row.target, is_secret: row.is_secret, created_at: row.created_at, updated_at: row.updated_at,
            }));
          return { results: rows as T[] };
        }
        throw new Error(`Unexpected all() query: ${query.slice(0, 140)}`);
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        if (query.startsWith("INSERT INTO application_env_vars")) {
          const [id, organizationId, projectId, keyName, environment, target, encryptedValue, valueIv, isSecret] = values as [string, string, string, string, string, string, string, string, number];
          for (const row of db.vars.values()) {
            if (row.project_id === projectId && row.key_name === keyName && row.environment === environment) {
              throw new Error("UNIQUE constraint failed: application_env_vars.project_id, application_env_vars.key_name, application_env_vars.environment");
            }
          }
          const now = new Date().toISOString();
          db.vars.set(`${projectId}:${id}`, {
            id, organization_id: organizationId, project_id: projectId, key_name: keyName,
            environment, target, encrypted_value: encryptedValue, value_iv: valueIv,
            is_secret: isSecret, created_by: null, created_at: now, updated_at: now,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("UPDATE application_env_vars")) {
          const idIdx = query.includes("encrypted_value = ?") ? 4 : 2;
          const envVarId = values[idIdx] as string;
          const projectId = values[idIdx + 1] as string;
          const orgId = values[idIdx + 2] as string;
          const row = db.vars.get(`${projectId}:${envVarId}`);
          if (!row || row.organization_id !== orgId) return { success: true, meta: { changes: 0 } };
          if (query.includes("encrypted_value = ?")) {
            const [encryptedValue, valueIv, target, isSecret] = values as [string, string, string, number];
            row.encrypted_value = encryptedValue;
            row.value_iv = valueIv;
            row.target = target;
            row.is_secret = isSecret;
          } else {
            const [target, isSecret] = values as [string, number];
            row.target = target;
            row.is_secret = isSecret;
          }
          row.updated_at = new Date().toISOString();
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("DELETE FROM application_env_vars")) {
          const [envVarId, projectId, orgId] = values as [string, string, string];
          const key = `${projectId}:${envVarId}`;
          const row = db.vars.get(key);
          if (!row || row.organization_id !== orgId) return { success: true, meta: { changes: 0 } };
          db.vars.delete(key);
          return { success: true, meta: { changes: 1 } };
        }
        if (query.startsWith("INSERT INTO audit_logs")) {
          // The action is an inlined SQL literal in these routes.
          const action = /'(deploy\.env_var\.[a-z]+)'/.exec(query)?.[1] ?? "unknown_audit_action";
          db.auditActions.push(action);
          return { success: true, meta: { changes: 1 } };
        }
        throw new Error(`Unexpected run() query: ${query.slice(0, 140)}`);
      },
    };
    return statement;
  }
  async batch(): Promise<Array<{ success: boolean; meta: { changes: number } }>> {
    throw new Error("Unexpected batch()");
  }
}

type StubRoute = {
  match: (url: URL) => boolean;
  respond: () => { status: number; body?: unknown; headers?: Record<string, string> };
};

let restoreFetch: (() => void) | null = null;

function withFetchStub(routes: StubRoute[]): { calls: string[] } {
  const calls: string[] = [];
  const original = globalThis.fetch;
  restoreFetch = () => { globalThis.fetch = original; };
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    calls.push(url.pathname + url.search);
    for (const route of routes) {
      if (route.match(url)) {
        const result = route.respond();
        const headers = new Headers(result.headers ?? {});
        headers.set("content-type", "application/json");
        return new Response(result.body === undefined ? "{}" : JSON.stringify(result.body), { status: result.status, headers });
      }
    }
    return new Response(JSON.stringify({ message: `stubbed route missing for ${url.pathname}` }), { status: 599, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls };
}

type ApiCall = {
  method: string;
  path: string;
  body?: Record<string, unknown>;
  env?: Record<string, string | undefined>;
  identity?: Identity | null;
  membershipRole?: string | null;
};

async function callApi(db: DeployEnvD1, call: ApiCall): Promise<{ status: number; json: Record<string, unknown>; text: string }> {
  db.identity = call.identity === undefined ? OWNER_IDENTITY : call.identity;
  if (call.membershipRole !== undefined) db.membershipRole = call.membershipRole;
  const env: Record<string, string | undefined> = {
    DB: db as unknown as D1Database,
    GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY,
    DEPLOY_ENV_ENCRYPTION_KEY: ENV_KEY,
    ...call.env,
  };
  const request = new Request(`https://worker.test${call.path}`, {
    method: call.method,
    headers: {
      authorization: `Bearer ${SESSION_TOKEN}`,
      "content-type": "application/json",
    },
    body: call.body === undefined ? undefined : JSON.stringify(call.body),
  });
  const response = await worker.fetch(request, env as never, { waitUntil: () => {} } as never);
  const text = await response.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* non-JSON */ }
  return { status: response.status, json, text };
}

const PROJECT_PATH = `/v1/github/projects/${PROJECT_1}/env-vars`;

async function seedVariable(db: DeployEnvD1, key: string, environment = "production", value = `value-for-${key}`): Promise<EnvVarRow> {
  const encrypted = await encryptWithKey(ENV_KEY, value);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const row: EnvVarRow = {
    id,
    organization_id: ORG_A,
    project_id: PROJECT_1,
    key_name: key,
    environment,
    target: "runtime",
    encrypted_value: encrypted.ciphertext,
    value_iv: encrypted.iv,
    is_secret: 1,
    created_by: null,
    created_at: now,
    updated_at: now,
  };
  db.vars.set(`${PROJECT_1}:${id}`, row);
  return row;
}

test("framework presets require authentication and expose the build contract", async () => {
  const db = new DeployEnvD1(null);
  const anonymous = await callApi(db, { method: "GET", path: "/v1/deploy/framework-presets", identity: null });
  assert.equal(anonymous.status, 401);

  const authed = await callApi(db, { method: "GET", path: "/v1/deploy/framework-presets" });
  assert.equal(authed.status, 200);
  const presets = authed.json.presets as Array<Record<string, unknown>>;
  const slugs = presets.map((preset) => preset.slug);
  assert.deepEqual(slugs.sort(), ["astro", "docusaurus", "eleventy", "gatsby", "next-static", "parcel", "react", "static", "vite", "vue"]);
  const next = presets.find((preset) => preset.slug === "next-static")!;
  assert.equal(next.outputDirectory, "out");
  assert.equal(next.requiresBuild, true);
  const statik = presets.find((preset) => preset.slug === "static")!;
  assert.equal(statik.requiresBuild, false);
  assert.equal(statik.buildCommand, null);
  for (const [slug, output] of [["gatsby", "public"], ["docusaurus", "build"], ["eleventy", "_site"], ["parcel", "dist"]] as const) {
    const preset = presets.find((item) => item.slug === slug)!;
    assert.equal(preset.outputDirectory, output, slug);
    assert.equal(preset.requiresBuild, true, slug);
    assert.equal(preset.buildCommand, "npm run build", slug);
  }
});

test("create stores AES-GCM ciphertext and returns metadata only", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const result = await callApi(db, {
    method: "POST", path: PROJECT_PATH,
    body: { key: "API_TOKEN", value: "super-secret-value", environment: "production", target: "both", isSecret: true },
  });
  assert.equal(result.status, 201);
  const variable = result.json.variable as Record<string, unknown>;
  assert.equal(variable.keyName, "API_TOKEN");
  assert.ok(variable.id);
  // Response must not carry any value material.
  assert.equal(result.text.includes("super-secret-value"), false);
  assert.ok(!("value" in variable) && !("encryptedValue" in variable) && !("iv" in variable));

  const stored = [...db.vars.values()];
  assert.equal(stored.length, 1);
  assert.notEqual(stored[0].encrypted_value, "super-secret-value");
  assert.equal(stored[0].encrypted_value.includes("super-secret-value"), false);
  assert.equal(stored[0].value_iv.length > 0, true);
  // The stored value must decrypt back exactly with the env key.
  const keyBytes = Uint8Array.from(ENV_KEY.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)));
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const raw = Uint8Array.from(atob(stored[0].encrypted_value), (ch) => ch.charCodeAt(0));
  const iv = Uint8Array.from(atob(stored[0].value_iv), (ch) => ch.charCodeAt(0));
  const plaintext = new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, raw));
  assert.equal(plaintext, "super-secret-value");
  assert.deepEqual(db.auditActions, ["deploy.env_var.created"]);
});

test("listing never exposes values or ciphertext", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await seedVariable(db, "DATABASE_URL", "production", "postgres://real-secret@example.test/db");
  await seedVariable(db, "FEATURE_FLAG", "preview", "flag-value");
  const result = await callApi(db, { method: "GET", path: PROJECT_PATH });
  assert.equal(result.status, 200);
  assert.equal(result.text.includes("postgres://real-secret"), false);
  assert.equal(result.text.includes("flag-value"), false);
  assert.equal(result.text.includes("encrypted_value"), false);
  assert.equal(result.text.includes("value_iv"), false);
  const variables = result.json.variables as Array<Record<string, unknown>>;
  assert.equal(variables.length, 2);
  for (const variable of variables) {
    assert.ok(variable.keyName && variable.environment && variable.target);
    assert.equal("value" in variable, false);
    assert.equal("encryptedValue" in variable, false);
  }
});

test("unauthenticated requests are rejected", async () => {
  const db = new DeployEnvD1(null);
  const created = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "A", value: "b" }, identity: null });
  assert.equal(created.status, 401);
  const listed = await callApi(db, { method: "GET", path: PROJECT_PATH, identity: null });
  assert.equal(listed.status, 401);
});

test("customer developer membership reaches env vars without the WHM gate", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  // The identity is an org MEMBER with an ACTIVE developer membership.
  const developer: Identity = {
    id: DEV_A, email: "dev@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "MEMBER", platformRole: null,
  };
  const result = await callApi(db, { method: "GET", path: PROJECT_PATH, identity: developer, membershipRole: "ACCOUNT_DEVELOPER" });
  assert.equal(result.status, 200);
  assert.deepEqual(result.json.variables, []);
  // The customer path must use the membership join, not the WHM platform gate.
  const created = await callApi(db, {
    method: "POST", path: PROJECT_PATH, identity: developer, membershipRole: "ACCOUNT_DEVELOPER",
    body: { key: "FROM_CUSTOMER", value: "ok" },
  });
  assert.equal(created.status, 201);
});

test("readonly membership cannot manage env vars", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const readonlyIdentity: Identity = {
    id: READONLY_A, email: "viewer@acme.test", displayName: null,
    organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
    role: "MEMBER", platformRole: null,
  };
  const result = await callApi(db, { method: "POST", path: PROJECT_PATH, identity: readonlyIdentity, membershipRole: "ACCOUNT_READONLY", body: { key: "NOPE", value: "x" } });
  assert.equal(result.status, 404);
  assert.equal(result.text.includes("NOPE"), false);
});

test("cross-tenant project access is 404 without existence leaks", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const outsider: Identity = {
    id: OUTSIDER, email: "outsider@beta.test", displayName: null,
    organizationId: ORG_B, organizationName: "Beta", organizationSlug: "beta",
    role: "MEMBER", platformRole: null,
  };
  const result = await callApi(db, { method: "GET", path: PROJECT_PATH, identity: outsider, membershipRole: "ACCOUNT_OWNER" });
  assert.equal(result.status, 404);
  const created = await callApi(db, { method: "POST", path: PROJECT_PATH, identity: outsider, membershipRole: "ACCOUNT_OWNER", body: { key: "X", value: "y" } });
  assert.equal(created.status, 404);
});

test("invalid keys, environments, targets, and value sizes are rejected", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const invalidKeys = ["1BAD", "WITH SPACE", "DASH-KEY", "lower-case-ok-but-", ""];
  for (const key of invalidKeys) {
    const result = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key, value: "v" } });
    assert.equal(result.status, 400, `key ${JSON.stringify(key)} must be rejected`);
  }
  const badEnvironment = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "OK", value: "v", environment: "staging" } });
  assert.equal(badEnvironment.status, 400);
  const badTarget = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "OK", value: "v", target: "buildtime" } });
  assert.equal(badTarget.status, 400);
  const emptyValue = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "OK", value: "" } });
  assert.equal(emptyValue.status, 400);
  const oversized = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "OK", value: "x".repeat(32_769) } });
  assert.equal(oversized.status, 400);
  // Boundary: 32768 chars is accepted.
  const boundary = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "BIG_OK", value: "x".repeat(32_768) } });
  assert.equal(boundary.status, 201);
});

test("duplicate key+environment is 409; same key in another environment succeeds", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const first = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "API_URL", value: "https://one.test", environment: "production" } });
  assert.equal(first.status, 201);
  const duplicate = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "API_URL", value: "https://two.test", environment: "production" } });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.text.includes("https://one.test"), false);
  const otherEnv = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "API_URL", value: "https://two.test", environment: "preview" } });
  assert.equal(otherEnv.status, 201);
});

test("missing DEPLOY_ENV_ENCRYPTION_KEY returns 503 with exact requirements", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const result = await callApi(db, { method: "POST", path: PROJECT_PATH, env: { DEPLOY_ENV_ENCRYPTION_KEY: undefined }, body: { key: "A", value: "b" } });
  assert.equal(result.status, 503);
  assert.equal(result.json.message, "DEPLOY_ENV_ENCRYPTION_KEY (64 hex chars) must be configured before environment variables can be stored.");
  const malformed = await callApi(db, { method: "POST", path: PROJECT_PATH, env: { DEPLOY_ENV_ENCRYPTION_KEY: "not-hex" }, body: { key: "A", value: "b" } });
  assert.equal(malformed.status, 503);
});

test("PATCH rotates the value with a fresh IV; metadata-only PATCH keeps ciphertext", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const row = await seedVariable(db, "ROTATING_KEY");
  const before = { ciphertext: row.encrypted_value, iv: row.value_iv };

  const metadataPatch = await callApi(db, {
    method: "PATCH", path: `${PROJECT_PATH}/${row.id}`,
    body: { target: "build", isSecret: false },
  });
  assert.equal(metadataPatch.status, 200);
  const afterMetadata = db.vars.get(`${PROJECT_1}:${row.id}`)!;
  assert.equal(afterMetadata.encrypted_value, before.ciphertext);
  assert.equal(afterMetadata.value_iv, before.iv);
  assert.equal(afterMetadata.target, "build");
  assert.equal(afterMetadata.is_secret, 0);

  const valuePatch = await callApi(db, {
    method: "PATCH", path: `${PROJECT_PATH}/${row.id}`,
    body: { value: "brand-new-value" },
  });
  assert.equal(valuePatch.status, 200);
  const afterValue = db.vars.get(`${PROJECT_1}:${row.id}`)!;
  assert.notEqual(afterValue.encrypted_value, before.ciphertext);
  assert.notEqual(afterValue.value_iv, before.iv);
  assert.equal(valuePatch.text.includes("brand-new-value"), false);
  assert.equal((valuePatch.json.variable as Record<string, unknown>).valueRotated, true);
});

test("PATCH and DELETE of unknown variables are 404; delete empties the list", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  const row = await seedVariable(db, "DOOMED");
  const missingPatch = await callApi(db, { method: "PATCH", path: `${PROJECT_PATH}/${crypto.randomUUID()}`, body: { target: "build" } });
  assert.equal(missingPatch.status, 404);
  const deleted = await callApi(db, { method: "DELETE", path: `${PROJECT_PATH}/${row.id}` });
  assert.equal(deleted.status, 200);
  const secondDelete = await callApi(db, { method: "DELETE", path: `${PROJECT_PATH}/${row.id}` });
  assert.equal(secondDelete.status, 404);
  const list = await callApi(db, { method: "GET", path: PROJECT_PATH });
  assert.deepEqual(list.json.variables, []);
});

test("per-project variable limit of 128 is enforced", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  for (let index = 0; index < 128; index += 1) {
    await seedVariable(db, `FILLER_${index}`);
  }
  const result = await callApi(db, { method: "POST", path: PROJECT_PATH, body: { key: "ONE_MORE", value: "v" } });
  assert.equal(result.status, 409);
});

function detectionRoutes(options: { tree?: unknown; treeStatus?: number; packageJson?: unknown; contentStatus?: number; headers?: Record<string, string> }): StubRoute[] {
  return [
    {
      match: (url) => url.pathname.startsWith(`/repos/${REPO_FULL}/git/trees/`),
      respond: () => ({ status: options.treeStatus ?? 200, body: options.tree ?? { tree: [], truncated: false }, headers: options.headers }),
    },
    {
      match: (url) => url.pathname === `/repos/${REPO_FULL}/contents/package.json`,
      respond: () => ({
        status: options.contentStatus ?? 200,
        body: options.packageJson === undefined
          ? { content: Buffer.from(JSON.stringify({ dependencies: {} })).toString("base64"), encoding: "base64" }
          : options.packageJson,
      }),
    },
  ];
}

test("framework presets, detection: Next.js is detected from dependencies", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  const { calls } = withFetchStub(detectionRoutes({
    tree: {
      truncated: false,
      tree: [
        { path: "package.json", type: "blob" },
        { path: "next.config.mjs", type: "blob" },
        { path: "app/page.tsx", type: "blob" },
      ],
    },
    packageJson: { content: Buffer.from(JSON.stringify({ dependencies: { next: "14.2.0", react: "^18" } })).toString("base64"), encoding: "base64" },
  }));
  const result = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(result.status, 200);
  assert.equal(result.json.framework, "next-static");
  assert.equal(result.json.outputDirectory, "out");
  assert.equal(result.json.buildCommand, "npm run build");
  assert.equal(result.json.detectedFrom, "package.json:dependencies:next");
  const evidence = result.json.evidence as Array<{ source: string; detail: string }>;
  assert.ok(evidence.some((item) => item.detail === "next.config.mjs"));
  assert.ok(calls.some((call) => call.startsWith(`/repos/${REPO_FULL}/git/trees/main`)));
  assert.ok(calls.some((call) => call.startsWith(`/repos/${REPO_FULL}/contents/package.json`)));
});

test("detection: astro config file without package.json still detects astro", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  withFetchStub(detectionRoutes({
    tree: { truncated: false, tree: [{ path: "astro.config.mjs", type: "blob" }, { path: "src/index.astro", type: "blob" }] },
    contentStatus: 404,
  }));
  const result = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(result.status, 200);
  assert.equal(result.json.framework, "astro");
  assert.equal(result.json.detectedFrom, "root-files:astro.config");
});

test("detection: plain HTML repository falls back to static with honest evidence", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  withFetchStub(detectionRoutes({
    tree: { truncated: false, tree: [{ path: "index.html", type: "blob" }, { path: "assets/site.css", type: "blob" }] },
  }));
  const result = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(result.status, 200);
  assert.equal(result.json.framework, "static");
  assert.equal(result.json.requiresBuild, false);
  assert.equal(result.json.detectedFrom, "root-files:index.html");
  const evidence = result.json.evidence as Array<{ source: string; detail: string }>;
  assert.ok(evidence.some((item) => item.detail === "index.html without package.json"));
});

test("detection: gatsby, docusaurus, eleventy, and parcel are detected from dependencies", async () => {
  const cases: Array<{ dependencies: Record<string, string>; framework: string; outputDirectory: string; detectedFrom: string; buildCommand: string }> = [
    { dependencies: { gatsby: "^5.0.0" }, framework: "gatsby", outputDirectory: "public", detectedFrom: "package.json:dependencies:gatsby", buildCommand: "npm run build" },
    { dependencies: { "@docusaurus/core": "^3.0.0" }, framework: "docusaurus", outputDirectory: "build", detectedFrom: "package.json:dependencies:@docusaurus/core", buildCommand: "npm run build" },
    { dependencies: { "@11ty/eleventy": "^2.0.0" }, framework: "eleventy", outputDirectory: "_site", detectedFrom: "package.json:dependencies:@11ty/eleventy", buildCommand: "npm run build" },
    { dependencies: { parcel: "^2.11.0" }, framework: "parcel", outputDirectory: "dist", detectedFrom: "package.json:dependencies:parcel", buildCommand: "npm run build" },
  ];
  for (const testCase of cases) {
    const db = new DeployEnvD1(OWNER_IDENTITY);
    await db.encryptGithubTokenForTest(GITHUB_TOKEN);
    withFetchStub(detectionRoutes({
      tree: { truncated: false, tree: [{ path: "package.json", type: "blob" }, { path: "src/index.js", type: "blob" }] },
      packageJson: { content: Buffer.from(JSON.stringify({ dependencies: testCase.dependencies })).toString("base64"), encoding: "base64" },
    }));
    const result = await callApi(db, {
      method: "POST", path: "/v1/github/projects/detect-framework",
      body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
    });
    assert.equal(result.status, 200, testCase.framework);
    assert.equal(result.json.framework, testCase.framework, testCase.framework);
    assert.equal(result.json.outputDirectory, testCase.outputDirectory, testCase.framework);
    assert.equal(result.json.detectedFrom, testCase.detectedFrom, testCase.framework);
    assert.equal(result.json.buildCommand, testCase.buildCommand, testCase.framework);
  }
});

test("detection: vite still wins over parcel when both are present", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  withFetchStub(detectionRoutes({
    tree: { truncated: false, tree: [{ path: "package.json", type: "blob" }] },
    packageJson: { content: Buffer.from(JSON.stringify({ devDependencies: { vite: "^5.0.0", parcel: "^2.11.0" } })).toString("base64"), encoding: "base64" },
  }));
  const result = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(result.status, 200);
  assert.equal(result.json.framework, "vite");
  assert.equal(result.json.detectedFrom, "package.json:dependencies:vite");
});

test("detection errors are honest: missing branch, rate limit, no connection", async () => {
  const db = new DeployEnvD1(OWNER_IDENTITY);
  // No GitHub connection seeded -> 409.
  withFetchStub([]);
  const noConnection = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(noConnection.status, 409);
  assert.equal(noConnection.json.message, "Connect GitHub first.");

  // 404 branch.
  await db.encryptGithubTokenForTest(GITHUB_TOKEN);
  withFetchStub(detectionRoutes({ treeStatus: 404 }));
  const missing = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "nope" },
  });
  assert.equal(missing.status, 404);

  // 403 with exhausted rate limit -> 429 plus reset time passthrough.
  const reset = Math.floor(Date.now() / 1000) + 600;
  withFetchStub(detectionRoutes({
    treeStatus: 403,
    headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset), "x-github-request-id": "REQ-123" },
  }));
  const limited = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(limited.status, 429);
  assert.equal(limited.json.rateLimitRemaining, 0);
  assert.equal(typeof limited.json.rateLimitReset, "string");
  assert.equal(limited.json.requestId, "REQ-123");

  // Invalid input -> 400, never reaches GitHub.
  withFetchStub([]);
  const invalid = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework",
    body: { repositoryId: 101, installationId: 7, repositoryFullName: "../escape", branch: "main" },
  });
  assert.equal(invalid.status, 400);
});

test("detection requires authentication", async () => {
  const db = new DeployEnvD1(null);
  withFetchStub([]);
  const result = await callApi(db, {
    method: "POST", path: "/v1/github/projects/detect-framework", identity: null,
    body: { repositoryId: 101, installationId: 7, repositoryFullName: REPO_FULL, branch: "main" },
  });
  assert.equal(result.status, 401);
});
