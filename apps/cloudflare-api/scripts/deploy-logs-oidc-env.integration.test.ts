import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createSign, createPublicKey, generateKeyPairSync } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// deploy-logs-oidc-env.integration.test.ts
//
// Regression tests for the Nexora Deploy batch-5 routes:
//
//   * POST /v1/github/deployments/:id/oidc/exchange — build-environment
//     injection: the verified builder receives the project's decrypted
//     variables for its deployment environment filtered to build targets,
//     with undecryptable rows reported, never silently dropped.
//   * POST /v1/github/deployments/:id/logs — builder log streaming; every
//     line is redacted at WRITE time against the project's decrypted
//     environment values and common token patterns.
//   * GET  /v1/github/projects/:id/deployments/:deploymentId/logs — member
//     read path with cursor pagination; cross-tenant access is 404.
//
// Scenarios:
//   1.  Exchange with valid OIDC identity injects production build-target
//       variables only (runtime-only and other-environment rows excluded).
//   2.  Preview deployments receive preview-environment variables.
//   3.  Undecryptable rows are counted and skipped, others still injected.
//   4.  A workflow SHA that is not trusted is rejected with 403 and injects
//       nothing.
//   5.  Log pushes redact injected environment values and generic token
//       patterns at write time; the read path never exposes them.
//   6.  Log pushes require the unconsumed upload capability (401 otherwise).
//   7.  Log batches beyond 200 lines or 4000-character lines are rejected.
//   8.  Sequence conflicts from concurrent writers return 409 with a retry.
//   9.  The member read path paginates by cursor and stays tenant-scoped.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "e".repeat(64);
const SESSION_HASH = createHash("sha256").update(SESSION_TOKEN).digest("hex");
const ORG_A = "11111111-1111-4111-8111-111111111111";
const OWNER_A = "aaaaaaa1-0000-4000-8000-000000000001";
const DEV_A = "aaaaaaa2-0000-4000-8000-000000000002";
const PROJECT_1 = "c1000000-0000-4000-8000-000000000001";
const DEPLOY_1 = "c2000000-0000-4000-8000-000000000001";
const RELEASE_1 = "c3000000-0000-4000-8000-000000000001";
const COMMIT_SHA = "a".repeat(40);
const TRUSTED_SHA = "e".repeat(40);
const TOKEN_KEY = "f".repeat(64);
const ENV_KEY = "a".repeat(64);
const OIDC_AUDIENCE = "https://api.nexoraedge.digital/github-deployments";
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const REPO_FULL = "acme/landing";
const REPO_ID = "98765432";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
// With encodings specified the keys come back as PEM strings.
const jwk = createPublicKey(publicKey as unknown as string).export({ format: "jwk" }) as { n: string; e: string };
const KID = "test-key-1";

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function signOidcToken(claims: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID }));
  const payload = b64url(JSON.stringify(claims));
  const signature = createSign("RSA-SHA256").update(header + "." + payload).sign(privateKey);
  return header + "." + payload + "." + b64url(signature);
}

function oidcClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: OIDC_ISSUER,
    aud: OIDC_AUDIENCE,
    exp: now + 240,
    iat: now,
    repository: REPO_FULL,
    repository_id: REPO_ID,
    ref: "refs/heads/main",
    sha: COMMIT_SHA,
    event_name: "workflow_dispatch",
    workflow_ref: `${REPO_FULL}/.github/workflows/nexora-deploy.yml@refs/heads/main`,
    runner_environment: "github-hosted",
    run_id: "1234567890",
    run_attempt: "1",
    workflow_sha: TRUSTED_SHA,
    ...overrides,
  };
}

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

type EnvVarRow = { key_name: string; environment: string; target: string; encrypted_value: string; value_iv: string };

type DeployRow = {
  id: string; organizationId: string; projectId: string; commitSha: string; branch: string;
  status: string; deploymentKind: string; repositoryId: string; repositoryFullName: string;
  trustedWorkflowSha: string | null;
};

type Identity = {
  id: string; email: string; displayName: string | null; organizationId: string;
  organizationName: string; organizationSlug: string; role: string; platformRole: string | null;
};

class DeployLogsD1 {
  deployment: DeployRow;
  release: { id: string; state: string } | null;
  envVars = new Map<string, EnvVarRow>(); // key `${key_name}:${environment}`
  logs: Array<{ seq: number; source: string; message: string; emittedAt: string }> = [];
  uploadToken: { tokenHash: string; deploymentId: string; expiresAt: string; consumed: boolean } | null = null;
  identity: Identity | null = null;
  membershipRole: string | null = "ACCOUNT_DEVELOPER";
  forceSeqConflict = false;
  releaseEvents: Array<{ eventCode: string }> = [];

  constructor(options: { deploymentKind?: string; withRelease?: boolean } = {}) {
    this.deployment = {
      id: DEPLOY_1,
      organizationId: ORG_A,
      projectId: PROJECT_1,
      commitSha: COMMIT_SHA,
      branch: "main",
      status: "queued",
      deploymentKind: options.deploymentKind ?? "production",
      repositoryId: REPO_ID,
      repositoryFullName: REPO_FULL,
      trustedWorkflowSha: TRUSTED_SHA,
    };
    this.release = options.withRelease === false ? null : { id: RELEASE_1, state: "queued" };
  }

  async seedVar(key: string, environment: string, target: string, value: string, encryptWith: string = ENV_KEY) {
    const encrypted = await encryptWithKey(encryptWith, value);
    this.envVars.set(`${key}:${environment}`, {
      key_name: key, environment, target,
      encrypted_value: encrypted.ciphertext, value_iv: encrypted.iv,
    });
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
        if (query.includes("FROM github_deployments d JOIN github_projects p")) {
          return { ...db.deployment } as T;
        }
        if (query.startsWith("SELECT id, state FROM application_releases WHERE deployment_id")) {
          return db.release ? { ...db.release } as T : null;
        }
        if (query.includes("FROM github_deployment_upload_tokens t JOIN github_deployments d")) {
          const [tokenHash, deploymentId, nowIso] = values as [string, string, string];
          const token = db.uploadToken;
          if (!token || token.consumed || token.deploymentId !== deploymentId || token.tokenHash !== tokenHash) return null;
          if (token.expiresAt <= nowIso) return null;
          return {
            organizationId: db.deployment.organizationId,
            projectId: db.deployment.projectId,
            deploymentId: db.deployment.id,
            status: "building",
          } as T;
        }
        if (query.includes("COUNT(*) AS total") && query.includes("github_deployment_logs")) {
          return { total: db.logs.length } as T;
        }
        if (query.startsWith("SELECT id, organization_id FROM github_projects")) {
          const [projectId, orgId] = values as [string, string];
          if (projectId === db.deployment.projectId && orgId === db.deployment.organizationId) {
            return { id: db.deployment.projectId, organization_id: db.deployment.organizationId } as T;
          }
          return null;
        }
        if (query.includes("FROM github_projects p") && query.includes("hosting_account_memberships")) {
          const [projectId, orgId, userId] = values as [string, string, string];
          if (projectId !== db.deployment.projectId || orgId !== db.deployment.organizationId) return null;
          if (userId !== db.identity?.id) return null;
          if (!db.membershipRole || !["ACCOUNT_OWNER", "ACCOUNT_ADMIN", "ACCOUNT_DEVELOPER"].includes(db.membershipRole)) return null;
          return { id: db.deployment.projectId, organization_id: db.deployment.organizationId } as T;
        }
        if (query.includes("SELECT id, status, log_excerpt AS logExcerpt FROM github_deployments")) {
          const [deploymentId, projectId, orgId] = values as [string, string, string];
          if (deploymentId === db.deployment.id && projectId === db.deployment.projectId && orgId === db.deployment.organizationId) {
            return { id: db.deployment.id, status: db.deployment.status, logExcerpt: "Build artifact received; awaiting archive validation." } as T;
          }
          return null;
        }
        throw new Error(`Unexpected first() query: ${query.slice(0, 140)}`);
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (query.includes("FROM application_env_vars") && query.includes("target IN ('build','both')")) {
          const [projectId, orgId, environment] = values as [string, string, string];
          if (projectId !== db.deployment.projectId || orgId !== db.deployment.organizationId) return { results: [] };
          const rows = [...db.envVars.values()]
            .filter((row) => row.environment === environment && ["build", "both"].includes(row.target))
            .sort((a, b) => a.key_name.localeCompare(b.key_name))
            .map((row) => ({ key_name: row.key_name, target: row.target, encrypted_value: row.encrypted_value, value_iv: row.value_iv }));
          return { results: rows as T[] };
        }
        if (query.startsWith("SELECT encrypted_value, value_iv FROM application_env_vars")) {
          const rows = [...db.envVars.values()].map((row) => ({ encrypted_value: row.encrypted_value, value_iv: row.value_iv }));
          return { results: rows as T[] };
        }
        if (query.includes("FROM github_deployment_logs") && query.includes("ORDER BY seq ASC LIMIT ?")) {
          const [deploymentId, orgId, after, limit] = values as [string, string, number, number];
          if (deploymentId !== db.deployment.id || orgId !== db.deployment.organizationId) return { results: [] };
          const rows = db.logs
            .filter((line) => line.seq > after)
            .sort((a, b) => a.seq - b.seq)
            .slice(0, limit)
            .map((line) => ({ seq: line.seq, source: line.source, message: line.message, emittedAt: line.emittedAt }));
          return { results: rows as T[] };
        }
        throw new Error(`Unexpected all() query: ${query.slice(0, 140)}`);
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        throw new Error(`Unexpected run() query: ${query.slice(0, 140)}`);
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>): Promise<Array<{ success: boolean; meta: { changes: number } }>> {
    if (this.forceSeqConflict) {
      throw new Error("UNIQUE constraint failed: github_deployment_logs.seq");
    }
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const stmt of statements) {
      const q = stmt.query;
      const v = stmt.getValues();
      if (q.startsWith("INSERT INTO github_deployment_upload_tokens")) {
        this.uploadToken = {
          tokenHash: String(v[1]),
          deploymentId: String(v[4]),
          expiresAt: String(v[10]),
          consumed: false,
        };
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE github_deployments SET status = 'building'")) {
        this.deployment.status = "building";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_releases SET state = 'authorized'")) {
        if (this.release) this.release.state = "authorized";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("UPDATE application_releases SET state = 'building'")) {
        if (this.release) this.release.state = "building";
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO application_release_events")) {
        this.releaseEvents.push({ eventCode: "release_event" });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      if (q.startsWith("INSERT INTO github_deployment_logs")) {
        const seq = Number(v[4]);
        const message = String(v[5]);
        if (this.logs.some((line) => line.seq === seq)) {
          throw new Error("UNIQUE constraint failed: github_deployment_logs.seq");
        }
        this.logs.push({ seq, source: "builder", message, emittedAt: new Date().toISOString() });
        results.push({ success: true, meta: { changes: 1 } });
        continue;
      }
      throw new Error("Unexpected batch statement: " + q.slice(0, 140));
    }
    return results;
  }
}

let restoreFetch: (() => void) | null = null;

function withFetchStub(handler: (url: URL, method: string) => { status: number; body?: unknown } | null): { calls: string[] } {
  const calls: string[] = [];
  const original = globalThis.fetch;
  restoreFetch = () => { globalThis.fetch = original; };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(method + " " + url.pathname);
    const result = handler(url, method);
    if (result) {
      const headers = new Headers({ "content-type": "application/json" });
      const body = result.status === 204 || result.body === undefined ? null : JSON.stringify(result.body);
      return new Response(body, { status: result.status, headers });
    }
    return new Response(JSON.stringify({ message: `stubbed route missing for ${method} ${url.pathname}` }), { status: 599, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls };
}

function standardFetchRoutes(): Stubless {
  return withFetchStub((url, method) => {
    if (url.pathname === "/.well-known/jwks" && url.host === "token.actions.githubusercontent.com") {
      return { status: 200, body: { keys: [{ kid: KID, kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" }] } };
    }
    if (url.pathname.startsWith("/app/installations/") && url.pathname.endsWith("/access_tokens") && method === "POST") {
      return { status: 201, body: { token: "ghs_installation", expires_at: new Date(Date.now() + 3600_000).toISOString() } };
    }
    return null;
  });
}

type Stubless = { calls: string[] };

const BASE_ENV = {
  DB: null as unknown as D1Database,
  GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY,
  DEPLOY_ENV_ENCRYPTION_KEY: ENV_KEY,
  GITHUB_OIDC_AUDIENCE: OIDC_AUDIENCE,
  GITHUB_APP_ID: "12345678",
  GITHUB_APP_PRIVATE_KEY: privateKey,
  ARTIFACTS: {} as unknown as R2Bucket,
};

async function callExchange(db: DeployLogsD1, claims: Record<string, unknown>, envOverrides: Record<string, string | undefined> = {}) {
  const token = signOidcToken(claims);
  const request = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/oidc/exchange`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
  });
  const env = { ...BASE_ENV, DB: db as unknown as D1Database, ...envOverrides };
  const response = await worker.fetch(request, env as never, { waitUntil: () => {} } as never);
  const text = await response.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* empty */ }
  return { status: response.status, json, text };
}

async function seedReadyState(db: DeployLogsD1) {
  await db.seedVar("API_KEY", "production", "build", "prod-secret-12345");
  await db.seedVar("LOG_FORMAT", "production", "runtime", "json-structured");
  await db.seedVar("PREVIEW_TOKEN", "preview", "build", "preview-secret-6789");
  await db.seedVar("DB_URL", "production", "both", "postgres://db.example.test/nx");
}

test("exchange injects production build-target variables only", async () => {
  const db = new DeployLogsD1();
  await seedReadyState(db);
  standardFetchRoutes();
  const result = await callExchange(db, oidcClaims());
  assert.equal(result.status, 201);
  assert.match(String(result.json.uploadToken), /^[a-f0-9]{64}$/);
  const variables = result.json.environmentVariables as Array<{ key: string; value: string; target: string }>;
  assert.deepEqual(variables.map((variable) => variable.key).sort(), ["API_KEY", "DB_URL"]);
  assert.equal(variables.find((variable) => variable.key === "API_KEY")?.value, "prod-secret-12345");
  assert.equal(variables.find((variable) => variable.key === "DB_URL")?.target, "both");
  assert.equal(result.json.environmentVariablesUndecryptable, 0);
  // Runtime-only values are never handed to the builder.
  assert.equal(result.text.includes("json-structured"), false);
  // Other-environment values are never handed to a production builder.
  assert.equal(result.text.includes("preview-secret-6789"), false);
});

test("preview deployments receive preview-environment variables", async () => {
  const db = new DeployLogsD1({ deploymentKind: "preview" });
  await seedReadyState(db);
  standardFetchRoutes();
  const result = await callExchange(db, oidcClaims());
  assert.equal(result.status, 201);
  const variables = result.json.environmentVariables as Array<{ key: string; value: string }>;
  assert.deepEqual(variables.map((variable) => variable.key), ["PREVIEW_TOKEN"]);
  assert.equal(result.text.includes("prod-secret-12345"), false);
});

test("undecryptable rows are counted and skipped, valid rows still inject", async () => {
  const db = new DeployLogsD1();
  await seedReadyState(db);
  // A value encrypted with a stale key (as after a rotation without re-entry).
  await db.seedVar("STALE_VAR", "production", "build", "stale-value", "b".repeat(64));
  standardFetchRoutes();
  const result = await callExchange(db, oidcClaims());
  assert.equal(result.status, 201);
  assert.equal(result.json.environmentVariablesUndecryptable, 1);
  const variables = result.json.environmentVariables as Array<{ key: string }>;
  assert.ok(variables.some((variable) => variable.key === "API_KEY"));
  assert.ok(!variables.some((variable) => variable.key === "STALE_VAR"));
});

test("an untrusted workflow SHA is rejected with 403 and injects nothing", async () => {
  const db = new DeployLogsD1();
  await seedReadyState(db);
  standardFetchRoutes();
  const result = await callExchange(db, oidcClaims({ workflow_sha: "9".repeat(40) }));
  assert.equal(result.status, 403);
  assert.ok(!("environmentVariables" in result.json));
});

test("log pushes redact injected values and token patterns at write time", async () => {
  const db = new DeployLogsD1();
  await seedReadyState(db);
  standardFetchRoutes();
  const exchange = await callExchange(db, oidcClaims());
  assert.equal(exchange.status, 201);
  const uploadToken = String(exchange.json.uploadToken);

  const push = async (lines: string[]) => {
    const request = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
      method: "POST",
      headers: { authorization: `Bearer ${uploadToken}`, "content-type": "application/json" },
      body: JSON.stringify({ lines }),
    });
    const response = await worker.fetch(request, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
    const json = await response.json() as Record<string, unknown>;
    return { status: response.status, json };
  };

  const leakedLine = "npm install API_KEY=prod-secret-12345 done";
  const tokenLine = "cloning with credential ghs_0123456789abcdefghij";
  const bearerLine = "upload to artifact store failed with Bearer ghsup_998877665544332211";
  const plainLine = "vite v5.0.0 building for production...";
  const result = await push([leakedLine, tokenLine, bearerLine, plainLine]);
  assert.equal(result.status, 201);
  assert.equal(result.json.appended, 4);

  const messages = db.logs.map((line) => line.message).join("\n");
  assert.equal(messages.includes("prod-secret-12345"), false);
  assert.equal(messages.includes("ghs_0123456789abcdefghij"), false);
  assert.equal(messages.includes("ghsup_998877665544332211"), false);
  assert.ok(messages.includes("[redacted]"));
  assert.ok(messages.includes("vite v5.0.0 building for production..."));
  // The plain line is preserved untouched.
  assert.equal(db.logs[3].message, "vite v5.0.0 building for production...");
});

test("log pushes require the unconsumed upload capability", async () => {
  const db = new DeployLogsD1();
  standardFetchRoutes();

  const noToken = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ lines: ["hi"] }),
  });
  const noTokenResponse = await worker.fetch(noToken, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  assert.equal(noTokenResponse.status, 401);

  // Wrong capability.
  const wrong = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
    method: "POST", headers: { authorization: `Bearer ${"9".repeat(64)}`, "content-type": "application/json" }, body: JSON.stringify({ lines: ["hi"] }),
  });
  const wrongResponse = await worker.fetch(wrong, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  assert.equal(wrongResponse.status, 401);

  // Consumed capability.
  await db.seedVar("API_KEY", "production", "build", "prod-secret-12345");
  const exchange = await callExchange(db, oidcClaims());
  const uploadToken = String(exchange.json.uploadToken);
  db.uploadToken!.consumed = true;
  const consumed = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
    method: "POST", headers: { authorization: `Bearer ${uploadToken}`, "content-type": "application/json" }, body: JSON.stringify({ lines: ["hi"] }),
  });
  const consumedResponse = await worker.fetch(consumed, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  assert.equal(consumedResponse.status, 401);
});

test("log batch bounds are enforced", async () => {
  const db = new DeployLogsD1();
  await db.seedVar("API_KEY", "production", "build", "prod-secret-12345");
  standardFetchRoutes();
  const exchange = await callExchange(db, oidcClaims());
  const uploadToken = String(exchange.json.uploadToken);
  const push = (lines: unknown[]) => {
    const request = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
      method: "POST", headers: { authorization: `Bearer ${uploadToken}`, "content-type": "application/json" },
      body: JSON.stringify({ lines }),
    });
    return worker.fetch(request, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  };
  const tooMany = await push(Array.from({ length: 201 }, (_, index) => `line ${index}`));
  assert.equal(tooMany.status, 400);
  const tooLong = await push(["x".repeat(4001)]);
  assert.equal(tooLong.status, 400);
  const empty = await push([]);
  assert.equal(empty.status, 400);
});

test("sequence conflicts from concurrent writers return 409 with a retry hint", async () => {
  const db = new DeployLogsD1();
  await db.seedVar("API_KEY", "production", "build", "prod-secret-12345");
  standardFetchRoutes();
  const exchange = await callExchange(db, oidcClaims());
  const uploadToken = String(exchange.json.uploadToken);
  db.forceSeqConflict = true;
  const request = new Request(`https://worker.test/v1/github/deployments/${DEPLOY_1}/logs`, {
    method: "POST", headers: { authorization: `Bearer ${uploadToken}`, "content-type": "application/json" },
    body: JSON.stringify({ lines: ["conflicting line"] }),
  });
  const response = await worker.fetch(request, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  assert.equal(response.status, 409);
  const json = await response.json() as { message?: string };
  assert.match(String(json.message), /retry from the current tail/);
});

async function callGetLogs(db: DeployLogsD1, identity: Identity | null, query = "", projectId = PROJECT_1) {
  db.identity = identity;
  const request = new Request(`https://worker.test/v1/github/projects/${projectId}/deployments/${DEPLOY_1}/logs${query}`, {
    headers: { authorization: `Bearer ${SESSION_TOKEN}` },
  });
  const response = await worker.fetch(request, { ...BASE_ENV, DB: db as unknown as D1Database } as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* empty */ }
  return { status: response.status, json };
}

const PLATFORM_IDENTITY: Identity = {
  id: OWNER_A, email: "owner@acme.test", displayName: null,
  organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
  role: "OWNER", platformRole: "PLATFORM_ADMIN",
};
const DEVELOPER_IDENTITY: Identity = {
  id: DEV_A, email: "dev@acme.test", displayName: null,
  organizationId: ORG_A, organizationName: "Acme Hosting", organizationSlug: "acme-hosting",
  role: "MEMBER", platformRole: null,
};

test("the member read path paginates by cursor and stays tenant-scoped", async () => {
  const db = new DeployLogsD1();
  db.logs = [0, 1, 2, 3, 4].map((seq) => ({
    seq, source: "builder", message: `build line ${seq}`, emittedAt: new Date().toISOString(),
  }));
  standardFetchRoutes();

  const first = await callGetLogs(db, DEVELOPER_IDENTITY, "?after=1&limit=2");
  assert.equal(first.status, 200);
  const lines = first.json.lines as Array<{ seq: number; message: string }>;
  assert.deepEqual(lines.map((line) => line.seq), [2, 3]);
  assert.equal(first.json.nextCursor, 3);
  assert.equal(first.json.status, "queued");

  const second = await callGetLogs(db, DEVELOPER_IDENTITY, "?after=3&limit=2");
  assert.equal((second.json.lines as Array<{ seq: number }>).map((line) => line.seq).join(","), "4");
  assert.equal(second.json.nextCursor, null);

  // Platform identity reads the same project.
  const platform = await callGetLogs(db, PLATFORM_IDENTITY, "?after=-1&limit=500");
  assert.equal((platform.json.lines as Array<unknown>).length, 5);

  // Cross-tenant project id is 404 without existence leaks.
  const crossTenant = await callGetLogs(db, DEVELOPER_IDENTITY, "", "c9999999-0000-4000-8000-000000000009");
  assert.equal(crossTenant.status, 404);

  // Unauthenticated reads are 401.
  db.identity = null;
  const anonymous = await callGetLogs(db, null);
  assert.equal(anonymous.status, 401);
});
