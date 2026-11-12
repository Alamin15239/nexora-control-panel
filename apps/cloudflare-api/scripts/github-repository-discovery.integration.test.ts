import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// github-repository-discovery.integration.test.ts
//
// Regression tests for GET /v1/github/repositories. The GitHub REST API is
// stubbed at the network boundary; every scenario asserts the exact error
// class, HTTP status, and safe diagnostics (request id, rate-limit fields)
// that the route must surface — and that it never fabricates success.
//
// Scenarios:
//   1.  Successful discovery including a private repository and installation
//       permission verification (metadata/contents).
//   2.  Zero installations with an actionable installation link and the
//       OAuth-authorization-vs-App-installation explanation.
//   3.  Expired user token without a refresh token -> explicit 409.
//   4.  Expired user token refreshed transparently, then success.
//   5.  Refresh rejected by GitHub -> explicit 409 (no fake repositories).
//   6.  Upstream 401 with a fresh token -> distinct 409 + request id.
//   7.  Upstream 403 with rate limit exhausted -> 429 + retry-after.
//   8.  Upstream 403 (forbidden) -> 403 with the app-mismatch explanation.
//   9.  Missing Contents permission and suspended installation reporting.
//   10. Multiple installations, each contributing its own repositories.
//   11. Repository pagination (100 + rest).
//   12. Per-installation listing failure is surfaced, not silently skipped.
//   13. OAuth client id / GitHub App id mismatch detection.
//   14. Upstream 422 -> 502 github_unprocessable.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "e".repeat(64);
const SESSION_HASH = createHash("sha256").update(SESSION_TOKEN).digest("hex");
const ORG_A = "11111111-1111-4111-8111-111111111111";
const OWNER_A = "aaaaaaa1-0000-4000-8000-000000000001";
const TOKEN_KEY = "f".repeat(64);

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function encryptForTest(plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const keyBytes = Uint8Array.from(TOKEN_KEY.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)));
  return { ciphertext: base64(encrypted), iv: base64(iv) };
}

type TokenRow = {
  encrypted_access_token: string;
  access_token_iv: string;
  encrypted_refresh_token: string | null;
  refresh_token_iv: string | null;
  token_expires_at: string | null;
  refresh_token_expires_at: string | null;
};

class GithubDiscoveryD1 {
  connection: TokenRow;
  constructor(tokenRow: TokenRow) {
    this.connection = tokenRow;
  }
  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      getValues() { return values; },
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>(): Promise<T | null> {
        if (query.includes("FROM auth_sessions")) {
          const tokenHash = values[0];
          if (tokenHash !== SESSION_HASH) return null;
          return {
            id: OWNER_A, email: "owner@acme.test", displayName: "Acme Owner",
            organizationId: ORG_A, organizationName: "Acme Hosting",
            organizationSlug: "acme-hosting", role: "OWNER", platformRole: null,
          } as T;
        }
        if (query.includes("SELECT id FROM github_connections")) return { id: "conn-1" } as T;
        if (query.includes("encrypted_access_token")) return { ...db.connection } as T;
        throw new Error(`Unexpected first() query: ${query.slice(0, 120)}`);
      },
      async all<T>(): Promise<{ results: T[] }> {
        throw new Error(`Unexpected all() query: ${query.slice(0, 120)}`);
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        if (query.startsWith("UPDATE github_connections")) {
          const expectedRefresh = values[7];
          if (db.connection.encrypted_refresh_token && expectedRefresh === db.connection.encrypted_refresh_token) {
            db.connection = {
              ...db.connection,
              encrypted_access_token: String(values[0]),
              access_token_iv: String(values[1]),
              encrypted_refresh_token: String(values[2]),
              refresh_token_iv: String(values[3]),
              token_expires_at: String(values[4]),
              refresh_token_expires_at: String(values[5]),
            };
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        throw new Error(`Unexpected run() query: ${query.slice(0, 120)}`);
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

async function callApi(db: GithubDiscoveryD1): Promise<{ status: number; json: Record<string, unknown> }> {
  const request = new Request("https://worker.test/v1/github/repositories", {
    headers: { authorization: `Bearer ${SESSION_TOKEN}` },
  });
  const env = {
    DB: db as unknown as D1Database,
    GITHUB_TOKEN_ENCRYPTION_KEY: TOKEN_KEY,
    GITHUB_APP_ID: "12345678",
    GITHUB_APP_PRIVATE_KEY: privateKey,
    GITHUB_APP_CLIENT_ID: "Iv1.nexoraclient",
    GITHUB_APP_CLIENT_SECRET: "client-secret-test",
  };
  const response = await worker.fetch(request, env as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* empty */ }
  return { status: response.status, json };
}

function freshTokenRow(overrides: Partial<TokenRow> = {}): TokenRow {
  return {
    encrypted_access_token: "",
    access_token_iv: "",
    encrypted_refresh_token: null,
    refresh_token_iv: null,
    token_expires_at: new Date(Date.now() + 3600_000).toISOString(),
    refresh_token_expires_at: null,
    ...overrides,
  };
}

const APP_MATCHER: StubRoute = {
  match: (url) => url.pathname === "/app",
  respond: () => ({ status: 200, body: { slug: "nexora-app", client_id: "Iv1.nexoraclient" }, headers: { "x-github-request-id": "req-app-1" } }),
};

const INSTALLATIONS_OK: StubRoute = {
  match: (url) => url.pathname === "/user/installations",
  respond: () => ({ status: 200, body: { installations: [{ id: 101, account: { login: "Alamin15239" }, repository_selection: "selected" }] } }),
};

const INSTALL_REPOS = (id: number, repos: unknown[]): StubRoute => ({
  match: (url) => url.pathname === `/user/installations/${id}/repositories`,
  respond: () => ({ status: 200, body: { repositories: repos } }),
});

const INSTALL_DETAIL = (id: number, permissions: Record<string, string>, suspendedAt?: string): StubRoute => ({
  match: (url) => url.pathname === `/app/installations/${id}`,
  respond: () => ({ status: 200, body: { permissions, suspended_at: suspendedAt ?? null } }),
});

const REPO = (id: number, name: string, priv = false) => ({
  id, name, full_name: `Alamin15239/${name}`, private: priv, default_branch: "main",
  html_url: `https://github.com/Alamin15239/${name}`, owner: { login: "Alamin15239" },
});

test("successful discovery lists granted repositories including private ones and verifies permissions", async () => {
  const token = "ghu_valid_token";
  const encrypted = await encryptForTest(token);
  const stub = withFetchStub([
    APP_MATCHER,
    INSTALLATIONS_OK,
    INSTALL_REPOS(101, [REPO(1, "Fleet-Manager-System", true), REPO(2, "nexora-site")]),
    INSTALL_DETAIL(101, { metadata: "read", contents: "read" }),
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const repositories = json.repositories as Array<{ fullName: string; private: boolean; installationId: number }>;
    assert.equal(repositories.length, 2);
    assert.equal(repositories[0].fullName, "Alamin15239/Fleet-Manager-System");
    assert.equal(repositories[0].private, true);
    assert.equal(repositories[0].installationId, 101);
    const installations = json.installations as Array<{ id: number; account: string | null; permissionIssues: string[]; suspended: boolean; repositorySelection: string | null }>;
    assert.equal(installations[0].permissionIssues.length, 0);
    assert.equal(installations[0].suspended, false);
    assert.equal(installations[0].repositorySelection, "selected");
    const app = json.app as { slug: string | null; installationUrl: string };
    assert.equal(app.slug, "nexora-app");
    assert.equal(app.installationUrl, "https://github.com/apps/nexora-app/installations/new");
    assert.equal(json.installationErrors?.length, 0);
    assert.ok(!JSON.stringify(json).includes(token), "token must never appear in the response");
  } finally { restoreFetch?.(); }
});

test("zero installations returns guidance with the installation link and no fake repositories", async () => {
  const encrypted = await encryptForTest("ghu_no_installations");
  const stub = withFetchStub([
    APP_MATCHER,
    { match: (url) => url.pathname === "/user/installations", respond: () => ({ status: 200, body: { installations: [] } }) },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    assert.deepEqual(json.repositories, []);
    assert.match(String(json.message), /no Nexora GitHub App installations/);
    assert.match(String(json.message), /install the GitHub App/);
    const app = json.app as { installationUrl: string };
    assert.equal(app.installationUrl, "https://github.com/apps/nexora-app/installations/new");
  } finally { restoreFetch?.(); }
});

test("expired user token without refresh token yields an explicit reconnect error", async () => {
  const encrypted = await encryptForTest("ghu_expired");
  const stub = withFetchStub([]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({
      encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv,
      token_expires_at: new Date(Date.now() - 3600_000).toISOString(),
    })));
    assert.equal(status, 409);
    assert.equal(json.error, "github_authorization_expired");
    assert.match(String(json.message), /Reconnect the Nexora GitHub App/);
    assert.equal(stub.calls.length, 0, "no GitHub API discovery calls should be made without a usable token");
  } finally { restoreFetch?.(); }
});

test("expired user token is refreshed transparently and discovery proceeds", async () => {
  const encrypted = await encryptForTest("ghu_expired_refreshable");
  const refreshed = await encryptForTest("ghu_refreshed_token");
  const db = new GithubDiscoveryD1(freshTokenRow({
    encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv,
    encrypted_refresh_token: refreshed.ciphertext, refresh_token_iv: refreshed.iv,
    token_expires_at: new Date(Date.now() - 60_000).toISOString(),
    refresh_token_expires_at: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }));
  const stub = withFetchStub([
    {
      match: (url) => url.pathname === "/login/oauth/access_token",
      respond: () => ({ status: 200, body: { access_token: "ghu_refreshed_token", refresh_token: "ghr_new_refresh", token_type: "bearer", expires_in: 28800, refresh_token_expires_in: 15725760 } }),
    },
    APP_MATCHER,
    INSTALLATIONS_OK,
    INSTALL_REPOS(101, [REPO(1, "Fleet-Manager-System")]),
    INSTALL_DETAIL(101, { metadata: "read", contents: "read" }),
  ]);
  try {
    const { status, json } = await callApi(db);
    assert.equal(status, 200);
    const repositories = json.repositories as Array<{ fullName: string }>;
    assert.equal(repositories.length, 1);
    assert.equal(repositories[0].fullName, "Alamin15239/Fleet-Manager-System");
    assert.ok(stub.calls.some((c) => c.startsWith("/login/oauth/access_token")), "refresh call recorded");
  } finally { restoreFetch?.(); }
});

test("rejected token refresh yields an explicit reconnect error instead of a generic 502", async () => {
  const encrypted = await encryptForTest("ghu_expired_bad_refresh");
  const refreshed = await encryptForTest("ghr_refresh_secret");
  const db = new GithubDiscoveryD1(freshTokenRow({
    encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv,
    encrypted_refresh_token: refreshed.ciphertext, refresh_token_iv: refreshed.iv,
    token_expires_at: new Date(Date.now() - 60_000).toISOString(),
    refresh_token_expires_at: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }));
  const stub = withFetchStub([
    { match: (url) => url.pathname === "/login/oauth/access_token", respond: () => ({ status: 400, body: { error: "bad_refresh_token" } }) },
  ]);
  try {
    const { status, json } = await callApi(db);
    assert.equal(status, 409);
    assert.equal(json.error, "github_authorization_expired");
    assert.deepEqual(json.repositories, undefined);
    assert.ok(!stub.calls.some((c) => c.startsWith("/user/installations")), "discovery must not proceed with an unusable token");
  } finally { restoreFetch?.(); }
});

test("upstream 401 with a fresh token surfaces github_authorization_invalid and the request id", async () => {
  const encrypted = await encryptForTest("ghu_revoked");
  const stub = withFetchStub([
    { match: (url) => url.pathname === "/user/installations", respond: () => ({ status: 401, body: { message: "Bad credentials" }, headers: { "x-github-request-id": "req-401" } }) },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 409);
    assert.equal(json.error, "github_authorization_invalid");
    assert.match(String(json.message), /401/);
    const github = json.github as { requestId?: string };
    assert.equal(github.requestId, "req-401");
  } finally { restoreFetch?.(); }
});

test("upstream 403 with exhausted rate limit surfaces 429 with retry-after", async () => {
  const encrypted = await encryptForTest("ghu_ratelimited");
  const stub = withFetchStub([
    {
      match: (url) => url.pathname === "/user/installations",
      respond: () => ({ status: 403, body: { message: "API rate limit exceeded" }, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 120), "retry-after": "30", "x-github-request-id": "req-403-rl" } }),
    },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 429);
    assert.equal(json.error, "github_rate_limited");
    assert.equal(json.retryAfterSeconds, 30);
    assert.match(String(json.message), /rate limit/i);
  } finally { restoreFetch?.(); }
});

test("upstream 403 forbidden explains the OAuth-versus-App mismatch instead of asking to reinstall", async () => {
  const encrypted = await encryptForTest("ghu_forbidden");
  const stub = withFetchStub([
    { match: (url) => url.pathname === "/user/installations", respond: () => ({ status: 403, body: { message: "Resource not accessible by integration" }, headers: { "x-ratelimit-remaining": "4500" } }) },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 403);
    assert.equal(json.error, "github_forbidden");
    assert.match(String(json.message), /same App|installation/i);
    assert.ok(!/Reinstall the Nexora GitHub App with repository access/.test(String(json.message)));
  } finally { restoreFetch?.(); }
});

test("missing Contents permission and suspended installations are reported per installation", async () => {
  const encrypted = await encryptForTest("ghu_permissions");
  const stub = withFetchStub([
    APP_MATCHER,
    INSTALLATIONS_OK,
    INSTALL_REPOS(101, [REPO(1, "Fleet-Manager-System")]),
    INSTALL_DETAIL(101, { metadata: "read" }, "2026-11-10T00:00:00Z"),
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const installations = json.installations as Array<{ permissionIssues: string[]; suspended: boolean }>;
    assert.deepEqual(installations[0].permissionIssues, ["contents:read"]);
    assert.equal(installations[0].suspended, true);
  } finally { restoreFetch?.(); }
});

test("multiple installations each contribute their repositories", async () => {
  const encrypted = await encryptForTest("ghu_multi");
  const stub = withFetchStub([
    APP_MATCHER,
    {
      match: (url) => url.pathname === "/user/installations",
      respond: () => ({ status: 200, body: { installations: [{ id: 101, account: { login: "Alamin15239" } }, { id: 202, account: { login: "acme-org" } }] } }),
    },
    INSTALL_REPOS(101, [REPO(1, "Fleet-Manager-System")]),
    INSTALL_REPOS(202, [REPO(2, "org-site", true)]),
    INSTALL_DETAIL(101, { metadata: "read", contents: "read" }),
    INSTALL_DETAIL(202, { metadata: "read", contents: "read" }),
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const repositories = json.repositories as Array<{ fullName: string; installationId: number; owner: string }>;
    assert.equal(repositories.length, 2);
    assert.equal(repositories[0].installationId, 101);
    assert.equal(repositories[1].installationId, 202);
    assert.equal(repositories[1].owner, "Alamin15239");
  } finally { restoreFetch?.(); }
});

test("repository listing paginates beyond the first 100 repositories", async () => {
  const encrypted = await encryptForTest("ghu_pagination");
  const firstPage = Array.from({ length: 100 }, (_, i) => REPO(i + 1, `repo-${i + 1}`));
  const stub = withFetchStub([
    APP_MATCHER,
    INSTALLATIONS_OK,
    { match: (url) => url.pathname === "/user/installations/101/repositories" && url.search.includes("page=2"), respond: () => ({ status: 200, body: { repositories: [REPO(101, "repo-101"), REPO(102, "Fleet-Manager-System")] } }) },
    INSTALL_REPOS(101, firstPage),
    INSTALL_DETAIL(101, { metadata: "read", contents: "read" }),
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const repositories = json.repositories as Array<{ fullName: string }>;
    assert.equal(repositories.length, 102);
    assert.equal(repositories[101].fullName, "Alamin15239/Fleet-Manager-System");
    assert.ok(stub.calls.filter((c) => c.startsWith("/user/installations/101/repositories")).length === 2, "both pages fetched");
  } finally { restoreFetch?.(); }
});

test("a failing installation listing is reported in installationErrors while others still resolve", async () => {
  const encrypted = await encryptForTest("ghu_partial");
  const stub = withFetchStub([
    APP_MATCHER,
    {
      match: (url) => url.pathname === "/user/installations",
      respond: () => ({ status: 200, body: { installations: [{ id: 101, account: { login: "Alamin15239" } }, { id: 202, account: { login: "broken-org" } }] } }),
    },
    INSTALL_REPOS(101, [REPO(1, "Fleet-Manager-System")]),
    {
      match: (url) => url.pathname === "/user/installations/202/repositories",
      respond: () => ({ status: 403, body: { message: "Resource not accessible by integration" }, headers: { "x-ratelimit-remaining": "4000", "x-github-request-id": "req-202" } }),
    },
    INSTALL_DETAIL(101, { metadata: "read", contents: "read" }),
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const repositories = json.repositories as Array<{ fullName: string }>;
    assert.equal(repositories.length, 1);
    const errors = json.installationErrors as Array<{ installationId: number; status: number; requestId?: string; message: string }>;
    assert.equal(errors.length, 1);
    assert.equal(errors[0].installationId, 202);
    assert.equal(errors[0].status, 403);
    assert.equal(errors[0].requestId, "req-202");
    assert.match(String(json.message), /installationErrors/);
  } finally { restoreFetch?.(); }
});

test("OAuth client id mismatch with the GitHub App id is detected and reported", async () => {
  const encrypted = await encryptForTest("ghu_mismatch");
  const stub = withFetchStub([
    { match: (url) => url.pathname === "/app", respond: () => ({ status: 200, body: { slug: "nexora-app", client_id: "Iv1.differentclient" } }) },
    { match: (url) => url.pathname === "/user/installations", respond: () => ({ status: 200, body: { installations: [] } }) },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 200);
    const app = json.app as { clientConfigMismatch?: boolean };
    assert.equal(app.clientConfigMismatch, true);
    assert.match(String(json.message), /does not match the GitHub App/);
  } finally { restoreFetch?.(); }
});

test("upstream 422 surfaces github_unprocessable with the upstream message", async () => {
  const encrypted = await encryptForTest("ghu_422");
  const stub = withFetchStub([
    { match: (url) => url.pathname === "/user/installations", respond: () => ({ status: 422, body: { message: "Validation Failed" }, headers: { "x-github-request-id": "req-422" } }) },
  ]);
  try {
    const { status, json } = await callApi(new GithubDiscoveryD1(freshTokenRow({ encrypted_access_token: encrypted.ciphertext, access_token_iv: encrypted.iv })));
    assert.equal(status, 502);
    assert.equal(json.error, "github_unprocessable");
    assert.match(String(json.message), /Validation Failed/);
  } finally { restoreFetch?.(); }
});

// Keep the public key import referenced so lint stays quiet about unused vars.
void publicKey;
