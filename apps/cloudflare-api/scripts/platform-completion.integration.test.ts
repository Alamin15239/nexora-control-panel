import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformCompletionD1, call, makeEnv, webhookSignature, isoInDays,
  SESSION_TOKEN, ORG_A, ORG_B, OWNER_A, MEMBER_A, ADMIN_A, OUTSIDER,
  PLATFORM_ADMIN, PLAN_BASIC, PLAN_SMALL, ACCOUNT_1, PRIMARY_TOKEN_HASH,
} from "./platform-completion-harness.ts";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// platform-completion.integration.test.ts
//
// Regression tests for organization administration, customer self-service,
// subscriptions/billing, email hosting, and the provisioning inspector.
// See platform-completion-harness.ts for the mock D1 contract.
// ---------------------------------------------------------------------------

function freshDb(): PlatformCompletionD1 {
  const db = new PlatformCompletionD1();
  db.seed();
  return db;
}

function loginAs(db: PlatformCompletionD1, userId: string): void {
  db.addSession(userId, userId === OUTSIDER ? ORG_B : ORG_A, PRIMARY_TOKEN_HASH);
  db.identity = db.asIdentity(userId);
}

// ---------------------------------------------------------------------------
// 1. Organization administration
// ---------------------------------------------------------------------------

test("org details return members and admin counts for a member of the organization", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const { status, json } = await call(db, "GET", `/v1/organizations/${ORG_A}`, makeEnv());
  assert.equal(status, 200);
  const members = json.members as Array<{ userId: string; role: string }>;
  assert.equal(members.length, 3);
  assert.equal(json.owners, 1);
  assert.equal(json.admins, 2);
});

test("org details are organization-isolated: a member of another org gets 404", async () => {
  const db = freshDb();
  loginAs(db, OUTSIDER);
  const { status } = await call(db, "GET", `/v1/organizations/${ORG_A}`, makeEnv());
  assert.equal(status, 404);
});

test("platform admin can inspect any organization", async () => {
  const db = freshDb();
  loginAs(db, PLATFORM_ADMIN);
  const { status, json } = await call(db, "GET", `/v1/organizations/${ORG_A}`, makeEnv());
  assert.equal(status, 200);
  assert.equal((json.members as unknown[]).length, 3);
});

test("scope=all organization listing requires platform admin", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const denied = await call(db, "GET", "/v1/organizations?scope=all", makeEnv());
  assert.equal(denied.status, 403);
  loginAs(db, PLATFORM_ADMIN);
  const allowed = await call(db, "GET", "/v1/organizations?scope=all", makeEnv());
  assert.equal(allowed.status, 200);
  assert.equal((allowed.json.organizations as unknown[]).length, 2);
});

test("admin can add an existing user as MEMBER but not as OWNER", async () => {
  const db = freshDb();
  loginAs(db, ADMIN_A);
  const added = await call(db, "POST", `/v1/organizations/${ORG_A}/members`, makeEnv(), { email: "member@beta.test", role: "MEMBER" });
  assert.equal(added.status, 201);
  const ownerDenied = await call(db, "POST", `/v1/organizations/${ORG_A}/members`, makeEnv(), { email: "member@beta.test", role: "OWNER" });
  assert.equal(ownerDenied.status, 403);
});

test("adding a member who is already a member is rejected with 409", async () => {
  const db = freshDb();
  loginAs(db, ADMIN_A);
  const result = await call(db, "POST", `/v1/organizations/${ORG_A}/members`, makeEnv(), { email: "customer@acme.test", role: "MEMBER" });
  assert.equal(result.status, 409);
});

test("removing a member revokes their sessions for the organization", async () => {
  const db = freshDb();
  loginAs(db, ADMIN_A);
  // Give MEMBER_A a live session in ORG_A.
  const memberToken = db.addSession(MEMBER_A, ORG_A);
  assert.ok(db.sessions.get(memberToken)!.revokedAt === null);
  const { status } = await call(db, "DELETE", `/v1/organizations/${ORG_A}/members/${MEMBER_A}`, makeEnv());
  assert.equal(status, 200);
  assert.ok(db.sessions.get(memberToken)!.revokedAt !== null, "sessions for the org must be revoked");
  assert.ok(!db.memberships.has(`${MEMBER_A}:${ORG_A}`));
});

test("the last OWNER cannot be removed or demoted", async () => {
  const db = freshDb();
  loginAs(db, PLATFORM_ADMIN); // platform admin bypasses role checks but not last-owner protection
  const removed = await call(db, "DELETE", `/v1/organizations/${ORG_A}/members/${OWNER_A}`, makeEnv());
  assert.equal(removed.status, 409);
  assert.match(String(removed.json.message), /last organization owner/);
  // Add a second owner, then demotion of the original becomes possible.
  db.memberships.set(`${ADMIN_A}:${ORG_A}`, { userId: ADMIN_A, organizationId: ORG_A, role: "OWNER" });
  const demoted = await call(db, "PATCH", `/v1/organizations/${ORG_A}/members/${OWNER_A}`, makeEnv(), { role: "ADMIN" });
  assert.equal(demoted.status, 200);
  assert.equal(db.memberships.get(`${OWNER_A}:${ORG_A}`)!.role, "ADMIN");
});

test("the last administrator cannot be demoted to a non-admin role", async () => {
  const db = freshDb();
  // Leave ADMIN_A as the only admin: remove the OWNER membership.
  db.memberships.delete(`${OWNER_A}:${ORG_A}`);
  loginAs(db, PLATFORM_ADMIN);
  const result = await call(db, "PATCH", `/v1/organizations/${ORG_A}/members/${ADMIN_A}`, makeEnv(), { role: "MEMBER" });
  assert.equal(result.status, 409);
  assert.match(String(result.json.message), /at least one owner or administrator/);
});

test("a non-admin member cannot manage members and cannot remove others", async () => {
  const db = freshDb();
  loginAs(db, MEMBER_A); // seeded as MEMBER
  const added = await call(db, "POST", `/v1/organizations/${ORG_A}/members`, makeEnv(), { email: "member@beta.test", role: "MEMBER" });
  assert.equal(added.status, 403);
  const removed = await call(db, "DELETE", `/v1/organizations/${ORG_A}/members/${OWNER_A}`, makeEnv());
  assert.equal(removed.status, 403);
});

test("closing an organization is blocked while hosting accounts exist", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const result = await call(db, "DELETE", `/v1/organizations/${ORG_A}`, makeEnv());
  assert.equal(result.status, 409);
  assert.match(String(result.json.message), /hosting account/);
});

test("closing an empty organization closes it and revokes all member sessions", async () => {
  const db = freshDb();
  db.accounts.delete(ACCOUNT_1);
  const ownerToken = db.addSession(OWNER_A, ORG_A);
  const memberToken = db.addSession(MEMBER_A, ORG_A);
  loginAs(db, OWNER_A);
  const result = await call(db, "DELETE", `/v1/organizations/${ORG_A}`, makeEnv());
  assert.equal(result.status, 200);
  assert.equal(db.orgs.get(ORG_A)!.status, "CLOSED");
  assert.ok(db.sessions.get(ownerToken)!.revokedAt !== null);
  assert.ok(db.sessions.get(memberToken)!.revokedAt !== null);
});

// ---------------------------------------------------------------------------
// 2. Customer self-service domains and databases
// ---------------------------------------------------------------------------

function customerLogin(db: PlatformCompletionD1): void {
  db.addSession(MEMBER_A, ORG_A, PRIMARY_TOKEN_HASH);
  db.identity = db.asIdentity(MEMBER_A);
}

test("customer adds a domain on their own account and an ADD_DOMAIN job is queued", async () => {
  const db = freshDb();
  customerLogin(db);
  const { status, json } = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/domains`, makeEnv(), { name: "Shop.Example.COM" });
  assert.equal(status, 201);
  const domain = json.domain as { id: string; name: string };
  assert.equal(domain.name, "shop.example.com");
  const job = [...db.jobs.values()].find((j) => j.operation === "ADD_DOMAIN" && j.idempotencyKey === `add-domain:${domain.id}`);
  assert.ok(job, "ADD_DOMAIN job must be queued");
});

test("customer domain add enforces the plan website limit", async () => {
  const db = freshDb();
  // Plan allows 2 websites; seed 2 existing domains.
  db.domains.set("dom-1", { id: "dom-1", hostingAccountId: ACCOUNT_1, name: "one.test", documentRoot: "/home/acme01/public_html/one.test", isPrimary: 1, status: "ACTIVE" });
  db.domains.set("dom-2", { id: "dom-2", hostingAccountId: ACCOUNT_1, name: "two.test", documentRoot: "/home/acme01/public_html/two.test", isPrimary: 0, status: "ACTIVE" });
  customerLogin(db);
  const { status, json } = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/domains`, makeEnv(), { name: "three.test" });
  assert.equal(status, 409);
  assert.match(String(json.message), /website limit/);
});

test("customer domain add is isolated to accounts the caller is a member of", async () => {
  const db = freshDb();
  loginAs(db, OUTSIDER); // member of ORG_B, no hosting-account membership
  const { status } = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/domains`, makeEnv(), { name: "evil.test" });
  assert.equal(status, 404);
  assert.equal(db.domains.size, 0);
});

test("ACCOUNT_READONLY cannot mutate domains; primary domain removal is protected", async () => {
  const db = freshDb();
  db.hostingAccountMemberships.set(`${ACCOUNT_1}:${MEMBER_A}`, { hostingAccountId: ACCOUNT_1, organizationId: ORG_A, userId: MEMBER_A, role: "ACCOUNT_READONLY", status: "ACTIVE" });
  customerLogin(db);
  const denied = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/domains`, makeEnv(), { name: "nope.test" });
  assert.equal(denied.status, 403);

  db.hostingAccountMemberships.set(`${ACCOUNT_1}:${MEMBER_A}`, { hostingAccountId: ACCOUNT_1, organizationId: ORG_A, userId: MEMBER_A, role: "ACCOUNT_OWNER", status: "ACTIVE" });
  const primary = { id: "dom-p", hostingAccountId: ACCOUNT_1, name: "primary.test", documentRoot: "/home/acme01/public_html", isPrimary: 1, status: "ACTIVE" };
  db.domains.set(primary.id, primary);
  const removed = await call(db, "DELETE", `/v1/customer/hosting-accounts/${ACCOUNT_1}/domains/dom-p`, makeEnv());
  assert.equal(removed.status, 409);
  assert.match(String(removed.json.message), /primary domain cannot be removed/);
});

test("customer creates a database with the account username prefix and plan quota enforcement", async () => {
  const db = freshDb();
  customerLogin(db);
  const created = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/databases`, makeEnv(), { name: "wordpress" });
  assert.equal(created.status, 202);
  assert.equal(created.json.name, "acme01_wordpress");
  // Plan allows 2 databases; seed the second so the next creation is over quota.
  db.databases.set("db-2", { id: "db-2", organizationId: ORG_A, hostingAccountId: ACCOUNT_1, name: "acme02_crm", engine: "MARIADB", status: "ACTIVE" });
  const overQuota = await call(db, "POST", `/v1/customer/hosting-accounts/${ACCOUNT_1}/databases`, makeEnv(), { name: "extra" });
  assert.equal(overQuota.status, 409);
  assert.match(String(overQuota.json.message), /database limit/);
});

test("customer database deletion queues DELETE_DATABASE for their own database", async () => {
  const db = freshDb();
  db.databases.set("db-1", { id: "db-1", organizationId: ORG_A, hostingAccountId: ACCOUNT_1, name: "acme01_wordpress", engine: "MARIADB", status: "ACTIVE" });
  customerLogin(db);
  const { status, json } = await call(db, "DELETE", `/v1/customer/hosting-accounts/${ACCOUNT_1}/databases/db-1`, makeEnv());
  assert.equal(status, 202);
  assert.equal(json.status, "DELETING");
  const job = [...db.jobs.values()].find((j) => j.operation === "DELETE_DATABASE");
  assert.ok(job);
  const payload = JSON.parse(job.requestPayload ?? "{}") as { databaseName?: string };
  assert.equal(payload.databaseName, "acme01_wordpress");
});

// ---------------------------------------------------------------------------
// 3. Subscriptions and billing
// ---------------------------------------------------------------------------

function adminLogin(db: PlatformCompletionD1): void {
  db.addSession(PLATFORM_ADMIN, ORG_A, PRIMARY_TOKEN_HASH);
  db.identity = db.asIdentity(PLATFORM_ADMIN);
}

function seedSubscription(db: PlatformCompletionD1, overrides: Partial<{ status: string; periodEndDays: number; cancelAtPeriodEnd: number; amountSarMinor: number | null; planId: string }> = {}) {
  const id = randomSubscriptionId();
  db.subscriptions.set(id, {
    id, organizationId: ORG_A, hostingAccountId: ACCOUNT_1, planId: overrides.planId ?? PLAN_BASIC,
    status: overrides.status ?? "ACTIVE", billingPeriod: "monthly", provider: "manual",
    amountSarMinor: overrides.amountSarMinor ?? 1500,
    currentPeriodStart: new Date().toISOString(), currentPeriodEnd: isoInDays(overrides.periodEndDays ?? 30),
    trialEnd: null, cancelAtPeriodEnd: overrides.cancelAtPeriodEnd ?? 0, cancelledAt: null, suspendedAt: null,
  });
  return id;
}

let subscriptionCounter = 0;
function randomSubscriptionId(): string {
  subscriptionCounter += 1;
  return `sub-0000-4000-8000-${String(subscriptionCounter).padStart(12, "0")}`;
}

test("subscription creation assigns ACTIVE with a one-month period and rejects a second live subscription", async () => {
  const db = freshDb();
  adminLogin(db);
  const created = await call(db, "POST", "/v1/subscriptions", makeEnv(), { hostingAccountId: ACCOUNT_1, planId: PLAN_BASIC, billingPeriod: "monthly" });
  assert.equal(created.status, 201);
  const subscription = created.json.subscription as { id: string; status: string };
  assert.equal(subscription.status, "ACTIVE");
  const duplicate = await call(db, "POST", "/v1/subscriptions", makeEnv(), { hostingAccountId: ACCOUNT_1, planId: PLAN_BASIC });
  assert.equal(duplicate.status, 409);
  assert.match(String(duplicate.json.message), /already has a live subscription/);
});

test("renewal extends the period, records a PAID invoice, and is idempotent per reference", async () => {
  const db = freshDb();
  adminLogin(db);
  const subscriptionId = seedSubscription(db);
  const first = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/renew`, makeEnv(), { idempotencyKey: "pay-2026-11-001", amountSarMinor: 1500 });
  assert.equal(first.status, 201);
  const invoice = first.json.invoice as { invoiceNumber: string; status: string };
  assert.equal(invoice.status, "PAID");
  assert.match(invoice.invoiceNumber, /INV-\d{4}-\d{6}/);
  const periodAfterFirst = db.subscriptions.get(subscriptionId)!.currentPeriodEnd!;
  // Replay with the same idempotency key: no second invoice, no second extension.
  const replay = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/renew`, makeEnv(), { idempotencyKey: "pay-2026-11-001", amountSarMinor: 1500 });
  assert.equal(replay.status, 200);
  assert.equal(replay.json.duplicate, true);
  assert.equal(db.invoices.size, 1);
  assert.equal(db.subscriptions.get(subscriptionId)!.currentPeriodEnd, periodAfterFirst);
});

test("plan downgrade is rejected when live usage exceeds the target plan quotas", async () => {
  const db = freshDb();
  db.domains.set("dom-1", { id: "dom-1", hostingAccountId: ACCOUNT_1, name: "one.test", documentRoot: "/home/acme01/public_html", isPrimary: 1, status: "ACTIVE" });
  db.domains.set("dom-2", { id: "dom-2", hostingAccountId: ACCOUNT_1, name: "two.test", documentRoot: "/home/acme01/public_html/two.test", isPrimary: 0, status: "ACTIVE" });
  adminLogin(db);
  const subscriptionId = seedSubscription(db);
  const result = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/plan`, makeEnv(), { planId: PLAN_SMALL });
  assert.equal(result.status, 409);
  const violations = result.json.violations as string[];
  assert.ok(violations.length >= 1);
  assert.match(violations[0], /Websites in use \(2\)/);
  assert.equal(db.subscriptions.get(subscriptionId)!.planId, PLAN_BASIC);
});

test("plan upgrade to a plan that fits current usage succeeds and updates the hosting account", async () => {
  const db = freshDb();
  adminLogin(db);
  const subscriptionId = seedSubscription(db, { planId: PLAN_SMALL });
  const result = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/plan`, makeEnv(), { planId: PLAN_BASIC });
  assert.equal(result.status, 200);
  assert.equal(db.subscriptions.get(subscriptionId)!.planId, PLAN_BASIC);
  assert.equal(db.accounts.get(ACCOUNT_1)!.planId, PLAN_BASIC);
  assert.ok(db.subscriptionEvents.some((e) => e.eventType === "plan_changed" && e.subscriptionId === subscriptionId));
});

test("suspend and reactivate move the subscription through SUSPENDED and back", async () => {
  const db = freshDb();
  adminLogin(db);
  const subscriptionId = seedSubscription(db);
  const suspended = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/suspend`, makeEnv());
  assert.equal(suspended.status, 200);
  assert.equal(db.subscriptions.get(subscriptionId)!.status, "SUSPENDED");
  const reactivate = await call(db, "POST", `/v1/subscriptions/${subscriptionId}/reactivate`, makeEnv());
  assert.equal(reactivate.status, 200);
  assert.equal(db.subscriptions.get(subscriptionId)!.status, "ACTIVE");
});

test("cancel at period end keeps the subscription live; immediate cancel ends it now", async () => {
  const db = freshDb();
  adminLogin(db);
  const scheduled = seedSubscription(db);
  const schedule = await call(db, "POST", `/v1/subscriptions/${scheduled}/cancel`, makeEnv(), {});
  assert.equal(schedule.status, 200);
  assert.equal(db.subscriptions.get(scheduled)!.cancelAtPeriodEnd, 1);
  assert.equal(db.subscriptions.get(scheduled)!.status, "ACTIVE");
  const immediate = seedSubscription(db);
  const cancelNow = await call(db, "POST", `/v1/subscriptions/${immediate}/cancel`, makeEnv(), { immediate: true });
  assert.equal(cancelNow.status, 200);
  assert.equal(db.subscriptions.get(immediate)!.status, "CANCELLED");
  // A cancelled subscription cannot be cancelled again or renewed.
  const recancel = await call(db, "POST", `/v1/subscriptions/${immediate}/cancel`, makeEnv(), { immediate: true });
  assert.equal(recancel.status, 409);
  const renewCancelled = await call(db, "POST", `/v1/subscriptions/${immediate}/renew`, makeEnv(), { idempotencyKey: "x" });
  assert.equal(renewCancelled.status, 409);
});

test("the lazy expiry sweep expires overdue subscriptions and honours scheduled cancellation", async () => {
  const db = freshDb();
  adminLogin(db);
  const overdue = seedSubscription(db, { periodEndDays: -1 });
  const scheduledEnd = seedSubscription(db, { periodEndDays: -2, cancelAtPeriodEnd: 1 });
  const future = seedSubscription(db, { periodEndDays: 10 });
  const { status, json } = await call(db, "GET", "/v1/subscriptions", makeEnv());
  assert.equal(status, 200);
  assert.equal(db.subscriptions.get(overdue)!.status, "EXPIRED");
  assert.equal(db.subscriptions.get(scheduledEnd)!.status, "CANCELLED");
  assert.equal(db.subscriptions.get(future)!.status, "ACTIVE");
  const list = json.subscriptions as Array<{ id: string; status: string }>;
  assert.ok(list.some((s) => s.id === overdue && s.status === "EXPIRED"));
});

test("subscriptions are organization-isolated: an org owner only sees their own org", async () => {
  const db = freshDb();
  seedSubscription(db); // ORG_A subscription
  db.subscriptions.set("sub-b", {
    id: "sub-b", organizationId: ORG_B, hostingAccountId: null, planId: PLAN_BASIC,
    status: "ACTIVE", billingPeriod: "monthly", provider: "manual", amountSarMinor: 1500,
    currentPeriodStart: null, currentPeriodEnd: isoInDays(10), trialEnd: null,
    cancelAtPeriodEnd: 0, cancelledAt: null, suspendedAt: null,
  });
  loginAs(db, OWNER_A);
  const { status, json } = await call(db, "GET", "/v1/subscriptions", makeEnv());
  assert.equal(status, 200);
  const list = json.subscriptions as Array<{ organizationId: string }>;
  assert.ok(list.length >= 1);
  assert.ok(list.every((s) => s.organizationId === ORG_A));
});

const WEBHOOK_SECRET = "whsec-0123456789abcdef0123456789abcdef";

function webhookRequest(db: PlatformCompletionD1, body: string, timestamp: string, signature: string, provider = "stripe") {
  const request = new Request(`https://worker.test/v1/billing/webhooks/${provider}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-nexora-signature": `t=${timestamp},v1=${signature}` },
    body,
  });
  const bindings = { DB: db as unknown as D1Database, ...makeEnv({ PAYMENT_WEBHOOK_SECRET: WEBHOOK_SECRET }) };
  return worker.fetch(request, bindings as never, { waitUntil: () => {} } as never);
}

test("payment webhooks without configuration answer 503 and unsigned requests are rejected", async () => {
  const db = freshDb();
  adminLogin(db);
  const unconfigured = await call(db, "POST", "/v1/billing/webhooks/stripe", makeEnv(), { eventId: "e1", invoiceRef: "r1", outcome: "paid" });
  assert.equal(unconfigured.status, 503);
  const body = JSON.stringify({ eventId: "e1", invoiceRef: "r1", outcome: "paid" });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const unsigned = await webhookRequest(db, body, timestamp, "0".repeat(64));
  assert.equal(unsigned.status, 401);
  const badSignature = await webhookRequest(db, body, timestamp, "f".repeat(64));
  assert.equal(badSignature.status, 401);
  const stale = await webhookRequest(db, body, String(Math.floor(Date.now() / 1000) - 600), webhookSignature(WEBHOOK_SECRET, String(Math.floor(Date.now() / 1000) - 600), body));
  assert.equal(stale.status, 401);
});

test("a verified webhook marks only the referenced invoice PAID and renews its subscription", async () => {
  const db = freshDb();
  adminLogin(db);
  const subscriptionId = seedSubscription(db);
  const invoiceId = "inv-0000-4000-8000-000000000001";
  db.invoices.set(invoiceId, {
    id: invoiceId, organizationId: ORG_A, subscriptionId, invoiceNumber: "INV-2026-000001",
    amountSarMinor: 1500, status: "OPEN", billingPeriod: "monthly", paidAt: null,
    paymentMethod: null, paymentOrderRef: "provider-ref-1", providerRef: null,
  });
  const body = JSON.stringify({ eventId: "evt-1", invoiceRef: "provider-ref-1", outcome: "paid" });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const response = await webhookRequest(db, body, timestamp, webhookSignature(WEBHOOK_SECRET, timestamp, body));
  assert.equal(response.status, 200);
  const payload = await response.json() as { processed: boolean };
  assert.equal(payload.processed, true);
  assert.equal(db.invoices.get(invoiceId)!.status, "PAID");
  assert.ok(db.invoices.get(invoiceId)!.paidAt !== null);
  assert.ok(db.subscriptions.get(subscriptionId)!.currentPeriodEnd! > isoInDays(20), "period must be extended");
  // Redelivery of the same event is acknowledged as a duplicate, not reprocessed.
  const replay = await webhookRequest(db, body, String(Math.floor(Date.now() / 1000)), webhookSignature(WEBHOOK_SECRET, String(Math.floor(Date.now() / 1000)), body));
  assert.equal(replay.status, 200);
  const replayPayload = await replay.json() as { duplicate: boolean };
  assert.equal(replayPayload.duplicate, true);
});

test("a webhook for an unknown invoice reference is recorded but never fakes success", async () => {
  const db = freshDb();
  adminLogin(db);
  const body = JSON.stringify({ eventId: "evt-unknown", invoiceRef: "no-such-ref", outcome: "paid" });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const response = await webhookRequest(db, body, timestamp, webhookSignature(WEBHOOK_SECRET, timestamp, body));
  assert.equal(response.status, 202);
  const payload = await response.json() as { processed: boolean };
  assert.equal(payload.processed, false);
  assert.equal(db.invoices.size, 0, "no invoice may be fabricated");
});

// ---------------------------------------------------------------------------
// 4. Email hosting honesty
// ---------------------------------------------------------------------------

test("email status reports mailbox hosting unavailable with exact requirements when no provider is configured", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const { status, json } = await call(db, "GET", "/v1/email/status", makeEnv());
  assert.equal(status, 200);
  const mailboxHosting = json.mailboxHosting as { available: boolean; requirements: string[] };
  assert.equal(mailboxHosting.available, false);
  assert.ok(mailboxHosting.requirements.some((r) => r.includes("EMAIL_PROVIDER")));
});

test("email domains register as inventory only and stay not_provisioned without a provider", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const { status, json } = await call(db, "POST", "/v1/email/domains", makeEnv(), { domain: "mail.acme.test", hostingAccountId: ACCOUNT_1 });
  assert.equal(status, 201);
  const emailDomain = json.emailDomain as { providerStatus: string };
  assert.equal(emailDomain.providerStatus, "not_provisioned");
  const provisioning = json.provisioning as { available: boolean; requirements: string[] };
  assert.equal(provisioning.available, false);
  assert.ok(provisioning.requirements.length >= 3, "must list the exact provider requirements");
  const inventory = await call(db, "GET", "/v1/email/domains", makeEnv());
  const domains = inventory.json.domains as Array<{ providerStatus: string }>;
  assert.equal(domains[0].providerStatus, "not_provisioned");
});

test("mailbox creation enforces the linked plan mailbox limit", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const domainResult = await call(db, "POST", "/v1/email/domains", makeEnv(), { domain: "mail.acme.test", hostingAccountId: ACCOUNT_1 });
  const domainId = (domainResult.json.emailDomain as { id: string }).id;
  const first = await call(db, "POST", `/v1/email/domains/${domainId}/mailboxes`, makeEnv(), { localPart: "hello", quotaMb: 1024 });
  assert.equal(first.status, 201);
  // Plan mailbox_limit is 1 for PLAN_BASIC: the second mailbox must be refused.
  const second = await call(db, "POST", `/v1/email/domains/${domainId}/mailboxes`, makeEnv(), { localPart: "world", quotaMb: 1024 });
  assert.equal(second.status, 409);
  assert.match(String(second.json.message), /mailbox/);
});

test("mailbox password change is refused with 503 and requirements when no provider is configured", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const domainResult = await call(db, "POST", "/v1/email/domains", makeEnv(), { domain: "mail.acme.test", hostingAccountId: ACCOUNT_1 });
  const domainId = (domainResult.json.emailDomain as { id: string }).id;
  const mailboxResult = await call(db, "POST", `/v1/email/domains/${domainId}/mailboxes`, makeEnv(), { localPart: "hello" });
  const mailboxId = (mailboxResult.json.mailbox as { id: string }).id;
  const result = await call(db, "PATCH", `/v1/email/mailboxes/${mailboxId}`, makeEnv(), { newPassword: "correct-horse-battery" });
  assert.equal(result.status, 503);
  const requirements = result.json.requirements as string[];
  assert.ok(requirements.length >= 3);
});

test("forwarding rules are recorded as desired state and marked not provisioned without a provider", async () => {
  const db = freshDb();
  loginAs(db, OWNER_A);
  const domainResult = await call(db, "POST", "/v1/email/domains", makeEnv(), { domain: "mail.acme.test" });
  const domainId = (domainResult.json.emailDomain as { id: string }).id;
  const created = await call(db, "POST", `/v1/email/domains/${domainId}/forwards`, makeEnv(), { source: "support", destination: "owner@acme.test" });
  assert.equal(created.status, 201);
  const forward = created.json.forward as { source: string; providerStatus: string };
  assert.equal(forward.source, "support@mail.acme.test");
  assert.equal(forward.providerStatus, "not_provisioned");
  const provisioning = created.json.provisioning as { available: boolean };
  assert.equal(provisioning.available, false);
});

// ---------------------------------------------------------------------------
// 5. Provisioning job inspector
// ---------------------------------------------------------------------------

test("the provisioning job inventory is platform-admin only and exposes failure reasons", async () => {
  const db = freshDb();
  db.jobs.set("job-1", {
    id: "job-1", hostingAccountId: ACCOUNT_1, operation: "ADD_DOMAIN", status: "FAILED",
    idempotencyKey: "add-domain:dom-1", attempts: 2, requestPayload: null,
    requestedAt: new Date().toISOString(), errorCode: "NGINX_CONFIG_INVALID", errorMessage: "nginx -t failed",
  });
  loginAs(db, OWNER_A);
  const denied = await call(db, "GET", "/v1/provisioning-jobs", makeEnv());
  assert.equal(denied.status, 403);
  adminLogin(db);
  const allowed = await call(db, "GET", "/v1/provisioning-jobs", makeEnv());
  assert.equal(allowed.status, 200);
  const jobs = allowed.json.jobs as Array<{ id: string; errorMessage: string | null; errorCode: string | null }>;
  const job = jobs.find((j) => j.id === "job-1")!;
  assert.equal(job.errorCode, "NGINX_CONFIG_INVALID");
  assert.equal(job.errorMessage, "nginx -t failed");
  assert.ok((allowed.json.retryableOperations as string[]).includes("ADD_DOMAIN"));
});

test("retry is restricted to FAILED jobs of retryable operations", async () => {
  const db = freshDb();
  db.jobs.set("job-restore", {
    id: "job-restore", hostingAccountId: ACCOUNT_1, operation: "RESTORE_BACKUP", status: "FAILED",
    idempotencyKey: "backup-restore:b1", attempts: 1, requestPayload: null,
    requestedAt: new Date().toISOString(), errorCode: null, errorMessage: "restore failed",
  });
  db.jobs.set("job-domain", {
    id: "job-domain", hostingAccountId: ACCOUNT_1, operation: "ADD_DOMAIN", status: "FAILED",
    idempotencyKey: "add-domain:dom-1", attempts: 1, requestPayload: null,
    requestedAt: new Date().toISOString(), errorCode: null, errorMessage: "agent unreachable",
  });
  db.jobs.set("job-running", {
    id: "job-running", hostingAccountId: ACCOUNT_1, operation: "ADD_DOMAIN", status: "RUNNING",
    idempotencyKey: "add-domain:dom-2", attempts: 1, requestPayload: null,
    requestedAt: new Date().toISOString(), errorCode: null, errorMessage: null,
  });
  adminLogin(db);
  const nonRetryable = await call(db, "POST", "/v1/provisioning-jobs/job-restore/retry", makeEnv());
  assert.equal(nonRetryable.status, 409);
  assert.match(String(nonRetryable.json.message), /cannot be retried from the inspector/);
  const notFailed = await call(db, "POST", "/v1/provisioning-jobs/job-running/retry", makeEnv());
  assert.equal(notFailed.status, 409);
  const retried = await call(db, "POST", "/v1/provisioning-jobs/job-domain/retry", makeEnv());
  assert.equal(retried.status, 201);
  const newJobId = retried.json.jobId as string;
  assert.notEqual(newJobId, "job-domain");
  const newJob = db.jobs.get(newJobId)!;
  assert.equal(newJob.status, "QUEUED");
  assert.match(newJob.idempotencyKey, /add-domain:dom-1:retry-2/);
  // The original FAILED job is preserved for audit.
  assert.equal(db.jobs.get("job-domain")!.status, "FAILED");
});
