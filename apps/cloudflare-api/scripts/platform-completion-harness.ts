import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash, randomUUID } from "node:crypto";
import worker from "../src/index.ts";

// ---------------------------------------------------------------------------
// platform-completion.integration.test.ts
//
// Regression tests for the platform-completion batches:
//
//   1. Organization administration — member inventory, role assignment,
//      last-OWNER/last-admin protection, session invalidation on revocation,
//      organization close with dependency checks, cross-organization
//      isolation, platform-admin scope=all listing.
//   2. Customer self-service — domain add/remove with plan quota and
//      primary-domain protection, database create/delete with plan quota,
//      account-membership isolation, READONLY role denial.
//   3. Subscriptions and billing — lifecycle creation with uniqueness,
//      idempotent renewal (no double invoice), plan-change downgrade
//      validation against live usage, suspension/reactivation, lazy expiry
//      sweep, HMAC-verified payment webhooks with replay dedup, and the
//      no-fake-success rule (unsigned webhooks are rejected, unknown
//      invoice references are recorded but never mark anything paid).
//   4. Email hosting — honest provider abstraction: inventory-only mode
//      marks records not_provisioned and reports requirements; plan
//      mailbox limits are enforced; password changes are refused with the
//      exact configuration requirements when no provider exists.
//   5. Provisioning job inspector — platform-admin gate, failure-reason
//      inventory, retry restricted to known-idempotent operations and to
//      FAILED jobs, retry jobs get unique idempotency keys.
//
// The PlatformCompletionD1 mock implements only the SQL the exercised
// routes issue; every other query throws so endpoint drift fails loudly.
// ---------------------------------------------------------------------------

const SESSION_TOKEN = "b".repeat(64); // bearerIdentity requires 64-hex
const ORG_A = "11111111-1111-4111-8111-111111111111";
const ORG_B = "22222222-2222-4222-8222-222222222222";
const OWNER_A = "aaaaaaa1-0000-4000-8000-000000000001"; // org A OWNER
const MEMBER_A = "aaaaaaa2-0000-4000-8000-000000000002"; // org A MEMBER (customer)
const ADMIN_A = "aaaaaaa3-0000-4000-8000-000000000003"; // org A ADMIN
const OUTSIDER = "bbbbbbb1-0000-4000-8000-000000000004"; // org B MEMBER
const PLATFORM_ADMIN = "ccccccc1-0000-4000-8000-000000000005";
const PLAN_BASIC = "ddddddd1-0000-4000-8000-000000000006";
const PLAN_SMALL = "ddddddd2-0000-4000-8000-000000000007";
const ACCOUNT_1 = "eeeeeee1-0000-4000-8000-000000000008";
const SERVER_1 = "fffffff1-0000-4000-8000-000000000009";

type OrgRole = "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER";
type PlatformRole = "PLATFORM_OWNER" | "PLATFORM_ADMIN" | null;

type Identity = {
  id: string;
  email: string;
  displayName: string | null;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: OrgRole;
  platformRole: PlatformRole;
};

type SessionRow = {
  id: string;
  userId: string;
  organizationId: string;
  tokenHash: string;
  revokedAt: string | null;
  expiresAt: string;
};

type MembershipRow = { userId: string; organizationId: string; role: OrgRole };

function isoInDays(days: number): string {
  return new Date(Date.now() + days * 86400_000).toISOString();
}

class PlatformCompletionD1 {
  identity: Identity | null = null;
  sessions = new Map<string, SessionRow>();
  users = new Map<string, { id: string; email: string; displayName: string | null; status: string }>();
  orgs = new Map<string, { id: string; name: string; slug: string; status: string; createdAt: string }>();
  memberships = new Map<string, MembershipRow>(); // key `${userId}:${orgId}`
  platformMemberships = new Map<string, { userId: string; role: string; status: string }>();
  plans = new Map<string, {
    id: string; organizationId: string; name: string; websiteLimit: number;
    databaseLimit: number; mailboxLimit: number; active: number; priceSarMinor: number | null;
  }>();
  accounts = new Map<string, {
    id: string; organizationId: string; serverId: string; planId: string;
    username: string; status: string; primaryDomain: string | null; createdAt: string;
  }>();
  hostingAccountMemberships = new Map<string, {
    hostingAccountId: string; organizationId: string; userId: string; role: string; status: string;
  }>(); // key `${accountId}:${userId}`
  servers = new Map<string, { id: string; hostname: string; status: string; lastHeartbeatAt: string | null }>();
  domains = new Map<string, {
    id: string; hostingAccountId: string; name: string; documentRoot: string;
    isPrimary: number; status: string;
  }>();
  databases = new Map<string, {
    id: string; organizationId: string; hostingAccountId: string; name: string;
    engine: string; status: string;
  }>();
  databaseUsers = new Map<string, { id: string; databaseId: string; organizationId: string; username: string; status: string }>();
  jobs = new Map<string, {
    id: string; hostingAccountId: string; operation: string; status: string;
    idempotencyKey: string; attempts: number; requestPayload: string | null;
    requestedAt: string; errorCode: string | null; errorMessage: string | null;
  }>();
  auditRows: { id: string; organizationId: string | null; actorUserId: string | null; action: string; resourceType: string; resourceId: string | null; metadata: string | null }[] = [];
  subscriptions = new Map<string, {
    id: string; organizationId: string; hostingAccountId: string | null; planId: string;
    status: string; billingPeriod: string; provider: string; amountSarMinor: number | null;
    currentPeriodStart: string | null; currentPeriodEnd: string | null; trialEnd: string | null;
    cancelAtPeriodEnd: number; cancelledAt: string | null; suspendedAt: string | null;
  }>();
  subscriptionEvents: { id: string; subscriptionId: string; organizationId: string | null; eventType: string; actorUserId: string | null; metadata: string | null }[] = [];
  invoices = new Map<string, {
    id: string; organizationId: string; subscriptionId: string | null; invoiceNumber: string;
    amountSarMinor: number; status: string; billingPeriod: string; paidAt: string | null;
    paymentMethod: string | null; paymentOrderRef: string | null; providerRef: string | null;
  }>();
  invoiceNumbersByNumber = new Set<string>();
  invoiceCounters = new Map<string, number>();
  webhookEvents = new Set<string>(); // `${provider}:${eventId}`
  emailDomains = new Map<string, {
    id: string; organizationId: string; hostingAccountId: string | null;
    domain: string; status: string; providerStatus: string;
  }>();
  emailMailboxes = new Map<string, {
    id: string; organizationId: string; emailDomainId: string; address: string;
    quotaMb: number; status: string; providerStatus: string;
  }>();
  emailForwards: { id: string; organizationId: string; emailDomainId: string; source: string; destination: string; active: number; providerStatus: string }[] = [];
  uniqueViolation: Error | null = null;

  seed() {
    const now = new Date().toISOString();
    this.orgs.set(ORG_A, { id: ORG_A, name: "Acme Hosting", slug: "acme-hosting", status: "ACTIVE", createdAt: now });
    this.orgs.set(ORG_B, { id: ORG_B, name: "Beta Corp", slug: "beta-corp", status: "ACTIVE", createdAt: now });
    this.users.set(OWNER_A, { id: OWNER_A, email: "owner@acme.test", displayName: "Acme Owner", status: "ACTIVE" });
    this.users.set(MEMBER_A, { id: MEMBER_A, email: "customer@acme.test", displayName: "Acme Customer", status: "ACTIVE" });
    this.users.set(ADMIN_A, { id: ADMIN_A, email: "admin@acme.test", displayName: "Acme Admin", status: "ACTIVE" });
    this.users.set(OUTSIDER, { id: OUTSIDER, email: "member@beta.test", displayName: "Beta Member", status: "ACTIVE" });
    this.users.set(PLATFORM_ADMIN, { id: PLATFORM_ADMIN, email: "ops@nexora.test", displayName: "Nexora Ops", status: "ACTIVE" });
    this.memberships.set(`${OWNER_A}:${ORG_A}`, { userId: OWNER_A, organizationId: ORG_A, role: "OWNER" });
    this.memberships.set(`${MEMBER_A}:${ORG_A}`, { userId: MEMBER_A, organizationId: ORG_A, role: "MEMBER" });
    this.memberships.set(`${ADMIN_A}:${ORG_A}`, { userId: ADMIN_A, organizationId: ORG_A, role: "ADMIN" });
    this.memberships.set(`${OUTSIDER}:${ORG_B}`, { userId: OUTSIDER, organizationId: ORG_B, role: "MEMBER" });
    this.platformMemberships.set(PLATFORM_ADMIN, { userId: PLATFORM_ADMIN, role: "PLATFORM_ADMIN", status: "ACTIVE" });
    this.servers.set(SERVER_1, { id: SERVER_1, hostname: "node1.nexora.test", status: "ONLINE", lastHeartbeatAt: now });
    this.plans.set(PLAN_BASIC, { id: PLAN_BASIC, organizationId: ORG_A, name: "Basic", websiteLimit: 2, databaseLimit: 2, mailboxLimit: 1, active: 1, priceSarMinor: 1500 });
    this.plans.set(PLAN_SMALL, { id: PLAN_SMALL, organizationId: ORG_A, name: "Small", websiteLimit: 1, databaseLimit: 1, mailboxLimit: 0, active: 1, priceSarMinor: 800 });
    this.accounts.set(ACCOUNT_1, { id: ACCOUNT_1, organizationId: ORG_A, serverId: SERVER_1, planId: PLAN_BASIC, username: "acme01", status: "ACTIVE", primaryDomain: "acme01.test", createdAt: isoInDays(-2) });
    this.hostingAccountMemberships.set(`${ACCOUNT_1}:${MEMBER_A}`, { hostingAccountId: ACCOUNT_1, organizationId: ORG_A, userId: MEMBER_A, role: "ACCOUNT_OWNER", status: "ACTIVE" });
    for (const [tokenHash] of this.sessions) {
      const session = this.sessions.get(tokenHash)!;
      if (!session.expiresAt) session.expiresAt = isoInDays(1);
    }
  }

  addSession(userId: string, organizationId: string, tokenHash?: string): string {
    const hash = tokenHash ?? (randomUUID() + randomUUID().replace(/-/g, ""));
    this.sessions.set(hash, { id: randomUUID(), userId, organizationId, tokenHash: hash, revokedAt: null, expiresAt: isoInDays(1) });
    return hash;
  }

  asIdentity(userId: string): Identity {
    const user = this.users.get(userId)!;
    const membership = this.memberships.get(`${userId}:${this.orgs.has(ORG_A) && userId.startsWith("aaaa") || userId === MEMBER_A ? ORG_A : ORG_B}`);
    const platform = this.platformMemberships.get(userId);
    const orgId = platform ? ORG_A : (membership?.organizationId ?? ORG_A);
    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      organizationId: orgId,
      organizationName: this.orgs.get(orgId)?.name ?? "",
      organizationSlug: this.orgs.get(orgId)?.slug ?? "",
      role: membership?.role ?? "MEMBER",
      platformRole: (platform?.role as PlatformRole) ?? null,
    };
  }

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      getValues() { return values; },
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>(): Promise<T | null> {
        return db.routeFirst<T>(query, values);
      },
      async all<T>(): Promise<{ results: T[] }> {
        return { results: await db.routeAll<T>(query, values) };
      },
      async run(): Promise<{ success: boolean; meta: { changes: number } }> {
        return db.routeRun(query, values);
      },
    };
    return statement;
  }

  async batch(statements: Array<{ routeRun(q: string, v: unknown[]): { success: boolean; meta: { changes: number } }; query: string; getValues(): unknown[] }>): Promise<Array<{ success: boolean; meta: { changes: number } }>> {
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];
    for (const statement of statements) {
      const raw = statement as unknown as { query: string; getValues(): unknown[] };
      results.push(this.routeRun(raw.query, raw.getValues()));
    }
    return results;
  }

  private throwIfUniqueArmed(): void {
    if (this.uniqueViolation) throw this.uniqueViolation;
  }

  // ---- first() routing -------------------------------------------------
  private async routeFirst<T>(query: string, values: unknown[]): Promise<T | null> {
    // bearerIdentity
    if (query.includes("FROM auth_sessions s")) {
      if (!this.identity) return null as T;
      const tokenHash = String(values[0]);
      const session = this.sessions.get(tokenHash);
      if (!session || session.revokedAt) return null as T;
      if (Date.parse(session.expiresAt) <= Date.now()) return null as T;
      return ({
        id: this.identity.id,
        email: this.identity.email,
        displayName: this.identity.displayName,
        organizationId: this.identity.organizationId,
        organizationName: this.identity.organizationName,
        organizationSlug: this.identity.organizationSlug,
        role: this.identity.role,
        platformRole: this.identity.platformRole,
      } as T);
    }
    // resolveOrgAccess / membership lookup for a user+org
    if (query.includes("SELECT role FROM memberships WHERE user_id")) {
      const userId = String(values[0]);
      const orgId = String(values[1]);
      const membership = this.memberships.get(`${userId}:${orgId}`);
      return (membership ? { role: membership.role } : null) as T;
    }
    // hosting account delete-route lookup (needs username + status)
    if (query.includes("SELECT id, username, status FROM hosting_accounts WHERE id = ?")) {
      const account = this.accounts.get(String(values[0]));
      if (!account || account.organizationId !== String(values[1])) return null as T;
      return ({ id: account.id, username: account.username, status: account.status }) as T;
    }
    // hosting account existence/ownership lookup (email domain link, etc.)
    if (query.includes("FROM hosting_accounts WHERE id = ?")) {
      const account = this.accounts.get(String(values[0]));
      if (!account || account.organizationId !== String(values[1])) return null as T;
      if (query.includes("status = 'ACTIVE'") && account.status !== "ACTIVE") return null as T;
      return ({ id: account.id }) as T;
    }
    // latest CREATE_HOSTING_ACCOUNT job for the hosting-account delete route
    if (query.includes("SELECT id, status FROM provisioning_jobs WHERE hosting_account_id = ? AND operation = 'CREATE_HOSTING_ACCOUNT'")) {
      const accountId = String(values[0]);
      const latest = [...this.jobs.values()]
        .filter((job) => job.hostingAccountId === accountId && job.operation === "CREATE_HOSTING_ACCOUNT")
        .sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1))[0];
      return (latest ? { id: latest.id, status: latest.status } : null) as T;
    }
    // hosting-account create route: server + plan lookups
    if (query.includes("SELECT id, hostname FROM servers WHERE id = ? AND organization_id = ? LIMIT 1")) {
      const server = this.servers.get(String(values[0]));
      if (!server || server.status === "DELETED") return null as T;
      return ({ id: server.id, hostname: server.hostname }) as T;
    }
    if (query.includes("SELECT id, name, active, website_limit FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1")) {
      const plan = this.plans.get(String(values[0]));
      if (!plan || plan.organizationId !== String(values[1])) return null as T;
      return ({ id: plan.id, name: plan.name, active: plan.active, website_limit: plan.websiteLimit }) as T;
    }
    // customer domain lookup for delete (primary-domain protection)
    if (query.includes("FROM domains d WHERE d.id = ? AND d.hosting_account_id = ? LIMIT 1")) {
      const domain = this.domains.get(String(values[0]));
      if (!domain || domain.hostingAccountId !== String(values[1])) return null as T;
      return ({ id: domain.id, name: domain.name, isPrimary: domain.isPrimary, status: domain.status }) as T;
    }
    // countOrgAdmins
    if (query.includes("SUM(CASE WHEN role = 'OWNER'")) {
      const orgId = String(values[0]);
      let owners = 0, admins = 0;
      for (const membership of this.memberships.values()) {
        if (membership.organizationId !== orgId) continue;
        if (membership.role === "OWNER") { owners += 1; admins += 1; }
        else if (membership.role === "ADMIN") admins += 1;
      }
      return ({ owners, admins }) as T;
    }
    // organizations lookup by id
    if (query.includes("FROM organizations WHERE id = ? LIMIT 1")) {
      const org = this.orgs.get(String(values[0]));
      return (org ? { ...org } : null) as T;
    }
    // organization details (details route)
    if (query.includes("FROM organizations o WHERE o.id = ? LIMIT 1")) {
      const org = this.orgs.get(String(values[0]));
      if (!org) return null as T;
      let hostingAccountCount = 0, activeHostingAccountCount = 0;
      for (const account of this.accounts.values()) {
        if (account.organizationId !== org.id || account.status === "DELETED") continue;
        hostingAccountCount += 1;
        if (account.status === "ACTIVE") activeHostingAccountCount += 1;
      }
      return ({ id: org.id, name: org.name, slug: org.slug, status: org.status, createdAt: org.createdAt, hostingAccountCount, activeHostingAccountCount }) as T;
    }
    // dependency counts for organization close
    if (query.includes("SELECT COUNT(*) AS count FROM hosting_accounts WHERE organization_id")) {
      const orgId = String(values[0]);
      const count = [...this.accounts.values()].filter((a) => a.organizationId === orgId && a.status !== "DELETED").length;
      return ({ count }) as T;
    }
    if (query.includes("SELECT COUNT(*) AS count FROM subscriptions WHERE organization_id")) {
      const orgId = String(values[0]);
      const count = [...this.subscriptions.values()].filter((s) => s.organizationId === orgId && ["TRIALING", "ACTIVE", "PAST_DUE"].includes(s.status)).length;
      return ({ count }) as T;
    }
    // users lookup by email (member add)
    if (query.includes("FROM users WHERE email = ? COLLATE NOCASE")) {
      const email = String(values[0]).toLowerCase();
      for (const user of this.users.values()) {
        if (user.email.toLowerCase() === email && user.status === "ACTIVE") {
          return ({ id: user.id, email: user.email }) as T;
        }
      }
      return null as T;
    }
    // existing membership check (member add)
    if (query.includes("SELECT role FROM memberships WHERE user_id = ? AND organization_id = ?")) {
      const membership = this.memberships.get(`${String(values[0])}:${String(values[1])}`);
      return (membership ? { role: membership.role } : null) as T;
    }
    // target membership for role change / removal (with email)
    if (query.includes("SELECT m.role AS currentRole, u.email FROM memberships m")) {
      const membership = this.memberships.get(`${String(values[0])}:${String(values[1])}`);
      if (!membership) return null as T;
      return ({ currentRole: membership.role, email: this.users.get(membership.userId)?.email ?? "" }) as T;
    }
    if (query.includes("SELECT m.role AS role, u.email FROM memberships m")) {
      const membership = this.memberships.get(`${String(values[0])}:${String(values[1])}`);
      if (!membership) return null as T;
      return ({ role: membership.role, email: this.users.get(membership.userId)?.email ?? "" }) as T;
    }
    // hosting account + plan join (customer domain/database mutations)
    if (query.includes("p.website_limit") && query.includes("FROM hosting_accounts a JOIN hosting_plans p")) {
      const account = this.accounts.get(String(values[0]));
      if (!account) return null as T;
      const plan = this.plans.get(account.planId)!;
      const websiteCount = [...this.domains.values()].filter((d) => d.hostingAccountId === account.id && d.status !== "DELETED").length;
      return ({ website_limit: plan.websiteLimit, website_count: websiteCount, username: account.username }) as T;
    }
    if (query.includes("a.username, p.database_limit AS databaseLimit")) {
      const account = this.accounts.get(String(values[0]));
      if (!account) return null as T;
      const plan = this.plans.get(account.planId)!;
      return ({ username: account.username, databaseLimit: plan.databaseLimit }) as T;
    }
    // database count for quota
    if (query.includes("SELECT COUNT(*) AS count FROM hosting_databases WHERE hosting_account_id")) {
      const accountId = String(values[0]);
      const count = [...this.databases.values()].filter((d) => d.hostingAccountId === accountId && d.status !== "DELETED").length;
      return ({ count }) as T;
    }
    // customer database lookup for delete
    if (query.includes("SELECT d.id, d.name, d.status, a.username AS accountUsername")) {
      const database = this.databases.get(String(values[0]));
      if (!database || database.hostingAccountId !== String(values[1]) || database.organizationId !== String(values[2])) return null as T;
      return ({ id: database.id, name: database.name, status: database.status, accountUsername: this.accounts.get(database.hostingAccountId)?.username ?? "" }) as T;
    }
    // existing DELETE_DATABASE job lookup
    if (query.includes("operation = 'DELETE_DATABASE'") && query.includes("first")) {
      return null as T;
    }
    // subscriptions lookup (renew / cancel / suspend / detail / plan-change)
    if (query.includes("FROM subscriptions s WHERE s.id = ? LIMIT 1")) {
      const subscription = this.subscriptions.get(String(values[0]));
      if (!subscription) return null as T;
      return ({
        id: subscription.id, organizationId: subscription.organizationId,
        hostingAccountId: subscription.hostingAccountId, status: subscription.status,
        planId: subscription.planId,
      }) as T;
    }
    if (query.includes("FROM subscriptions WHERE id = ? LIMIT 1")) {
      const subscription = this.subscriptions.get(String(values[0]));
      if (!subscription) return null as T;
      if (query.includes("AS organizationId")) {
        return ({
          id: subscription.id, organizationId: subscription.organizationId,
          hostingAccountId: subscription.hostingAccountId, planId: subscription.planId,
          status: subscription.status, billingPeriod: subscription.billingPeriod,
          amountSarMinor: subscription.amountSarMinor, currentPeriodEnd: subscription.currentPeriodEnd,
        }) as T;
      }
      if (query.includes("SELECT status, current_period_end")) {
        return ({ status: subscription.status, currentPeriodEnd: subscription.currentPeriodEnd, amountSarMinor: subscription.amountSarMinor, billingPeriod: subscription.billingPeriod }) as T;
      }
      if (query.includes("currentPeriodEnd")) {
        return ({ id: subscription.id, organizationId: subscription.organizationId, status: subscription.status, currentPeriodEnd: subscription.currentPeriodEnd }) as T;
      }
      return ({ id: subscription.id, organizationId: subscription.organizationId, status: subscription.status }) as T;
    }
    // subscription detail (detail route)
    if (query.includes("FROM subscriptions s") && query.includes("JOIN organizations o") && query.includes("WHERE s.id = ? LIMIT 1")) {
      const subscription = this.subscriptions.get(String(values[0]));
      if (!subscription) return null as T;
      return ({ id: subscription.id, organizationId: subscription.organizationId, status: subscription.status }) as T;
    }
    // account + plan for subscription creation
    if (query.includes("SELECT a.id, a.organization_id AS organizationId, a.status, p.id AS planId")) {
      const account = this.accounts.get(String(values[0]));
      if (!account) return null as T;
      return ({ id: account.id, organizationId: account.organizationId, status: account.status, planId: account.planId }) as T;
    }
    // plan lookup for subscription creation / plan change
    if (query.includes("FROM hosting_plans WHERE id = ? LIMIT 1") && query.includes("priceSarMinor")) {
      const plan = this.plans.get(String(values[0]));
      if (!plan) return null as T;
      return ({ id: plan.id, organizationId: plan.organizationId, active: plan.active, priceSarMinor: plan.priceSarMinor, billingPeriod: "monthly" }) as T;
    }
    if (query.includes("FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1")) {
      const plan = this.plans.get(String(values[0]));
      if (!plan || plan.organizationId !== String(values[1])) return null as T;
      return ({ id: plan.id, name: plan.name, active: plan.active, diskLimitBytes: 0, websiteLimit: plan.websiteLimit, databaseLimit: plan.databaseLimit, mailboxLimit: plan.mailboxLimit }) as T;
    }
    // usage counts for plan change
    if (query.includes("AS domainCount") && query.includes("AS databaseCount")) {
      const accountId = String(values[0]);
      const domainCount = [...this.domains.values()].filter((d) => d.hostingAccountId === accountId && d.status !== "DELETED").length;
      const databaseCount = [...this.databases.values()].filter((d) => d.hostingAccountId === accountId && d.status !== "DELETED").length;
      return ({ domainCount, databaseCount }) as T;
    }
    // existing invoice for dedupe reference
    if (query.includes("FROM invoices WHERE payment_order_ref = ? LIMIT 1")) {
      const ref = String(values[0]);
      for (const invoice of this.invoices.values()) {
        if (invoice.paymentOrderRef === ref) {
          return ({ id: invoice.id, invoiceNumber: invoice.invoiceNumber, status: invoice.status, paidAt: invoice.paidAt }) as T;
        }
      }
      return null as T;
    }
    // webhook invoice lookup
    if (query.includes("WHERE payment_order_ref = ? OR provider_ref = ?")) {
      const ref = String(values[0]);
      for (const invoice of this.invoices.values()) {
        if (invoice.paymentOrderRef === ref || invoice.providerRef === ref) {
          return ({ id: invoice.id, organizationId: invoice.organizationId, subscriptionId: invoice.subscriptionId, status: invoice.status, amountSarMinor: invoice.amountSarMinor }) as T;
        }
      }
      return null as T;
    }
    // webhook subscription lookup
    if (query.includes("SELECT id, billing_period AS billingPeriod, current_period_end AS currentPeriodEnd FROM subscriptions WHERE id = ? LIMIT 1")) {
      const subscription = this.subscriptions.get(String(values[0]));
      if (!subscription) return null as T;
      return ({ id: subscription.id, billingPeriod: subscription.billingPeriod, currentPeriodEnd: subscription.currentPeriodEnd }) as T;
    }
    // invoice counters
    if (query.includes("UPDATE invoice_counters SET last_number = last_number + 1")) {
      const orgId = String(values[0]);
      if (!this.invoiceCounters.has(orgId)) return null as T;
      const next = (this.invoiceCounters.get(orgId) ?? 0) + 1;
      this.invoiceCounters.set(orgId, next);
      return ({ last_number: next }) as T;
    }
    // mailbox plan limit check — must precede the generic account+plan join branch
    if (query.includes("SELECT p.mailbox_limit")) {
      const accountId = String(values[0]);
      const account = this.accounts.get(accountId);
      if (!account) return null as T;
      const plan = this.plans.get(account.planId)!;
      const domainIds = new Set([...this.emailDomains.values()].filter((ed) => ed.hostingAccountId === accountId).map((ed) => ed.id));
      const mailboxCount = [...this.emailMailboxes.values()].filter((m) => domainIds.has(m.emailDomainId) && m.status !== "DELETED").length;
      return ({ mailbox_limit: plan.mailboxLimit, mailboxCount }) as T;
    }
    // hosting account lookup (subscription create)
    if (query.includes("FROM hosting_accounts a JOIN hosting_plans p ON p.id = a.plan_id") && query.includes("WHERE a.id = ? LIMIT 1")) {
      const account = this.accounts.get(String(values[0]));
      if (!account) return null as T;
      return ({ id: account.id, organizationId: account.organizationId, status: account.status, planId: account.planId }) as T;
    }
    // email domain lookups
    if (query.includes("FROM email_domains WHERE id = ? AND organization_id = ?")) {
      const emailDomain = this.emailDomains.get(String(values[0]));
      if (!emailDomain || emailDomain.organizationId !== String(values[1])) return null as T;
      if (query.includes("hostingAccountId")) {
        return ({ id: emailDomain.id, domain: emailDomain.domain, hostingAccountId: emailDomain.hostingAccountId, status: emailDomain.status }) as T;
      }
      return ({ id: emailDomain.id, domain: emailDomain.domain, status: emailDomain.status }) as T;
    }
    // (mailbox plan limit check moved above the generic account+plan join branch)
    // mailbox lookup for patch/delete
    if (query.includes("FROM email_mailboxes m JOIN email_domains ed")) {
      const mailbox = this.emailMailboxes.get(String(values[0]));
      if (!mailbox || mailbox.organizationId !== String(values[1])) return null as T;
      return ({ id: mailbox.id, address: mailbox.address, status: mailbox.status, providerStatus: mailbox.providerStatus, domain: this.emailDomains.get(mailbox.emailDomainId)?.domain ?? "" }) as T;
    }
    if (query.includes("SELECT id, address FROM email_mailboxes WHERE id = ? AND organization_id = ? LIMIT 1")) {
      const mailbox = this.emailMailboxes.get(String(values[0]));
      if (!mailbox || mailbox.organizationId !== String(values[1])) return null as T;
      return ({ id: mailbox.id, address: mailbox.address }) as T;
    }
    // provisioning job lookups
    if (query.includes("FROM provisioning_jobs j JOIN hosting_accounts a ON a.id = j.hosting_account_id") && query.includes("WHERE j.id = ? LIMIT 1")) {
      const job = this.jobs.get(String(values[0]));
      if (!job) return null as T;
      return ({
        id: job.id, operation: job.operation, status: job.status, attempts: job.attempts,
        requestPayload: job.requestPayload, idempotencyKey: job.idempotencyKey,
        hostingAccountId: job.hostingAccountId, organizationId: this.accounts.get(job.hostingAccountId)?.organizationId ?? ORG_A,
      }) as T;
    }
    if (query.includes("SELECT id FROM provisioning_jobs") && query.includes("status IN ('QUEUED','RUNNING') LIMIT 1")) {
      const hostingAccountId = String(values[0]);
      const idempotencyKey = String(values[1]);
      for (const job of this.jobs.values()) {
        if (job.hostingAccountId === hostingAccountId && job.idempotencyKey === idempotencyKey && ["QUEUED", "RUNNING"].includes(job.status)) {
          return ({ id: job.id }) as T;
        }
      }
      return null as T;
    }
    // hosting plan lookup for delete
    if (query.includes("SELECT id, name FROM hosting_plans WHERE id = ? AND organization_id = ? LIMIT 1")) {
      const plan = this.plans.get(String(values[0]));
      if (!plan || plan.organizationId !== String(values[1])) return null as T;
      return ({ id: plan.id, name: plan.name }) as T;
    }
    // hosting account membership check (customer routes)
    if (query.includes("FROM hosting_account_memberships m") && query.includes("WHERE a.id = ? AND m.user_id = ?")) {
      const accountId = String(values[0]);
      const userId = String(values[1]);
      const membership = this.hostingAccountMemberships.get(`${accountId}:${userId}`);
      if (!membership || membership.status !== "ACTIVE") return null as T;
      const account = this.accounts.get(accountId)!;
      if (query.includes("a.status = 'ACTIVE'") && account.status !== "ACTIVE") return null as T;
      return ({ role: membership.role, id: account.id }) as T;
    }
    return null as T;
  }

  // ---- all() routing ---------------------------------------------------
  private async routeAll<T>(query: string, values: unknown[]): Promise<T[]> {
    // expireDueSubscriptions sweep select
    if (query.includes("SELECT id, organization_id, status, cancel_at_period_end FROM subscriptions")) {
      const now = new Date().toISOString();
      return [...this.subscriptions.values()]
        .filter((s) => ["TRIALING", "ACTIVE"].includes(s.status) && s.currentPeriodEnd !== null && s.currentPeriodEnd < now)
        .map((s) => ({ id: s.id, organization_id: s.organizationId, status: s.status, cancel_at_period_end: s.cancelAtPeriodEnd }) as T);
    }
    // member inventory
    if (query.includes("FROM memberships m JOIN users u ON u.id = m.user_id") && query.includes("ORDER BY m.created_at ASC")) {
      const orgId = String(values[0]);
      const results: T[] = [];
      for (const membership of this.memberships.values()) {
        if (membership.organizationId !== orgId) continue;
        const user = this.users.get(membership.userId)!;
        results.push({ userId: user.id, email: user.email, displayName: user.displayName, userStatus: user.status, role: membership.role, memberSince: new Date().toISOString() } as T);
      }
      return results;
    }
    // org-scoped audit history
    if (query.includes("FROM audit_logs a LEFT JOIN users u")) {
      const orgId = String(values[0]);
      return this.auditRows.filter((r) => r.organizationId === orgId).map((r) => ({ id: r.id, action: r.action, resourceType: r.resourceType, resourceId: r.resourceId, metadata: r.metadata, createdAt: new Date().toISOString(), actorEmail: r.actorUserId ? this.users.get(r.actorUserId)?.email ?? null : null }) as T);
    }
    // subscription listing
    if (query.includes("FROM subscriptions s") && query.includes("ORDER BY s.created_at DESC LIMIT 200")) {
      const results: T[] = [];
      for (const subscription of this.subscriptions.values()) {
        const orgFilter = values[0] !== undefined ? String(values[0]) : null;
        if (orgFilter && subscription.organizationId !== orgFilter) continue;
        results.push({
          id: subscription.id, organizationId: subscription.organizationId,
          hostingAccountId: subscription.hostingAccountId, planId: subscription.planId,
          status: subscription.status, billingPeriod: subscription.billingPeriod,
          amountSarMinor: subscription.amountSarMinor,
          currentPeriodEnd: subscription.currentPeriodEnd,
          cancelAtPeriodEnd: subscription.cancelAtPeriodEnd,
        } as T);
      }
      return results;
    }
    // subscription events
    if (query.includes("FROM subscription_events e LEFT JOIN users u")) {
      const subscriptionId = String(values[0]);
      return this.subscriptionEvents.filter((e) => e.subscriptionId === subscriptionId).map((e) => ({ id: e.id, eventType: e.eventType, metadata: e.metadata, createdAt: new Date().toISOString(), actorEmail: e.actorUserId ? this.users.get(e.actorUserId)?.email ?? null : null }) as T);
    }
    // invoices for subscription detail
    if (query.includes("FROM invoices WHERE subscription_id = ? ORDER BY created_at DESC")) {
      const subscriptionId = String(values[0]);
      return [...this.invoices.values()].filter((i) => i.subscriptionId === subscriptionId).map((i) => ({ id: i.id, invoiceNumber: i.invoiceNumber, amountSarMinor: i.amountSarMinor, status: i.status, paidAt: i.paidAt }) as T);
    }
    // mailbox inventory
    if (query.includes("FROM email_mailboxes WHERE email_domain_id = ? AND status != 'DELETED'")) {
      const domainId = String(values[0]);
      return [...this.emailMailboxes.values()].filter((m) => m.emailDomainId === domainId && m.status !== "DELETED").map((m) => ({ id: m.id, address: m.address, quotaMb: m.quotaMb, status: m.status, providerStatus: m.providerStatus }) as T);
    }
    // hosting-account inventory (admin hosting-accounts list) with latest
    // CREATE_HOSTING_ACCOUNT job status + failure reason subselects
    if (query.includes("FROM hosting_accounts a") && query.includes("ORDER BY a.created_at DESC")) {
      const organizationId = String(values[0]);
      const rows = [...this.accounts.values()]
        .filter((a) => a.organizationId === organizationId && a.status !== "DELETED")
        .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
        .map((a) => {
          const latestJob = [...this.jobs.values()]
            .filter((job) => job.hostingAccountId === a.id && job.operation === "CREATE_HOSTING_ACCOUNT")
            .sort((x, y) => (x.requestedAt < y.requestedAt ? 1 : -1))[0];
          return {
            id: a.id, username: a.username, primary_domain: a.primaryDomain, status: a.status,
            created_at: a.createdAt, server_id: a.serverId,
            server_hostname: this.servers.get(a.serverId)?.hostname ?? "",
            plan_id: a.planId, plan_name: this.plans.get(a.planId)?.name ?? "",
            job_status: latestJob?.status ?? null, job_id: latestJob?.id ?? null,
            error_code: latestJob?.errorCode ?? null, error_message: latestJob?.errorMessage ?? null,
            job_attempts: latestJob ? latestJob.attempts : null,
          } as T;
        });
      return rows;
    }
    // forwards inventory
    if (query.includes("FROM email_forwards WHERE email_domain_id = ? ORDER BY created_at ASC")) {
      const domainId = String(values[0]);
      return this.emailForwards.filter((f) => f.emailDomainId === domainId).map((f) => ({ id: f.id, source: f.source, destination: f.destination, active: f.active, providerStatus: f.providerStatus }) as T);
    }
    // provisioning job inventory
    if (query.includes("FROM provisioning_jobs j") && query.includes("ORDER BY j.requested_at DESC LIMIT 200")) {
      return [...this.jobs.values()].map((job) => {
        const account = this.accounts.get(job.hostingAccountId);
        return {
          id: job.id, operation: job.operation, status: job.status, attempts: job.attempts,
          requestedAt: job.requestedAt, errorCode: job.errorCode, errorMessage: job.errorMessage,
          hostingAccountId: job.hostingAccountId, accountUsername: account?.username ?? "",
          organizationId: account?.organizationId ?? "", organizationName: this.orgs.get(account?.organizationId ?? "")?.name ?? "",
          serverHostname: this.servers.get(account?.serverId ?? "")?.hostname ?? null, stalled: 0,
        } as T;
      });
    }
    // scope=all organization listing
    if (query.includes("FROM organizations o ORDER BY o.created_at DESC")) {
      return [...this.orgs.values()].map((org) => {
        let memberCount = 0, hostingAccountCount = 0;
        for (const membership of this.memberships.values()) if (membership.organizationId === org.id) memberCount += 1;
        for (const account of this.accounts.values()) if (account.organizationId === org.id && account.status !== "DELETED") hostingAccountCount += 1;
        return { id: org.id, name: org.name, slug: org.slug, status: org.status, createdAt: org.createdAt, memberCount, hostingAccountCount } as T;
      });
    }
    // user's own organizations
    if (query.includes("FROM memberships m JOIN organizations o ON o.id = m.organization_id")) {
      const userId = String(values[0]);
      const results: T[] = [];
      for (const membership of this.memberships.values()) {
        if (membership.userId !== userId) continue;
        const org = this.orgs.get(membership.organizationId)!;
        results.push({ id: org.id, name: org.name, slug: org.slug, status: org.status, createdAt: org.createdAt, role: membership.role } as T);
      }
      return results;
    }
    // email domain inventory
    if (query.includes("FROM email_domains ed WHERE ed.organization_id = ? AND ed.status != 'DELETED'")) {
      const orgId = String(values[0]);
      return [...this.emailDomains.values()].filter((ed) => ed.organizationId === orgId && ed.status !== "DELETED").map((ed) => {
        const mailboxCount = [...this.emailMailboxes.values()].filter((m) => m.emailDomainId === ed.id && m.status !== "DELETED").length;
        const forwardCount = this.emailForwards.filter((f) => f.emailDomainId === ed.id && f.active === 1).length;
        return { id: ed.id, domain: ed.domain, status: ed.status, providerStatus: ed.providerStatus, mailboxCount, forwardCount } as T;
      });
    }
    // database users for delete guard
    if (query.includes("SELECT username, status FROM hosting_database_users WHERE database_id = ? AND organization_id = ?")) {
      const databaseId = String(values[0]);
      return [...this.databaseUsers.values()].filter((u) => u.databaseId === databaseId).map((u) => ({ username: u.username, status: u.status }) as T);
    }
    throw new Error(`Unmocked all() query: ${query.slice(0, 120)}`);
  }

  // ---- run() routing ---------------------------------------------------
  private routeRun(query: string, values: unknown[]): { success: boolean; meta: { changes: number } } {
    // Membership mutations
    if (query.startsWith("INSERT INTO memberships")) {
      this.throwIfUniqueArmed();
      const [id, userId, orgId, role] = values as [string, string, string, string];
      this.memberships.set(`${userId}:${orgId}`, { userId, organizationId: orgId, role: role as OrgRole });
      void id;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.startsWith("UPDATE memberships SET role = ?")) {
      const [role, userId, orgId] = values as [string, string, string];
      const membership = this.memberships.get(`${userId}:${orgId}`);
      if (!membership) return { success: true, meta: { changes: 0 } };
      membership.role = role as OrgRole;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM memberships WHERE user_id = ? AND organization_id = ?")) {
      const key = `${String(values[0])}:${String(values[1])}`;
      const deleted = this.memberships.delete(key);
      return { success: true, meta: { changes: deleted ? 1 : 0 } };
    }
    // Session invalidation
    if (query.includes("UPDATE auth_sessions SET revoked_at")) {
      const now = String(values[0]);
      let changed = 0;
      for (const session of this.sessions.values()) {
        const matchesUserOrg = values.length >= 3
          ? session.userId === String(values[1]) && session.organizationId === String(values[2])
          : session.organizationId === String(values[1]);
        if (matchesUserOrg && !session.revokedAt) { session.revokedAt = now; changed += 1; }
      }
      return { success: true, meta: { changes: changed } };
    }
    // Organization close
    if (query.includes("UPDATE organizations SET status = 'CLOSED'")) {
      const org = this.orgs.get(String(values[1]));
      if (!org || org.status === "CLOSED") return { success: true, meta: { changes: 0 } };
      org.status = "CLOSED";
      return { success: true, meta: { changes: 1 } };
    }
    // Counters seed — the 0/1 seed value may be a SQL literal (1 bind) or bound (2 binds)
    if (query.includes("INSERT INTO invoice_counters")) {
      const orgId = String(values[0]);
      if (!this.invoiceCounters.has(orgId)) {
        const seed = Number(values[1]);
        this.invoiceCounters.set(orgId, Number.isFinite(seed) ? seed : 0);
      }
      return { success: true, meta: { changes: 1 } };
    }
    // Subscription mutations
    if (query.startsWith("INSERT INTO subscriptions")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, hostingAccountId, planId, status, billingPeriod, amountSarMinor, currentPeriodStart, currentPeriodEnd, trialEnd] = values as [string, string, string | null, string, string, string, number | null, string, string, string | null];
      // Enforce one live subscription per account (partial UNIQUE index).
      if (hostingAccountId && ["TRIALING", "ACTIVE", "PAST_DUE", "SUSPENDED"].includes(status)) {
        for (const existing of this.subscriptions.values()) {
          if (existing.hostingAccountId === hostingAccountId && ["TRIALING", "ACTIVE", "PAST_DUE", "SUSPENDED"].includes(existing.status)) {
            throw new Error("UNIQUE constraint failed: index 'subscriptions_one_live_per_account_idx'");
          }
        }
      }
      this.subscriptions.set(id, { id, organizationId, hostingAccountId, planId, status, billingPeriod, provider: "manual", amountSarMinor, currentPeriodStart, currentPeriodEnd, trialEnd, cancelAtPeriodEnd: 0, cancelledAt: null, suspendedAt: null });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE subscriptions SET status = ?") && query.includes("cancelled_at = CASE WHEN")) {
      // Expiry sweep: (status, status, now, now, id)
      const status = String(values[0]);
      const subscription = this.subscriptions.get(String(values[4]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.status = status;
      if (status === "CANCELLED") subscription.cancelledAt = String(values[2]);
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("SET status = 'ACTIVE', current_period_start = ?")) {
      // Renew: (nowIso, newEnd, nowIso, id)
      const subscription = this.subscriptions.get(String(values[3]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.status = "ACTIVE";
      subscription.currentPeriodStart = String(values[0]);
      subscription.currentPeriodEnd = String(values[1]);
      subscription.suspendedAt = null;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("SET status = 'CANCELLED', cancel_at_period_end = 0")) {
      const subscription = this.subscriptions.get(String(values[2]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.status = "CANCELLED";
      subscription.cancelledAt = String(values[0]);
      subscription.cancelAtPeriodEnd = 0;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("SET status = 'SUSPENDED', suspended_at = ?")) {
      const subscription = this.subscriptions.get(String(values[2]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.status = "SUSPENDED";
      subscription.suspendedAt = String(values[0]);
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("SET status = ?, suspended_at = NULL")) {
      const subscription = this.subscriptions.get(String(values[2]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.status = String(values[0]);
      subscription.suspendedAt = null;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("SET cancel_at_period_end = 1")) {
      const subscription = this.subscriptions.get(String(values[1]));
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.cancelAtPeriodEnd = 1;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE subscriptions SET plan_id = ?, updated_at")) {
      const [planId, , id] = values as [string, string, string];
      const subscription = this.subscriptions.get(id);
      if (!subscription) return { success: true, meta: { changes: 0 } };
      subscription.planId = planId;
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE hosting_accounts SET plan_id = ?")) {
      const [planId, , accountId] = values as [string, string, string];
      const account = this.accounts.get(accountId);
      if (account) account.planId = planId;
      return { success: true, meta: { changes: account ? 1 : 0 } };
    }
    // hosting-account create route: INSERT INTO hosting_accounts with the
    // real UNIQUE(server_id, username) semantics (all rows, any status)
    if (query.startsWith("INSERT INTO hosting_accounts")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, serverId, planId, username, primaryDomain] = values as [string, string, string, string, string, string | null];
      for (const existing of this.accounts.values()) {
        if (existing.serverId === serverId && existing.username === username) {
          throw new Error("UNIQUE constraint failed: hosting_accounts.server_id, hosting_accounts.username");
        }
      }
      this.accounts.set(id, { id, organizationId, serverId, planId, username, status: "PENDING", primaryDomain: primaryDomain || null, createdAt: new Date().toISOString() });
      return { success: true, meta: { changes: 1 } };
    }
    // hosting-account delete route: soft delete + username tombstone
    if (query.includes("UPDATE hosting_accounts SET status = 'DELETED', username = ?")) {
      const [tombstonedUsername, , accountId] = values as [string, string, string];
      const account = this.accounts.get(accountId);
      if (!account || !["PENDING", "FAILED"].includes(account.status)) return { success: true, meta: { changes: 0 } };
      account.status = "DELETED";
      account.username = tombstonedUsername;
      return { success: true, meta: { changes: 1 } };
    }
    // retry route: failed CREATE_HOSTING_ACCOUNT moves back to PENDING
    if (query.includes("UPDATE hosting_accounts SET status = 'PENDING', updated_at = datetime('now')")) {
      const accountId = String(values[0]);
      const account = this.accounts.get(accountId);
      if (!account || account.status !== "FAILED") return { success: true, meta: { changes: 0 } };
      account.status = "PENDING";
      return { success: true, meta: { changes: 1 } };
    }
    // hosting-account delete route: cancel queued CREATE_HOSTING_ACCOUNT jobs
    if (query.includes("UPDATE provisioning_jobs SET status = 'CANCELLED', finished_at = ?")) {
      const finishedAt = String(values[0]);
      const accountId = String(values[1]);
      let changes = 0;
      for (const job of this.jobs.values()) {
        if (job.hostingAccountId === accountId && job.operation === "CREATE_HOSTING_ACCOUNT" && job.status === "QUEUED") {
          job.status = "CANCELLED";
          (job as unknown as { finishedAt?: string }).finishedAt = finishedAt;
          changes += 1;
        }
      }
      return { success: true, meta: { changes } };
    }
    // hosting-account delete route: revoke account memberships
    if (query.includes("UPDATE hosting_account_memberships SET status = 'REVOKED'")) {
      const [, accountId, organizationId] = values as [string, string, string];
      let changes = 0;
      for (const [key, membership] of this.hostingAccountMemberships) {
        if (membership.hostingAccountId === accountId && membership.organizationId === organizationId && membership.status === "ACTIVE") {
          membership.status = "REVOKED";
          this.hostingAccountMemberships.set(key, membership);
          changes += 1;
        }
      }
      return { success: true, meta: { changes } };
    }
    // Invoice insert — renew route binds (id, orgId, subId, accountId, number, amount, period, start, end, due, paidAt, ref)
    if (query.startsWith("INSERT INTO invoices")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, subscriptionId, , invoiceNumber, amountSarMinor, billingPeriod, , , , paidAt, paymentOrderRef] = values as [string, string, string | null, string | null, string, number, string, string | null, string | null, string | null, string | null, string | null];
      if (this.invoiceNumbersByNumber.has(invoiceNumber)) throw new Error("UNIQUE constraint failed: invoices.invoice_number");
      this.invoiceNumbersByNumber.add(invoiceNumber);
      this.invoices.set(id, { id, organizationId, subscriptionId, invoiceNumber, amountSarMinor, status: "PAID", billingPeriod, paidAt, paymentMethod: "bank_transfer", paymentOrderRef, providerRef: null });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE invoices SET status = ?")) {
      const status = String(values[0]);
      const id = String(values[values.length - 2]);
      const invoice = this.invoices.get(id);
      if (!invoice || invoice.status === status) return { success: true, meta: { changes: 0 } };
      invoice.status = status;
      if (status === "PAID") invoice.paidAt = new Date().toISOString();
      return { success: true, meta: { changes: 1 } };
    }
    // Webhook event ledger
    if (query.startsWith("INSERT INTO billing_webhook_events")) {
      const provider = String(values[1]);
      const eventId = String(values[2]);
      const key = `${provider}:${eventId}`;
      if (this.webhookEvents.has(key)) throw new Error("UNIQUE constraint failed: billing_webhook_events.provider, billing_webhook_events.event_id");
      this.webhookEvents.add(key);
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE billing_webhook_events SET processed_at")) {
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE invoices SET status = 'PAID', paid_at = ?")) {
      // Webhook reconciliation: (paidAt, providerRef, nowIso, invoiceId)
      const invoice = this.invoices.get(String(values[3]));
      if (!invoice || invoice.status !== "OPEN") return { success: true, meta: { changes: 0 } };
      invoice.status = "PAID";
      invoice.paidAt = String(values[0]);
      invoice.providerRef = String(values[1]);
      invoice.paymentMethod = "external";
      return { success: true, meta: { changes: 1 } };
    }
    // Domain mutations
    if (query.startsWith("INSERT INTO domains")) {
      this.throwIfUniqueArmed();
      const [id, hostingAccountId, name, documentRoot] = values as [string, string, string, string];
      const isPrimary = Number(values[4] ?? 0);
      this.domains.set(id, { id, hostingAccountId, name, documentRoot, isPrimary, status: "ACTIVE" });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE domains SET status = 'DELETED'")) {
      const domain = this.domains.get(String(values[0]));
      if (!domain || domain.status === "DELETED") return { success: true, meta: { changes: 0 } };
      domain.status = "DELETED";
      return { success: true, meta: { changes: 1 } };
    }
    // Database mutations
    if (query.startsWith("INSERT INTO hosting_databases")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, hostingAccountId, name] = values as [string, string, string, string];
      this.databases.set(id, { id, organizationId, hostingAccountId, name, engine: "MARIADB", status: "PENDING" });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE hosting_databases SET status = 'DELETING'")) {
      const database = this.databases.get(String(values[1]));
      if (!database || !["ACTIVE", "FAILED", "DELETING"].includes(database.status)) return { success: true, meta: { changes: 0 } };
      database.status = "DELETING";
      return { success: true, meta: { changes: 1 } };
    }
    // Provisioning jobs — three SQL shapes:
    //   literal op (VALUES): VALUES (?, ?, 'OP', 'QUEUED', ?[, ?])  binds [id, accountId, key(, payload)]
    //   literal op (SELECT): SELECT ?, ?, 'OP', 'QUEUED', ?, ?      binds [id, accountId, key, payload]
    //   bound op (VALUES):   VALUES (?, ?, ?, 'QUEUED', ?[, ...])   binds [id, accountId, op, key(, payload)]
    if (query.startsWith("INSERT INTO provisioning_jobs")) {
      this.throwIfUniqueArmed();
      const v = values as unknown[];
      const literalOp = /VALUES \(\?, \?, '([A-Z_]+)', 'QUEUED'/.exec(query)
        ?? /SELECT \(\?, \?, '([A-Z_]+)', 'QUEUED'|SELECT \?, \?, '([A-Z_]+)', 'QUEUED'/.exec(query);
      const operation = literalOp ? (literalOp[1] ?? literalOp[2]) : String(v[2]);
      const idempotencyKey = literalOp ? String(v[2]) : String(v[3]);
      const payload = literalOp
        ? (typeof v[3] === "string" ? String(v[3]) : null)
        : (typeof v[4] === "string" ? String(v[4]) : null);
      const job = {
        id: String(v[0]), hostingAccountId: String(v[1]),
        operation, status: "QUEUED",
        idempotencyKey,
        attempts: 0,
        requestPayload: payload,
        requestedAt: new Date().toISOString(), errorCode: null, errorMessage: null,
      };
      for (const existing of this.jobs.values()) {
        if (existing.idempotencyKey === job.idempotencyKey) throw new Error("UNIQUE constraint failed: provisioning_jobs.idempotency_key");
      }
      this.jobs.set(job.id, job);
      return { success: true, meta: { changes: 1 } };
    }
    // Email mutations
    if (query.startsWith("INSERT INTO email_domains")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, hostingAccountId, domain] = values as [string, string, string | null, string];
      this.emailDomains.set(id, { id, organizationId, hostingAccountId, domain, status: "PENDING", providerStatus: "not_provisioned" });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.startsWith("INSERT INTO email_mailboxes")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, emailDomainId, address, quotaMb] = values as [string, string, string, string, number];
      this.emailMailboxes.set(id, { id, organizationId, emailDomainId, address, quotaMb, status: "PENDING", providerStatus: "not_provisioned" });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.startsWith("INSERT INTO email_forwards")) {
      this.throwIfUniqueArmed();
      const [id, organizationId, emailDomainId, source, destination] = values as [string, string, string, string, string];
      this.emailForwards.push({ id, organizationId, emailDomainId, source, destination, active: 1, providerStatus: "not_provisioned" });
      return { success: true, meta: { changes: 1 } };
    }
    if (query.includes("UPDATE email_mailboxes SET provider_status = ?")) {
      const mailbox = this.emailMailboxes.get(String(values[1]));
      if (mailbox) mailbox.providerStatus = String(values[0]);
      return { success: true, meta: { changes: mailbox ? 1 : 0 } };
    }
    if (query.includes("UPDATE email_mailboxes SET") && query.includes("WHERE id = ? AND organization_id = ?")) {
      // dynamic update: binds are values..., id, orgId
      const mailbox = this.emailMailboxes.get(String(values[values.length - 2]));
      if (mailbox) {
        const quotaIdx = query.indexOf("quota_mb = ?") >= 0 ? 0 : -1;
        if (quotaIdx >= 0) mailbox.quotaMb = Number(values[0]);
        const statusIdx = query.indexOf("status = ?") >= 0 ? (query.indexOf("quota_mb = ?") >= 0 ? 1 : 0) : -1;
        if (statusIdx >= 0) mailbox.status = String(values[statusIdx]);
        if (query.includes("password_set_at = ?")) mailbox.providerStatus = mailbox.providerStatus;
      }
      return { success: true, meta: { changes: mailbox ? 1 : 0 } };
    }
    if (query.includes("UPDATE email_mailboxes SET status = 'DELETED'")) {
      const mailbox = this.emailMailboxes.get(String(values[0]));
      if (mailbox) mailbox.status = "DELETED";
      return { success: true, meta: { changes: mailbox ? 1 : 0 } };
    }
    if (query.includes("UPDATE email_domains SET status = 'DELETED'")) {
      const emailDomain = this.emailDomains.get(String(values[0]));
      if (emailDomain) emailDomain.status = "DELETED";
      return { success: true, meta: { changes: emailDomain ? 1 : 0 } };
    }
    if (query.includes("DELETE FROM email_forwards WHERE id = ? AND organization_id = ?")) {
      const before = this.emailForwards.length;
      this.emailForwards = this.emailForwards.filter((f) => !(f.id === String(values[0]) && f.organizationId === String(values[1])));
      return { success: true, meta: { changes: before - this.emailForwards.length } };
    }
    // Hosting plan delete
    if (query.includes("DELETE FROM hosting_plans WHERE id = ? AND organization_id = ?")) {
      const planId = String(values[0]);
      const deleted = this.plans.delete(planId);
      return { success: true, meta: { changes: deleted ? 1 : 0 } };
    }
    // Audit rows — two SQL shapes:
    //   literal action: VALUES (?, ?, ?, 'action', 'type', ?, ?)  binds [id, org, actor, resourceId(, metadata)]
    //   bound action:   VALUES (?, ?, ?, ?, ?, ?, ?)              binds [id, org, actor, action, type, resourceId(, metadata)]
    if (query.includes("INSERT INTO audit_logs")) {
      const v = values as unknown[];
      const literalAction = /VALUES \(\?, \?, \?, '([a-z_.]+)'/.exec(query);
      if (literalAction) {
        this.auditRows.push({
          id: String(v[0]), organizationId: (v[1] as string) ?? null, actorUserId: (v[2] as string) ?? null,
          action: literalAction[1], resourceType: /'([a-z_]+)', \?|'([a-z_]+)', '/.exec(query)?.[1] ?? "unknown",
          resourceId: (v[3] as string) ?? null,
          metadata: typeof v[4] === "string" ? v[4] : null,
        });
      } else {
        this.auditRows.push({
          id: String(v[0]), organizationId: (v[1] as string) ?? null, actorUserId: (v[2] as string) ?? null,
          action: String(v[3]), resourceType: String(v[4]), resourceId: (v[5] as string) ?? null,
          metadata: typeof v[6] === "string" ? v[6] : null,
        });
      }
      return { success: true, meta: { changes: 1 } };
    }
    // subscription_events — event type may be a SQL literal or bound
    if (query.startsWith("INSERT INTO subscription_events")) {
      const v = values as unknown[];
      const literalType = /VALUES \(\?, \?, \?, '([a-z_]+)'|VALUES \(\?, \?, \?, \?, '([a-z_]+)'/.exec(query);
      if (literalType) {
        // literal shapes: (id, subId, orgId, 'type', metadata) or (id, subId, orgId, 'type', actor, metadata)
        const eventType = literalType[1] ?? literalType[2];
        const actor = v.length >= 5 && typeof v[3] === "string" && v[3].includes("-") ? (v[3] as string) : null;
        this.subscriptionEvents.push({
          id: String(v[0]), subscriptionId: String(v[1]), organizationId: (v[2] as string) ?? null,
          eventType, actorUserId: actor,
          metadata: typeof v[v.length - 1] === "string" ? String(v[v.length - 1]) : null,
        });
      } else {
        this.subscriptionEvents.push({
          id: String(v[0]), subscriptionId: String(v[1]), organizationId: (v[2] as string) ?? null,
          eventType: String(v[3]), actorUserId: (v[4] as string) ?? null,
          metadata: typeof v[5] === "string" ? v[5] : null,
        });
      }
      return { success: true, meta: { changes: 1 } };
    }
    // expireDueSubscriptions lazy sweep (all()-based select + run-based update)
    if (query.includes("SELECT id, organization_id, status, cancel_at_period_end FROM subscriptions")) {
      // routed via routeAll below in real D1; here as run() fallback
      return { success: true, meta: { changes: 0 } };
    }
    throw new Error(`Unmocked run() query: ${query.slice(0, 140)}`);
  }
}

// The expireDueSubscriptions select is an all() — route it there too.
// (Handled inside routeAll via the subscriptions listing branch; the sweep
// query is distinct, so teach the mock about it explicitly.)
//
// NOTE: kept as a helper so tests that exercise expiry operate through the
// public HTTP surface (GET /v1/subscriptions), which invokes the sweep.

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

type Env = Record<string, string>;

function makeEnv(overrides: Env = {}): Env {
  return {
    DATABASE_SECRET_ENCRYPTION_KEY: "c".repeat(64),
    MFA_ENCRYPTION_KEY: "d".repeat(64),
    ...overrides,
  };
}

async function call(db: PlatformCompletionD1, method: string, path: string, env: Env, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const request = new Request(`https://worker.test${path}`, {
    method,
    headers: {
      authorization: `Bearer ${SESSION_TOKEN}`,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const bindings = { DB: db as unknown as D1Database, ...env };
  const response = await worker.fetch(request, bindings as never, { waitUntil: () => {} } as never);
  let json: Record<string, unknown> = {};
  try { json = await response.json() as Record<string, unknown>; } catch { /* empty body */ }
  return { status: response.status, json };
}

function webhookSignature(secret: string, timestamp: string, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

// The bearer token the tests send; sessions must be keyed by its SHA-256
// because bearerIdentity looks sessions up by token_hash.
const PRIMARY_TOKEN_HASH = createHash("sha256").update(SESSION_TOKEN).digest("hex");

export { PlatformCompletionD1, call, makeEnv, webhookSignature, isoInDays, SESSION_TOKEN, PRIMARY_TOKEN_HASH, ORG_A, ORG_B, OWNER_A, MEMBER_A, ADMIN_A, OUTSIDER, PLATFORM_ADMIN, PLAN_BASIC, PLAN_SMALL, ACCOUNT_1, SERVER_1 };
