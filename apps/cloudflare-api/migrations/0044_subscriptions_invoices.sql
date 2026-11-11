-- Subscription lifecycle, invoices, and auditable billing events.
--
-- Background:
--   The platform previously supported only manual bank-transfer payment
--   orders (0033_manual_bank_transfer_checkout.sql). There was no durable
--   subscription record, so renewals, expirations, suspensions, plan
--   changes, and invoicing had nothing to attach to.
--
-- This migration adds:
--
--   subscriptions        One row per hosted service under contract. The
--                        lifecycle is TRIALING -> ACTIVE -> (PAST_DUE) ->
--                        (SUSPENDED) -> EXPIRED | CANCELLED, with
--                        cancel_at_period_end for graceful cancellation.
--                        A partial UNIQUE index guarantees at most one
--                        live subscription per hosting account.
--
--   subscription_events  Append-only audit trail of every subscription
--                        transition (created, renewed, plan_changed,
--                        suspended, reactivated, cancelled, expired).
--
--   invoices             Billing documents. Amounts are minor units
--                        (SAR halalas) to match payment_orders. Invoice
--                        numbers are sequential per organization via a
--                        per-org counter table to avoid scan-and-max
--                        races. UNIQUE payment_order_ref and
--                        provider_event refs make invoice creation and
--                        webhook reconciliation idempotent.
--
--   billing_webhook_events  Deduplication ledger for payment-provider
--                        webhooks. UNIQUE(provider, event_id) ensures a
--                        replayed or re-delivered webhook is processed at
--                        most once.
--
-- No existing tables are modified and no data is migrated, so this is
-- safe to apply on both fresh and existing databases.

CREATE TABLE subscriptions (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  hosting_account_id TEXT REFERENCES hosting_accounts(id) ON DELETE SET NULL,
  plan_id TEXT NOT NULL REFERENCES hosting_plans(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'TRIALING' CHECK (status IN (
    'TRIALING','ACTIVE','PAST_DUE','SUSPENDED','CANCELLED','EXPIRED'
  )),
  billing_period TEXT NOT NULL DEFAULT 'monthly' CHECK (billing_period IN ('monthly','yearly')),
  provider TEXT NOT NULL DEFAULT 'manual' CHECK (provider IN ('manual','bank_transfer','external')),
  amount_sar_minor INTEGER,
  current_period_start TEXT,
  current_period_end TEXT,
  trial_end TEXT,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK (cancel_at_period_end IN (0,1)),
  cancelled_at TEXT,
  suspended_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX subscriptions_org_status_idx ON subscriptions(organization_id, status);
CREATE INDEX subscriptions_period_end_idx ON subscriptions(status, current_period_end);
CREATE UNIQUE INDEX subscriptions_one_live_per_account_idx
  ON subscriptions(hosting_account_id)
  WHERE hosting_account_id IS NOT NULL AND status IN ('TRIALING','ACTIVE','PAST_DUE','SUSPENDED');

CREATE TABLE subscription_events (
  id TEXT PRIMARY KEY NOT NULL,
  subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'created','renewed','plan_changed','suspended','reactivated',
    'cancel_scheduled','cancel_cancelled','cancelled','expired','payment_recorded'
  )),
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  metadata TEXT CHECK (metadata IS NULL OR json_valid(metadata)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX subscription_events_sub_idx ON subscription_events(subscription_id, created_at);

CREATE TABLE invoice_counters (
  organization_id TEXT PRIMARY KEY NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  last_number INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE invoices (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  subscription_id TEXT REFERENCES subscriptions(id) ON DELETE SET NULL,
  hosting_account_id TEXT REFERENCES hosting_accounts(id) ON DELETE SET NULL,
  invoice_number TEXT NOT NULL UNIQUE,
  amount_sar_minor INTEGER NOT NULL CHECK (amount_sar_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'SAR',
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','PAID','VOID','UNCOLLECTIBLE')),
  billing_period TEXT NOT NULL DEFAULT 'monthly' CHECK (billing_period IN ('monthly','yearly')),
  period_start TEXT,
  period_end TEXT,
  due_date TEXT,
  paid_at TEXT,
  payment_method TEXT CHECK (payment_method IS NULL OR payment_method IN ('bank_transfer','external','manual')),
  payment_order_id TEXT REFERENCES payment_orders(id) ON DELETE SET NULL,
  payment_order_ref TEXT UNIQUE,
  provider_ref TEXT UNIQUE,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX invoices_org_created_idx ON invoices(organization_id, created_at DESC);
CREATE INDEX invoices_subscription_idx ON invoices(subscription_id, created_at DESC);
CREATE INDEX invoices_status_idx ON invoices(status, created_at DESC);

CREATE TABLE billing_webhook_events (
  id TEXT PRIMARY KEY NOT NULL,
  provider TEXT NOT NULL,
  event_id TEXT NOT NULL,
  payload_digest TEXT,
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  processed_at TEXT,
  UNIQUE (provider, event_id)
);
