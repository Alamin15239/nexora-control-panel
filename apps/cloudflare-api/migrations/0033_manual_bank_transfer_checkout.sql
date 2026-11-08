-- Manual bank-transfer checkout and platform-owned public hosting catalogue.
PRAGMA foreign_keys = ON;

ALTER TABLE hosting_plans ADD COLUMN price_sar_minor INTEGER;
ALTER TABLE hosting_plans ADD COLUMN billing_period TEXT NOT NULL DEFAULT 'monthly'
  CHECK (billing_period IN ('monthly','yearly'));
ALTER TABLE hosting_plans ADD COLUMN public_enabled INTEGER NOT NULL DEFAULT 0
  CHECK (public_enabled IN (0,1));

CREATE TABLE payment_settings (
  organization_id TEXT PRIMARY KEY NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  bank_name TEXT,
  account_holder TEXT,
  iban TEXT,
  payment_instructions TEXT,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE payment_orders (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_id TEXT NOT NULL REFERENCES hosting_plans(id) ON DELETE RESTRICT,
  order_reference TEXT NOT NULL UNIQUE,
  plan_name TEXT NOT NULL,
  amount_sar_minor INTEGER NOT NULL CHECK (amount_sar_minor > 0),
  billing_period TEXT NOT NULL CHECK (billing_period IN ('monthly','yearly')),
  desired_username TEXT NOT NULL,
  primary_domain TEXT,
  status TEXT NOT NULL DEFAULT 'AWAITING_PAYMENT' CHECK (status IN (
    'AWAITING_PAYMENT','RECEIPT_SUBMITTED','UNDER_REVIEW','APPROVED','REJECTED',
    'PROVISIONING','ACTIVE','PROVISIONING_FAILED','CANCELLED'
  )),
  transfer_reference TEXT,
  receipt_key TEXT,
  receipt_content_type TEXT,
  receipt_size INTEGER,
  reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TEXT,
  review_note TEXT,
  hosting_account_id TEXT REFERENCES hosting_accounts(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX payment_orders_customer_idx ON payment_orders(organization_id,user_id,created_at DESC);
CREATE INDEX payment_orders_status_idx ON payment_orders(status,created_at DESC);
