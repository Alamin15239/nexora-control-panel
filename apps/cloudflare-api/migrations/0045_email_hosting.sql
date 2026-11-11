-- Email hosting inventory: domains, mailboxes, and forwarding rules.
--
-- Background:
--   The platform previously had only OUTBOUND notification email via the
--   Resend API (password reset, verification, incidents). Actual hosted
--   mailboxes (IMAP/SMTP) require an external mail server. This migration
--   adds the local inventory and desired-state records so the control
--   panel can manage email domains, mailboxes, quotas, and forwards —
--   while provisioning honesty is enforced in the API layer: without a
--   configured mail provider, mutations of provisioning state are refused
--   (503) and inventory rows stay clearly marked as not provisioned.
--
--   A separate provider_status column records what the control panel
--   actually knows: 'not_provisioned' until a provider confirms otherwise.
--
-- No existing tables are modified; safe on fresh and existing databases.

CREATE TABLE email_domains (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hosting_account_id TEXT REFERENCES hosting_accounts(id) ON DELETE SET NULL,
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','FAILED','DELETING','DELETED')),
  provider_status TEXT NOT NULL DEFAULT 'not_provisioned' CHECK (provider_status IN ('not_provisioned','provisioning','provisioned','failed')),
  dns_guidance TEXT CHECK (dns_guidance IS NULL OR json_valid(dns_guidance)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (organization_id, domain)
);
CREATE INDEX email_domains_org_idx ON email_domains(organization_id, status);

CREATE TABLE email_mailboxes (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email_domain_id TEXT NOT NULL REFERENCES email_domains(id) ON DELETE CASCADE,
  address TEXT NOT NULL UNIQUE,
  quota_mb INTEGER NOT NULL DEFAULT 1024 CHECK (quota_mb BETWEEN 128 AND 51200),
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','DELETING','DELETED')),
  provider_status TEXT NOT NULL DEFAULT 'not_provisioned' CHECK (provider_status IN ('not_provisioned','provisioning','provisioned','failed')),
  password_set_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX email_mailboxes_domain_idx ON email_mailboxes(email_domain_id, status);

CREATE TABLE email_forwards (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email_domain_id TEXT NOT NULL REFERENCES email_domains(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  provider_status TEXT NOT NULL DEFAULT 'not_provisioned' CHECK (provider_status IN ('not_provisioned','provisioning','provisioned','failed')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (email_domain_id, source, destination)
);
CREATE INDEX email_forwards_domain_idx ON email_forwards(email_domain_id, active);
