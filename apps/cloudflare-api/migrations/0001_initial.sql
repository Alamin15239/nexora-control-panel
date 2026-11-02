PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT,
  display_name TEXT,
  status TEXT NOT NULL DEFAULT 'INVITED' CHECK (status IN ('ACTIVE', 'INVITED', 'SUSPENDED')),
  mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE organizations (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE memberships (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'MEMBER' CHECK (role IN ('OWNER', 'ADMIN', 'BILLING', 'SUPPORT', 'MEMBER')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (user_id, organization_id)
);
CREATE INDEX memberships_org_role_idx ON memberships(organization_id, role);

CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_id TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX auth_sessions_user_state_idx ON auth_sessions(user_id, revoked_at, expires_at);

CREATE TABLE login_attempts (
  id TEXT PRIMARY KEY NOT NULL,
  bucket_key TEXT NOT NULL UNIQUE,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  window_start TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  blocked_until TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX login_attempts_blocked_idx ON login_attempts(blocked_until);

CREATE TABLE servers (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  primary_ip TEXT NOT NULL,
  region TEXT,
  agent_version TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ONLINE', 'DEGRADED', 'OFFLINE', 'MAINTENANCE')),
  last_heartbeat_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX servers_org_status_idx ON servers(organization_id, status);
CREATE INDEX servers_status_heartbeat_idx ON servers(status, last_heartbeat_at);

CREATE TABLE agent_enrollments (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL UNIQUE REFERENCES servers(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX agent_enrollments_org_expiry_idx ON agent_enrollments(organization_id, expires_at);
CREATE INDEX agent_enrollments_expiry_consumed_idx ON agent_enrollments(expires_at, consumed_at);

CREATE TABLE server_telemetry (
  id TEXT PRIMARY KEY NOT NULL,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  agent_version TEXT NOT NULL,
  cpu_usage_percent REAL,
  memory_total_bytes INTEGER,
  memory_used_bytes INTEGER,
  disk_total_bytes INTEGER,
  disk_used_bytes INTEGER,
  load_average_1m REAL,
  collected_at TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX server_telemetry_server_collected_idx ON server_telemetry(server_id, collected_at);
CREATE INDEX server_telemetry_received_idx ON server_telemetry(received_at);

CREATE TABLE hosting_plans (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  disk_limit_bytes INTEGER NOT NULL,
  bandwidth_limit_bytes INTEGER,
  website_limit INTEGER NOT NULL DEFAULT 1,
  database_limit INTEGER NOT NULL DEFAULT 1,
  mailbox_limit INTEGER NOT NULL DEFAULT 0,
  cpu_quota_percent INTEGER,
  memory_limit_bytes INTEGER,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (organization_id, name)
);
CREATE INDEX hosting_plans_org_active_idx ON hosting_plans(organization_id, active);

CREATE TABLE hosting_accounts (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
  plan_id TEXT NOT NULL REFERENCES hosting_plans(id) ON DELETE RESTRICT,
  username TEXT NOT NULL,
  primary_domain TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'FAILED', 'DELETING', 'DELETED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (server_id, username)
);
CREATE INDEX hosting_accounts_org_status_idx ON hosting_accounts(organization_id, status);
CREATE INDEX hosting_accounts_server_status_idx ON hosting_accounts(server_id, status);

CREATE TABLE domains (
  id TEXT PRIMARY KEY NOT NULL,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL UNIQUE,
  document_root TEXT NOT NULL,
  is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX domains_account_idx ON domains(hosting_account_id);

CREATE TABLE provisioning_jobs (
  id TEXT PRIMARY KEY NOT NULL,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE RESTRICT,
  operation TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
  idempotency_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  started_at TEXT,
  finished_at TEXT,
  error_code TEXT,
  error_message TEXT
);
CREATE INDEX provisioning_jobs_status_requested_idx ON provisioning_jobs(status, requested_at);
CREATE INDEX provisioning_jobs_account_requested_idx ON provisioning_jobs(hosting_account_id, requested_at);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  source_ip TEXT,
  metadata TEXT CHECK (metadata IS NULL OR json_valid(metadata)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX audit_logs_org_created_idx ON audit_logs(organization_id, created_at);
CREATE INDEX audit_logs_actor_created_idx ON audit_logs(actor_user_id, created_at);
