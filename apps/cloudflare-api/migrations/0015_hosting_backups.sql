PRAGMA foreign_keys = ON;

CREATE TABLE hosting_backups (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE RESTRICT,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'QUEUED'
    CHECK (status IN ('QUEUED', 'RUNNING', 'AVAILABLE', 'FAILED', 'RESTORING', 'RESTORE_STAGED', 'DELETING')),
  archive_name TEXT,
  size_bytes INTEGER,
  sha256 TEXT,
  database_names_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(database_names_json)),
  error_message TEXT,
  requested_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  completed_at TEXT,
  staged_at TEXT
);

CREATE INDEX hosting_backups_account_created_idx
  ON hosting_backups(hosting_account_id, created_at DESC);

CREATE INDEX hosting_backups_org_status_idx
  ON hosting_backups(organization_id, status);
