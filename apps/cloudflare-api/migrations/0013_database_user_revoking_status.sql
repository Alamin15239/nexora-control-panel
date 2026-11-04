-- Rebuild the database-user table to permit the transitional REVOKING state.
-- Preserve encrypted one-time credentials while rebuilding the parent table.
CREATE TABLE hosting_database_users_new (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  database_id TEXT NOT NULL REFERENCES hosting_databases(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  privileges TEXT NOT NULL CHECK (json_valid(privileges)),
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'FAILED', 'REVOKING', 'REVOKED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (database_id, username)
);
INSERT INTO hosting_database_users_new (id, organization_id, database_id, username, privileges, status, created_at)
SELECT id, organization_id, database_id, username, privileges, status, created_at
FROM hosting_database_users;

CREATE TABLE database_user_secrets_backup AS
SELECT database_user_id, organization_id, ciphertext, iv, expires_at, revealed_at, created_at
FROM database_user_secrets;

DROP TABLE database_user_secrets;
DROP TABLE hosting_database_users;
ALTER TABLE hosting_database_users_new RENAME TO hosting_database_users;

CREATE INDEX hosting_database_users_org_idx ON hosting_database_users(organization_id, database_id);

CREATE TABLE database_user_secrets (
  database_user_id TEXT PRIMARY KEY NOT NULL REFERENCES hosting_database_users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revealed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO database_user_secrets (database_user_id, organization_id, ciphertext, iv, expires_at, revealed_at, created_at)
SELECT database_user_id, organization_id, ciphertext, iv, expires_at, revealed_at, created_at
FROM database_user_secrets_backup;
DROP TABLE database_user_secrets_backup;
CREATE INDEX database_user_secrets_expiry_idx ON database_user_secrets(expires_at, revealed_at);
