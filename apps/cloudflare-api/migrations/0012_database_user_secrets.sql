CREATE TABLE database_user_secrets (
  database_user_id TEXT PRIMARY KEY NOT NULL REFERENCES hosting_database_users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revealed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX database_user_secrets_expiry_idx ON database_user_secrets(expires_at, revealed_at);
