-- Bind a GitHub App installation to the Nexora organization after verifying
-- the signed GitHub setup callback. OAuth credentials remain separately stored.
ALTER TABLE github_connections ADD COLUMN github_installation_id TEXT;
ALTER TABLE github_connections ADD COLUMN github_installation_account TEXT;
ALTER TABLE github_connections ADD COLUMN github_installation_account_type TEXT;

CREATE TABLE github_installation_states (
  state_hash TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_github_installation_states_expiry
  ON github_installation_states(expires_at, consumed_at);
