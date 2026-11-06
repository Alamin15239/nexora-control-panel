-- GitHub repository integrations and immutable deployment history.
-- Access tokens are encrypted by the API before storage; never store plaintext tokens.

CREATE TABLE IF NOT EXISTS github_connections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  github_user_id TEXT NOT NULL,
  github_login TEXT NOT NULL,
  encrypted_access_token TEXT NOT NULL,
  access_token_iv TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS github_oauth_states (
  state_hash TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_states_expiry ON github_oauth_states(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS github_projects (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  github_connection_id TEXT NOT NULL REFERENCES github_connections(id) ON DELETE CASCADE,
  github_repository_id TEXT NOT NULL,
  repository_full_name TEXT NOT NULL,
  production_branch TEXT NOT NULL DEFAULT 'main',
  root_directory TEXT NOT NULL DEFAULT '.',
  install_command TEXT,
  build_command TEXT,
  output_directory TEXT NOT NULL DEFAULT 'dist',
  framework TEXT NOT NULL DEFAULT 'auto',
  auto_deploy INTEGER NOT NULL DEFAULT 1 CHECK (auto_deploy IN (0, 1)),
  webhook_id TEXT,
  webhook_secret_hash TEXT,
  status TEXT NOT NULL DEFAULT 'configured' CHECK (status IN ('configured', 'building', 'ready', 'failed', 'paused')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(hosting_account_id),
  UNIQUE(github_repository_id, hosting_account_id)
);

CREATE INDEX IF NOT EXISTS idx_github_projects_org ON github_projects(organization_id, created_at);

CREATE TABLE IF NOT EXISTS github_deployments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  branch TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('manual', 'push', 'rollback')),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'cloning', 'installing', 'building', 'publishing', 'succeeded', 'failed', 'cancelled')),
  commit_message TEXT,
  deployment_url TEXT,
  log_excerpt TEXT,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  started_at TEXT,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_github_deployments_project ON github_deployments(project_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_github_deployments_queue ON github_deployments(status, requested_at);
