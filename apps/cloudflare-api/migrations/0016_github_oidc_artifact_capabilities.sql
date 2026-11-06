-- One-time, short-lived GitHub Actions artifact upload capabilities.
-- Only SHA-256 token hashes are stored; raw capabilities are returned once.
CREATE TABLE IF NOT EXISTS github_deployment_upload_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  deployment_id TEXT NOT NULL UNIQUE REFERENCES github_deployments(id) ON DELETE CASCADE,
  repository_id TEXT NOT NULL,
  branch TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  run_id TEXT NOT NULL,
  run_attempt INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(run_id, run_attempt)
);
CREATE INDEX IF NOT EXISTS idx_github_deployment_upload_tokens_expiry
ON github_deployment_upload_tokens(expires_at, consumed_at);
ALTER TABLE github_deployments ADD COLUMN workflow_run_id TEXT;
ALTER TABLE github_deployments ADD COLUMN workflow_run_attempt INTEGER;
ALTER TABLE github_deployments ADD COLUMN workflow_sha TEXT;
