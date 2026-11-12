-- Deploy platform foundation (Nexora Deploy batches 3-4).
--
-- Adds the schema the Vercel-class deployment platform needs on top of the
-- existing github_projects / github_deployments tables:
--
--   * deployment_kind on github_deployments distinguishes production deploys
--     from preview (branch/PR) deploys; source_deployment_id links a preview
--     deployment to the production deployment it forks state from.
--   * github_projects gains preview toggling, ignored build paths (docs-only
--     pushes do not deploy), and the encrypted webhook secret used to verify
--     GitHub push/PR webhook signatures.
--   * application_env_vars stores per-project environment variables encrypted
--     at rest with AES-GCM under DEPLOY_ENV_ENCRYPTION_KEY (a key that is
--     independent from GITHUB_TOKEN_ENCRYPTION_KEY so credentials can be
--     rotated separately). Values are never returned by the API; responses
--     expose metadata only.
--   * application_deployment_aliases maps stable hostnames (production and
--     per-deployment preview URLs) to releases; promotion re-points the
--     alias, rollback re-points it back — no rebuild required.
--   * github_webhook_deliveries records every push/PR webhook outcome
--     (including skips and rejections) with redacted detail, making the
--     auto-deploy decision auditable and webhooks idempotent by delivery id.

ALTER TABLE github_deployments ADD COLUMN deployment_kind TEXT NOT NULL DEFAULT 'production';
ALTER TABLE github_deployments ADD COLUMN actions_run_id TEXT;
ALTER TABLE github_deployments ADD COLUMN actions_run_attempt INTEGER;
ALTER TABLE github_deployments ADD COLUMN source_deployment_id TEXT REFERENCES github_deployments(id) ON DELETE SET NULL;

CREATE INDEX idx_github_deployments_kind ON github_deployments(project_id, deployment_kind, requested_at);

ALTER TABLE github_projects ADD COLUMN preview_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_projects ADD COLUMN ignored_build_paths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE github_projects ADD COLUMN webhook_secret_encrypted TEXT;
ALTER TABLE github_projects ADD COLUMN webhook_secret_iv TEXT;

CREATE TABLE application_env_vars (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL CHECK (
    length(key_name) >= 1 AND length(key_name) <= 128
    AND key_name GLOB '[A-Za-z_]*'
    AND key_name NOT GLOB '*[^A-Za-z0-9_]*'
  ),
  environment TEXT NOT NULL CHECK (environment IN ('production', 'preview', 'development')),
  target TEXT NOT NULL DEFAULT 'runtime' CHECK (target IN ('build', 'runtime', 'both')),
  encrypted_value TEXT NOT NULL,
  value_iv TEXT NOT NULL,
  is_secret INTEGER NOT NULL DEFAULT 1 CHECK (is_secret IN (0, 1)),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (project_id, key_name, environment)
);

CREATE INDEX idx_application_env_vars_project ON application_env_vars(project_id, environment);

-- Tenant guard: a variable row must always belong to the same organization
-- as the project it decorates.
CREATE TRIGGER application_env_vars_org_insert_guard
BEFORE INSERT ON application_env_vars
WHEN NEW.organization_id != (SELECT organization_id FROM github_projects WHERE id = NEW.project_id)
BEGIN
  SELECT RAISE(ABORT, 'environment variable organization must match the linked project');
END;

CREATE TRIGGER application_env_vars_org_update_guard
BEFORE UPDATE OF organization_id, project_id ON application_env_vars
WHEN NEW.organization_id != (SELECT organization_id FROM github_projects WHERE id = NEW.project_id)
BEGIN
  SELECT RAISE(ABORT, 'environment variable organization must match the linked project');
END;

CREATE TABLE application_deployment_aliases (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  alias TEXT NOT NULL CHECK (
    length(alias) >= 3 AND length(alias) <= 253 AND alias = lower(alias)
    AND alias NOT GLOB '*[^a-z0-9.-]*' AND alias NOT GLOB '.*' AND alias NOT GLOB '*.'
  ),
  kind TEXT NOT NULL CHECK (kind IN ('preview', 'production')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'error')),
  release_id TEXT REFERENCES application_releases(id) ON DELETE SET NULL,
  deployment_id TEXT REFERENCES github_deployments(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (alias, kind),
  UNIQUE (deployment_id, kind)
);

CREATE INDEX idx_application_deployment_aliases_project ON application_deployment_aliases(project_id, kind);

CREATE TRIGGER application_deployment_aliases_org_insert_guard
BEFORE INSERT ON application_deployment_aliases
WHEN NEW.organization_id != (SELECT organization_id FROM github_projects WHERE id = NEW.project_id)
BEGIN
  SELECT RAISE(ABORT, 'deployment alias organization must match the linked project');
END;

CREATE TRIGGER application_deployment_aliases_org_update_guard
BEFORE UPDATE OF organization_id, project_id ON application_deployment_aliases
WHEN NEW.organization_id != (SELECT organization_id FROM github_projects WHERE id = NEW.project_id)
BEGIN
  SELECT RAISE(ABORT, 'deployment alias organization must match the linked project');
END;

CREATE TABLE github_webhook_deliveries (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id TEXT NOT NULL,
  delivery_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  branch TEXT,
  commit_sha TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN (
    'dispatched',
    'skipped_auto_deploy_disabled',
    'skipped_branch_mismatch',
    'skipped_branch_deleted',
    'skipped_ignored_paths',
    'skipped_commit_message',
    'skipped_in_flight',
    'skipped_replay',
    'skipped_preview_disabled',
    'skipped_pull_request_closed',
    'skipped_untracked_repository',
    'rejected_signature',
    'rejected_payload',
    'error'
  )),
  detail_redacted TEXT,
  received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_github_webhook_deliveries_repo ON github_webhook_deliveries(repository_id, received_at DESC);
