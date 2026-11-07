-- Multi-runtime application deployment control-plane schema.
-- Metadata only: this migration does not create compute nodes or enable publishing.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS application_runtime_profiles (
  id TEXT PRIMARY KEY,
  runtime_family TEXT NOT NULL CHECK (runtime_family IN (
    'static','nodejs','php','python','go','java','dotnet','ruby','container'
  )),
  profile_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  profile_version INTEGER NOT NULL DEFAULT 1 CHECK (profile_version > 0),
  execution_kind TEXT NOT NULL CHECK (execution_kind IN ('static','managed','oci')),
  default_port INTEGER CHECK (default_port BETWEEN 1 AND 65535),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS application_node_pools (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  environment TEXT NOT NULL CHECK (environment IN ('development','staging','production')),
  region TEXT NOT NULL,
  runtime_engine TEXT NOT NULL CHECK (runtime_engine IN ('containerd','microvm','static')),
  status TEXT NOT NULL DEFAULT 'provisioning' CHECK (status IN ('provisioning','ready','draining','disabled','failed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS application_nodes (
  id TEXT PRIMARY KEY,
  node_pool_id TEXT NOT NULL REFERENCES application_node_pools(id) ON DELETE RESTRICT,
  node_identity TEXT NOT NULL UNIQUE,
  enrollment_key_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','online','offline','draining','revoked')),
  agent_version TEXT,
  last_heartbeat_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_application_nodes_pool_status
ON application_nodes(node_pool_id, status, last_heartbeat_at);

CREATE TABLE IF NOT EXISTS application_project_settings (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL UNIQUE REFERENCES github_projects(id) ON DELETE CASCADE,
  runtime_profile_id TEXT REFERENCES application_runtime_profiles(id) ON DELETE RESTRICT,
  spec_version INTEGER NOT NULL DEFAULT 1 CHECK (spec_version > 0),
  build_method TEXT NOT NULL DEFAULT 'managed' CHECK (build_method IN ('static','managed','dockerfile')),
  build_context TEXT NOT NULL DEFAULT '.',
  build_command TEXT,
  output_directory TEXT,
  start_command TEXT,
  listen_port INTEGER CHECK (listen_port BETWEEN 1 AND 65535),
  health_check_path TEXT,
  cpu_millis INTEGER NOT NULL DEFAULT 500 CHECK (cpu_millis BETWEEN 100 AND 64000),
  memory_mib INTEGER NOT NULL DEFAULT 512 CHECK (memory_mib BETWEEN 128 AND 131072),
  disk_mib INTEGER NOT NULL DEFAULT 2048 CHECK (disk_mib BETWEEN 128 AND 1048576),
  process_limit INTEGER NOT NULL DEFAULT 128 CHECK (process_limit BETWEEN 16 AND 4096),
  spec_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(organization_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_application_project_settings_org
ON application_project_settings(organization_id, updated_at);

CREATE TABLE IF NOT EXISTS application_releases (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  deployment_id TEXT NOT NULL UNIQUE REFERENCES github_deployments(id) ON DELETE CASCADE,
  node_pool_id TEXT REFERENCES application_node_pools(id) ON DELETE RESTRICT,
  runtime_profile_id TEXT REFERENCES application_runtime_profiles(id) ON DELETE RESTRICT,
  spec_version INTEGER NOT NULL CHECK (spec_version > 0),
  state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN (
    'queued','authorized','building','artifact_uploaded','validating',
    'ready_to_publish','publishing','health_checking','succeeded',
    'failed','cancelled','rolled_back'
  )),
  source_commit_sha TEXT NOT NULL CHECK (length(source_commit_sha) = 40),
  artifact_digest TEXT,
  artifact_bytes INTEGER CHECK (artifact_bytes IS NULL OR artifact_bytes BETWEEN 1 AND 1073741824),
  image_digest TEXT,
  deployment_url TEXT,
  failure_code TEXT,
  failure_message_redacted TEXT,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_application_releases_org_project
ON application_releases(organization_id, project_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_application_releases_state
ON application_releases(state, requested_at);

CREATE TABLE IF NOT EXISTS application_release_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  release_id TEXT NOT NULL REFERENCES application_releases(id) ON DELETE CASCADE,
  from_state TEXT,
  to_state TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user','control_plane','builder','node','system')),
  actor_id TEXT,
  event_code TEXT NOT NULL,
  details_redacted_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_application_release_events_release
ON application_release_events(organization_id, release_id, created_at);

CREATE TABLE IF NOT EXISTS application_workloads (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  active_release_id TEXT REFERENCES application_releases(id) ON DELETE SET NULL,
  node_id TEXT REFERENCES application_nodes(id) ON DELETE RESTRICT,
  workload_kind TEXT NOT NULL CHECK (workload_kind IN ('web','worker','scheduled')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','starting','healthy','unhealthy','stopped','failed')),
  desired_replicas INTEGER NOT NULL DEFAULT 1 CHECK (desired_replicas BETWEEN 0 AND 100),
  observed_replicas INTEGER NOT NULL DEFAULT 0 CHECK (observed_replicas BETWEEN 0 AND 100),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(organization_id, project_id, workload_kind)
);

CREATE INDEX IF NOT EXISTS idx_application_workloads_org_status
ON application_workloads(organization_id, status);

-- Seed profiles are catalog entries only. Disabled until a runtime has passed its
-- build, isolation, ingress, observability and rollback acceptance tests.
INSERT OR IGNORE INTO application_runtime_profiles
(id, runtime_family, profile_key, display_name, execution_kind, default_port, enabled)
VALUES
('runtime-static-v1','static','static-v1','Static website','static',NULL,0),
('runtime-nodejs-v1','nodejs','nodejs-v1','Node.js application','oci',3000,0),
('runtime-php-v1','php','php-v1','PHP-FPM application','oci',8080,0),
('runtime-python-v1','python','python-v1','Python web application','oci',8000,0),
('runtime-go-v1','go','go-v1','Go web application','oci',8080,0),
('runtime-java-v1','java','java-v1','Java web application','oci',8080,0),
('runtime-dotnet-v1','dotnet','dotnet-v1','ASP.NET Core application','oci',8080,0),
('runtime-ruby-v1','ruby','ruby-v1','Ruby web application','oci',3000,0),
('runtime-container-v1','container','container-v1','Custom OCI container','oci',8080,0);

-- Enforce organization/project ownership on settings, releases, workloads and events.
CREATE TRIGGER IF NOT EXISTS application_project_settings_org_guard_insert
BEFORE INSERT ON application_project_settings
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_project_settings_org_guard_update
BEFORE UPDATE OF organization_id, project_id ON application_project_settings
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_releases_org_guard_insert
BEFORE INSERT ON application_releases
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_workloads_org_guard_insert
BEFORE INSERT ON application_workloads
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_releases_terminal_state_immutable
BEFORE UPDATE OF state ON application_releases
WHEN (
  OLD.state IN ('failed','cancelled','rolled_back') AND NEW.state <> OLD.state
) OR (
  OLD.state = 'succeeded' AND NEW.state NOT IN ('succeeded','rolled_back')
)
BEGIN SELECT RAISE(ABORT, 'terminal release state is immutable'); END;


-- Validate every cross-table tenant relationship, not only the project FK.
CREATE TRIGGER IF NOT EXISTS application_releases_deployment_guard_insert
BEFORE INSERT ON application_releases
WHEN NOT EXISTS (
  SELECT 1 FROM github_deployments d
  WHERE d.id = NEW.deployment_id
    AND d.project_id = NEW.project_id
    AND d.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'deployment project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_releases_deployment_guard_update
BEFORE UPDATE OF organization_id, project_id, deployment_id ON application_releases
WHEN NOT EXISTS (
  SELECT 1 FROM github_deployments d
  WHERE d.id = NEW.deployment_id
    AND d.project_id = NEW.project_id
    AND d.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'deployment project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_releases_project_guard_update
BEFORE UPDATE OF organization_id, project_id ON application_releases
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_workloads_org_guard_update
BEFORE UPDATE OF organization_id, project_id ON application_workloads
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'project organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_workloads_release_guard_insert
BEFORE INSERT ON application_workloads
WHEN NEW.active_release_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM application_releases r
  WHERE r.id = NEW.active_release_id
    AND r.project_id = NEW.project_id
    AND r.organization_id = NEW.organization_id
    AND r.state = 'succeeded'
)
BEGIN SELECT RAISE(ABORT, 'active release must be a successful release for this project'); END;

CREATE TRIGGER IF NOT EXISTS application_workloads_release_guard_update
BEFORE UPDATE OF active_release_id, organization_id, project_id ON application_workloads
WHEN NEW.active_release_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM application_releases r
  WHERE r.id = NEW.active_release_id
    AND r.project_id = NEW.project_id
    AND r.organization_id = NEW.organization_id
    AND r.state = 'succeeded'
)
BEGIN SELECT RAISE(ABORT, 'active release must be a successful release for this project'); END;

CREATE TRIGGER IF NOT EXISTS application_release_events_org_guard_insert
BEFORE INSERT ON application_release_events
WHEN NOT EXISTS (
  SELECT 1 FROM application_releases r
  WHERE r.id = NEW.release_id AND r.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'release organization mismatch'); END;

CREATE TRIGGER IF NOT EXISTS application_release_events_org_guard_update
BEFORE UPDATE OF organization_id, release_id ON application_release_events
WHEN NOT EXISTS (
  SELECT 1 FROM application_releases r
  WHERE r.id = NEW.release_id AND r.organization_id = NEW.organization_id
)
BEGIN SELECT RAISE(ABORT, 'release organization mismatch'); END;

-- Permit only explicit forward transitions; terminal outcomes cannot be rewritten.
CREATE TRIGGER IF NOT EXISTS application_releases_state_transition_guard
BEFORE UPDATE OF state ON application_releases
WHEN NEW.state <> OLD.state AND NOT (
  (OLD.state = 'queued' AND NEW.state IN ('authorized','failed','cancelled')) OR
  (OLD.state = 'authorized' AND NEW.state IN ('building','failed','cancelled')) OR
  (OLD.state = 'building' AND NEW.state IN ('artifact_uploaded','failed','cancelled')) OR
  (OLD.state = 'artifact_uploaded' AND NEW.state IN ('validating','failed','cancelled')) OR
  (OLD.state = 'validating' AND NEW.state IN ('ready_to_publish','failed','cancelled')) OR
  (OLD.state = 'ready_to_publish' AND NEW.state IN ('publishing','failed','cancelled')) OR
  (OLD.state = 'publishing' AND NEW.state IN ('health_checking','failed','cancelled')) OR
  (OLD.state = 'health_checking' AND NEW.state IN ('succeeded','failed','cancelled')) OR
  (OLD.state = 'succeeded' AND NEW.state = 'rolled_back')
)
BEGIN SELECT RAISE(ABORT, 'invalid release state transition'); END;
