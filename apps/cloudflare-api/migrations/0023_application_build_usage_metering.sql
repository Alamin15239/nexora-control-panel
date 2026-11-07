-- Monthly build-minute allowance and idempotent usage ledger.
-- Usage is recorded only by a future authenticated builder metering path; no customer builds are enabled here.
ALTER TABLE hosting_plans
  ADD COLUMN app_build_minutes_month INTEGER NOT NULL DEFAULT 300
  CHECK (app_build_minutes_month BETWEEN 0 AND 100000);

CREATE TABLE application_usage_periods (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  period_start TEXT NOT NULL CHECK (period_start GLOB '????-??-01'),
  build_seconds_used INTEGER NOT NULL DEFAULT 0 CHECK (build_seconds_used >= 0),
  build_minutes_limit INTEGER NOT NULL CHECK (build_minutes_limit BETWEEN 0 AND 100000),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (organization_id, project_id, period_start)
);

CREATE TABLE application_usage_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE CASCADE,
  deployment_id TEXT NOT NULL REFERENCES github_deployments(id) ON DELETE CASCADE,
  period_start TEXT NOT NULL CHECK (period_start GLOB '????-??-01'),
  build_seconds INTEGER NOT NULL CHECK (build_seconds BETWEEN 0 AND 604800),
  source TEXT NOT NULL CHECK (source = 'isolated_builder'),
  recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (organization_id, project_id, deployment_id)
);

CREATE INDEX application_usage_periods_org_period_idx
  ON application_usage_periods(organization_id, period_start);
CREATE INDEX application_usage_events_project_period_idx
  ON application_usage_events(organization_id, project_id, period_start);

CREATE TRIGGER application_usage_period_tenant_insert
BEFORE INSERT ON application_usage_periods
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN
  SELECT RAISE(ABORT, 'application usage period tenant mismatch');
END;

CREATE TRIGGER application_usage_period_tenant_update
BEFORE UPDATE OF organization_id, project_id, period_start ON application_usage_periods
WHEN NOT EXISTS (
  SELECT 1 FROM github_projects p
  WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
)
BEGIN
  SELECT RAISE(ABORT, 'application usage period tenant mismatch');
END;

CREATE TRIGGER application_usage_event_scope_insert
BEFORE INSERT ON application_usage_events
WHEN NOT EXISTS (
  SELECT 1 FROM application_usage_periods u
  WHERE u.organization_id = NEW.organization_id
    AND u.project_id = NEW.project_id
    AND u.period_start = NEW.period_start
) OR NOT EXISTS (
  SELECT 1 FROM github_deployments d
  WHERE d.id = NEW.deployment_id
    AND d.organization_id = NEW.organization_id
    AND d.project_id = NEW.project_id
)
BEGIN
  SELECT RAISE(ABORT, 'application usage event scope mismatch');
END;

CREATE TRIGGER application_usage_event_immutable_update
BEFORE UPDATE ON application_usage_events
BEGIN
  SELECT RAISE(ABORT, 'application usage events are immutable');
END;
