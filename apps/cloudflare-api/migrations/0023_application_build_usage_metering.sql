-- Monthly build-minute allowance and idempotent usage ledger.
-- Usage is recorded only by a future authenticated builder metering path; no customer builds are enabled here.
ALTER TABLE hosting_plans
  ADD COLUMN app_build_minutes_month INTEGER NOT NULL DEFAULT 300
  CHECK (app_build_minutes_month BETWEEN 0 AND 100000);

CREATE TABLE application_usage_periods (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  period_start TEXT NOT NULL CHECK (period_start GLOB '????-??-01'),
  build_seconds_used INTEGER NOT NULL DEFAULT 0 CHECK (build_seconds_used >= 0),
  build_minutes_limit INTEGER NOT NULL CHECK (build_minutes_limit BETWEEN 0 AND 100000),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (organization_id, project_id, period_start),
  FOREIGN KEY (organization_id, project_id)
    REFERENCES github_projects(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE application_usage_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  period_start TEXT NOT NULL CHECK (period_start GLOB '????-??-01'),
  build_seconds INTEGER NOT NULL CHECK (build_seconds BETWEEN 0 AND 604800),
  source TEXT NOT NULL CHECK (source = 'isolated_builder'),
  recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (organization_id, project_id, deployment_id),
  FOREIGN KEY (organization_id, project_id)
    REFERENCES github_projects(organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, project_id, period_start)
    REFERENCES application_usage_periods(organization_id, project_id, period_start) ON DELETE CASCADE
);

CREATE INDEX application_usage_periods_org_period_idx
  ON application_usage_periods(organization_id, period_start);
CREATE INDEX application_usage_events_project_period_idx
  ON application_usage_events(organization_id, project_id, period_start);
