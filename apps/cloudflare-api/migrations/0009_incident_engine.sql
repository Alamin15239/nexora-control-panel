PRAGMA foreign_keys = ON;

CREATE TABLE server_incidents (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,

  incident_type TEXT NOT NULL CHECK (
    incident_type IN ('SERVICE', 'SERVER_HEARTBEAT')
  ),

  incident_key TEXT NOT NULL,

  severity TEXT NOT NULL CHECK (
    severity IN ('WARNING', 'CRITICAL')
  ),

  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (
    status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')
  ),

  title TEXT NOT NULL,
  description TEXT,

  opened_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  resolved_at TEXT,

  acknowledged_at TEXT,
  acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL,

  CHECK (
    (status = 'RESOLVED' AND resolved_at IS NOT NULL)
    OR
    (status != 'RESOLVED' AND resolved_at IS NULL)
  )
);

CREATE UNIQUE INDEX server_incidents_one_open_key_idx
  ON server_incidents(server_id, incident_key)
  WHERE resolved_at IS NULL;

CREATE INDEX server_incidents_org_status_opened_idx
  ON server_incidents(organization_id, status, opened_at DESC);

CREATE INDEX server_incidents_server_status_opened_idx
  ON server_incidents(server_id, status, opened_at DESC);

CREATE INDEX server_incidents_org_opened_idx
  ON server_incidents(organization_id, opened_at DESC);
