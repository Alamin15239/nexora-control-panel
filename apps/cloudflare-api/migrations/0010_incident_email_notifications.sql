PRAGMA foreign_keys = ON;

CREATE TABLE incident_notification_settings (
  organization_id TEXT PRIMARY KEY NOT NULL
    REFERENCES organizations(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  recipients_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(recipients_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE incident_notification_outbox (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL
    REFERENCES organizations(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL
    REFERENCES server_incidents(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL CHECK (event_type IN ('OPENED', 'RESOLVED')),
  recipients_json TEXT NOT NULL CHECK (json_valid(recipients_json)),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'PROCESSING', 'RETRY', 'SENT', 'FAILED')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT NOT NULL,
  locked_until TEXT,
  sent_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (incident_id, event_type)
);

CREATE INDEX incident_notification_outbox_due_idx
  ON incident_notification_outbox(status, next_attempt_at, locked_until);

CREATE INDEX incident_notification_outbox_org_created_idx
  ON incident_notification_outbox(organization_id, created_at DESC);
