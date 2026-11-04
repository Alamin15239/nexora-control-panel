CREATE TABLE server_service_checks (
  id TEXT PRIMARY KEY NOT NULL,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  service_key TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (
    status IN ('ACTIVE', 'INACTIVE', 'FAILED', 'NOT_INSTALLED', 'UNKNOWN')
  ),
  checked_at TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX server_service_checks_server_checked_idx
  ON server_service_checks(server_id, checked_at DESC);

CREATE INDEX server_service_checks_server_key_checked_idx
  ON server_service_checks(server_id, service_key, checked_at DESC);
