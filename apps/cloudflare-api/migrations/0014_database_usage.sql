CREATE TABLE database_usage (
  database_id TEXT PRIMARY KEY NOT NULL REFERENCES hosting_databases(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0 AND used_bytes <= 9007199254740991),
  collected_at TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX database_usage_server_idx
  ON database_usage(server_id, organization_id);
