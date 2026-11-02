PRAGMA foreign_keys = ON;

CREATE TABLE agent_credentials (
  node_id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL UNIQUE REFERENCES servers(id) ON DELETE CASCADE,
  secret_hash TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT
);
CREATE INDEX agent_credentials_org_server_idx ON agent_credentials(organization_id, server_id, revoked_at);

CREATE TABLE agent_nonces (
  node_id TEXT NOT NULL REFERENCES agent_credentials(node_id) ON DELETE CASCADE,
  nonce TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (node_id, nonce)
);
CREATE INDEX agent_nonces_created_idx ON agent_nonces(created_at);
