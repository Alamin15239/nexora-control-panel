-- Per-node Ed25519 identity and replay protection for isolated builder requests.
ALTER TABLE application_nodes
  ADD COLUMN signing_public_key TEXT
  CHECK (signing_public_key IS NULL OR (length(signing_public_key) = 64 AND signing_public_key NOT GLOB '*[^0-9a-f]*'));

ALTER TABLE application_nodes
  ADD COLUMN enrollment_consumed_at TEXT;

ALTER TABLE application_nodes
  ADD COLUMN last_signature_at TEXT;

ALTER TABLE application_usage_events
  ADD COLUMN node_id TEXT REFERENCES application_nodes(id) ON DELETE RESTRICT;

DROP TRIGGER IF EXISTS application_usage_event_immutable_update;

CREATE TRIGGER application_usage_event_immutable_update
BEFORE UPDATE OF id, organization_id, project_id, deployment_id, period_start,
                 build_seconds, source, build_result, recorded_at, node_id
ON application_usage_events
BEGIN
  SELECT RAISE(ABORT, 'application usage events are immutable');
END;

CREATE TABLE IF NOT EXISTS application_node_request_nonces (
  node_id TEXT NOT NULL REFERENCES application_nodes(id) ON DELETE RESTRICT,
  nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 32 AND 128),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (node_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_application_node_nonces_expiry
  ON application_node_request_nonces(expires_at);
