-- Operator-controlled node revocation and proof-of-possession signing-key rotation.
ALTER TABLE application_nodes
  ADD COLUMN revoked_at TEXT;

ALTER TABLE application_nodes
  ADD COLUMN revoked_reason TEXT
  CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 500);

ALTER TABLE application_nodes
  ADD COLUMN key_rotation_challenge_hash TEXT
  CHECK (key_rotation_challenge_hash IS NULL OR
    (length(key_rotation_challenge_hash) = 64 AND key_rotation_challenge_hash NOT GLOB '*[^0-9a-f]*'));

ALTER TABLE application_nodes
  ADD COLUMN key_rotation_challenge_expires_at TEXT;

ALTER TABLE application_nodes
  ADD COLUMN signing_key_rotated_at TEXT;

CREATE TABLE IF NOT EXISTS application_node_signing_key_history (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES application_nodes(id) ON DELETE RESTRICT,
  public_key TEXT NOT NULL
    CHECK (length(public_key) = 64 AND public_key NOT GLOB '*[^0-9a-f]*'),
  activated_at TEXT NOT NULL DEFAULT (datetime('now')),
  retired_at TEXT,
  UNIQUE(node_id, public_key)
);

CREATE INDEX IF NOT EXISTS idx_application_node_key_history
  ON application_node_signing_key_history(node_id, activated_at);

-- Revocation is terminal: no status/key/challenge mutation can reactivate a revoked node.
CREATE TRIGGER IF NOT EXISTS application_node_revocation_terminal
BEFORE UPDATE ON application_nodes
WHEN OLD.status = 'revoked' AND (
  NEW.status <> 'revoked' OR
  NEW.signing_public_key IS NOT OLD.signing_public_key OR
  NEW.enrollment_key_hash IS NOT OLD.enrollment_key_hash OR
  NEW.revoked_at IS NOT OLD.revoked_at
)
BEGIN
  SELECT RAISE(ABORT, 'revoked application nodes are terminal');
END;

-- A node identity cannot be reassigned to a different signing key through ordinary updates.
CREATE TRIGGER IF NOT EXISTS application_node_key_history_immutable
BEFORE UPDATE OF public_key, node_id, activated_at ON application_node_signing_key_history
BEGIN
  SELECT RAISE(ABORT, 'application node signing key history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS application_node_key_history_retirement_once
BEFORE UPDATE OF retired_at ON application_node_signing_key_history
WHEN OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
BEGIN
  SELECT RAISE(ABORT, 'signing key retirement is one-time and immutable');
END;
