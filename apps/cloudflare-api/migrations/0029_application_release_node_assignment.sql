-- Bind every application release to one exact enrolled runtime node.
-- Pool membership alone must never authorize retrieval of another node's tenant artifacts.
ALTER TABLE application_releases
  ADD COLUMN assigned_node_id TEXT REFERENCES application_nodes(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_application_releases_assigned_node_state
  ON application_releases(assigned_node_id, state, requested_at DESC);

CREATE TRIGGER application_release_assigned_node_insert_guard
BEFORE INSERT ON application_releases
WHEN NEW.runtime_profile_id IS NOT NULL AND (
  NEW.assigned_node_id IS NULL OR NOT EXISTS (
    SELECT 1
    FROM application_nodes n
    JOIN application_node_pools p ON p.id = n.node_pool_id
    WHERE n.id = NEW.assigned_node_id
      AND n.node_pool_id = NEW.node_pool_id
      AND n.node_role = 'runtime'
      AND n.status = 'online'
      AND n.revoked_at IS NULL
      AND n.signing_public_key IS NOT NULL
      AND p.status = 'ready'
      AND p.isolation_level IN ('rootless','microvm')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'application release requires one enrolled online runtime node in its assigned isolated pool');
END;

CREATE TRIGGER application_release_assigned_node_update_guard
BEFORE UPDATE OF assigned_node_id, node_pool_id, runtime_profile_id ON application_releases
WHEN NEW.runtime_profile_id IS NOT NULL AND (
  NEW.assigned_node_id IS NULL OR NOT EXISTS (
    SELECT 1
    FROM application_nodes n
    JOIN application_node_pools p ON p.id = n.node_pool_id
    WHERE n.id = NEW.assigned_node_id
      AND n.node_pool_id = NEW.node_pool_id
      AND n.node_role = 'runtime'
      AND n.status = 'online'
      AND n.revoked_at IS NULL
      AND n.signing_public_key IS NOT NULL
      AND p.status = 'ready'
      AND p.isolation_level IN ('rootless','microvm')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'application release requires one enrolled online runtime node in its assigned isolated pool');
END;
