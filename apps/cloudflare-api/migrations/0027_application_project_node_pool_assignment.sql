-- Operator-controlled runtime pool assignment for application projects.
-- Assignments are metadata only; they do not enable customer execution or allocate capacity.
ALTER TABLE application_project_settings
  ADD COLUMN node_pool_id TEXT REFERENCES application_node_pools(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_application_project_settings_node_pool
  ON application_project_settings(node_pool_id);

CREATE TRIGGER application_project_settings_node_pool_insert_guard
BEFORE INSERT ON application_project_settings
WHEN NEW.node_pool_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM application_node_pools p
  WHERE p.id = NEW.node_pool_id
    AND p.status = 'ready'
    AND p.isolation_level IN ('rootless','microvm')
    AND EXISTS (
      SELECT 1 FROM application_nodes n
      WHERE n.node_pool_id = p.id
        AND n.node_role = 'runtime'
        AND n.status = 'online'
        AND n.revoked_at IS NULL
        AND n.signing_public_key IS NOT NULL
    )
)
BEGIN
  SELECT RAISE(ABORT, 'project runtime assignment requires a ready isolated pool with an enrolled online runtime node');
END;

CREATE TRIGGER application_project_settings_node_pool_update_guard
BEFORE UPDATE OF node_pool_id ON application_project_settings
WHEN NEW.node_pool_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM application_node_pools p
  WHERE p.id = NEW.node_pool_id
    AND p.status = 'ready'
    AND p.isolation_level IN ('rootless','microvm')
    AND EXISTS (
      SELECT 1 FROM application_nodes n
      WHERE n.node_pool_id = p.id
        AND n.node_role = 'runtime'
        AND n.status = 'online'
        AND n.revoked_at IS NULL
        AND n.signing_public_key IS NOT NULL
    )
)
BEGIN
  SELECT RAISE(ABORT, 'project runtime assignment requires a ready isolated pool with an enrolled online runtime node');
END;
