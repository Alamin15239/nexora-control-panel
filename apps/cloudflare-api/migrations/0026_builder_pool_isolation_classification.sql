-- Explicit isolation classification and node role prevent ordinary app nodes from reporting builder usage.
ALTER TABLE application_node_pools
  ADD COLUMN isolation_level TEXT NOT NULL DEFAULT 'untrusted'
  CHECK (isolation_level IN ('untrusted','rootless','microvm'));

ALTER TABLE application_nodes
  ADD COLUMN node_role TEXT NOT NULL DEFAULT 'runtime'
  CHECK (node_role IN ('builder','runtime'));

CREATE INDEX IF NOT EXISTS idx_application_nodes_role_status
  ON application_nodes(node_role, status, node_pool_id);

-- Usage events may only be attributed to enrolled builder identities from an explicitly isolated pool.
CREATE TRIGGER application_usage_event_builder_isolation_insert
BEFORE INSERT ON application_usage_events
WHEN NEW.node_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM application_nodes n
  JOIN application_node_pools p ON p.id = n.node_pool_id
  WHERE n.id = NEW.node_id
    AND n.node_role = 'builder'
    AND n.status = 'online'
    AND p.status = 'ready'
    AND p.isolation_level IN ('rootless','microvm')
)
BEGIN
  SELECT RAISE(ABORT, 'usage event requires an online isolated builder node');
END;
