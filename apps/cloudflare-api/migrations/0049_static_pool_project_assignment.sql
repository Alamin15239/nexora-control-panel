-- Align the project runtime-pool assignment guards with the node enrollment
-- and deployment-admission predicate.
--
-- Migration 0028 admitted only rootless/microVM pools. The static publisher
-- node (runtime_engine='static', isolation_level='untrusted') is enrolled
-- through an explicit admission exception in the enrollment endpoint and in
-- isRuntimeAssignmentAdmitted, but the 0028 triggers still aborted any
-- project assignment of such a pool — leaving static deployments permanently
-- unpublishable. Recreate both guards with the same compound predicate so
-- assignment, enrollment, and admission can never disagree again.

DROP TRIGGER IF EXISTS application_project_settings_node_pool_insert_guard;
DROP TRIGGER IF EXISTS application_project_settings_node_pool_update_guard;

CREATE TRIGGER application_project_settings_node_pool_insert_guard
BEFORE INSERT ON application_project_settings
WHEN NEW.node_pool_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM application_node_pools p
  WHERE p.id = NEW.node_pool_id
    AND p.status = 'ready'
    AND (
      p.isolation_level IN ('rootless', 'microvm')
      OR (p.runtime_engine = 'static' AND p.isolation_level = 'untrusted')
    )
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
  SELECT RAISE(ABORT, 'project runtime assignment requires a ready isolated or static-publishing pool with an enrolled online runtime node');
END;

CREATE TRIGGER application_project_settings_node_pool_update_guard
BEFORE UPDATE OF node_pool_id ON application_project_settings
WHEN NEW.node_pool_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM application_node_pools p
  WHERE p.id = NEW.node_pool_id
    AND p.status = 'ready'
    AND (
      p.isolation_level IN ('rootless', 'microvm')
      OR (p.runtime_engine = 'static' AND p.isolation_level = 'untrusted')
    )
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
  SELECT RAISE(ABORT, 'project runtime assignment requires a ready isolated or static-publishing pool with an enrolled online runtime node');
END;
