-- Immutable audit records for a node-confirmed, locally verified static release rollback.
CREATE TABLE IF NOT EXISTS application_rollback_acknowledgements (
  operation_id TEXT PRIMARY KEY CHECK (length(operation_id) BETWEEN 3 AND 128),
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL REFERENCES github_projects(id) ON DELETE RESTRICT,
  node_id TEXT NOT NULL REFERENCES application_nodes(id) ON DELETE RESTRICT,
  failed_release_id TEXT NOT NULL REFERENCES application_releases(id) ON DELETE RESTRICT,
  target_release_id TEXT NOT NULL REFERENCES application_releases(id) ON DELETE RESTRICT,
  failed_deployment_id TEXT NOT NULL,
  target_deployment_id TEXT NOT NULL,
  target_artifact_sha256 TEXT NOT NULL CHECK (
    length(target_artifact_sha256) = 64 AND target_artifact_sha256 NOT GLOB '*[^a-f0-9]*'
  ),
  http_status INTEGER NOT NULL CHECK (http_status BETWEEN 200 AND 299),
  probe_duration_ms INTEGER NOT NULL CHECK (probe_duration_ms BETWEEN 0 AND 30000),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (failed_release_id <> target_release_id),
  CHECK (failed_deployment_id <> target_deployment_id)
);

CREATE INDEX IF NOT EXISTS idx_application_rollback_ack_project_created
ON application_rollback_acknowledgements(organization_id, project_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS application_rollback_ack_binding_guard
BEFORE INSERT ON application_rollback_acknowledgements
WHEN NOT EXISTS (
  SELECT 1
  FROM application_releases failed
  JOIN application_releases target
    ON target.id = NEW.target_release_id
   AND target.organization_id = NEW.organization_id
   AND target.project_id = NEW.project_id
   AND target.deployment_id = NEW.target_deployment_id
   AND target.assigned_node_id = NEW.node_id
   AND target.state = 'succeeded'
  JOIN github_deployments failed_deployment
    ON failed_deployment.id = failed.deployment_id
   AND failed_deployment.id = NEW.failed_deployment_id
   AND failed_deployment.organization_id = NEW.organization_id
   AND failed_deployment.project_id = NEW.project_id
  JOIN github_deployments target_deployment
    ON target_deployment.id = target.deployment_id
   AND target_deployment.organization_id = NEW.organization_id
   AND target_deployment.project_id = NEW.project_id
  WHERE failed.id = NEW.failed_release_id
    AND failed.organization_id = NEW.organization_id
    AND failed.project_id = NEW.project_id
    AND failed.assigned_node_id = NEW.node_id
    AND failed.node_pool_id = target.node_pool_id
    AND failed.state = 'failed'
    AND target.artifact_digest = NEW.target_artifact_sha256
)
BEGIN
  SELECT RAISE(ABORT, 'rollback acknowledgement release binding mismatch');
END;

CREATE TRIGGER IF NOT EXISTS application_rollback_ack_update_immutable
BEFORE UPDATE ON application_rollback_acknowledgements
BEGIN
  SELECT RAISE(ABORT, 'rollback acknowledgement audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS application_rollback_ack_delete_immutable
BEFORE DELETE ON application_rollback_acknowledgements
BEGIN
  SELECT RAISE(ABORT, 'rollback acknowledgement audit is append-only');
END;
