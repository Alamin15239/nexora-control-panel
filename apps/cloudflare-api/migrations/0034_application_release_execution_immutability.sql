-- Deployment identity and runtime assignment are immutable after release creation.
-- A release may never be moved to another tenant, project, commit, pool, profile or node.
CREATE TRIGGER application_release_execution_binding_immutable
BEFORE UPDATE OF id, organization_id, project_id, deployment_id, node_pool_id,
                 runtime_profile_id, assigned_node_id, spec_version, source_commit_sha
ON application_releases
WHEN NEW.id IS NOT OLD.id
  OR NEW.organization_id IS NOT OLD.organization_id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.deployment_id IS NOT OLD.deployment_id
  OR NEW.node_pool_id IS NOT OLD.node_pool_id
  OR NEW.runtime_profile_id IS NOT OLD.runtime_profile_id
  OR NEW.assigned_node_id IS NOT OLD.assigned_node_id
  OR NEW.spec_version IS NOT OLD.spec_version
  OR NEW.source_commit_sha IS NOT OLD.source_commit_sha
BEGIN
  SELECT RAISE(ABORT, 'application release execution binding is immutable');
END;

-- The first accepted artifact digest/size pair is immutable for the life of a release.
CREATE TRIGGER application_release_artifact_identity_immutable
BEFORE UPDATE OF artifact_digest, artifact_bytes ON application_releases
WHEN OLD.artifact_digest IS NOT NULL
  AND (NEW.artifact_digest IS NOT OLD.artifact_digest
       OR NEW.artifact_bytes IS NOT OLD.artifact_bytes)
BEGIN
  SELECT RAISE(ABORT, 'application release artifact identity is immutable');
END;
