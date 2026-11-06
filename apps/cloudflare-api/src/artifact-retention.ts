type ArtifactRetentionBindings = {
  DB: D1Database;
  ARTIFACTS?: R2Bucket;
};

type RetentionCandidate = {
  id: string;
  artifactKey: string;
};

/**
 * Remove only artifacts belonging to failed/cancelled deployments after the
 * recovery window. Successful artifacts are deliberately retained until the
 * publisher records explicit active-release and rollback references.
 *
 * R2 deletion is idempotent. The D1 row is cleared only after the delete
 * succeeds, so a transient R2 failure is retried by the next scheduled run.
 */
export async function pruneFailedDeploymentArtifacts(
  env: ArtifactRetentionBindings,
): Promise<{ examined: number; deleted: number; failed: number }> {
  if (!env.ARTIFACTS) return { examined: 0, deleted: 0, failed: 0 };

  const result = await env.DB.prepare(
    `SELECT id, artifact_key AS artifactKey
     FROM github_deployments
     WHERE status IN ('failed', 'cancelled')
       AND finished_at IS NOT NULL
       AND finished_at <= datetime('now', '-30 days')
       AND artifact_key IS NOT NULL
     ORDER BY finished_at ASC
     LIMIT 25`,
  ).all<RetentionCandidate>();

  const candidates = result.results ?? [];
  let deleted = 0;
  let failed = 0;

  for (const candidate of candidates) {
    try {
      await env.ARTIFACTS.delete(candidate.artifactKey);
      const cleared = await env.DB.prepare(
        `UPDATE github_deployments
         SET artifact_key = NULL, artifact_bytes = NULL, artifact_sha256 = NULL
         WHERE id = ?
           AND status IN ('failed', 'cancelled')
           AND finished_at IS NOT NULL
           AND finished_at <= datetime('now', '-30 days')
           AND artifact_key = ?`,
      ).bind(candidate.id, candidate.artifactKey).run();

      if ((cleared.meta.changes ?? 0) === 1) deleted += 1;
    } catch (error) {
      failed += 1;
      console.error(
        "R2 artifact retention failed:",
        candidate.id,
        error instanceof Error ? error.message : "unknown error",
      );
    }
  }

  return { examined: candidates.length, deleted, failed };
}
