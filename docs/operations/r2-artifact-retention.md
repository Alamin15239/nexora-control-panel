# R2 artifact retention policy

## Safety policy

The API's scheduled retention task deletes an artifact only when all of the following are true:

- The deployment is in a terminal `failed` or `cancelled` state.
- `finished_at` is at least 30 days old.
- The deployment still references the exact staged object key selected by the cleanup query.

The task processes at most 25 objects per scheduled invocation. It deletes the R2 object first and clears the matching D1 artifact reference only after R2 confirms the delete operation. If deletion fails, the D1 reference remains and a later invocation retries it.

## Successful deployments and rollback

Successful deployment artifacts are **not automatically deleted**. They remain available until the publisher persists an explicit active-release pointer and a bounded rollback-retention set. A future retention change must preserve:

1. The currently active production release.
2. Every release inside the documented rollback window.
3. Any release referenced by an in-progress rollback or recovery operation.

Do not add a broad R2 lifecycle expiration rule to the `staging/` prefix: R2 lifecycle rules cannot consult D1 deployment state and could delete an artifact still required by an active deployment or rollback.

## Non-terminal deployments

Queued and active deployments are never eligible. The cleanup task does not infer that a deployment is abandoned from age alone. Stale-run reconciliation must first confirm the GitHub Actions run is terminal and transition the deployment to `failed` or `cancelled`.

## Operational limits

- R2 remains private: no `r2.dev` URL, custom domain, or public bucket access.
- Incomplete multipart uploads continue to be aborted after seven days by the bucket's existing rule.
- Each cron invocation examines at most 25 eligible objects.
- Monitor the `R2 artifact retention failed` log event; failed deletes remain retryable.
- This task is storage cleanup only. It does not validate, extract, publish, or activate customer code.
