export type RuntimeAssignmentAdmission = {
  runtimeEnabled: number;
  nodePoolId: string | null;
  poolStatus: string | null;
  isolationLevel: string | null;
  runtimeEngine?: string | null;
  assignedNodeId: string | null;
};

/**
 * A deployment is admitted only when every runtime trust prerequisite is
 * present. Missing settings and partially provisioned pools must fail closed.
 *
 * Two pool classes are admitted, mirroring the node enrollment gate exactly:
 *
 *  1. Rootless or microVM pools — full host isolation for managed runtimes.
 *  2. The static publishing exception — a pool whose runtime engine is
 *     explicitly `static` with `isolation_level='untrusted'`. The host runs a
 *     root-owned Nginx vhost broker, so the VM itself is not an isolation
 *     boundary; admission is scoped to the static-v1 artifact pipeline which
 *     only ever serves files staged by the isolated GitHub-hosted builder.
 *
 * Assignments that do not carry a runtimeEngine (legacy callers) can never
 * trigger the static exception, so they keep the original fail-closed shape.
 */
export function isRuntimeAssignmentAdmitted(
  assignment: RuntimeAssignmentAdmission | null | undefined,
): boolean {
  if (!assignment) return false;
  if (assignment.runtimeEnabled !== 1 || !assignment.nodePoolId ||
      assignment.poolStatus !== "ready" || !assignment.assignedNodeId) {
    return false;
  }
  if (["rootless", "microvm"].includes(assignment.isolationLevel ?? "")) return true;
  return assignment.runtimeEngine === "static" && assignment.isolationLevel === "untrusted";
}
