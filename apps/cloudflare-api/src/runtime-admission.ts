export type RuntimeAssignmentAdmission = {
  runtimeEnabled: number;
  nodePoolId: string | null;
  poolStatus: string | null;
  isolationLevel: string | null;
  assignedNodeId: string | null;
};

/**
 * A deployment is admitted only when every runtime trust prerequisite is
 * present. Missing settings and partially provisioned pools must fail closed.
 */
export function isRuntimeAssignmentAdmitted(
  assignment: RuntimeAssignmentAdmission | null | undefined,
): boolean {
  return Boolean(
    assignment &&
    assignment.runtimeEnabled === 1 &&
    assignment.nodePoolId &&
    assignment.poolStatus === "ready" &&
    ["rootless", "microvm"].includes(assignment.isolationLevel ?? "") &&
    assignment.assignedNodeId,
  );
}
