import test from "node:test";
import assert from "node:assert/strict";
import { isRuntimeAssignmentAdmitted } from "../src/runtime-admission.ts";

const ready = {
  runtimeEnabled: 1,
  nodePoolId: "pool-a",
  poolStatus: "ready",
  isolationLevel: "rootless",
  runtimeEngine: "containerd",
  assignedNodeId: "node-a",
};

test("runtime admission accepts a fully provisioned isolated runtime", () => {
  assert.equal(isRuntimeAssignmentAdmitted(ready), true);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "microvm" }), true);
  // Legacy rows never recorded the pool engine; isolation alone stays decisive.
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, runtimeEngine: null }), true);
});

test("runtime admission rejects missing project runtime settings", () => {
  assert.equal(isRuntimeAssignmentAdmitted(null), false);
  assert.equal(isRuntimeAssignmentAdmitted(undefined), false);
});

test("runtime admission rejects disabled runtime profiles", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, runtimeEnabled: 0 }), false);
});

test("runtime admission rejects missing or unready pools", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, nodePoolId: null }), false);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, poolStatus: null }), false);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, poolStatus: "provisioning" }), false);
});

test("runtime admission rejects untrusted isolation except the static publisher", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "untrusted" }), false);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: null }), false);
  // Static publishing exception: explicitly static engine + untrusted isolation
  // mirrors the node enrollment gate for the static release pipeline only.
  assert.equal(
    isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "untrusted", runtimeEngine: "static" }),
    true,
  );
  // A non-static engine with untrusted isolation remains rejected.
  assert.equal(
    isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "untrusted", runtimeEngine: "containerd" }),
    false,
  );
});

test("runtime admission rejects missing runtime node assignment", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, assignedNodeId: null }), false);
  assert.equal(
    isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "untrusted", runtimeEngine: "static", assignedNodeId: null }),
    false,
  );
});
