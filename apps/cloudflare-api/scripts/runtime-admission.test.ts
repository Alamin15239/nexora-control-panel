import test from "node:test";
import assert from "node:assert/strict";
import { isRuntimeAssignmentAdmitted } from "../src/runtime-admission.ts";

const ready = {
  runtimeEnabled: 1,
  nodePoolId: "pool-a",
  poolStatus: "ready",
  isolationLevel: "rootless",
  assignedNodeId: "node-a",
};

test("runtime admission accepts a fully provisioned isolated runtime", () => {
  assert.equal(isRuntimeAssignmentAdmitted(ready), true);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "microvm" }), true);
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

test("runtime admission rejects untrusted isolation modes", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: "untrusted" }), false);
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, isolationLevel: null }), false);
});

test("runtime admission rejects missing runtime node assignment", () => {
  assert.equal(isRuntimeAssignmentAdmitted({ ...ready, assignedNodeId: null }), false);
});
