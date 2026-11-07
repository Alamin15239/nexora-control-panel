import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";

const operatorToken = "operator-token-" + "x".repeat(40);

class RuntimePoolD1 {
  profileEnabled = 1;
  hasActiveWorkload = 0;
  poolReady = true;
  isolationLevel = "microvm";
  runtimeNodeOnline = true;
  assignedPoolId: string | null = null;

  prepare(query: string) {
    const db = this;
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) { values = args; return statement; },
      async first<T>() {
        if (query.includes("FROM application_project_settings s")) {
          return {
            settingsId: "settings-a",
            previousNodePoolId: db.assignedPoolId,
            runtimeEnabled: db.profileEnabled,
            hasActiveWorkload: db.hasActiveWorkload,
          } as T;
        }
        if (query.includes("FROM application_node_pools p")) {
          const requested = values[0];
          return requested === "pool-runtime" && db.poolReady &&
            ["rootless", "microvm"].includes(db.isolationLevel) && db.runtimeNodeOnline
            ? ({ id: "pool-runtime" } as T) : null;
        }
        return null;
      },
      async all<T>() {
        return {
          results: db.poolReady && db.runtimeNodeOnline && ["rootless", "microvm"].includes(db.isolationLevel)
            ? [{
                id: "pool-runtime", name: "Runtime Pool", environment: "staging", region: "test-region",
                runtimeEngine: "microvm", isolationLevel: db.isolationLevel, onlineRuntimeNodes: 1,
              } as T]
            : [],
        };
      },
      async run() {
        if (query.includes("UPDATE application_project_settings SET node_pool_id")) {
          const [poolId, settingsId] = values;
          if (settingsId !== "settings-a" || db.hasActiveWorkload) return { success: true, meta: { changes: 0 } };
          db.assignedPoolId = String(poolId);
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return statement;
  }
}

function environment(db: RuntimePoolD1, token?: string) {
  return {
    DB: db as unknown as D1Database,
    APPLICATION_NODE_OPERATOR_TOKEN: token,
  };
}

function assignmentRequest(body: unknown, token = operatorToken) {
  return new Request("https://api.test/internal/v1/operator/application-projects/project-a/runtime-pool", {
    method: "POST",
    headers: {
      authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

test("runtime pool assignment fails closed when operator authorization is not configured", async () => {
  const db = new RuntimePoolD1();
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }),
    environment(db), {} as ExecutionContext);
  assert.equal(response.status, 503);
  assert.equal(db.assignedPoolId, null);
});

test("runtime pool assignment requires the operator token", async () => {
  const db = new RuntimePoolD1();
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }, "wrong-token"),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 401);
  assert.equal(db.assignedPoolId, null);
});

test("runtime pool assignment rejects disabled runtime profiles", async () => {
  const db = new RuntimePoolD1();
  db.profileEnabled = 0;
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 409);
  assert.equal(db.assignedPoolId, null);
});

test("runtime pool assignment rejects untrusted pools and builder-only capacity", async () => {
  const db = new RuntimePoolD1();
  db.isolationLevel = "untrusted";
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 409);
  assert.equal(db.assignedPoolId, null);
});

test("runtime pool assignment rejects projects with active workloads", async () => {
  const db = new RuntimePoolD1();
  db.hasActiveWorkload = 1;
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 409);
  assert.equal(db.assignedPoolId, null);
});

test("operator can assign a project to a ready isolated pool with an online runtime node", async () => {
  const db = new RuntimePoolD1();
  const response = await worker.fetch(assignmentRequest({ nodePoolId: "pool-runtime" }),
    environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as {
    assigned: boolean; nodePoolId: string; executionEnabled: boolean; capacityAllocated: boolean;
  };
  assert.equal(body.assigned, true);
  assert.equal(body.nodePoolId, "pool-runtime");
  assert.equal(body.executionEnabled, false);
  assert.equal(body.capacityAllocated, false);
  assert.equal(db.assignedPoolId, "pool-runtime");
});

test("operator runtime pool discovery only returns eligible online runtime capacity", async () => {
  const db = new RuntimePoolD1();
  const response = await worker.fetch(new Request("https://api.test/internal/v1/operator/application-node-pools", {
    headers: { authorization: "Bearer " + operatorToken },
  }), environment(db, operatorToken), {} as ExecutionContext);
  assert.equal(response.status, 200);
  const body = await response.json() as { pools: { id: string }[]; executionEnabled: boolean; capacityAllocated: boolean };
  assert.deepEqual(body.pools.map((pool) => pool.id), ["pool-runtime"]);
  assert.equal(body.executionEnabled, false);
  assert.equal(body.capacityAllocated, false);
});
