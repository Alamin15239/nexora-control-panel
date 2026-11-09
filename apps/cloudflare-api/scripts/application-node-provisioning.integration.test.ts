import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../src/index.ts";

const operatorToken = "operator-token-" + "x".repeat(40);

type ProvisionedNode = {
  id: string;
  nodePoolId: string;
  nodeIdentity: string;
  enrollmentKeyHash: string;
  nodeRole: string;
  status: string;
  signingPublicKey?: string | null;
  enrollmentConsumed?: boolean;
  agentVersion?: string | null;
};

class NodeProvisioningD1 {
  poolStatus = "ready";
  isolationLevel = "microvm";
  nodes: ProvisionedNode[] = [];
  audits: Array<{ action: string; resourceId: string; metadata: string }> = [];

  prepare(query: string) {
    let values: unknown[] = [];
    const statement = {
      query,
      bind(...args: unknown[]) {
        values = args;
        return statement;
      },
      getValues() {
        return values;
      },
    };
    return statement;
  }

  async batch(statements: Array<{ query: string; getValues(): unknown[] }>) {
    const pendingNodes: ProvisionedNode[] = [];
    const pendingAudits: Array<{ action: string; resourceId: string; metadata: string }> = [];
    const results: Array<{ success: boolean; meta: { changes: number } }> = [];

    for (const statement of statements) {
      const values = statement.getValues();

      if (statement.query.includes("INSERT INTO application_nodes")) {
        const [id, nodeIdentity, enrollmentKeyHash, nodePoolId] = values as string[];
        const eligible = nodePoolId === "pool-runtime" &&
          this.poolStatus === "ready" &&
          ["rootless", "microvm"].includes(this.isolationLevel);
        const duplicate = this.nodes.some((node) => node.nodeIdentity === nodeIdentity);
        if (eligible && !duplicate) {
          pendingNodes.push({
            id,
            nodePoolId,
            nodeIdentity,
            enrollmentKeyHash,
            nodeRole: "runtime",
            status: "pending",
          });
          results.push({ success: true, meta: { changes: 1 } });
        } else {
          results.push({ success: true, meta: { changes: 0 } });
        }
        continue;
      }

      if (statement.query.includes("INSERT INTO audit_logs")) {
        const [, resourceId, metadata, expectedNodeId] = values as string[];
        const exists = pendingNodes.some((node) => node.id === expectedNodeId);
        if (exists) {
          pendingAudits.push({
            action: "application.node_enrollment_issued",
            resourceId,
            metadata,
          });
          results.push({ success: true, meta: { changes: 1 } });
        } else {
          results.push({ success: true, meta: { changes: 0 } });
        }
        continue;
      }

      results.push({ success: true, meta: { changes: 0 } });
    }

    // Apply mock writes only when both statements succeeded, mirroring D1 batch atomicity.
    if (results.length === 2 && results.every((result) => result.meta.changes === 1)) {
      this.nodes.push(...pendingNodes);
      this.audits.push(...pendingAudits);
    }

    return results;
  }
}


class EnrollmentFlowD1 extends NodeProvisioningD1 {
  keyHistory: Array<{ nodeId: string; publicKey: string }> = [];

  override prepare(query: string) {
    const base = super.prepare(query);
    let values: unknown[] = [];
    const db = this;

    const statement = {
      query,
      bind(...args: unknown[]) {
        values = args;
        base.bind(...args);
        return statement;
      },
      getValues() { return values; },
      async first<T>() {
        if (query.includes("FROM application_nodes WHERE node_identity")) {
          const [identity] = values;
          const node = db.nodes.find((item) => item.nodeIdentity === identity);
          return node ? ({
            id: node.id,
            nodeIdentity: node.nodeIdentity,
            status: node.status,
            agentVersion: node.agentVersion ?? null,
          } as T) : null;
        }
        return null;
      },
    };
    return statement;
  }

  override async batch(statements: Array<{ query: string; getValues(): unknown[] }>) {
    if (!statements[0]?.query.includes(
      "UPDATE application_nodes SET signing_public_key = ?, enrollment_consumed_at"
    )) {
      return super.batch(statements);
    }

    const [publicKey, agentVersion, identity, tokenHash] =
      statements[0].getValues() as string[];

    const node = this.nodes.find((item) => item.nodeIdentity === identity);
    const eligible = !!node &&
      node.status === "pending" &&
      !node.signingPublicKey &&
      !node.enrollmentConsumed &&
      node.enrollmentKeyHash === tokenHash &&
      this.poolStatus === "ready";

    const historyValues = statements[1]?.getValues() as string[] | undefined;
    const historyEligible = !!node &&
      !!historyValues &&
      historyValues[1] === identity &&
      historyValues[2] === publicKey &&
      eligible;

    const changes = eligible && historyEligible ? 1 : 0;

    if (changes === 1 && node) {
      node.signingPublicKey = publicKey;
      node.agentVersion = agentVersion;
      node.status = "online";
      node.enrollmentConsumed = true;
      this.keyHistory.push({ nodeId: node.id, publicKey });
    }

    return [
      { success: true, meta: { changes } },
      { success: true, meta: { changes } },
    ];
  }
}

function environment(db: NodeProvisioningD1, token?: string) {
  return {
    DB: db as unknown as D1Database,
    APPLICATION_NODE_OPERATOR_TOKEN: token,
  };
}

function createRequest(body: unknown, token = operatorToken) {
  return new Request("https://api.test/internal/v1/operator/application-nodes", {
    method: "POST",
    headers: {
      authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

test("node provisioning fails closed when operator authorization is not configured", async () => {
  const db = new NodeProvisioningD1();
  const response = await worker.fetch(
    createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a" }),
    environment(db),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 503);
  assert.equal(db.nodes.length, 0);
});

test("node provisioning requires the operator token", async () => {
  const db = new NodeProvisioningD1();
  const response = await worker.fetch(
    createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a" }, "wrong-token"),
    environment(db, operatorToken),
    {} as ExecutionContext,
  );
  assert.equal(response.status, 401);
  assert.equal(db.nodes.length, 0);
});

test("node provisioning rejects malformed and unexpected fields", async () => {
  const db = new NodeProvisioningD1();
  for (const body of [
    { nodePoolId: "pool-runtime", nodeIdentity: "x" },
    { nodePoolId: "../pool", nodeIdentity: "runtime-node-a" },
    { nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a", status: "online" },
  ]) {
    const response = await worker.fetch(createRequest(body), environment(db, operatorToken), {} as ExecutionContext);
    assert.equal(response.status, 400);
  }
  assert.equal(db.nodes.length, 0);
});

test("node provisioning rejects pools that are not ready or not isolated", async () => {
  for (const configuration of [
    { poolStatus: "provisioning", isolationLevel: "microvm" },
    { poolStatus: "ready", isolationLevel: "untrusted" },
  ]) {
    const db = new NodeProvisioningD1();
    db.poolStatus = configuration.poolStatus;
    db.isolationLevel = configuration.isolationLevel;
    const response = await worker.fetch(
      createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a" }),
      environment(db, operatorToken),
      {} as ExecutionContext,
    );
    assert.equal(response.status, 409);
    assert.equal(db.nodes.length, 0);
    assert.equal(db.audits.length, 0);
  }
});

test("node provisioning rejects duplicate identities without writing an audit record", async () => {
  const db = new NodeProvisioningD1();
  db.nodes.push({
    id: "existing-node",
    nodePoolId: "pool-runtime",
    nodeIdentity: "runtime-node-a",
    enrollmentKeyHash: "existing-hash",
    nodeRole: "runtime",
    status: "pending",
  });

  const response = await worker.fetch(
    createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a" }),
    environment(db, operatorToken),
    {} as ExecutionContext,
  );

  assert.equal(response.status, 409);
  assert.equal(db.nodes.length, 1);
  assert.equal(db.audits.length, 0);
});

test("operator can issue a one-time token for a pending runtime node", async () => {
  const db = new NodeProvisioningD1();
  const response = await worker.fetch(
    createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-node-a" }),
    environment(db, operatorToken),
    {} as ExecutionContext,
  );

  assert.equal(response.status, 201);
  const body = await response.json() as {
    created: boolean;
    node: { id: string; identity: string; nodePoolId: string; role: string; status: string };
    enrollmentToken: string;
    tokenUsage: string;
    executionEnabled: boolean;
  };

  assert.equal(body.created, true);
  assert.equal(body.node.identity, "runtime-node-a");
  assert.equal(body.node.nodePoolId, "pool-runtime");
  assert.equal(body.node.role, "runtime");
  assert.equal(body.node.status, "pending");
  assert.match(body.enrollmentToken, /^[a-f0-9]{64}$/);
  assert.equal(body.tokenUsage, "single_use");
  assert.equal(body.executionEnabled, false);

  assert.equal(db.nodes.length, 1);
  assert.equal(db.nodes[0].enrollmentKeyHash, createHash("sha256").update(body.enrollmentToken).digest("hex"));
  assert.notEqual(db.nodes[0].enrollmentKeyHash, body.enrollmentToken);
  assert.equal(db.nodes[0].nodeRole, "runtime");
  assert.equal(db.nodes[0].status, "pending");

  assert.equal(db.audits.length, 1);
  assert.equal(db.audits[0].action, "application.node_enrollment_issued");
  assert.equal(db.audits[0].resourceId, db.nodes[0].id);
  assert.equal(db.audits[0].metadata.includes(body.enrollmentToken), false);
  assert.equal(db.audits[0].metadata.includes(db.nodes[0].enrollmentKeyHash), false);
});


test("operator-issued enrollment token enrolls a node once and registers its Ed25519 key", async () => {
  const db = new EnrollmentFlowD1();

  const provisionResponse = await worker.fetch(
    createRequest({ nodePoolId: "pool-runtime", nodeIdentity: "runtime-e2e-a" }),
    environment(db, operatorToken),
    {} as ExecutionContext,
  );

  assert.equal(provisionResponse.status, 201);

  const provisioned = await provisionResponse.json() as {
    node: { id: string; identity: string; status: string; role: string };
    enrollmentToken: string;
    executionEnabled: boolean;
  };

  assert.equal(provisioned.node.status, "pending");
  assert.equal(provisioned.node.role, "runtime");
  assert.equal(provisioned.executionEnabled, false);

  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"]
  );

  const publicKey = Array.from(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");

  const enrollmentBody = {
    nodeIdentity: provisioned.node.identity,
    enrollmentToken: provisioned.enrollmentToken,
    publicKey,
    agentVersion: "0.1.0",
  };

  const enroll = () => worker.fetch(
    new Request("https://api.test/internal/v1/application-nodes/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(enrollmentBody),
    }),
    environment(db),
    {} as ExecutionContext,
  );

  const enrollmentResponse = await enroll();
  assert.equal(enrollmentResponse.status, 200);

  const enrollment = await enrollmentResponse.json() as {
    enrolled: boolean;
    node: { id: string; identity: string; status: string; agentVersion: string };
    credentialModel: string;
    executionEnabled: boolean;
  };

  assert.equal(enrollment.enrolled, true);
  assert.equal(enrollment.node.id, provisioned.node.id);
  assert.equal(enrollment.node.status, "online");
  assert.equal(enrollment.node.agentVersion, "0.1.0");
  assert.equal(enrollment.credentialModel, "ed25519_per_node");
  assert.equal(enrollment.executionEnabled, false);

  const node = db.nodes.find((item) => item.id === provisioned.node.id);
  assert.ok(node);
  assert.equal(node.status, "online");
  assert.equal(node.signingPublicKey, publicKey);
  assert.equal(node.enrollmentConsumed, true);

  assert.equal(
    node.enrollmentKeyHash,
    createHash("sha256").update(provisioned.enrollmentToken).digest("hex"),
  );

  assert.deepEqual(db.keyHistory, [
    { nodeId: provisioned.node.id, publicKey },
  ]);

  const replayResponse = await enroll();
  assert.equal(replayResponse.status, 409);
  assert.equal(node.signingPublicKey, publicKey);
  assert.equal(db.keyHistory.length, 1);
  assert.equal(db.audits.length, 1);
});
