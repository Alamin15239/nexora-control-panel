# Automatic rollback acknowledgement protocol

## Status

Design specification only. Automatic rollback execution remains disabled. The runtime-node poller is read-only; it accepts desired-state metadata and explicitly rejects execution commands. The health-check API currently returns rollback guidance, while the release publisher exposes a local compare-and-switch primitive. These components are not yet wired into an execution workflow.

## Safety invariants

1. A health-check failure must never cause the control plane to claim that rollback completed.
2. The node performs the local rollback even when the control plane is unreachable. A control-plane outage must not block recovery.
3. Before changing the active release, the node verifies that the failed release is still active and that the previous release exists in the same immutable release store.
4. A stale rollback must not overwrite a newer deployment. The release publisher's compare-and-switch operation is the required primitive.
5. The node derives its identity from its authenticated Ed25519 request key. A node ID supplied only in the JSON body is never authoritative.
6. A rollback acknowledgement is accepted only for the exact failed release, target deployment, target release, project, organization, assigned node, and artifact identities already bound to the release record.
7. The node verifies the restored workload using the configured local health-check path before reporting success. A successful filesystem switch alone is not a successful workload rollback.
8. Reporting is at-least-once from a durable local outbox and idempotent at the API. Local rollback completion must be persisted before attempting network delivery.
9. The node never executes customer build commands as part of rollback. Rollback only selects a previously validated immutable release.
10. Runtime admission remains fail-closed unless the node pool is ready and isolation is rootless or microVM.

## Protocol

### 1. Failure detection

The runtime node probes the active release using the configured loopback-only health check. It submits the existing signed health-check report. The control plane validates the request signature, nonce, node assignment, release state, and artifact digest, then records the failed health-check event.

The response may provide rollback guidance, but it is not itself an executable command and must not be interpreted as proof of rollback.

### 2. Durable local intent

Before attempting the switch, the node writes a bounded rollback operation to its root/service-owned durable state store. The record contains only opaque identifiers and integrity metadata:

- operation ID (random, unique, stable across retries)
- failed deployment and release IDs
- previous deployment and release IDs
- project ID and organization ID
- assigned node identity
- expected active release ID
- creation time and attempt metadata
- operation state: pending, switched, verified, reported, or blocked

No customer secrets, environment values, source code, build logs, or arbitrary URLs are stored in the outbox.

The write must be atomic and fsynced before local mutation. The outbox must have strict size/count limits, owner-only permissions, symlink rejection, strict JSON decoding, and crash-safe replacement. Recovery must inspect the active release and reconcile each pending operation before retrying it.

### 3. Compare-and-switch

The node calls the release publisher's compare-and-switch rollback with the exact failed release ID and previous release ID. The operation is serialized with normal activation. It succeeds only if the failed release is still active, or if the previous release is already active as an idempotent retry. Any other active target is a stale/conflicting rollback and must be blocked.

After the switch, the node persists switched before proceeding.

### 4. Workload verification

The node probes the restored release on loopback using the project's configured health-check path and a bounded timeout. It verifies the response is successful and that the active release link still resolves to the expected previous release. It then persists verified and the bounded probe result.

If verification fails, the node must not report success. It records a bounded failure code and keeps the operation visible for operator intervention; it must not blindly switch repeatedly between releases.

### 5. Signed acknowledgement

The node sends an Ed25519-signed, replay-protected request to a dedicated rollback-completion endpoint. The canonical signature binds protocol version, authenticated node identity, timestamp and fresh nonce, HTTP method and exact path, and SHA-256 digest of the exact JSON request body.

The body contains the operation ID, failed deployment/release, restored deployment/release, expected artifact digest, verification status, HTTP status, probe duration, and completion timestamp. It contains no caller-selected organization or node authority.

The API resolves the node from the signing public key and identity headers, consumes the nonce, and independently joins the release/deployment/project/node records. It rejects mismatched assignments, stale timestamps, invalid digests, non-success verification, unknown fields, and conflicting operation IDs.

### 6. Durable control-plane audit

The API writes the rollback-completed event and release-state transition in one database batch. The event is append-only and records the authenticated node actor, operation ID, exact release transition, verification result, and server receipt time. A unique constraint on operation ID provides idempotency:

- same operation ID and identical immutable payload: return the original accepted result;
- same operation ID with different payload: return conflict;
- unknown, unassigned, or mismatched release: reject without changing state.

The API acknowledges success only after the event and state transition are durably committed.

### 7. Outbox delivery and recovery

The node marks the outbox item reported only after receiving a valid API acknowledgement matching the operation ID and release identities. On timeout, network failure, or API error, it retains the verified item and retries with bounded exponential backoff and jitter. A retry uses a fresh request nonce but the same operation ID and immutable payload.

At startup, the node reconciles all non-terminal outbox entries against the active release and local health probe before sending reports. It never assumes that a network timeout means the API did not commit; idempotency resolves that ambiguity.

## Required tests before implementation is admitted

- Forged signature, unknown/revoked node, stale timestamp, reused nonce, malformed body, unknown JSON fields.
- Authenticated node reporting a release assigned to another node or pool.
- Wrong organization, project, failed release, restored release, or artifact digest.
- Non-success HTTP verification and inconsistent active symlink.
- Successful first report and identical retry.
- Conflicting retry with the same operation ID.
- Process crash before switch, after switch, after verification, and after API commit but before response.
- Control-plane outage during local rollback followed by successful outbox delivery.
- Concurrent deployment activation racing rollback; stale rollback must never replace the newer release.
- Corrupt, oversized, symlinked, or group/world-writable outbox state.
- Full runtime-node and Linux-agent CI, plus disposable-node integration tests.

## Admission gate

This protocol is not production-ready until the local outbox, rollback executor, signed API endpoint, atomic audit transition, crash-recovery tests, and disposable-node integration tests are implemented and passing. Do not enable customer execution or install/enable the runtime service on the production VM before that gate is met.
