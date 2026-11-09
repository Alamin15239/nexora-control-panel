# Rollback outbox and local executor

## Status

The Linux agent now contains a durable rollback outbox and a separately gated local
executor. These packages are not wired into the runtime-node polling loop, and the
executor is not enabled by the service configuration. This is a safety boundary:
the current desired-state API remains read-only and does not deliver executable
rollback commands.

## Execution contract

A future caller may invoke the executor only after it has authenticated the
control-plane request, verified the node assignment and tenant/project/release
bindings, and established that both the failed release and rollback target are
present on this same node. The executor itself does not authenticate control-plane
signatures, discover release assignments, or select network destinations.

The executor then performs this sequence:

1. Persist immutable intent in rollbackoutbox before touching the active release.
2. Call the release publisher's compare-and-switch rollback. It changes the active
   link only while the expected failed release is still active; retries after the
   target is already active are idempotent, and a newer release is never replaced.
3. Persist switched.
4. Probe the target workload through a caller-supplied prober. Production probers
   must use only a trusted loopback port and health path from the node assignment.
5. Persist verified only for a healthy 2xx response with bounded duration.
6. Submit a caller-supplied signed acknowledgement. A transport or API error leaves
   the operation in verified for retry.
7. Persist reported only after the reporter has validated the server response.

An unhealthy probe or a compare-and-switch conflict moves the operation to
blocked. A blocked operation is terminal and never represents a successful
rollback.

## Crash recovery

| Crash point | Retry behavior |
|---|---|
| Before intent persistence | No local state changed; caller may retry admission |
| After intent, before switch | Re-run compare-and-switch |
| After switch, before switched persistence | Compare-and-switch recognizes the target is already active |
| After switched, before probe | Probe the restored workload |
| After verified, before acknowledgement | Re-probe and retry the idempotent acknowledgement |
| After acknowledgement, before reported persistence | Retry the acknowledgement with the same operation ID |

The signed pending-static-releases poll also returns same-node rollback intents. This recovers the gap where a publisher could crash after the control plane marks a release failed but before the first local outbox write. Each durable operation stores its hosting-account ID, canonical hostname, and health-check path so the service can resume pending, switched, or verified work after restart. The publisher retries verified acknowledgements from its local outbox even after the API has marked the workload healthy.

The outbox uses strict bounded JSON, private owner-only files, atomic replacement,
file and directory fsync, and an advisory lock shared across store instances and
processes. The operation ID is immutable: an identical retry returns the existing
record, while a conflicting payload is rejected.

## Required work before enabling

- Add the authenticated control-plane rollback-intent delivery path.
- Add an API acknowledgement endpoint with Ed25519 node authentication, timestamp
  and nonce replay protection, exact deployment/release/artifact/node binding,
  immutable operation-ID idempotency, and append-only audit.
- Implement the production prober using trusted runtime assignment data.
- Implement the reporter and validate the acknowledgement body, not just HTTP 200.
- Enforce same-node assignment for this local filesystem executor. Cross-node
  rollback needs a separate scheduler/traffic-switch protocol and must not be
  represented as a local symlink rollback.
- Add end-to-end tests for API authorization, crash recovery, replay, duplicate
  acknowledgements, node revocation, and a newer deployment racing rollback.
- Keep the runtime execution gate off until the complete path passes acceptance.

No production runtime service, node pool, or deployment execution setting is
changed by these packages.
