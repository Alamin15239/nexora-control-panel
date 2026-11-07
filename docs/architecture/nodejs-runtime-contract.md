# Node.js application runtime contract (nodejs-v1)

**Status: contract and admission validation only. Runtime execution remains disabled.**

This is the first server-rendered application profile intended for Next.js and other Node.js web services. It is deliberately narrower than a generic container platform.

## Workload contract

The control plane may expose a workload to the Node.js runtime poller only when all of these conditions hold:

- Runtime profile key is `nodejs-v1`, family is `nodejs`, execution kind is `oci`, and the profile is enabled.
- Workload kind is `web`; the first release supports one replica only.
- The active release is successful and has an immutable OCI image reference in `registry/repository@sha256:<64 lowercase hex>` form.
- The assigned listen port is exactly `3000`.
- CPU, memory, disk and process limits are within the platform's hard bounds.
- Release and settings spec versions are positive integers.
- The node identity, node signature, request timestamp and one-time nonce have already been authenticated by the control plane.

The runtime node rejects every other profile and malformed image reference. It does not accept a shell command, entrypoint override, arbitrary environment map, source archive, secret value or arbitrary port from the control plane.

## Image build contract

Customer source must be built on a disposable, isolated hosted build worker—not on the control-plane Worker, privileged hosting agent, runtime node or current VirtualBox development VM.

The builder must produce an OCI image pinned by digest and push it to an operator-approved registry. The runtime node pulls only that digest. Tags such as `latest` are not deployment identities.

The image must:

- Use a supported Node.js LTS base image, pinned by digest at build time.
- Install dependencies from the lockfile with a reproducible package-manager install.
- Run the production build in the isolated build stage.
- Contain only production runtime dependencies and the built application in the final image.
- Run as an unprivileged UID/GID (10001:10001), with no package manager or build tool required at runtime.
- Bind the HTTP server to `0.0.0.0:3000`; do not bind only to localhost.
- Use a fixed image-defined startup command. The control plane must not override it.
- Include a bounded HTTP readiness endpoint at `/healthz` returning success only after the app is ready.
- Exclude repository metadata, local dependencies, test artifacts, and all `.env*`, credentials, private keys and local configuration from the build context.
- Never bake runtime secrets into image layers, build arguments, labels or image metadata.

### Next.js SSR

For a conventional Next.js server-rendered deployment, the image build runs `npm ci` and `npm run build`; the final image starts the production server using a fixed image command (for example `npm run start` with `next start -H 0.0.0.0 -p 3000`, or the Next.js standalone `server.js` output). A static `dist/` directory is not a valid substitute for a Next.js SSR server.

The application must read runtime configuration from injected environment variables or mounted secret files. Secret values are delivered only by a future scoped runtime secret provider; they are not part of the desired-state polling response.

## Runtime isolation requirements before execution

The current Podman supervisor is a foundation, not an approved production sandbox. Before enabling this profile, the runtime implementation must additionally demonstrate:

1. Rootless Podman (or stronger microVM) and cgroup v2 resource enforcement.
2. Per-workload storage quotas, immutable image verification, and safe persistent-volume ownership.
3. No direct public host-port publishing. A host-owned ingress proxy must route only to assigned loopback ports or sockets.
4. Default-deny egress with explicit DNS and application dependency policy; rootless networking alone is not an egress policy.
5. Secret delivery through short-lived, per-workload, read-only mounts; rotation and revocation without logging values.
6. Bounded log retention, redaction, and tenant-scoped retrieval.
7. HTTP readiness/liveness probes with startup grace periods, restart backoff and unhealthy-state reporting.
8. Atomic release rollout, traffic switch, last-known-good retention and tested rollback.
9. Tenant isolation, resource exhaustion, hostile image, host-boundary, node-revocation and crash-recovery tests.

## Current implementation boundary

- The API desired-state endpoint is read-only and returns `executionEnabled: false`.
- It now filters out disabled profiles and only exposes the enabled `nodejs-v1` OCI profile.
- The Go poller validates the exact Node.js workload contract and rejects mutable image tags, wrong ports, other profiles and multi-replica requests.
- The runtime-node daemon still rejects any response that attempts to enable execution or deliver commands/secrets. It does not start containers.
- No build worker, image registry credentials, ingress proxy, secret provider, health controller or rollback orchestrator is enabled by this change.
- `nodejs-v1` remains disabled in the seeded production profile catalog until the full acceptance gates above pass.

## Acceptance sequence

1. Implement a pinned, disposable build workflow and prove repository/branch/commit identity and artifact provenance.
2. Implement registry authentication and digest-bound image delivery.
3. Implement isolated runtime lifecycle and ingress without exposing host ports.
4. Implement health checks, logs, secret injection and failure-safe rollback.
5. Pass adversarial tenant-isolation and host-boundary tests on a dedicated non-production node pool.
6. Only then enable `nodejs-v1` for a controlled test project.
