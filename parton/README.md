# parton

Host agent for cell control-plane heartbeat reporting and Docker / host actions.

This crate provides:

- A shared heartbeat contract used by the agent and the control plane's ingest endpoint.
- A periodic sender-loop binary (`src/main.rs`) for node telemetry.
- Typed container action contracts and Docker CLI execution helpers.
- Signed handoff directives (re-enroll / revoke) and claim/result/lease HTTP clients.

## Feature overview

- Heartbeat model: `NodeHeartbeatReport`, `build_heartbeat_report`, `send_heartbeat`
- Command queue: claim, extend-lease, and result against `/api/parton/actions/*`
- Docker lifecycle: `start`, `stop`, `restart`, `logs`, `inspect`, `deploy`, `ensure_network`, `ensure_docker_image`
- Host ops: `probe_host`, `diagnostic`, `grow_fs`, `wireguard_peer`
- Allowlisted `templated_exec`: see `TemplatedExecId` (full catalog in rustdoc)
- Queue-only kinds: `health_check`, `handoff_bundle_import`, `deploy_handoff`, `teardown_handoff`
- Directives: apply signed `ReEnroll` / `Revoke` to `parton.env`
- Policy: digest pins, SSRF guards, optional cosign; Prometheus `agent_metrics`

## Getting started

Setup, the offline examples, and how to run the agent against a control plane are in the
[root README](https://github.com/unified-field-dev/parton#getting-started). The examples are
described in [`examples/README.md`](https://github.com/unified-field-dev/parton/blob/main/parton/examples/README.md).

## Runtime configuration (binary)

| Variable | Default | Purpose |
|---|---|---|
| `PARTON_HEARTBEAT_URL` | `http://127.0.0.1:3000/api/parton/heartbeat` | Control-plane heartbeat ingest URL |
| `PARTON_NODE_ID` | **required** | Stable node identifier (fail closed if unset/blank) |
| `PARTON_CELL_ID` | `local-default` | Cell/group identifier |
| `PARTON_HEARTBEAT_INTERVAL_SECS` | `10` | Heartbeat interval seconds |
| `PARTON_SHARED_TOKEN` | _(unset)_ | Shared token (`x-parton-token`); required for production shared-token auth |
| `PARTON_CP_CA_PATH` | _(unset)_ | CA bundle for the control plane. When set, Parton trusts only this CA, requires an `https` `PARTON_HEARTBEAT_URL`, and presents its client certificate (see [Agent mTLS](#agent-mtls)) |
| `PARTON_STATE_DIR` | `/etc/parton` | Where the host key, CSR and signed client certificate are stored |
| `PARTON_AUTH_MODE` | `shared_token` | `shared_token` / `dual` / `spiffe`; see [`docs/spiffe.md`](https://github.com/unified-field-dev/parton/blob/main/docs/spiffe.md) |
| `PARTON_COSIGN_MODE` | `off` | `off` / `key` / `keyless`; cosign verify before pull/run |
| `PARTON_ENROLLMENT_TOKEN` | _(unset)_ | One-time enrollment token |
| `PARTON_ACTION_LEASE_SECS` | `120` | Claim lease duration |
| `PARTON_ACTION_LEASE_EXTEND_SECS` | `600` | Lease extension before long actions |
| `PARTON_HANDOFF_IMPORT_BASE_URL` | _(unset)_ | Optional import base URL for handoff results |
| `PARTON_DIRECTIVE_GRACE_SECS` | `300` | Post re-enroll grace window |
| `PARTON_AUTHORITY_VERIFY_KEY` | _(unset)_ | Ed25519 verify key for handoff directives (required for signed handoffs) |
| `PARTON_IMAGE_TARBALL` | _(unset)_ | After inspect miss + pull failure, `docker load -i` this file then re-inspect |
| `PARTON_IMAGE_TARBALL_DIR` | _(unset)_ | Same fallback: load `{dir}/{sha256}.tar` or `.tar.gz` when `image_ref` is digest-pinned |

## Security

Deploy policy defaults to deny host networking/mounts and require digest-pinned images.
Optional cosign (`PARTON_COSIGN_MODE`) and SPIFFE (`PARTON_AUTH_MODE`) are implemented.
Vulnerability reporting: [`SECURITY.md`](https://github.com/unified-field-dev/parton/blob/main/SECURITY.md). Air-gapped tarballs are
operator-supplied files on the agent host (same trust as a manual `docker load`).

## Docs

```bash
RUSTDOCFLAGS="-D warnings" cargo doc -p parton --no-deps
```

See the [root README](https://github.com/unified-field-dev/parton#verify) for verification, and the
crate docs plus [`docs/spiffe.md`](https://github.com/unified-field-dev/parton/blob/main/docs/spiffe.md)
for auth modes.

## Agent mTLS

With `PARTON_CP_CA_PATH` set and `PARTON_ENROLLMENT_TOKEN` (`ghe.<id>.<secret>`) present, Parton generates its own key on the first heartbeat and asks the control plane to sign it. The key never leaves the host.

1. Writes `client.key` (mode 0600) and `client.csr` under `PARTON_STATE_DIR`.
2. Sends `POST <heartbeat-origin>/api/parton/enroll/sign-csr` with `{"enrollment_id": "<id>", "token": "<full token>", "csr_pem": "..."}`.
3. Stores the response `{"cert_pem": "...", "chain_pem": "..."}` (`chain_pem` optional) as `client.crt`.

Later calls to the control plane (heartbeat, action claim, result and lease extension) present that certificate and verify the server against the CA. If the endpoint answers 404 or 501, Parton logs a warning and keeps heartbeating without a certificate. Other failures are logged and retried on the next beat. Certificate renewal is not implemented yet.
