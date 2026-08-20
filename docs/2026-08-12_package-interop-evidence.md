# Package-to-package release evidence

Status: checklist, schema, and interop harness, 2026-08-12

## Objective

Prove the downloadable macOS client package against the downloadable Linux
server package on separate managed hosts. Source-tree and same-container tests
do not substitute for this gate.

## Canonical checklist

`packaging/evidence/checklist-v2.json` enumerates every required positive and
negative case from the Homebrew delivery contract. The matrix records client
artifact profiles `darwin-arm64` / `darwin-amd64` against server profiles
`linux-amd64` / `linux-arm64`. Missing runner pairs are `not_run`, never `pass`.

## Evidence document

Schema: `schemas/release-evidence-v2.schema.json`

Go validation: `internal/releaseevidence`

Every evidence document MUST bind:

- `contract_id` and `contract_checklist_sha256`
- `clean_tree_proof`
- release version and source commit
- client and server package SHA-256
- client and server artifact-profile IDs
- client and server engine manifest SHA-256
- platform and architecture strings
- `host_target`, `authorization_policy`, `route_count`, and `restart_policies`
- test identity, exact commands, timestamps
- `package_to_package: true`
- `source_tree_substitution: false`
- one result for every checklist id

`releaseevidence.CompleteV2` is true only when every result is `pass`.

## Harness

```sh
export WARPTWEET_CI_PACKAGE_INTEROP=1
export WARPTWEET_INTEROP_ROLE=orchestrator
export WARPTWEET_RELEASE_VERSION=1.0.0
export WARPTWEET_SOURCE_COMMIT=<40-hex>
export WARPTWEET_CLIENT_PACKAGE_SHA256=<64-hex>
export WARPTWEET_SERVER_PACKAGE_SHA256=<64-hex>
export WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID=darwin-arm64
export WARPTWEET_SERVER_ARTIFACT_PROFILE_ID=linux-amd64
export WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256=<64-hex>
export WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256=<64-hex>
export WARPTWEET_EVIDENCE_OUTPUT=/tmp/warptweet-evidence.json
./scripts/test-package-interop.sh
```

The script fails closed when any checklist case is `fail` or `not_run`. Hosted
release runners must implement the dual-host cases until the document is
complete. Local preflight probes may pass individual package inventory checks
when installed package paths are supplied; they never mark dual-host cases as
pass without evidence.

### Optional dual-host enroll env (client/orchestrator role)

When the installed package controllers are available on the client host:

| Variable | Purpose |
| --- | --- |
| `WARPTWEET_CLIENT_CTRL` | Installed client `warptweet` path (package prefix only) |
| `WARPTWEET_ENROLL_INVITE` | Fresh `.wtinvite` minted on the server host |
| `WARPTWEET_ENROLL_BAD_INVITE` | Expired/altered/cross-target invite for fail-closed |
| `WARPTWEET_TUNNEL_ID` | Tunnel id after enroll (for status/down/rotate/revoke) |

With those set, the harness can mark `invite-enroll-single-use`,
`invite-fail-closed`, and the client half of
`stop-restart-rotate-revoke-upgrade` as `pass` or `fail`. Tunnel algorithm,
rekey, readiness, payload, and confinement cases remain dual-host data-plane
work. Source-tree `./bin/warptweet` is rejected.

### Local control-plane confidence (not WP8)

```sh
./scripts/test-enrollment-control-plane.sh
```

Loopback Go tests for invite mint, Accept, Submit enroll/rotate/revoke, and unit
contracts. Does not light the public CTA.

### Phase A dual-host orchestrator (partial matrix)

```sh
cp scripts/interop/config.example.env scripts/interop/config.env
# pin digests, artifact filenames, server host/listen
ssh-add ...
./scripts/interop/orchestrate.sh --config scripts/interop/config.env
```

Installs pinned packages from an artifacts directory (Option B), runs echo
fixture on the Linux server, mints invite, `connect`s from the local Mac
package controller, proves deterministic payload, and writes a schema-complete
evidence document with remaining cases `not_run`. See
`docs/2026-08-14_dual-host-interop-orchestrator.md`.

The local `.pkg` install is the only administrator-prompt boundary. The
installed `connect` and lifecycle commands run as the login administrator and
cross the typed package provisioner socket; the harness must not chown state to
the operator, add the operator to `_warptweet`, or elevate individual client
commands.

## Relationship to other gates

| Gate | Role |
| --- | --- |
| `test-enrollment-control-plane.sh` | Local pinned-TLS enrollment confidence (not package evidence) |
| `test-server-preflight.sh` | Single-host installed server preflight |
| `test-live-tunnel.sh` | Same-host Linux live tunnel negatives/positives |
| `test-package-interop.sh` | Package-to-package host-to-host release evidence |

## Website CTA boundary

The website Homebrew command may activate only after a complete package-interop
evidence document exists for the published release artifacts.
