# Package-to-package release evidence

Status: checklist, schema, and interop harness, 2026-08-12

## Objective

Prove the downloadable macOS client package against the downloadable Linux
server package on separate managed hosts. Source-tree and same-container tests
do not substitute for this gate.

## Canonical checklist

`packaging/evidence/checklist-v1.json` enumerates every required positive and
negative case from the Homebrew delivery contract. The matrix records client
artifact profiles `darwin-arm64` / `darwin-amd64` against server profiles
`linux-amd64` / `linux-arm64`. Missing runner pairs are `not_run`, never `pass`.

## Evidence document

Schema: `schemas/release-evidence-v1.schema.json`

Go validation: `internal/releaseevidence`

Every evidence document MUST bind:

- release version and source commit
- client and server package SHA-256
- client and server artifact-profile IDs
- client and server engine manifest SHA-256
- platform and architecture strings
- test identity, exact commands, timestamps
- `package_to_package: true`
- `source_tree_substitution: false`
- one result for every checklist id

`releaseevidence.Complete` is true only when every result is `pass`.

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

## Relationship to other gates

| Gate | Role |
| --- | --- |
| `test-server-preflight.sh` | Single-host installed server preflight |
| `test-live-tunnel.sh` | Same-host Linux live tunnel negatives/positives |
| `test-package-interop.sh` | Package-to-package host-to-host release evidence |

## Website CTA boundary

The website Homebrew command may activate only after a complete package-interop
evidence document exists for the published release artifacts.
