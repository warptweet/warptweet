# Release-evidence v3

- Status: **Implemented contract**
- Date: 2026-08-24
- Frozen parent: `docs/2026-08-24_host-bind-and-advertise.md`

This edition records bind/dial publication. It does not loosen
`schemas/release-evidence-v2.schema.json`. v2 remains historical with
`additionalProperties: false`.

## Documents

| Artifact | Path |
| --- | --- |
| Checklist | `packaging/evidence/checklist-v3.json` |
| Report schema | `schemas/release-evidence-v3.schema.json` |
| Index schema | `schemas/release-evidence-index-v3.schema.json` |
| Go types | `internal/releaseevidence/v3.go` |
| Writer | `cmd/write-release-evidence` |

The writer `Validate`s, then writes atomically. Duplicate result IDs and
unknown JSON properties fail closed without creating the output file.

## Public index

The required architecture matrix is unchanged: darwin-arm64/amd64 ×
linux-amd64/arm64. That is four cells.

Additional networking cells:

| ID | Required | Model |
| --- | --- | --- |
| `gce-one-to-one-nat` | yes | GCE 1:1 NAT, darwin-arm64 × linux-arm64, bind ≠ data dial, no DNAT helper |
| `port-mapped` | yes | Independent data and enrollment publication |
| `dns-dial` | yes | DNS locators, recorded resolved addresses |
| `ipv6-bind-equals-dial` | yes | IPv6 bind equals dial |
| `passthrough-nlb` | no | Passthrough TCP load balancer |

Proxy load balancers, TLS termination, and PROXY protocol are not cells.

A GCE arm64 run is one networking cell. It does not complete the four-cell
matrix by itself.

## Networking fields

Every v3 report carries binds, dials, invite dials, observed listeners,
absence of test DNAT and loopback aliases, client dial results with error
class, SPKI and host-key results, `published_endpoint_generation`,
`enrollment_resolved_addr`, `data_resolved_addr`, operator firewall and
load-balancer assumptions, package-only, and clean tree.

`match_binds` is true only when observed listener `address:port` values
canonicalize to the recorded binds. `invite_dials_match_published` is true
only when the minted invite locators equal the published dials.
`clean_tree` is true only for `clean` / `git-status-empty` proofs.

Client error classes stay on the client and in evidence:
`dns_resolution`, `tcp_connect`, `tls_negotiate`, `tls_spki`,
`invite_authorization`, `ssh_host_key`, `forward_target`.

## Interop harness

- `WARPTWEET_INTEROP_SERVER_LISTEN` is bind.
- `WARPTWEET_INTEROP_SERVER_ADVERTISE` is unset by default.
- `--advertise` is passed only when advertise is set.
- Mac TCP uses published dials.
- Guest observations fail closed: iptables and nft must both be queried.
  `test_dnat_absent` is true only when neither table rewrites the published
  data/enrollment locator (LISTEN/ADVERTISE ports or advertise address).
  Docker DNAT of loopback Postgres (`127.0.0.1:5432`) is ignored. Missing
  tools remain fail-closed. Loopback must be listed, and `ss`/`netstat`
  listeners must be captured. `match_binds` and `test_dnat_absent` are never
  defaulted to true.
- darwin-arm64 × linux-arm64 with IP `ADVERTISE` ≠ `LISTEN` is classified as
  the `gce-one-to-one-nat` networking cell.
- There is no in-tree `wt-gcp-bind` DNAT unit.

## Website gate

`packaging/evidence/public-release.json` points at checklist-v3. The Homebrew
CTA stays dark until a complete v3 index exists. Do not enable the CTA in this
edition.
