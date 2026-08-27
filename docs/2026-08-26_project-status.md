# WarpTweet project status

- Date: 2026-08-26
- Audience: technical owner
- Freeze branch: `first-edition`
- Version in tree: `0.1.0-dev` (`internal/command.Version`)
- This document is a snapshot. It is not release evidence and does not replace the v3 index.

Normative contracts remain in the dated design docs and in
`packaging/evidence/`. Prefer those over older README sentences when they
disagree. The README and `public-release.json` now split **qualification
complete** from **public distribution ready**; the Homebrew command is not
shown until the latter is true.

---

## 1. What the product is

WarpTweet makes **one remote TCP service** appear on **localhost**. The operator
manages both endpoints. The client never gets a shell, SOCKS, mesh, or a
WarpTweet account.

Canonical path:

1. Linux host: `warptweet host --to 127.0.0.1:5432` (or another concrete
   target). The host binds data-plane SSH and pinned-TLS enrollment, then mints
   a single-use invite.
2. Apple Silicon Mac: `warptweet connect <invite.wtinvite>` enrolls and opens a
   loopback-only listener (`127.0.0.1:<port>`).
3. Ordinary tools (`psql`, `curl`) talk to that local port. Credentials for the
   target service stay with the target, not in WarpTweet.

Crypto profile is immutable Profile v1: OpenSSH 10.4p1, OpenSSL 3.5.7, KEX
`mlkem768x25519-sha256`, host/user `ssh-mldsa44-ed25519@openssh.com`, cipher
`chacha20-poly1305@openssh.com`. No classical fallback.

Public CLI: `host` on Linux, `connect` / `up` / `down` / `status` / `rotate` /
`revoke` on the client. `gateway` and `server init` / `server invite` are
rejected, not aliased.

---

## 2. Snapshot identity

| Item | Value |
| --- | --- |
| Freeze branch | `first-edition` |
| Evidence source commit in the index | `ef12b34` (Intel Mac dropped from the required matrix; packages and interop ran here) |
| Version string | `0.1.0-dev` |
| Existing tags in this clone | `v0.1.0-rc.1` … `v0.1.0-rc.8` |
| Intended remote | `https://github.com/warptweet/warptweet.git` |
| Qualification | complete (`qualification_complete: true`) |
| Public distribution | not ready (`public_distribution_ready: false`) |

Do not retag `v0.1.0-rc.8` or invent `rc.9` for this work. A public release is
a new signed tag of a non-`dev` version with matching artifacts.

The four-PR bind/advertise stack that this branch absorbs is locally named
`execute-plan/d12c7250-pr-1` … `pr-4`. A deferred fifth PR (if any) is not in
this snapshot. `main` in this clone is still `7f93b24` (“Pre networking
assessment overhaul”) and is behind this branch.

---

## 3. Where we actually are

The **implementation and lab evidence** for first-edition Apple Silicon are
done. The **public distribution channel** is not.

In one sentence: a technical owner can prove the signed Mac client talks to the
signed Linux host on the required topologies. The website records that
qualification as complete and still withholds the Homebrew command until
public distribution is ready.

| Facet | State |
| --- | --- |
| Product CLI and data plane | Implemented on this branch |
| Package-to-package evidence (v3) | Complete for the first-edition matrix |
| Website | Qualification complete; Homebrew command hidden until `public_distribution_ready` |
| Homebrew tap + GitHub release | Not published |
| Linux apt/yum repository | Not published |
| Official `homebrew/cask` | Not started |
| Windows client | Roadmap only |
| Intel Mac client as a gated platform | Explicitly out of first edition |

---

## 4. Evidence and the Homebrew gate

### Contract

- Checklist: `packaging/evidence/checklist-v3.json`
- Checklist SHA-256: `fc0b77c83b84814abec97f0770f9f1a50a507e99211b9e2d048ac019141984a1`
- Index: `packaging/evidence/release-evidence-index-v3.json`
- Gate: `packaging/evidence/public-release.json`
- Validator: `go run ./cmd/verify-public-release` and
  `internal/publicrelease.ValidateEnabledCTA`

`CompleteV3` (matrix reports) requires every checklist result `pass`,
package-to-package, clean tree, no test DNAT, no loopback alias, invite schema
3 matching published dials, guest listeners matching binds.

`CompleteNetworking` (topology reports) does not require the two workstation
reboot/pid-reuse cases. Those may remain `not_run` on networking-only reports.

### First-edition matrix (required)

Apple Silicon client only:

| Client | Server | Report | Checklist |
| --- | --- | --- | --- |
| `darwin-arm64` | `linux-amd64` | matrix, 28/28 pass | reboot + pid-reuse included |
| `darwin-arm64` | `linux-arm64` | matrix + `gce-one-to-one-nat`, 28/28 pass | same |

`darwin-amd64` remains a **buildable** artifact profile
(`internal/artifactprofile`, `scripts/build-macos-pkg.sh`). It is **not** a
CTA cell. The Homebrew cask is `depends_on arch: :arm64` and has no Intel URL.
Lab Intel `.pkg` files may exist under gitignored `artifacts/`; they do not
gate the site.

### Required networking cells

| Cell | Publication | Notes |
| --- | --- | --- |
| `gce-one-to-one-nat` | bind guest NIC, dial GCE public IPv4 | Combined with the linux-arm64 matrix report. No guest iptables/nft DNAT helper. |
| `port-mapped` | equal public ports on different hosts (443) | socat on a second VM; guest still binds 2222/29722 |
| `dns-dial` | nip.io A-labels, resolve-once | Dials are DNS names, not IP literals |
| `ipv6-bind-equals-dial` | GUA bind = GUA dial | Home DHCPv6-PD client, GCE dual-stack host |

Optional, not in the index: `passthrough-nlb`. Proxy load balancers, TLS
termination, and PROXY protocol are not first-edition cells.

### Packages the index actually proves

All five reports use `release_version` `0.1.0-dev` and source commit
`ef12b34`:

| Artifact | SHA-256 prefix |
| --- | --- |
| `warptweet-client_0.1.0-dev_arm64.pkg` | `9ac81eb1d624…` (notarized; Team ID `CP4268Q8UF`) |
| `warptweet_0.1.0-dev_arm64.deb` | `0492cd8c0455…` (GPG `7738DDB55DE99435`) |
| `warptweet_0.1.0-dev_amd64.deb` | `3752505cae23…` |

Those files live in gitignored `artifacts/`. The committed index records the
digests, not the blobs. A public release of version `0.1.0` (or any non-`dev`
string) is **new artifacts** and needs a new index.

### Workstation cases that were blocking CTA

| ID | Consumer meaning | Status on matrix reports |
| --- | --- | --- |
| `reboot-unless-stopped-manual-down` | After a real Mac reboot, `unless-stopped` comes back; `manual` and `down` stay down | pass |
| `pid-reuse-and-stop-failure` | `status` is not Ready for a killed `_warptweet` pid | pass |

The harness is two-phase: `WARPTWEET_INTEROP_ALLOW_REBOOT=1` writes
`scripts/interop/work/reboot-resume.json`, reboots, then `make interop` resumes.

---

## 5. Website

Stack: Astro 7 static site, `pnpm@10.15.1`, Node 22. Entry:
`src/pages/index.astro`. Install panel reads
`packaging/evidence/public-release.json` via `src/lib/install.ts`.

**Now:** the install panel reports first-edition qualification complete and
does **not** render `brew install` while `public_distribution_ready` is false.
Next-action copy remains `warptweet connect <invite-file>`.

Verified in this tree with `pnpm run verify` (astro check, build,
`src/scripts/verify-site-output.mjs`). That is HTML/build verification, not a
click-through of a deployed warptweet.com.

**Not done:** GitHub release assets, the public tap, a clean-Mac brew install
bound as distribution evidence, then `public_distribution_ready: true` and
production deploy.

Treat `public-release.json` as authority over older docs that still mention a
single `homebrew_cta_enabled` flag.

---

## 6. Distribution

### macOS client

- Layout: `/Library/Application Support/WarpTweet`, service user `_warptweet`,
  root provisioner `com.warptweet.provisioner`.
- Installer: Developer ID + notary + stapler (`scripts/build-macos-pkg.sh`).
- Cask template: `homebrew/Casks/warptweet.rb.tmpl`, rendered by
  `go run ./cmd/warptweet-cask --version … --sha256-arm64 …`.
- First edition: **arm64 only**. `depends_on macos: ">= :ventura"`.
- Mach-O `minos` on current binaries has been 13.0. A dedicated macOS 13
  runner was waived; Ventura remains the cask floor.

### Linux host

- Public `host` is Linux-only. Darwin `host` fails closed.
- Packages: `.deb` for `linux-amd64` and `linux-arm64`, detached GPG.
- Units: `warptweet-sshd`, `warptweet-hostsign`, enrollment as a static unit
  started by `host`. Privilege probe: sshd euid 901, `cap_net_bind_service`
  only; host-sign root/egid 901; host key not readable by the parser.
- No guest `iptables`/`nft` DNAT in maintainer scripts. Publication is bind +
  `--advertise`, plus operator firewall / second-VM port-map / LB.

### What is not shipped

- No GitHub Release for `0.1.0-dev` matching the cask URL pattern
  `…/releases/download/v#{version}/warptweet-#{version}-darwin-arm64.pkg`.
- No public or private Homebrew tap with the rendered cask and pinned SHA-256.
- No Linux package repository metadata (apt source, RPM repo).
- No SBOM / provenance attestations on a release tag.
- `scripts/release-candidate.sh` still expects a non-`dev` version plus
  installer identity, notary profile, and GPG key. Invited-tap doc
  (`docs/2026-08-16_private-tap-invited-install.md`) is the intended channel
  before official Homebrew.

Until those exist, qualification-complete is a **repository** fact, not an
installable product.

---

## 7. Implementation contract (first edition)

Schemas in force:

| Surface | Version |
| --- | --- |
| Invite | 3 |
| Client tunnels | 2 (`Server.Host`) |
| Server gateway / `server.wt` | 2 |
| Release evidence | 3 |
| Client route desired-state | 1 (`unless-stopped` / `manual`) |

Bind/advertise (see `docs/2026-08-24_host-bind-and-advertise.md`):

- Bind ≠ dial is allowed and required for GCE 1:1 NAT.
- One bind address per service; both-families unique candidates fail closed
  and name `--listen`.
- DNS locators: lowercase ASCII A-labels, resolve-once, interleaved sequential
  IPv6/IPv4 walk, no happy-eyeballs, `ResolvedDialPlan` recorded.
- Enrollment restarts on published-set / generation / cert-leaf change.
- Host-operation flock spans write+apply+verify+mint; enroll returns 503 while
  held.
- HMAC `invite.mac-key` is gone. Do not recreate it.
- Empty SAN certificates; SPKI pin in the invite.
- Default `maxConnsPerSource = 4` (proxy LBs collapse that bucket).

---

## 8. Testing

### In-tree

- `make test` / `go test ./…` — unit and package tests, including evidence
  schema, CTA gate, cask renderer, host bind/dial.
- `make test-race`, `make test-openssh-integration` (needs
  `WARPTWEET_OPENSSH_PREFIX`).
- `make site-check` → `pnpm run verify`.
- GitHub Actions `.github/workflows/ci.yml`: website verify, schema copy
  check, compose config, website image build. CI becomes authoritative after
  this freeze is pushed.

### Package-to-package interop

- Entry: `make interop` (loads gitignored `.env`).
- Orchestrator: `scripts/interop/orchestrate.sh`.
- Dual-host, signed `.pkg` + `.deb` only. Source-tree controllers are
  rejected.
- Lab used GCE us-west2 spots (`c4a` ARM, `n2` amd64), 4 hour
  `maxRunDuration` then **STOP** (disks keep billing; ephemeral public IPv4
  **changes** on start). SSH is IP + key, not OS Login.
- GCE IPv6 required converting the default VPC auto-mode → custom-mode
  (one-way) and dual-stacking `us-west2` with EXTERNAL IPv6.

Interop does **not** replace CI. It is the release evidence producer.

---

## 9. Documentation debt

These still speak in the past tense relative to this snapshot:

- `docs/2026-08-16_adoption-and-release-strategy.md` — still written as if
  there were no package evidence.
- `docs/2026-08-16_private-tap-invited-install.md` — still requires both Mac
  archs for invited install.
- `docs/2026-08-12_public-release-path.md` — may still show an older gate JSON
  example; the live file uses `qualification_complete` /
  `public_distribution_ready`.

Do not treat 2026-08-15 reviewer briefs as current release truth.

---

## 10. What needs further work

Ordered for a public first edition. Do not expand scope until the install
command actually installs.

### P0 — make `brew install` true

1. Pick a non-`dev` version (or keep `-dev` only for lab; do not put `-dev` on
   the public cask).
2. Rebuild/notarize `darwin-arm64` `.pkg` and GPG-sign both Linux `.deb`s from
   that tag. Digests will change; **re-run the v3 index** (or at least bind
   new SHA-256s through a new complete interop) before setting
   `public_distribution_ready`.
3. Create GitHub release assets at the URL the cask template encodes.
4. Publish `homebrew/Casks/warptweet.rb` to `warptweet/homebrew-tap` with
   exact version + arm64 SHA-256 (`cmd/warptweet-cask`).
5. Deploy the website that is already built from the light CTA.
6. Refresh README and the invited-tap / adoption docs so they do not
   contradict the gate.

### P1 — release hygiene

- Signed source tag; do not move `v0.1.0-rc.8`.
- SBOM and provenance for the published blobs.
- Linux repository metadata if `apt install` is a promised path (Homebrew is
  the website primary).
- After this freeze is on GitHub, let CI run on `first-edition` / `main`.
- Keep the public Homebrew command dark until a clean supported Mac has
  installed the published artifact.

### P2 — explicitly later

- Intel Mac (`darwin-amd64`) as a supported, evidenced platform.
- Passthrough NLB cell.
- Windows client (`docs/2026-08-24_windows-client-implementation-roadmap.md`).
- macOS 13 as a dedicated evidence runner (cask floor remains Ventura).
- Official Homebrew/core or Homebrew/cask submission.
- Proxy load balancers (out of contract).

### Operational leftovers (lab)

- Spot VMs auto-STOP after 4 hours; start them again for more interop.
- Ephemeral IPv4 changes on start; `.env` advertise names must be updated.
- Leftover client routes from many interop names accumulate on the operator
  Mac (`interop-mac-*`, old `mac-rc*`). `forget` / uninstall as needed.
- GCE default VPC is custom-mode with us-west2 dual-stack; leave that unless
  tearing the lab down.

---

## 11. How to verify this snapshot

```sh
go run ./cmd/verify-public-release
go test ./internal/publicrelease ./internal/releaseevidence ./internal/releasemetadata
pnpm run verify
```

`public-release.json` must have `qualification_complete: true`,
`public_distribution_ready: false` until a bound brew install exists, and
`required_evidence_document` equal to
`packaging/evidence/release-evidence-index-v3.json`. The index must still
hash-match checklist-v3.

A successful `brew install --cask warptweet/tap/warptweet` on a clean Apple
Silicon Mac is the missing external proof. It is not recorded in this
repository yet.
