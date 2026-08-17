# WarpTweet project status (reviewer brief)

Status date: 2026-08-15  
Audience: top-down technical / product review  
Version in tree: `0.1.0-dev` (not a public release tag)  
Website Homebrew CTA: **dark** (`packaging/evidence/public-release.json`)

This document is a **historical 2026-08-15 snapshot**. The current
implementation and release contract are defined in
`docs/2026-08-16_adoption-and-release-strategy.md`. Do not treat this brief as
current release truth.

This document is a snapshot for orientation. Prefer linked design docs for
normative contracts. It is not release evidence.

---

## 1. What this is

WarpTweet is a **managed TCP tunnel** product built on a **pinned, fail-closed
OpenSSH + OpenSSL profile** (post-quantum KEX and vendor-qualified composite
host/user auth). It is **not** a general SSH client, shell, SOCKS proxy, or
ad-hoc port-forward toolkit.

Canonical user story:

1. Linux host runs a WarpTweet **host** aimed at one internal TCP target
   (for example Postgres on `127.0.0.1:5432`).
2. Operator mints a **single-use invite**.
3. macOS (or Linux) client **enrolls**, then **`up`** opens a **loopback-only**
   local port that forwards over the fixed crypto profile to that target.

Example:

```text
psql → 127.0.0.1:15432  ── WarpTweet ──►  host ──►  127.0.0.1:5432 (Postgres)
```

Docker Compose fits by publishing the DB only on host loopback (or an internal
network) and pointing the host at that address; cloud firewalls open tunnel
ports, not the database.

---

## 2. Product principles (do not dilute in review)

- Prefer ideal system design over expedient protocol or security compromises.
- Immutable wire profile; **no classical KEX fallback** on post-quantum-required
  profiles.
- Do not brand WarpTweet itself as “experimental”; scope that word only to
  OpenSSH’s description of its vendor-qualified authentication binding.
- Do not market the OpenSSH vendor-qualified auth binding as standardized,
  quantum-proof, or FIPS validated.
- `.wt` is a versioned **manifest**, never a private-key container.
- Website install CTA stays off until **package-to-package** dual-host evidence
  exists for the published digests.

Primary design entry points:

| Topic | Doc |
| --- | --- |
| Architecture / CLI / invites | `docs/2026-08-14_reviewer-catchup-cli-invites-architecture.md` |
| Homebrew delivery contract | `docs/2026-08-12_homebrew-delivery.md` |
| Public CTA gate | `docs/2026-08-12_public-release-path.md` |
| Package interop evidence | `docs/2026-08-12_package-interop-evidence.md` |
| Dual-host orchestrator | `docs/2026-08-14_dual-host-interop-orchestrator.md` |
| Client lifecycle | `docs/2026-08-12_client-lifecycle.md` |
| macOS layout / attestation | `docs/2026-08-12_macos-client-attestation.md` |

---

## 3. Architecture (top-down)

```text
┌──────────────────── client ────────────────────┐
│ warptweet (controller)                         │
│   enroll / connect / up / run / status / down  │
│   production layout + codesign + preflight     │
│ pinned OpenSSH client (static OpenSSL)         │
│ state: identity, trust, client.wt              │
│ runtime: /Library/Caches/wt or /run/...        │
└────────────────── SSH data plane ──────────────┘
                      │
                      │ mlkem768x25519-sha256
                      │ ssh-mldsa44-ed25519@openssh.com
                      │ chacha20-poly1305 / AES-GCM
                      ▼
┌──────────────────── server ────────────────────┐
│ warptweet host                                 │
│   identity, policy, both listeners, invite     │
│ internal server enrollment service             │
│ pinned OpenSSH sshd (PermitOpen = one target)  │
│ systemd units (sshd + enroll)                  │
└────────────────────────────────────────────────┘
```

**Wire vs platform:** cryptographic profile is separate from
platform artifact profiles (`linux-amd64`, `linux-arm64`, `darwin-arm64`,
`darwin-amd64`). Do not weaken Linux ELF gates to admit Darwin; Darwin has its
own layout and Mach-O rules.

**CLI split worth knowing:**

| Command | Role |
| --- | --- |
| `host` | Server bootstrap + invite + enroll listener |
| `connect` | Enroll from invite then bring tunnel up |
| `enroll` | Durable local activation only |
| `up <id>` | Operator-facing start; spawns `run`, updates lifecycle status; **defaults to `--once`** |
| `run` | Foreground data-plane supervisor (service units use this) |
| `status` / `down` / `rotate` / `revoke` | Lifecycle |

Restart policy: keepalives detect dead paths (~15s × 3). With `--once`, the
process does not self-restart (LaunchDaemon/systemd should). Without `--once`
on `run`, the in-process supervisor uses bounded exponential backoff from the
client manifest. Enrollment is durable across network flaps; the SSH session is
not.

---

## 4. What is substantially built

### Control plane and CLI

- Invite mint/accept, single-use semantics, and invite-pinned HTTPS control plane.
- Client lifecycle: enroll, up/run, status, down, rotate, revoke surfaces.
- Host path for “mint invite + ensure enroll listen.”
- Doctor / doctor-server preflight with typed profile status fields
  (`authentication_binding_status`, `support_status`).
- Production path fail-closed checks (layout, ownership, linkage, codesign on
  Darwin when Team ID is set).

### Engines and packages

- Authenticated OpenSSH + OpenSSL **fetch/build** scripts for Linux and Darwin
  (full upstream regress; local-dev may skip known-broken cases such as `scp3`
  on some macOS hosts for client stages that do not ship `scp`).
- Linux `.deb` assembly (`scripts/build-linux-packages.sh`) and systemd units.
- macOS `.pkg` assembly (`scripts/build-macos-pkg.sh`), dedicated non-login
  `_warptweet` identity, a typed root provisioner on a `root:admin` Unix socket,
  and generated per-tunnel LaunchDaemons that run the data plane as
  `_warptweet`.
- Local-dev artifact helper: `scripts/interop/ensure-artifacts.sh` (client pkg
  local; server deb via Docker or remote host).
- Sample artifacts may exist under `artifacts/` as `0.1.0-dev` builds (lab only).

### Interop / evidence harness

- Phase A dual-host orchestrator: `make interop` → `scripts/interop/dev-run.sh`
  → `orchestrate.sh` + libs (SSH pin/TOFU for local-dev, package install, echo
  fixture, host, connect, payload, evidence NDJSON/JSON).
- Website public-release gate remains **disabled** until complete evidence.

### Website

- Astro site with install panel driven by the dark CTA gate; local
  `make site-up` / preview targets exist.

### Recent hardening (in-flight on working tree as of this brief)

Not all of the following may be committed; reviewers should diff `main` and the
working tree.

- Enrollment locks: non-Unix path must not treat PID as stable lock identity;
  Plan 9 / unsupported owner probes.
- Interop: full JSON escaping; package DB ownership for provenance; fixture
  cleanup trap; deb post-install verify; signature case vs digest pins; SSH
  `StrictHostKeyChecking=yes` + known_hosts/fingerprint; lifecycle `up --once`
  failure handling; evidence exit codes for `fail` vs expected `not_run`.
- Darwin production Team ID set to **CP4268Q8UF** (Baldwinson Corporation
  Developer ID).
- OpenSSH `-o` values: quote tokens that need spaces (Application Support
  paths); do not quote bare keywords like `none`.
- Private client identity file mode **0600** (OpenSSH rejects group-readable
  keys).
- Server `authorized_keys` written **0644** so sshd privsep can read a
  non-home path.
- Enroll activation chowns client state files to service group when root.
- Interop: always pull the invite minted this run; skip redundant deb
  reinstall; run installed Darwin client commands as the login administrator
  through the typed provisioner without `sudo` or AppleScript elevation;
  optional codesign in `ensure-artifacts`.
- Enrollment control requests use exact TLS 1.3, hybrid
  `X25519MLKEM768`, `http/1.1`, and the invite-pinned Ed25519 SPKI. Certificate
  renewal preserves the pinned key.
- Enrollment, rotation, and revocation use durable pending states and
  converge exact retries after response loss or restart.
- The foreground supervisor stops after ten consecutive failed launches; a
  stable run resets the counter.

Prior lab notes report **enroll + authenticated forward + echo payload** on a
real VPS and Mac with signed client binaries. That evidence predates the current
revision and must be reproduced from clean packages before release. Full green
`make interop` / complete WP8 matrix is **not** yet a release gate pass.

---

## 5. Critical gaps before “easy public first release”

Ordered by dependency, not calendar estimates (sizing stays in productivity
points elsewhere).

### P0 — Prove the operator privilege model from the package

- The zero-password-after-install path is implemented in source: the `.pkg`
  creates a dedicated non-login identity, starts one root provisioner with a
  typed `enroll` / `up` / `status` / `down` / `rotate` / `revoke` request
  protocol, and generates a closed per-tunnel LaunchDaemon running as
  `_warptweet`.
- The login administrator calls the installed CLI normally. The provisioner
  socket is `root:admin` mode `0660`; active state remains protected and the
  `_warptweet` group has no supplementary users. No arbitrary shell, path,
  launch label, plist, owner, mode, or OpenSSH option crosses the socket.
- This is not yet release evidence. A clean signed-package run must prove the
  exact account, socket, ACL, state, launchd PID, no-second-prompt, restart,
  upgrade, and uninstall contracts on both supported Mac architectures.

### P0 — Release artifacts and evidence

- No signed release tag; version still `0.1.0-dev`.
- No complete committed `warptweet.release-evidence` for published digests.
- Homebrew CTA must stay dark until package-to-package dual-host evidence is
  complete and wired into `public-release.json`.
- Notarized, arch-specific client pkgs + signed Linux server packages + pinned
  cask URLs/checksums are required for the public install path.
- Official Homebrew/homebrew-cask is optional later; first public path is the
  **owned tap** (`warptweet/tap/warptweet`) per delivery docs.

### P1 — Lifecycle and ops evidence

- `up` deliberately launches `run --once`; launchd or systemd owns service
  restart. Direct `run` remains bounded to ten consecutive failed launches.
- `host` now converges the fixed host identity, server manifest,
  authorization state, restricted sshd, pinned-TLS enrollment service, and
  invite, and reports ready only after both listeners accept connections.
- The deb assembler uses `dpkg-deb --root-owner-group`, and postinstall
  reasserts fixed account and path policy. These contracts still need a clean
  package-only dual-host run against the exact release digest.

### P1 — Interop automation quality

- Phase A orchestrator now uses only `host` and the typed macOS provisioner.
  Firewall setup and package signing remain operator/release-runner inputs;
  current package-to-package evidence is still incomplete.
- Signature verification cases often `not_run` until platform signer tooling
  and release signing are standard.
- Full WP8 negative matrix remains largely unexecuted in automation.

### P2 — Website and messaging

- CTA scaffolding and qualification copy exist; do not enable install command
  early.
- Keep status axes typed (product vs OpenSSH binding disclosure).

---

## 6. Suggested first public bar

A single sentence gate:

> Clean Mac + clean Linux VPS: install signed packages only, one invite,
> enroll without repeated admin password after install, `up`, loopback payload
> matches, evidence JSON complete, website CTA still policy-gated until that
> evidence is committed for those digests.

Concrete checklist:

1. Prove the implemented Darwin provisioner and per-tunnel LaunchDaemon path
   from a clean signed package on arm64 and amd64.  
2. Produce signed+notarized client pkgs and signed Linux server packages; pin
   digests.  
3. Run the complete automated dual-host matrix on those artifacts (not source-tree
   controllers).  
4. Tag release, publish artifacts, SBOM/provenance as required by release docs.  
5. Commit evidence; enable CTA only via `public-release.json` validation.

---

## 7. How to navigate the tree

| Area | Path |
| --- | --- |
| Controller CLI | `cmd/warptweet`, `internal/command` |
| Engine / preflight / SSH policy | `internal/engine` |
| Enrollment | `internal/enrollment` |
| Supervisor / lifecycle state | `internal/supervisor`, `internal/lifecycle` |
| Profiles | `internal/profile`, `internal/artifactprofile` |
| Install layout constants | `internal/installlayout` |
| OpenSSH build | `scripts/build-openssh.sh`, `build-openssh-darwin.sh` |
| Packages | `scripts/build-linux-packages.sh`, `build-macos-pkg.sh`, `packaging/` |
| Interop | `scripts/interop/`, `make interop` |
| Website | `src/`, `make site-*` |
| Public gate | `packaging/evidence/public-release.json`, `internal/publicrelease` |

Useful make targets: `check`, `check-go`, `test`, `interop`, `site-check`,
`site-up`.

---

## 8. Risk register (reviewer focus)

1. **Shipping before package-level service-user proof** → a source contract
   mistaken for a working zero-password installation.  
2. **Lighting Homebrew CTA without package-to-package evidence** → policy and
   trust failure.  
3. **Over-claiming crypto** (standardized / FIPS / “quantum-proof”) → explicit
   project prohibition.  
4. **Lab-only binary swaps** (scp controller onto VPS) mistaken for release
   quality → require package digests only.  
5. **Nested restart policies** (`run` restart vs unit restart) if both enabled
   carelessly.  
6. **Darwin path spaces + OpenSSH `-o` quoting** → fixed in engine; keep tests
   covering Application Support paths.  
7. **authorized_keys mode / identity 0600** → easy to regress; OpenSSH and
   privsep are strict.

---

## 9. Working tree note (2026-08-15)

As of this brief, `main` history is shallow (early WIP commits) with a large
set of uncommitted or partially committed interop and Darwin client fixes.
Reviewers should treat **design docs + package contracts** as the north star
and the working tree as active integration toward the dual-host bar, not as a
frozen release candidate.

---

## 10. One-page summary

| Axis | State |
| --- | --- |
| Product definition | Clear: managed PQ-profile TCP tunnel, loopback client, single target |
| Core Go + engines | Largely implemented; production fail-closed posture |
| Packages | Assemblers exist; public signed/notarized release path incomplete |
| Dual-host proof | Lab progress; full automated evidence gate not green |
| macOS zero-password UX | Implemented in source; clean signed-package proof incomplete |
| Public install CTA | Correctly dark |
| First release blocker | Signed artifacts + clean package lifecycle proof + complete evidence run |

**Review ask:** pressure-test the typed provisioner and package lifecycle,
then prioritize signed artifact production and package-to-package evidence over
expanding the command or transport surface.
