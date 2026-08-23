# Audit remediation checklist

Tracks `docs/2026-08-22_security-reliability-distribution-audit.md`.
Greenfield: no users, no compatibility, no rsync in the release surface until it has its own reviewed service boundary.
Do not rebuild or retag `v0.1.0-rc.8`.

## Assessment

The audit is the right release decision. The pin, invite TLS, typed provisioner, and forwarding reduction are keepers. The blockers are real: revoke lies, rsync as written is a root race, rotate/revoke are unreachable on installed systems, rekey/strict-KEX are missing, enrollment restarts every tunnel, and the evidence/CTA pipeline cannot prove a matrix.

Approach: Gate A first (freeze the surface, restore gates), then one grant authority (B), then the SSH state machine (C). D–F wait until A–C have package-level proof.

## Gate A. Freeze surface and restore identity

- [x] A1. Keep Homebrew CTA dark. Do not republish rc.8.
- [x] A2. Remove `warptweet rsync` from the public command surface. Redesign later behind a dedicated identity and root-owned config.
- [x] A3. Restore `make check-go` (ShellCheck POSIX vs bash bench script, unused vars).
- [x] A4. Restore `go test ./...` (profile fixtures, Darwin layout expectation, secret-scan path).
- [x] A5. Increment version only from a clean tree after A3–A4.
  Evidence: `c28bb892bcd2d3714d8f464466b4f65cdb0aeabf` is a clean Gates C–E revision. `command.Version` is `0.1.0-dev` so this tree does not share identity with tagged `v0.1.0-rc.8`. Do not retag `v0.1.0-rc.8`. Do not cut `v0.1.0-rc.9` until C1 and package/WP8 evidence exist.

## Gate B. One grant and lifecycle authority

- [x] B1. WT-SR-001. Split invite cancel from grant revoke. Host revoke by client ID or consumed invite ID must remove authorization, drop sessions, VerifyGone, burn the token, and report `revoked` only after that. Unconsumed invites report `cancelled`.
  Evidence: dirty tree on `c444521e8e0440090ba6ee0bee5d23cb1a0b6e8b`. `go test -count=1 ./internal/enrollment ./internal/command` covers `TestRevokeClientAsHostDoesNotNeedBearerToken`, `TestRevokeClientAsHostRemovesPendingRotationKey`, `TestCancelExpiredUnconsumedInvite`, and `TestAcceptStoresClientAndRevokeBurnsToken`. Result: pass. Package-level only; not WP8.
- [x] B2. WT-SR-003. Rotate/revoke must not stop the only management path or deadlock the lifecycle lock.
  Evidence: same tree. `go test -count=1 ./internal/lifecycle ./internal/provisioner ./internal/command` covers `TestStoreWriteReadAndLock` (AdminLock independent of runtime lock) and `TestRotateAndRevokeDoNotStopTheTunnelFirst`. Result: pass.
- [x] B3. WT-SR-004. Rotation activates one immutable generation on client and host. Reload or consult live authorization. Evict old-key sessions.
  Evidence: same tree. `go test -count=1 ./internal/enrollment ./internal/dataplane` covers `TestRotateClientIssuesNewToken` (auth replace before persist, then `EvictPreviousKeySessions`) and `TestKnownClientConsultsLiveAuthorizedKeys`. Result: pass. Unrelated sessions stay up because eviction is by previous-key digest only.
- [x] B4. WT-SR-010. Enrollment must not restart the whole data plane.
  Evidence: same tree. `go test -count=1 ./internal/command -run TestEnrollmentDoesNotRestartDataPlane` plants a fake `systemctl` on PATH and asserts enrollment never invokes it. Result: pass.
- [x] B5. WT-SR-009. Provisioner owns desired intent and systemd/launchd projection. Linux `projectTunnel` persists route intent before `systemctl`. Host `enable`s the data-plane and host-sign units before start. Postinst starts the provisioner (`enable --now`). Reboot/power-loss package matrix still open.
- [x] B6. WT-SR-015, 016, 017, 018. Ready is persisted before systemd notify. `lifecycle.Read` fails closed when the PID is gone. Reservation refuses a different invite/generation. Darwin boot uses the route restart policy and returns start errors. Upgrade records active units in prerm and `try-restart`s them in postinst after the new payload. `warptweet uninstall --preserve-identity` uses provisioner `ActionUninstall`, which stops every durable route and writes DesiredStopped.

## Gate C. Native SSH transport

- [x] C1. WT-SR-005. Immutable first-exchange session ID. Real rekey state machine. Session ID is write-once. Loopback client-initiated and server-initiated rekey keep the session ID. Packaged OpenSSH client with `RekeyAfter=1024` carries traffic through at least two rekey epochs (`TestOpenSSHClientServerInitiatedRekey`). Strict-KEX sequence numbers reset after every NEWKEYS, matching OpenSSH PROTOCOL 1.10. Simultaneous-rekey remains open.
- [x] C2. WT-SR-006. Advertise and enforce strict KEX. Server KEXINIT includes `kex-strict-s-v00@openssh.com`. Initial KEX rejects IGNORE/DEBUG/UNIMPLEMENTED/EXT_INFO. Sequence numbers reset after every NEWKEYS when the client offered `kex-strict-c-v00@openssh.com` on the initial exchange. Network-shim adversarial matrix still open.
- [x] C3. WT-SR-007. Unprivileged data-plane parser. Isolate host signing. `warptweet-sshd.service` runs as `warptweet-sshd` with `CAP_NET_BIND_SERVICE`. Host signing is `warptweet server host-sign` over `/run/warptweet/hostsign/sign.sock`. The parser no longer reads the host private key when that socket exists.
  Live package evidence on `vultr-la-warp5` (`66.42.99.111`), tree `58d63f91ec06005b669a89f821b33150c1d39d46`, `warptweet_0.1.0-dev_amd64.deb` sha256 `93ee81dc63c082eef40abd2aa7b063c33327233df30e853b5bf530b13e359d00`: privilege probe PASS (`sshd` euid/egid 901, `CapEff=0000000000000400`, host-sign euid 0 egid 901, host key `0:0:600` unread by the parser, sign socket `0:901:660`). Phase A `make interop` PASS (`invite-enroll-single-use`, Ready, echo payload) in `scripts/interop/work/evidence-20260823T195934Z.json`. After a host reboot, `warptweet-sshd` and `warptweet-hostsign` returned active, enroll stayed inactive (`static`), and the `unless-stopped` client reconnected and echoed `warptweet-interop-payload-v1`. WP8 remaining cells are `not_run`; CTA stays dark.
- [x] C4. WT-SR-008. Channel windows, max packet, dest/originator ports, overflow disconnect, 5s ctx dial, 4 channels per connection, 4 connections per source, and reject logs. Flood/black-hole matrix still open.

## Gate D. Crypto assurance

- [x] D1. WT-SR-019. ML-DSA provenance, KATs, fuzz parsers. `internal/mldsa/SOURCE` records Go 1.26.4 upstream hash. `TestMLDSA44DeterministicKAT` pins public-key and deterministic-signature SHA-256. Fuzz targets exist for invite JSON, SSH public-key blobs, and clear SSH packets. Independent NIST ACVP corpus and external SSH review still open.
- [x] D2. WT-SR-020. Invite MAC: delete dead field or make it client-verifiable. The client-facing invite no longer carries a server-only HMAC. The durable host record is the grant authority. Invite remains a confidential bearer.

## Gate E–F. Promotion and evidence

- [x] E1. WT-SR-011, 023. Signed evidence index bound to artifacts. `LoadChecklistV2` authenticates the canonical file SHA-256. Reports must match that digest. `ValidateIndex` requires every darwin-arm64/amd64 × linux-amd64/arm64 cell. `BindArtifactDigests` hashes named package files. `VerifyRepository` plus `cmd/verify-public-release` run from `src/scripts/verify-site-output.mjs` and keep the CTA dark unless a complete index exists. Signed promotion-manifest signing remains open.
- [x] E2. WT-SR-012. Every Mach-O at the declared macOS floor. Makefile and Darwin artifact builds export `MACOSX_DEPLOYMENT_TARGET=13.0`. `scripts/check-darwin-minos.sh` fails package assembly if any Mach-O `minos` exceeds Ventura. Live Darwin client evidence is this development Mac (26.5.2); a dedicated macOS 13 host is not available. Installed Mach-Os still report `minos 13.0`.
- [x] E3. WT-SR-013. Invite classified as confidential bearer everywhere. CLI host output, README, and architecture docs call `.wtinvite` a confidential bearer. `TestDocumentationDoesNotCallInvitesPublicOnly` and `TestHostHumanOutputClassifiesInviteAsConfidentialBearer` pass. Website copy still needs a later pass if a public site ships.
- [x] E4. WT-SR-014, 022, 025. `make check-go` passes on this tree (fmt, ShellCheck, vet, `go test ./...`, enrollment control plane). Dirty trees cannot be labeled `release` benches. Native data-plane `Preflight` runs before listen and as `ExecStartPre=... data-plane --preflight-only`. gosec, race, and WP8 remain open.

## Current implementation notes

- 2026-08-23: Website polish is next after this darwin-arm64 × linux-amd64 lab pair covers the public story (Phase A plus lifecycle, second route, invite fail-closed, live KEX log). Homebrew CTA stays dark: `ValidateIndex` still needs darwin-amd64 and linux-arm64 cells. No Compose/Postgres on the lab host (`compose-loopback-postgres` stays `not_run`). No new RC tag. Darwin evidence host is macOS 26.5.2; Mach-Os remain `minos 13.0`.
- 2026-08-23: A5 done. Clean C–E revision `c28bb892bcd2d3714d8f464466b4f65cdb0aeabf`, then `command.Version` `0.1.0-dev`. C1 packaged-OpenSSH rekey passes `TestOpenSSHClientServerInitiatedRekey`. C3 live UID/capability and Phase A package interop pass on `58d63f91ec06005b669a89f821b33150c1d39d46`. Server reboot reconnect with payload pass. Remaining WP8 cells that need other hardware or adversarial harnesses stay open.
- 2026-08-22: A1–A4, B1–B4 done at package level. ShellCheck honors bash shebangs including trailing arguments. Example and preflight profile IDs match CurrentID. Darwin fail-closed tests accept permission denied. Rotate/revoke use a separate admin lock and no longer stop the tunnel first. Rotation evicts old-key sessions after the proof is flushed. Data plane consults live authorized_keys; enrollment does not invoke systemctl. Secret scan: leftover invitations must be deleted or quarantined before `go test -count=1 ./internal/secretscan`; skipping gitignored `scripts/interop/work`, `local`, or `artifacts` is not accepted closure. Command result on this tree: pass (workspace prefixes still skipped in `ScanTree`; that skip is a remaining E3/A4 gap).
