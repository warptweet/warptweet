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
- [ ] A5. Increment version only from a clean tree after A3–A4.

## Gate B. One grant and lifecycle authority

- [x] B1. WT-SR-001. Split invite cancel from grant revoke. Host revoke by client ID or consumed invite ID must remove authorization, drop sessions, VerifyGone, burn the token, and report `revoked` only after that. Unconsumed invites report `cancelled`.
  Evidence: dirty tree on `c444521e8e0440090ba6ee0bee5d23cb1a0b6e8b`. `go test -count=1 ./internal/enrollment ./internal/command` covers `TestRevokeClientAsHostDoesNotNeedBearerToken`, `TestRevokeClientAsHostRemovesPendingRotationKey`, `TestCancelExpiredUnconsumedInvite`, and `TestAcceptStoresClientAndRevokeBurnsToken`. Result: pass. Package-level only; not WP8.
- [x] B2. WT-SR-003. Rotate/revoke must not stop the only management path or deadlock the lifecycle lock.
  Evidence: same tree. `go test -count=1 ./internal/lifecycle ./internal/provisioner ./internal/command` covers `TestStoreWriteReadAndLock` (AdminLock independent of runtime lock) and `TestRotateAndRevokeDoNotStopTheTunnelFirst`. Result: pass.
- [x] B3. WT-SR-004. Rotation activates one immutable generation on client and host. Reload or consult live authorization. Evict old-key sessions.
  Evidence: same tree. `go test -count=1 ./internal/enrollment ./internal/dataplane` covers `TestRotateClientIssuesNewToken` (auth replace before persist, then `EvictPreviousKeySessions`) and `TestKnownClientConsultsLiveAuthorizedKeys`. Result: pass. Unrelated sessions stay up because eviction is by previous-key digest only.
- [x] B4. WT-SR-010. Enrollment must not restart the whole data plane.
  Evidence: same tree. `go test -count=1 ./internal/command -run TestEnrollmentDoesNotRestartDataPlane` plants a fake `systemctl` on PATH and asserts enrollment never invokes it. Result: pass.
- [ ] B5. WT-SR-009. Provisioner owns desired intent and systemd/launchd projection.
- [ ] B6. WT-SR-015, 016, 017, 018. Status truth, reservation idempotency, reboot policy, upgrade/uninstall.

## Gate C. Native SSH transport

- [ ] C1. WT-SR-005. Immutable first-exchange session ID. Real rekey state machine. Session ID is now write-once; rekey state machine remains open.
- [ ] C2. WT-SR-006. Advertise and enforce strict KEX.
- [ ] C3. WT-SR-007. Unprivileged data-plane parser. Isolate host signing.
- [ ] C4. WT-SR-008. Channel windows, max packet, channel quotas, dial timeouts, admission control.

## Gate D. Crypto assurance

- [ ] D1. WT-SR-019. ML-DSA provenance, KATs, fuzz parsers.
- [ ] D2. WT-SR-020. Invite MAC: delete dead field or make it client-verifiable.

## Gate E–F. Promotion and evidence

- [ ] E1. WT-SR-011, 023. Signed evidence index bound to artifacts.
- [ ] E2. WT-SR-012. Every Mach-O at the declared macOS floor.
- [ ] E3. WT-SR-013. Invite classified as confidential bearer everywhere.
- [ ] E4. WT-SR-014, 022, 025. Green required gates. No dirty `release` benches. Native data-plane preflight.

## Current implementation notes

- 2026-08-22: A1–A4, B1–B4 done at package level. ShellCheck honors bash shebangs including trailing arguments. Example and preflight profile IDs match CurrentID. Darwin fail-closed tests accept permission denied. Rotate/revoke use a separate admin lock and no longer stop the tunnel first. Rotation evicts old-key sessions after the proof is flushed. Data plane consults live authorized_keys; enrollment does not invoke systemctl. Secret scan: leftover invitations must be deleted or quarantined before `go test -count=1 ./internal/secretscan`; skipping gitignored `scripts/interop/work`, `local`, or `artifacts` is not accepted closure. Command result on this tree: pass (workspace prefixes still skipped in `ScanTree`; that skip is a remaining E3/A4 gap). Rekey, strict KEX, privilege drop, and remaining gates still open.
