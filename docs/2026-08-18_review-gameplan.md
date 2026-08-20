# Review gameplan

Implementation plan. Incorporates `docs/reviews/2026-08-18_claude-holistic-review.md` and `docs/reviews/2026-08-18_review-reconciliation.md`.

WarpTweet has no users and no compatibility debt. Do not patch expedient paths. Delete them and ship the contracts already written in `docs/2026-08-16_adoption-and-release-strategy.md` sections 7.6 through 7.9, PRIV-005 through PRIV-008, LEASE-009 through LEASE-014, and SEC-001.

The cryptographic core is already at the standard this plan requires. The work is the lifecycle, privilege, release, and operator-contract layers catching up to that core.

## Stance

- No dual implementations, feature flags, or "until v2" shims.
- No PID-as-authority, even with start-time or nonce binding.
- No v1 release evidence. Delete it.
- No `|| true` on security-boundary commands.
- No root process that execs the tunnel engine, even as a fallback.
- No invite secret material in JSON, logs, status, website, or evidence.
- No calendar estimates. Sizing is productivity points.

## Decisions locked by the reconciliation

Adopt the gameplan's overrides of the original review. In particular: delete `lifecycle.Store.Signal`; delete the `runUp` fallback; three invite output channels; one grant journal; full Linux account tuple or fail the transaction; delete v1 evidence rather than repointing it; pin the Go toolchain before adding analyzers; make `run` unit-only; fold clock rollback into the grant journal; delete public `connect --once`.

Three amendments from the reconciliation, plus one correction to its privilege-path recommendation:

1. Settle the `up`/`down` privilege path as the first deliverable of B, before C, D, or E. The path is a Linux provisioner, not a path unit. See below.
2. Darwin exec-binding is the sealed generation directory plus a code-signature check. Linux uses `/proc/self/fd/<N>` through `os/exec`, not raw `execveat`.
3. Delete v1 evidence in A, not I. I keeps the fixture and interop-fail-closed work that depends on F.

## Privilege path

This was unspecified and blocks B.

Rejected:

- `sudo warptweet up`. Recreates the root CLI. Manifest parsing, invite handling, and state writes run as root.
- Polkit rules on `warptweet-tunnel@*`. New dependency. Absent on minimal and container hosts.
- Operator writes `/etc/warptweet/routes/*/desired.json` and a `systemd.path` unit fires reconcile. Contradicts the already-specified layout: that tree is root-owned package authority (`docs/2026-08-10_client-layout.md`, CLIENT-001). An unprivileged operator cannot write it. `connect` must also commit identity, manifest, and receipt into that sealed tree, not only flip desired state. A drop-box plus path unit is a provisioner with extra steps and a worse input surface. Path activation also makes connect readiness a timer race.

Required: the same typed unix-socket provisioner macOS already has (`internal/provisioner`, `cmd/warptweet-provisioner`).

```text
unprivileged warptweet connect|up|down|repair|rotate|revoke
        -> validate locally
        -> typed request on /run/warptweet/provisioner.sock
        -> root warptweet-provisioner
              writes sealed route tree
              projects warptweet-tunnel@<validated-route-id>
        -> CLI waits for unit readiness and reports

boot / crash recovery
        -> warptweet-reconcile.service
              reads sealed tree
              projects the same units
              never execs the engine
```

Rules:

- Socket is `root:warptweet-operator` mode `0660`. `warptweet-operator` is a group only, not a login or service account. Do not reuse `warptweet` or `warptweet-client`.
- Protocol stays typed. No shell text, paths, unit fragments, executable options, or environment values (strategy 7.8). Delete `Once` from the protocol when public `--once` dies.
- Provisioner writes the sealed tree and projects synchronously. `connect` does not wait on a path unit. After the provisioner returns, the CLI waits for authenticated-forward readiness with a bounded timeout. Timeout is `enrolled_not_ready` with hint `warptweet repair <route>`, not a separate path-activation code.
- Missing provisioner is `provisioner_unavailable`.
- `status` and `routes` read sealed state and unit evidence. They do not require the provisioner for the read path.
- `run` remains unit-only. The provisioner never calls `run` or `ssh`. It only `systemctl start|stop|enable|disable` on a validated unit name.
- Boot reconcile is the same projector without an operator. Keep the oneshot. Do not add a path unit.
- macOS stays on the existing provisioner. One protocol, two service-manager backends.

This is B's first deliverable, not a research spike. C, D, and E do not start until Linux `up`/`down` go through the socket and a tunnel process is never root.

## Target design

### 1. Process authority

Service manager is the only thing that starts or stops a tunnel. The CLI never signals a PID.

`lifecycle.State` keeps generation, unit name, listen endpoint, phase, and observed PID as evidence. It loses `Signal`. `processAlive(pid)` is deleted from command, lifecycle, enroll, and provisioner. A running tunnel is identified by the unit plus `/proc/<pid>/exe` or the launchd program path, compared to the attested generation, and only for status.

`run` accepts only a managed-lifecycle invocation from the unit (systemd credentials or the launchd equivalent, plus `--managed-lifecycle`). Direct `warptweet run` returns `usage` and exit 2.

Linux reconcile and provisioner:

- Root may validate route IDs and issue `start`/`stop`/`enable`/`disable` on `warptweet-tunnel@<validated-route-id>` only.
- Route ID is validated before interpolation. No shell. Argv vector only.
- Projection failure is a hard failure for that route. Never `runUp`.
- Harden `warptweet-reconcile.service` to the set `warptweet-tunnel@.service` already carries, including `KillMode=control-group`. The template is not the problem. The reconcile unit and the `runUp` fallback are.
- `prerm` stops and disables sshd, enroll, provisioner, reconcile, and every `warptweet-tunnel@` instance.

macOS: `RunAtLoad` derives from desired state and current boot identity on every boot. No static prior-boot plist authority.

### 2. Connect transaction

Implement strategy 7.7 in this exact order. The current order is inverted (`SubmitEnrollment` at `lifecycle.go:158`, `ReservePort` at `:225`).

1. Strict-read and validate the invite.
2. Show the operator view. Require `--yes` for non-TTY.
3. Atomically reserve route ID and listen port. Persist a transaction record.
4. Stage generation and local secrets.
5. Enroll over invite-pinned hybrid TLS.
6. Persist host proof and authorization expiry.
7. Activate generation and desired state via the provisioner.
8. Provisioner projects to the service manager as the dedicated identity.
9. Wait for authenticated-forward readiness bound to the unit.
10. Report `connected` only after readiness.

Transaction states are durable and explicit: `reserved`, `staged`, `enrolled`, `activating`, `connected`, `enrolled_not_ready`, `failed`. A crash leaves the record. It never leaves a consumed invite with no local authority.

`connect` on the same invite file is the exact-retry path when the host record and local pending identity still match.

`warptweet repair <route>` finishes activation and projection for `enrolled_not_ready`. It does not re-enroll and does not mint anything.

`--listen-port` collision fails closed with `local_port_conflict`. WarpTweet never picks a different port.

Delete public `connect --once`. `--restart unless-stopped|manual` is the only public restart flag. Contradictory flag pairs are usage errors.

### 3. Grant journal

One typed state machine for every host-side grant mutation.

```text
active
  -> revocation_pending -> revoked
  -> expiry_pending     -> expired
  -> rotation_pending   -> active (new generation) | revoked (old)
  -> clock_blocked      -> (operator recovery) active | revoked
```

The reconciler runs before the enrollment listener is marked ready, and on a periodic loop:

1. Ensure the authorization line is absent or replaced as required.
2. Terminate every mapped session for that generation.
3. Verify the processes and local forward are gone.
4. Burn the management token only after verification.
5. Commit the terminal status.

Interrupted revoke, expire, or rotate cannot leave an established session as the steady state.

Clock rollback uses the same journal: remove effective authorization, terminate sessions, persist `clock_blocked`, refuse new invites until an explicit recovery command.

### 4. Host lock and enroll listener

One host-wide exclusive lock covers identity derivation, invite-secret creation, TLS material, listener start, manifest write, and invite mint. Contention returns `host_busy` with the lock path.

The enrollment listener:

- Accept semaphore before `tls.NewListener`, sized below the process FD budget, released on `Conn.Close` and on abandoned connections.
- Handshake deadline independent of handler timeouts.
- Per-source token bucket behind an LRU. No full-scan limiter.
- Header and body caps stay.

Hardening sequence step 3 then makes enroll ephemeral. Do not invest in a permanent public enroll surface beyond these bounds.

### 5. Operator contract

One public outcome type, used by every command. `--json` is global. If requested, stdout is exactly one JSON object on success and on failure. Human stderr is derived from the same typed error.

Exit 0 success. Exit 2 usage, including unknown command and bad flags. `--help` is exit 0.

Documented codes:

| Code | Next action |
| --- | --- |
| `usage` | Fix flags or command. `--stdout --json` together is this. |
| `preflight_failed` | Repair the package-owned layout. Do not substitute system ssh. |
| `engine_missing` | Reinstall the package. |
| `host_busy` | Retry. |
| `stale_state` | `warptweet repair <route>` or inspect the unit. Never signal a PID. |
| `local_port_conflict` | `down` the holder or pass `--listen-port N`. |
| `host_unreachable` | Check host and enroll port, then retry the same invite. |
| `invite_expired` | Ask the host for a new invite. |
| `invite_consumed_retryable` | Host record matches and local pending identity is intact. Retry the same `connect`. |
| `invite_consumed` | Invite is burned and local pending identity is gone. Ask the host for a new invite. |
| `invite_mismatch` | Do not retry. Request a new invite. |
| `enrolled_not_ready` | `warptweet repair <route>`. |
| `provisioner_unavailable` | Start or reinstall the client package so the provisioner socket exists. |
| `clock_blocked` | Operator recovery on the host. |
| `package_boundary` | Missing systemctl, wrong service account, or layout mismatch. |

`gateway`, `server init`, and `server invite` print the replacement command and exit 2.

Invite output channels are exclusive:

- Default: write the invite file. Human summary on stderr or stdout as today, without MAC or nonce.
- `--stdout`: raw invite bytes on stdout. No JSON wrapper.
- `--json`: metadata only (`invite_id`, `invite_expires_at`, `authorization_duration_seconds`, path). File write still happens. Never `invite`, `mac`, or `nonce` at any depth.
- `--stdout --json` is `usage`.

Flags and help come from one table per command. Internal flags (`--ready-fd`, `--managed-lifecycle`) are absent from public help and rejected without the managed-lifecycle context.

### 6. Package and supply chain

Linux maintainer scripts match the macOS installer, then go further:

- Fixed system UID/GID for `warptweet`, `warptweet-client`, `warptweet-sshd`.
- `warptweet-operator` group for provisioner socket access.
- Pre-existing name allowed only if the entire tuple matches. Otherwise fail the transaction.
- `usermod`, `daemon-reload`, `enable`, `disable` failures fail the transaction.
- No `|| true` in the RPM spec or in `postinst`/`prerm`.

Go toolchain and interop images meet the OpenSSH fetch standard: closed version to SHA-256 table, `mktemp -d` mode 0700, no predictable `/tmp` names, no env override on evidence or release paths, digest check before extraction, images pinned by digest.

`*.wtinvite`, `/artifacts/`, `*.pem`, `*.key`, `*.p12`, `*.pfx` are gitignored. The live invite is deleted. Tracked installers leave the index. CI scans for invite and key patterns. History rewrite happens before the repository is public.

### 7. Release gate

v2 is the only evidence schema. `ValidateEnabledCTA` calls `LoadChecklistV2` / `ValidateReportV2` / `CompleteV2`, requires the expected source commit and published package digests, and is invoked from the publish workflow.

The Astro check requires a real evidence route. Every README and website command example is fixture-tested against the CLI. `make interop` fails on partial evidence.

### 8. Exec binding and small correctness

- Linux: hold the inspected `O_PATH` descriptor and exec `/proc/self/fd/<N>` through `os/exec`. Do not call `execveat` from Go.
- Darwin: sealed root-owned generation directory is the primary contract, plus a code-signature validity check at launch. There is no fd-exec.
- Trust assets live in that sealed generation directory.
- Management-token and digest compares go through one `constantTimeDigestEqual`.
- Invite file write fsyncs the file and the parent directory.
- Failed readiness unlinks the mux socket through the retained root.
- Client hashing and `ssh -V/-Q/-G` capture use the server preflight size bound.

The exec-swap threat requires write access to root-owned `/opt/warptweet/bin`. It is defense-in-depth. Do not block B, C, or D on it. The other items in this section are cheap and do not wait on exec work.

## Workstreams

### A. Hygiene and v1 deletion — 1

Delete `staging-db.wtinvite`. Update `.gitignore`. `git rm --cached` the committed installers. Confirm `security@warptweet.com` is monitored. Add the CI secret-pattern scan. Delete `checklist-v1.json`, `LoadChecklist`, `ValidateReport`, `Complete`, and every test that writes v1 fixtures. Point `ValidateEnabledCTA` at v2.

No other work starts while a live invite can be published by `git add -A`, or while complete v1 evidence can turn the CTA green.

### B. Process authority — 8

Linux provisioner socket and group. Delete PID signaling. Make `run` unit-only. Make reconcile a projector with no `runUp` fallback. Harden the reconcile unit to the tunnel template's profile. Fail-closed Linux accounts and maintainer scripts. `prerm` tears everything down.

C, D, and E do not start until Linux `up`/`down` go through the provisioner.

### C. Connect journal — 5

Reserve-then-enroll. Durable transaction states. Exact-retry `connect`. `repair` for activation. Delete public `--once`. Collision is `local_port_conflict`.

### D. Grant journal — 5

One pending-state reconciler for revoke, expire, rotate, and clock-block. Restart simulation with a persisted pending record and a live session.

### E. Host lock and bounded enroll — 3

Exclusive host lock through ready and invite mint. Accept-bounded listener. LRU token bucket. Concurrent `host` tests. Abandoned-connection permit release.

### F. Operator contract — 5

One outcome package. Exit taxonomy. Global `--json`. Generated help. `gateway` replacement message. Invite output channels. Redaction tests.

### G. Exec binding and crypto hygiene — 3

`/proc/self/fd` on Linux, sealed directory plus signature check on Darwin, constant-time digest helper, invite dir fsync, bounded copies, mux cleanup on failed readiness.

The non-exec items may land as soon as A is done. Exec binding may overlap B/C/D and must not gate them.

### H. Supply chain — 3

Pinned Go toolchain and interop images. Private temp dirs. ShellCheck. `gosec` with reviewed suppressions only.

### I. Docs and interop fail-closed — 2

Website and README fixtures against the real CLI. Real evidence URL. `make interop` fails on partial evidence.

Depends on F's output contract.

## Sequence

```text
A hygiene + delete v1
  -> B process authority, starting with the Linux provisioner
       -> C connect journal
       -> D grant journal
       -> E host lock and bounded enroll
  -> F operator contract   (can overlap C/D/E once the outcome type exists)
  -> G cheap items anytime after A; exec binding overlaps and does not gate
  -> H supply chain        (can overlap after A)
  -> I docs and interop    (last: depends on F)
```

Do not start hardening-sequence step 2 until B, C, and D are in a package. Step 3 replaces the permanent enroll listener after E's bounds exist. Step 4 stays last.

## Tests that must exist

- PID reuse: stale state file, recycled PID of an unrelated process, `down` does not signal it.
- `warptweet run` without managed-lifecycle context returns usage and exit 2.
- Reconcile privilege: cgroup UID/GID/exe/argv/env/caps read-back. Tunnel is never root. Reconcile and provisioner never exec `ssh` or `warptweet run`.
- Unprivileged `up`/`down` succeed only via the provisioner socket. Direct `systemctl` from the CLI is absent.
- Maintainer scripts: conflicting pre-existing account fails the package transaction. Each script failure fails RPM/dpkg.
- Connect crash between enroll and reserve is impossible because reserve is first. Crash after enroll leaves `enrolled_not_ready` and `repair` finishes it.
- Restart with `revocation_pending` and a live grant-session reaches `revoked` and a dead session without a second operator `revoke`.
- Clock rollback closes sessions and blocks invites.
- More than `N` partial-TLS connections held; one valid enroll still succeeds.
- Accept semaphore releases when the peer drops without a clean close.
- Concurrent `host` returns `host_busy` and does not double-mint identity.
- `--json` failure for every error class is one object, no invite MAC/nonce, no management token.
- `host --json` contains no `invite`, `mac`, or `nonce` at any depth. `host --stdout --json` is usage.
- Invite file on the real write path is mode 0600 and the parent directory is fsynced.
- v2 gate rejects complete v1 evidence and incomplete WP8.
- `make interop` fails when any required v2 case is missing.
- README `render-authorized-key` and website CLI card match `warptweet` output fixtures.
- CI secret-pattern scan fails on a planted `.wtinvite` and a planted private key.
- Root `/tmp` symlink attack against bootstrap and interop scripts fails closed.

## Do not do

- Do not add a classical KEX or host-key fallback.
- Do not put shell, exec, SFTP, or a multiplexed control channel on the WarpTweet data plane.
- Do not keep `runUp` "just for macOS" or "just when systemctl is missing."
- Do not add polkit, `sudo warptweet`, or a group-writable drop-box under `/etc/warptweet`.
- Do not add a `systemd.path` reconciler as a second authority next to the provisioner.
- Do not version-gate the Error schema behind a second output mode.
- Do not leave `checklist-v1.json` in the tree as a reference.
- Do not brand WarpTweet experimental.
- Do not start the WarpTweet-only daemon or a management-plane product from this plan.

## Related

- `docs/reviews/2026-08-18_claude-holistic-review.md`
- `docs/reviews/2026-08-18_review-reconciliation.md`
- `docs/2026-08-16_adoption-and-release-strategy.md`
- `docs/2026-08-18_hardening-sequence.md`
- `docs/2026-08-18_use-cases-and-roadmap.md`
- `docs/2026-08-17_host-state-layout.md`
- `docs/2026-08-10_client-layout.md`
