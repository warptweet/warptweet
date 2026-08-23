# WarpTweet security and reliability distribution audit

Status date: 2026-08-22  
Audit type: independent source, lifecycle, protocol, and release-boundary review  
Audited revision: `c444521e8e0440090ba6ee0bee5d23cb1a0b6e8b` (`v0.1.0-rc.8`) plus the dirty working-tree snapshot below  
Audit environment: macOS 26.5.2, arm64, Go 1.26.4  
Release decision: **NO-GO for public distribution**  
Public Homebrew CTA: **must remain disabled**

Working-tree snapshot for the release decision (paths relative to the repository root). The tagged object is `c444521e8e0440090ba6ee0bee5d23cb1a0b6e8b`. Dirty and untracked files that informed the original findings:

| Path | SHA-256 | Note |
| --- | --- | --- |
| `internal/command/rsync.go` | (absent) | Present and untracked at audit time; removed from the tree after the NO-GO. Do not restore it. |
| `scripts/run-bench.sh` | `3a7e67871cf323b113d99905e7f4027d48af4cbc293b3cd63a2470ae8e5e33a8` | Untracked bench runner. |
| `internal/composite/bench_test.go` | `45a70ba95218eaacc4b7383642fd3247ab3a0dc23ad73e5695ee871fbd04f3d8` | Untracked. |
| `internal/dataplane/bench_test.go` | `35434334fe0daf31872505424aced0a1f344dfa3d7f9faba069b458b53691b82` | Untracked. |

The remainder of the dirty tree is the in-progress remediation on top of `c444521`. A later candidate must be cut from a clean immutable revision, not this snapshot.

## 1. Executive conclusion

WarpTweet has progressed well beyond a concept demonstration. The repository contains several strong controls: an exact hybrid cryptographic profile with no classical fallback, composite host and user authentication, invite-pinned TLS enrollment, bounded and strict JSON parsing in important paths, forwarding-only authorization, typed provisioner protocols, PID-reuse-resistant Linux session authority, pinned upstream source identities, and a deliberately dark public-install gate.

Those controls are meaningful. They do not, however, make the current candidate safe to distribute.

This audit found two critical release blockers:

1. `warptweet server revoke <consumed-invite-id>` can report `"status":"revoked"` while the enrolled client's authorization and established sessions remain usable.
2. The new, currently untracked rsync helper places a root-consumed daemon configuration under a shared `nobody`-owned directory. If released as written, it creates a credible local root escalation and root file-clobber path. It can also expose an unauthenticated writable rsync module on a non-loopback target address.

It also found high-severity defects in installed rotation and revocation, authorization reload, SSH rekeying, strict key-exchange behavior, SSH channel flow control, root privilege separation, Linux reboot intent, package lifecycle, macOS compatibility, and release-evidence authority. Several are structural state-machine defects that unit tests can pass without exercising.

The correct conclusion is therefore:

> The product direction is viable and its core controls are substantial, but `v0.1.0-rc.8` and the current dirty worktree are not distribution-ready. A new candidate should be cut only after the critical findings and the release-blocking high findings are closed with package-level evidence.

This is a release decision, not a claim that every reviewed component is insecure. No exploit was executed, no signing key was used, and no external system was changed.

## 2. Scope and method

The review traced the current execution paths rather than accepting historical design documents as implementation proof. It covered:

- invite creation, parsing, enrollment, consumption, rotation, revocation, expiry, and clock rollback;
- client route generation, desired state, lifecycle locking, readiness, status, reboot, upgrade, uninstall, and crash recovery;
- the native SSH data plane's identification, KEX, authentication, packet protection, forwarding policy, channel flow control, session registration, and shutdown;
- Linux systemd and macOS launchd privilege boundaries;
- macOS and Linux package assembly, signer checks, artifact identity, supported-platform claims, CI gates, interoperation evidence, public CTA validation, and benchmark provenance;
- cryptographic implementation provenance, tests, cross-implementation evidence, fuzzing, and static-analysis coverage.

The review compared the implementation with:

- the repository's threat model and cryptographic profile;
- RFC 4253 and RFC 4254 state and flow-control requirements;
- OpenSSH's strict-KEX behavior and its published Terrapin countermeasure;
- the repository's release-evidence checklist and package contracts;
- the Central security, reliability, testing, supply-chain, and evidence requirements.

The historical `docs/2026-08-15_project-status-reviewer-brief.md` correctly labels itself as a stale snapshot. It still describes a pinned OpenSSH server in places, while the current code operates a native Go SSH data plane. This audit treats the current code as authority and identifies the resulting documentation drift separately.

### 2.1 Severity model

| Severity | Meaning in this audit |
| --- | --- |
| Critical | A practical condition can yield host privilege escalation, or the product can claim that compromised access was revoked while it remains authorized. Release is blocked. |
| High | A plausible condition defeats a core confidentiality, authentication, recovery, lifecycle, platform-support, or release-integrity guarantee. Release is blocked until fixed and proven. |
| Medium | Defense in depth, assurance, or a narrower operational contract is materially incomplete. It may become release-blocking when combined with another finding. |
| Low | A bounded hardening, usability, or correctness defect with limited direct security impact. |

## 3. Release-blocking findings

### WT-SR-001: Host revocation can claim success without revoking access

**Severity:** Critical  
**Rules:** SEC-002, SEC-006, ARCH-002, REL-001, UX-004, REPORT-001

#### Evidence

- `internal/command/server_admin.go:58-76` accepts an invite ID, calls `enrollment.Revoke`, and returns JSON containing `"status":"revoked"` and the consumed invite's `client_id`.
- `internal/enrollment/invite.go:285-302` only changes the invite record's status and timestamp. It does not revoke the resulting client record, remove its authorization, burn its management token, or terminate its sessions.
- `internal/command/server_admin.go:78-80` refuses direct client-ID revocation without the client's management token.
- `docs/2026-08-12_client-lifecycle.md:80-82` and `docs/2026-08-12_linux-server-packages.md:64-68` present host-side `server revoke` as an operator recovery path.
- Grants may last up to 365 days under `internal/grant/policy.go:33-40` and `internal/grant/duration.go:14-17`.

#### Failure scenario and impact

An operator loses a client device or suspects its key is compromised. The operator invokes the documented host-side command with the original invite ID. WarpTweet reports that the invite and associated client were revoked, but the client's durable authorization and any established sessions remain active.

This is more severe than a missing feature because the output asserts a security transition that did not occur. The host also lacks a supported root-authoritative emergency revocation path independent of the possibly compromised client's bearer token.

#### Required remediation

Use distinct operations and states for:

- cancellation of an unconsumed invitation; and
- revocation of a consumed grant.

For a consumed invitation, the host authority must resolve the immutable `ClientID`, persist `revocation_pending`, remove and reread authorization, terminate all matching data-plane sessions, call `VerifyGone`, invalidate the management token, and commit `revoked` only after those facts are proven. Root-authoritative client-ID revocation must not require a bearer held only by the compromised client.

#### Closure evidence

- A live authenticated session is closed by host-side client-ID and consumed-invite-ID revocation.
- A new connection using the old key fails immediately.
- The result persists across daemon and host restart.
- Failure after every transaction phase resumes safely and never reports `revoked` before removal and session teardown are proven.
- Exact retries are idempotent.

### WT-SR-002: The proposed rsync helper creates a root-consumed configuration race

**Severity:** Critical in the current dirty worktree  
**Rules:** SEC-001, SEC-002, SEC-003, SEC-004, ARCH-003, REL-001

This finding applies to the untracked `internal/command/rsync.go` and its registration in the modified command tree. It is not attributed to clean `v0.1.0-rc.8`, but it must not be committed or distributed in its current form.

#### Evidence

- `internal/command/rsync.go:77-104` writes a fixed rsync daemon configuration and starts `rsync --daemon --config=<fixed-path>` from a privileged host command.
- `internal/command/rsync.go:282-293` changes both the configuration parent and inbox to the shared `nobody:nogroup` identity with mode `0770`.
- `internal/command/rsync.go:90` uses `os.WriteFile` on that fixed path. A process under the shared identity can unlink, replace, race, or symlink the file before the privileged daemon consumes it.
- `internal/command/rsync.go:337-360` generates `use chroot = false`, writable and write-only module settings, and no `auth users` or secrets file.
- `internal/command/rsync.go:82` binds the daemon to the manifest target address, which need not be loopback.
- `internal/command/rsync.go:40-43` resolves the privileged executable through `PATH`.

#### Failure scenario and impact

A local process sharing the generic `nobody` identity replaces the root-consumed configuration with one that runs the daemon as root against an attacker-selected path, or races a symlink to clobber a root-owned file. Separately, a host configured with a reachable non-loopback target address can expose anonymous write access and unbounded disk consumption outside the authenticated WarpTweet tunnel.

#### Required remediation

Keep the feature out of the release. If it remains in scope later:

- use a dedicated, non-login service identity that is not shared with unrelated daemons;
- keep the configuration directory root-owned and non-writable by the daemon;
- create fixed files atomically with no-follow semantics and verify owner, type, mode, device, and inode before use;
- execute a fixed, attested binary path;
- bind only to an explicitly loopback-only endpoint unless a separately authenticated design is adopted;
- add authentication, quota, disk-full behavior, confinement, service-manager lifecycle, upgrade, shutdown, and audit controls;
- never derive a privileged daemon's security boundary from a user-writable configuration.

#### Closure evidence

Symlink, rename, shared-identity, path substitution, anonymous upload, disk exhaustion, restart, and package-upgrade adversarial tests must pass on clean Linux hosts.

### WT-SR-003: Installed rotate and revoke stop their only management path

**Severity:** High  
**Rules:** ARCH-001, ARCH-002, SEC-006, REL-001, TEST-002

#### Evidence

- The macOS provisioner stops the tunnel before invoking rotate or revoke at `internal/provisioner/server.go:157-161`.
- The Linux provisioner does the same at `internal/provisioner/server_linux.go:139-143`.
- Rotate then POSTs through the tunnel's localhost management forward at `internal/command/lifecycle.go:588-600`; revoke does so at `internal/command/lifecycle.go:709-718`.
- `internal/command/lifecycle.go:969-985` derives that management endpoint from the route's local listen port.
- Keeping the tunnel running does not solve the problem. A managed `run` holds the lifecycle lock for its entire lifetime at `internal/command/command.go:673-681`, while rotate and revoke require the same lock at `internal/command/lifecycle.go:563-568` and `internal/command/lifecycle.go:692-697`.

#### Impact

The standard compromise-recovery and key-rotation commands are structurally unreachable on installed systems: stop first and the endpoint is gone; do not stop and the lifecycle lock is busy.

#### Required remediation

Separate service runtime ownership from administrative transaction locking. Keep an authenticated control path alive until the host has durably acknowledged the operation. A separately authenticated management connection or the invite-SPKI-pinned TLS endpoint with strict bearer authorization and abuse controls are viable designs. Persist all phases so response loss or interruption resumes toward one result.

#### Closure evidence

Package-only rotate and revoke must pass on macOS and Linux with response loss, process kill, host restart, client restart, an active application connection, and an unavailable management endpoint.

### WT-SR-004: Rotation does not activate one coherent new key generation

**Severity:** High  
**Rules:** ARCH-002, ARCH-003, SEC-004, REL-001

This is a combined client and server authority defect.

#### Client evidence

- Initial enrollment correctly creates and activates an immutable route generation at `internal/command/lifecycle.go:232-253`.
- Rotation instead copies the new key into legacy global paths at `internal/command/lifecycle.go:619-640` and changes receipt metadata at `internal/command/lifecycle.go:642-648`.
- It never creates or activates `routes/<route>/generations/<generation>`.
- Runtime always resolves the active route generation at `internal/command/command.go:625-635`, `internal/command/command.go:843-850`, `internal/command/command.go:873-882`, and `internal/routestate/generation.go:98-118`.

#### Server evidence

- The data plane reads authorized keys once at startup at `internal/dataplane/listen.go:23-44` and authenticates from that snapshot at `internal/dataplane/conn.go:297-299` and `internal/dataplane/conn.go:369-375`.
- The dynamic grant authority later checks the current client record at `internal/grantsession/authority.go:160-192`.
- `/v1/rotate` replaces the durable key at `internal/command/enroll_server.go:226-274` but does not reload the data plane or terminate old-key sessions.
- Pending-rotation reconciliation can render the old `record.PublicKey` at `internal/command/enroll_server.go:705-755`, allowing interruption to restore old authorization.

#### Impact

After host authorization changes, the client can continue selecting its old route identity. The new key can be rejected by the static server snapshot, while the old key is rejected by the dynamic grant record. Existing sessions authenticated by a compromised old key are not evicted. The likely result is outage plus incomplete compromise recovery.

#### Required remediation

Make a versioned grant/key generation the single authority across client state, host authorization, and live sessions. Client rotation must stage, fsync, validate, and atomically activate a complete immutable route generation. The server must atomically publish a new authorization snapshot or consult the durable authority during authentication. Old-generation sessions must be selectively terminated and proven gone before rotation is final.

#### Closure evidence

Test every interruption boundary, exact response retry, old-session eviction, new-key success, old-key failure, restart recovery, and simultaneous unaffected clients.

### WT-SR-005: The native SSH server does not implement rekeying correctly

**Severity:** High  
**Rules:** SEC-004, SEC-006, ARCH-003, REL-001

#### Evidence

- `internal/engine/client.go:434` renders `RekeyLimit 512M 1h` for the OpenSSH client.
- `internal/dataplane/conn.go:129-161` accepts later `SSH_MSG_KEXINIT` messages by merely replacing `clientKex`. It does not send a new server `KEXINIT`, enter a rekey state, or constrain application messages during rekey.
- `internal/dataplane/conn.go:192-242` overwrites `sessionID` with every exchange hash at line 217. RFC 4253 requires the session identifier to remain the first key exchange's hash for the life of the connection.
- The current function installs new cipher state before writing `SSH_MSG_NEWKEYS`; that ordering cannot be reused safely for a real rekey, where old keys protect traffic until each direction processes `NEWKEYS`.
- `packaging/evidence/checklist-v2.json` explicitly requires `rekey-same-profile`.

#### Impact

Long-lived tunnels are expected to hang or disconnect when OpenSSH initiates rekey at one hour or 512 MiB. An attempted incremental fix that reuses the current function could also break authentication session binding and key-transition sequencing.

#### Required remediation

Implement an explicit, tested KEX state machine with:

- immutable first-exchange session ID;
- distinct current and pending inbound/outbound keys;
- RFC-compliant `KEXINIT`, exchange, and `NEWKEYS` transitions;
- rejection of application traffic in prohibited states;
- server- and client-initiated rekey;
- cancellation, timeout, sequence exhaustion, and collision behavior.

See [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html), especially sections 7 through 9.

#### Closure evidence

Run a packaged OpenSSH client with `RekeyLimit=1K 0`, carry deterministic traffic through at least two complete rekey epochs, and prove the exact KEX, host-key, and cipher profile in both directions. Add simultaneous-rekey, malformed-rekey, dropped-`NEWKEYS`, and high-byte-count tests.

### WT-SR-006: Strict KEX and its transcript-sequencing protections are absent

**Severity:** High  
**Rules:** SEC-001, SEC-004, SEC-006

#### Evidence

- `internal/dataplane/kexinit.go:13-33` does not advertise `kex-strict-s-v00@openssh.com`.
- `internal/dataplane/conn.go:129-160` tolerates `IGNORE`, `UNIMPLEMENTED`, `DEBUG`, and `EXT_INFO` while initial key exchange is in progress.
- SSH packet sequence numbers are not reset at a strict-KEX `NEWKEYS` boundary.
- `docs/2026-08-09_threat-model.md:130` and `docs/2026-08-09_crypto-profile.md:138` already require strict KEX behavior.

#### Impact

The OpenSSH client cannot negotiate strict KEX with WarpTweet's server, leaving the standardized OpenSSH countermeasure for Terrapin-class prefix manipulation disabled. This audit did not demonstrate a successful exploit against WarpTweet's exact message set, but the implementation violates its own active-network-attacker contract.

#### Required remediation

Implement OpenSSH-compatible strict KEX: negotiate the server extension, reject unexpected messages during initial KEX, reset sequence counters at the correct `NEWKEYS` boundaries, and preserve that behavior for rekey. Use [OpenSSH 9.6 release notes](https://www.openssh.com/txt/release-9.6) and OpenSSH's current `PROTOCOL` and `kex.c` as interoperability references.

#### Closure evidence

A controllable network shim must inject, delete, duplicate, reorder, and delay pre-KEX and rekey messages. Strict peers must fail closed with deterministic audit output; normal OpenSSH peers must interoperate.

### WT-SR-007: The network-facing native SSH parser and session engine run as root

**Severity:** High  
**Rules:** SEC-001, SEC-002, SEC-004, ARCH-005

#### Evidence

- `packaging/systemd/warptweet-sshd.service:11-15` runs `warptweet server data-plane` as `User=root` and `Group=root`.
- `internal/command/dataplane.go:13-33` loads the manifest and starts the native server in that process.
- Identification parsing, KEX and signature processing, authentication, channel parsing, outbound dialing, session tracking, and the host private key therefore coexist in one privileged network-facing process.
- The unit applies useful systemd hardening, but UID 0 still gives a parser compromise access to sensitive in-process keys and every file allowed by the sandbox.

#### Impact

A memory-safety issue in cgo, logic flaw, unsafe dependency, parser resource attack, or future code-execution bug has unnecessarily broad host impact. A custom SSH implementation does not inherit OpenSSH's mature privilege-separation architecture.

#### Required remediation

Run the network parser and forwarder as a dedicated non-login service identity. Isolate host signing and narrowly privileged session mutation behind small, versioned, authenticated local IPC. Use socket activation or a narrowly scoped bind capability only if the configured port requires it. Keep private material unreadable to the parser where practical.

The enrollment and management HTTP/TLS parsers should receive the same treatment. `packaging/systemd/warptweet-enroll.service` and `warptweet-mgmt.service` currently run as root with broad process-control capabilities.

#### Closure evidence

Package inspection and live process evidence must prove effective UID/GID, capabilities, file access, socket ownership, key isolation, IPC authorization, malformed-request denial, and clean helper failure.

### WT-SR-008: SSH channel flow control and resource limits are incomplete

**Severity:** High  
**Rules:** SEC-003, SEC-006, REL-001, PERF-001

#### Evidence

- `internal/dataplane/listen.go:84-129` limits concurrent SSH connections to 64 and uses a 15-second handshake deadline, but has no per-source admission control for the SSH listener.
- `internal/dataplane/forward.go:9-78` allows an unbounded number of `direct-tcpip` channels per authenticated connection. Each successful channel creates a target connection and goroutines.
- `internal/dataplane/forward.go:39-55` uses `net.Dial` without a context or application timeout.
- `internal/dataplane/forward.go:140-172` accepts incoming channel data without tracking or enforcing the advertised receive window and maximum packet size.
- `internal/dataplane/forward.go:175-192` adds peer window adjustments without preventing `uint32` overflow.
- The originator port is narrowed from `uint32` to `uint16` without validating the range at `internal/dataplane/forward.go:48`.
- Connection errors are discarded at `internal/dataplane/listen.go:127-129`, limiting attack and outage observability.

RFC 4254 requires channel data to respect both the remaining window and maximum packet size, and requires the window not to exceed `2^32-1`. See [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html), section 5.2.

#### Impact

One authenticated client can create unbounded channel, socket, goroutine, and memory pressure. A black-holed allowed target can hold all global connection slots for kernel TCP timeout periods. Protocol-violating peers can bypass the server's stated receive window. Repeated pre-authentication KEX work can also consume ML-KEM and ML-DSA/signing resources within the connection deadline.

#### Required remediation

- Add global, per-source, pre-authentication, per-identity, and per-connection limits.
- Bound channels and pending target dials.
- Use a context-aware `net.Dialer` with a short explicit timeout and server cancellation.
- Track receive windows exactly, reject oversize data, and prevent window overflow.
- Validate all port widths and consume every required field exactly.
- Rate-limit expensive KEX/signing attempts and disallow repeated initial-KEX work.
- Emit privacy-safe, rate-limited rejection and saturation telemetry.

#### Closure evidence

Run malformed packet, oversize channel data, window overflow, thousands-of-channels, black-hole target, KEX flood, 64-slot saturation, shutdown-under-load, and one-valid-client-amid-attack tests with explicit CPU, memory, descriptor, goroutine, and recovery budgets.

### WT-SR-009: Linux lifecycle intent and reboot behavior are not durable

**Severity:** High  
**Rules:** ARCH-002, REL-001, OPS-001

#### Evidence

- Installed `up` returns immediately after the provisioner call at `internal/command/lifecycle.go:355-360`, before the non-provisioned path writes `DesiredRunning` at line 369.
- Installed `down` returns at `internal/command/lifecycle.go:484-488`, before the non-provisioned path writes `DesiredStopped` at line 489.
- The Linux provisioner only calls `systemctl start|stop` at `internal/provisioner/server_linux.go:168-191`; it does not own a durable desired-state transaction.
- Boot reconciliation trusts that durable state at `internal/command/lifecycle.go:1415-1428`.
- `warptweet host` starts but does not enable the data plane at `internal/command/host.go:877-903`.
- `packaging/linux/postinst.sh:97-102` enables management, provisioner, and reconcile services, but not the data-plane service. It enables the provisioner without starting it.

#### Impact

- A user-stopped tunnel can return after reboot because `desired.json` still says running.
- A user-started tunnel can disappear after reboot because intent still says stopped.
- A configured WarpTweet host can lose its data-plane listener after reboot.
- An immediate non-root client command after package installation can fail because the provisioner socket has not started.

#### Required remediation

The typed provisioner must own one transaction that validates the route, persists desired intent, projects systemd state, and reads back the exact unit and listener state. Successful host convergence must durably enable the data plane only after configuration and preflight pass. Postinstall must start the provisioner when the package contract promises immediate use.

#### Closure evidence

Clean-package tests must cover install, immediate connect, manual down, manual up, unless-stopped, reboot, service failure, power interruption between intent and projection, and recovery without silent intent reversal.

### WT-SR-010: Enrollment restarts the whole data plane and interrupts unrelated tunnels

**Severity:** High  
**Rules:** ARCH-002, REL-001, UX-004

#### Evidence

- The native data plane snapshots authorized keys once at `internal/dataplane/listen.go:23-44`.
- After accepting one enrollment, `internal/command/enroll_server.go:422-455` runs `systemctl restart warptweet-sshd.service`.
- The unit uses `KillMode=control-group` at `packaging/systemd/warptweet-sshd.service:15-19`.
- The server sends no explicit drain or readiness proof for existing and new clients around this global restart.

#### Impact

Adding one client disconnects every established WarpTweet tunnel on the host. A proof can also be returned while the restarted daemon is not yet ready. This violates multi-client reliability and makes enrollment an availability attack for anyone holding a valid invitation.

#### Required remediation

Make authorization dynamically authoritative or implement atomic, validated, versioned hot reload. Enrollment must not restart the whole data plane. Existing sessions should survive enrollment; revoke and expiry should terminate only the matching grant generation.

#### Closure evidence

Keep two long-lived payload streams active while enrolling, rotating, revoking, and expiring an independent third client. Only the intended session may be interrupted.

### WT-SR-011: Public release evidence does not authoritatively bind the distribution matrix

**Severity:** High  
**Rules:** SEC-005, SEC-006, TEST-003, TEST-004, REPORT-001

#### Evidence

- `packaging/evidence/checklist-v2.json:149-152` requires all Darwin arm64/amd64 client and Linux arm64/amd64 server combinations.
- `internal/publicrelease/gate.go:94-124` validates only one evidence report.
- `internal/releaseevidence/v2.go:75-165` checks field shapes and timestamps but does not open and hash the referenced release artifacts.
- `internal/releaseevidence/v2.go:206-216` considers a submitted report complete when all submitted statuses are `pass`; it does not prove the full matrix index.
- `internal/publicrelease/gate_test.go:156-197` accepts invented commit and digest values and result objects without execution evidence.
- `scripts/test-package-interop.sh:330-360` defaults `clean_tree_proof` to `not_recorded`.
- `internal/releaseevidence/v2.go:53-72` loads checklist structure but does not authenticate the canonical checklist bytes. The checked adoption-contract digest is not the SHA-256 of `packaging/evidence/checklist-v2.json`.
- `src/lib/install.ts:27-33` and `src/scripts/verify-site-output.mjs:59-72` check only website gate shape and command presence. The website container does not run the Go release validator.
- Interop can skip selected packages when same-version binaries are already installed at `scripts/interop/lib/package.sh:135-147` and `scripts/interop/lib/package.sh:190-201`.

#### Impact

A hand-authored, syntactically valid, single-platform all-pass JSON can enable the CTA without proving that the referenced artifacts, signer identities, source revision, installed bytes, or required matrix were tested.

The CTA is currently correctly disabled, so this is a latent promotion-boundary defect rather than an active false public claim.

#### Required remediation

Use a signed release-evidence index that enumerates and validates every matrix cell. The validator must hash the canonical checklist and exact release assets, verify source/tag/version, signer and notary identity, package metadata, extracted and installed executable hashes, engine manifests, OS/architecture, clean source proof, commands, and signed logs. Run the authoritative validator inside the website build that exposes the CTA.

#### Closure evidence

Negative fixtures must prove rejection of fake digests, absent artifacts, incomplete cells, duplicate assets, stale installed bytes, dirty source, wrong signer, wrong architecture, missing detail, `not_run`, and a modified checklist.

### WT-SR-012: Current macOS controllers require macOS 26 while the cask claims macOS 13

**Severity:** High  
**Rules:** ARCH-005, TEST-004, REPORT-001

#### Evidence

- `homebrew/Casks/warptweet.rb.tmpl:27` declares macOS Ventura or newer.
- `scripts/build-openssh-darwin.sh:215-222` sets `MACOSX_DEPLOYMENT_TARGET=13.0` for the OpenSSH stage.
- Controller and provisioner compilation at `scripts/interop/ensure-artifacts.sh:164-170` does not set that target.
- `scripts/build-macos-pkg.sh:90-127` does not inspect each packaged Mach-O's `LC_BUILD_VERSION`.
- A fresh local build through the current path produced:

  ```text
  warptweet              minos 26.0
  warptweet-provisioner  minos 26.0
  ssh                    minos 13.0
  ssh-keygen             minos 13.0
  ```

#### Impact

A cask-advertised installation on macOS 13 through 15 can succeed but install the two control binaries that the operating system cannot execute.

#### Required remediation and evidence

Set the supported deployment target for every compiled Mach-O, including Go and cgo outputs. Extract the final package and fail assembly if any Mach-O exceeds the declared floor. Prove install, launch, connect, lifecycle, and uninstall on a real macOS 13 host before claiming Ventura support.

### WT-SR-013: The invitation is a sensitive bearer capability, despite conflicting documentation

**Severity:** High  
**Rules:** SEC-003, PRIV-001, PRIV-003, UX-004, DOC-002

#### Evidence

- `internal/enrollment/accept.go:82-118` selects a durable invitation using file-contained ID, nonce, and facts.
- The first valid requester chooses the public key, tunnel ID, and management token at `internal/enrollment/accept.go:136-195`.
- The file is single use and expires after 15 minutes, which bounds but does not remove bearer risk.
- `internal/enrollment/invitefile.go:139-192` correctly uses exclusive creation and mode `0600`.
- `docs/2026-08-15_public-release-convergence.md:42` correctly calls it a short-lived confidential capability.
- `docs/2026-08-14_reviewer-catchup-cli-invites-architecture.md:64` still labels it `Public only`, and line 195 labels the enrollment request public-only.

#### Impact

Anyone who obtains the file before the intended client uses it can race to enroll their own composite key for the host-selected authorization duration. Calling the file public encourages unsafe transfer behavior.

#### Required remediation

Classify `.wtinvite` consistently as a confidential, short-lived, single-use bearer capability. CLI help, docs, file metadata, website copy, logs, evidence, and support guidance must require confidential authenticated transfer and immediate deletion after consumption or expiry. A stronger design may bind the invite to a pre-exchanged client-key fingerprint or require host confirmation.

#### Closure evidence

Run disclosure, race, reuse, altered invite, wrong host, wrong target, expired invite, stdout/argv/log leakage, filesystem mode, and redaction tests. Verify all public documentation uses the same classification.

### WT-SR-014: The tagged candidate and current mandatory source gates are not green

**Severity:** High release-process defect  
**Rules:** TEST-003, TEST-004, SEC-005, REPORT-001

#### Current failures

- `make check-go` fails in ShellCheck because `scripts/check-shell.sh:114-118` forces all scripts through POSIX `sh`, while untracked `scripts/run-bench.sh` has a Bash shebang and `set -o pipefail`. It also declares an unused `WT_COMMIT_SHORT`.
- Full `go test ./...` fails in:
  - a Darwin installed-layout test that encounters `permission denied` under the protected fixed layout rather than the expected unprovisioned-state error;
  - release tests because fixed-layout scripts omit the current `-chacha20` profile suffix;
  - manifest conformance because published examples still use the older profile;
  - the secret scan because an ignored local interop invitation remains under `scripts/interop/work/`. The file was not read during this audit.
- Focused release tests confirm that the stale profile references are present in tagged `v0.1.0-rc.8`, not caused by the dirty benchmark work.
- Full `go test -race ./...` fails on the same source/test gates.
- `./scripts/check-gosec.sh` reports 299 untriaged findings. Many are likely false positives in adapted ML-DSA or generated/cgo code, but `internal/dataplane/forward.go:48` includes a real integer-width concern. `Makefile:88` omits `gosec` from `check-go`, so CI does not execute it.

#### Impact

The tagged candidate cannot satisfy the repository's own definition of a release candidate. Dirty changes also retain the same `0.1.0-rc.8` version while adding a public command, so rebuilding under the existing version would create materially different artifacts with the same identity.

#### Required remediation

Do not rebuild or republish `rc.8`. Restore all required gates, remove local secret-bearing evidence from scanned paths through a safe evidence lifecycle, triage static findings, add repository-wide exact-profile drift tests, increment the version, and cut a new candidate from a clean detached checkout.

## 4. Additional high and medium findings

### WT-SR-015: Readiness and status can assert a state that is no longer true

**Severity:** High reliability

- `internal/command/command.go:748-770` notifies systemd readiness before persisting WarpTweet's durable `Ready` state. A state-write failure can therefore occur after `systemctl start` has returned success.
- `internal/lifecycle/state.go:147-171` claims to refresh process liveness but only reads JSON.
- The supervisor exposes detailed phases, but `internal/command/command.go:781-785` constructs it without a state observer. The durable record can remain `Ready` while the SSH child is absent and the controller is backing off.
- Provisioner status does not reconcile systemd or launchd authority at `internal/provisioner/server.go:149-154` and `internal/provisioner/server_linux.go:131-136`.

Commit durable internal state first, notify external observers last, project every supervisor transition, store controller and child identities separately, and reconcile status against the service manager plus exact listener ownership.

### WT-SR-016: Route reservation idempotency can overwrite a different interrupted enrollment

**Severity:** High reliability and authorization integrity

- Enrollment reserves before host contact at `internal/command/lifecycle.go:132-136`.
- `internal/routestate/generation.go:153-165` treats an existing same route and port as an idempotent match without comparing invite ID or generation.
- `internal/routestate/transaction.go:65-92` then overwrites `transaction.json`.

If enrollment A is accepted by the host and the client crashes, enrollment B for a different invitation but the same route and port can replace A's local journal and leave an orphaned host grant. Exact idempotency must compare route, port, invite ID, generation, expected state, and irreversible effects. Conflicts need an explicit replace operation.

### WT-SR-017: macOS reboot changes durable routes into one-shot jobs

**Severity:** High reliability

- `internal/provisioner/server.go:717-741` reconstructs boot jobs with `once=true` regardless of durable restart policy.
- The generated launchd job has `KeepAlive=false`, and `--once` disables internal restart at `internal/provisioner/server.go:419-448`.
- Start errors are logged but not included in the returned reconciliation error set.

Boot reconciliation must derive behavior from the route's restart policy and report every projection failure. A transient failure after reboot must not silently strand an `unless-stopped` tunnel.

### WT-SR-018: Upgrade and uninstall do not prove that installed processes are gone or current

**Severity:** High operational reliability

- Debian `prerm` restarts active services before the new package payload is installed at `packaging/linux/prerm.sh:11-21` and `packaging/linux/prerm.sh:52-66`; postinstall does not restart them after replacement.
- A running old process can therefore survive with replaced on-disk bytes.
- Public uninstall calls a projection path that is unavailable on Darwin and unprivileged Linux at `internal/command/lifecycle.go:1444-1450` and `internal/command/lifecycle.go:1481-1521`.

Record active units before upgrade, restart them only after new payload installation, verify running executable build IDs or hashes, and add a typed provisioner stop-all/uninstall operation that enumerates every durable route and proves all jobs and sessions are gone.

### WT-SR-019: Native cryptographic and SSH protocol assurance is below the release claim

**Severity:** Medium, elevated by the custom network protocol surface

- `internal/mldsa` is a substantial adaptation of Go's internal FIPS 140 ML-DSA implementation, but the repository records no exact upstream commit/hash or mechanically reviewable adaptation diff.
- `internal/mldsa` has no package tests or imported known-answer vectors.
- `internal/composite/composite_test.go` provides a basic round trip and mutation check, but not a comprehensive vector corpus.
- No Go fuzz target exists for invite, key, packet, KEX, authentication, channel, or lifecycle parsers.
- `docs/2026-08-09_crypto-profile.md:162-173` already calls for deterministic and randomized vectors, malformed inputs, two implementations, and fuzz/DoS evidence.

This is an assurance finding, not evidence that the ML-DSA primitive is incorrect. Record exact provenance, import upstream and NIST vectors, maintain a mechanical diff, add independent cross-implementation corpora, fuzz every untrusted parser and state machine, and commission focused external review of the native SSH implementation before distribution.

### WT-SR-020: Invite MAC semantics do not match the production path

**Severity:** Medium

- Invite HMAC generation and `ParseAndVerify` exist at `internal/enrollment/invite.go:161-201`.
- Production search found no caller of `ParseAndVerify`.
- The client shape-parses the invite and omits the MAC from its enrollment request; the server validates durable invite-record fields instead.

The current MAC neither gives the client issuer authenticity nor gates server acceptance, contrary to older architecture text. Remove the dead field and document bearer semantics, or replace it with a client-verifiable signature anchored outside the invite.

### WT-SR-021: Clock rollback and direct management fallback have residual authority gaps

**Severity:** Medium

- Clock rollback writes a blocked marker and attempts authorization removal/session teardown, but authentication does not independently consult the blocked marker on every decision. Cached data-plane keys make teardown success part of the security boundary.
- Direct management-listener detection uses PID plus current socket ownership but does not prove original executable incarnation. A reused PID that owns the expected loopback socket can be accepted in the fallback path.

The blocked-clock state must be checked by service start and every authentication authority. Distribution paths should require service-manager identity; any retained direct fallback must bind boot ID, start time, executable inode/digest, and pidfd-safe identity.

### WT-SR-022: Benchmark runs labelled `release` are dirty by construction

**Severity:** Medium release-evidence defect

- `scripts/run-bench.sh:21-35` labels a run `release` from tag/version equality alone.
- It creates an untracked output directory before recording tree cleanliness at lines 39-56, so its own output makes the result dirty.
- Current metadata says both `"kind":"release"` and `"dirty":true`.
- The benchmark code, runner, and outputs are all untracked and therefore are not authenticated by the named tag.
- The measurements are in-process microbenchmarks, not package-only dual-host performance tests.

Treat current results as local engineering signals only. Release benchmarks need a clean isolated checkout, authenticated tag and binary digests, stable hardware/OS/power/load metadata, raw samples, statistical comparison, explicit budgets, and no dirty `release` classification.

### WT-SR-023: Package trust and supported-platform authorities remain fragmented

**Severity:** High release-identity defect

- Artifact assembly is not one fail-closed operation rooted in a clean authenticated tag. `scripts/build-linux-rc-remote.sh:222-231` copies the current working tree without `.git`, and lines 305-324 compile and package those bytes. Version equality is checked, but source cleanliness, exact tag identity, and authenticated commit identity are not carried to the remote build.
- `scripts/release-candidate.sh:27-65` checks local cleanliness and prints subsequent assembly commands, but does not itself verify an exact signed tag, CI result, artifact digest, or already-published asset identity.
- `Makefile:12-13` removes VCS metadata from the normal binaries, and Linux package metadata does not independently bind the source commit.
- The repository does not publish and enforce the full WarpTweet release-signing fingerprint and rotation/revocation policy. Local tag verification was inconclusive because the audit keyring lacked the public key.
- Linux dependency metadata is incomplete for observed `libcrypt.so.1` linkage, the RPM path does not assemble an RPM, and fixed numeric account IDs can collide.
- Code, evidence, docs, CI, and the cask disagree on the supported OS/architecture matrix.

Create one signed promotion manifest binding tag, commit, version, toolchain, upstream receipts, SBOM, package digests, signer identities, platform floor, and evidence index. Derive all support claims and CTA behavior from one versioned, proven matrix.

### WT-SR-024: Several local input and UX hardening issues remain

**Severity:** Low

- Raw invite JSON can be accepted on argv, exposing a short-lived bearer to shell history and process telemetry.
- Some invite and proof reads use unbounded `os.ReadFile`; special or oversized files can block or exhaust a privileged caller before parser limits apply.
- Raw substring scanning for `private` or `seed` can reject valid invitations containing names such as `seedbox`.

Accept a bounded regular file or bounded stdin, avoid secret-bearing argv, and inspect decoded schema fields rather than serialized substrings.

### WT-SR-025: The native data-plane service bypasses the documented installed-server preflight

**Severity:** Medium, elevated by release documentation drift

- `packaging/systemd/warptweet-sshd.service:4-7` asserts that the controller, manifest, host key, and authorization file exist, but does not run `doctor-server` or an equivalent native-data-plane preflight.
- Its only `ExecStartPre` at line 46 records the Linux boot ID.
- `internal/command/dataplane.go:13-33` loads the manifest, constructs policy, and serves. It does not independently verify the installed controller's ownership and ancestry, executable digest, host-key metadata, authorization canonicality, or an expected package inventory.
- `README.md:13-16` and `README.md:94-104` claim that the installed server fails startup or reload unless the documented fixed-layout preflight passes. Those passages still describe bundled OpenSSH `sshd` checks that are not the startup gate for the native server.

Define a native-data-plane preflight contract rather than reusing stale OpenSSH-server language. The service must fail closed on unexpected executable, ownership, path, manifest, host-key, authorization, and package identity before it opens a network listener. Update current documentation and add package-level tamper tests for every asserted fact.

## 5. Strong controls observed

The following controls materially reduce risk and should be preserved:

### Cryptography and protocol policy

- The active profile is exact and fail-closed: hybrid `ML-KEM-768 + X25519`, composite `ML-DSA-44 + Ed25519`, and ChaCha20-Poly1305, with no classical fallback.
- Composite signing and verification require both component algorithms.
- Host and client algorithm lists are pinned rather than negotiated from a broad compatibility set.
- The native policy permits only `direct-tcpip` to the manifest target and the private management endpoint. Shell, PTY, exec, subsystem, SFTP, agent, X11, TUN, remote, dynamic, and unrelated forwarding surfaces are rejected.
- SSH packets are bounded to 256 KiB, sequence exhaustion is checked, concurrent pre-authentication connections are bounded, and handshake and idle deadlines exist.

### Enrollment and authorization

- Enrollment TLS requires TLS 1.3, `X25519MLKEM768`, fixed ALPN, Ed25519 SPKI pinning, certificate signature verification, and validity checks.
- HTTP redirects and proxy inheritance are disabled; response sizes are bounded.
- Invite parsing rejects duplicate and unknown fields and applies explicit size limits.
- Invite files use exclusive creation, mode `0600`, file sync, and directory sync.
- Target changes are denied while live invitations or grants exist.
- Enrollment, rotation, and revocation have durable pending-state concepts and exact-retry machinery in their server-side stores.
- Grant session records bind boot ID, PID, process start time, executable, client key, and connection identity. Linux termination uses pidfd-safe identity and verifies disappearance.

### Privilege and lifecycle

- The client tunnel systemd unit uses a dedicated identity, no capabilities, `NoNewPrivileges`, a strict filesystem sandbox, bounded restart behavior, and a control-group kill policy.
- The macOS and Linux provisioner protocols are typed and bounded. Validated identifiers and fixed argv vectors are used instead of shell interpolation.
- Supervisor startup is PID-bound, races child exit against readiness, and terminates and reaps the child on post-start failure.
- Startup timeout, retry count, backoff, shutdown, and kill grace are bounded.

### Supply chain and release honesty

- OpenSSH and OpenSSL archives, hashes, and upstream release-key fingerprints are pinned and verified.
- CI actions and Docker images are digest or commit pinned, checkout credentials are disabled, and CI permissions are read-only.
- Website dependencies use a lockfile and currently report no known high-severity dependency advisory.
- macOS package scripts contain fail-closed Team ID, signing, notarization, and stapling controls.
- Cask URLs are versioned and SHA-256-bound.
- The README and security policy do not claim a supported end-to-end release.
- The Homebrew CTA remains dark.

### Interoperability evidence

A focused local OpenSSH client `direct-tcpip` interoperability test passed. This proves a useful narrow fact: an OpenSSH client and the native data plane completed the current basic handshake, composite authentication, and forwarding path in the test environment. It does not prove rekey, strict KEX, package identity, real service managers, dual-host operation, or lifecycle recovery.

## 6. Verification record

### 6.1 Passed checks

| Command | Material result | Proven scope |
| --- | --- | --- |
| `go vet ./...` | Pass | Go vet diagnostics for the inspected source tree. |
| `gofmt -l $(rg --files -g '*.go')` | No output | All discovered Go files formatted. |
| `git diff --check` | Pass | No whitespace errors in the current diff. |
| `go test -race -count=1 ./internal/supervisor ./internal/enrollment ./internal/routestate ./internal/lifecycle ./internal/dataplane ./internal/grantsession` | Pass | Focused race-enabled lifecycle, data-plane, and grant packages. |
| `go test -count=1 ./internal/enrollment ./internal/provisioner ./internal/grantsession ./internal/command ./internal/server` | Pass | Focused security and privilege-path unit/integration tests. |
| `go test ./internal/dataplane -run '^TestOpenSSHClientDirectTCPIP$' -count=1 -v` | Pass | Narrow local OpenSSH-client handshake, auth, and direct-TCP interoperability. |
| `pnpm run verify` | Pass; Astro check reported 24 files with no errors, warnings, or hints; site build and output verification passed | Source-level website validation only. |
| `pnpm audit --audit-level=high` | Pass; no known vulnerabilities reported | Current website dependency lockfile against the consulted registry advisory data. |

Some focused commands were rerun with a writable temporary Go build cache and local permissions because sandbox restrictions prevented loopback binding and access to fixed `/Library` paths. Those reruns passed in their stated scope.

### 6.2 Failed checks

| Command | Material result | Consequence |
| --- | --- | --- |
| `make check-go` | Fail in ShellCheck on untracked benchmark runner: Bash `pipefail` checked as POSIX `sh`, plus unused variable | Mandatory source gate is red. |
| `go test ./...` | Fail in protected-layout expectation, stale release profile fixtures/examples, and secret-scan handling of ignored local interop evidence | Full unit/integration gate is red. |
| `go test -race ./...` | Fail on the same suite-level defects | Full race gate is red. |
| Focused `go test -count=1 ./internal/release ./internal/publicrelease ./internal/releaseevidence ./internal/releasemetadata ./internal/artifactprofile` | `internal/release` failed stale-profile and example-manifest tests; the other packages passed | Tagged `rc.8` cannot satisfy its release tests. |
| `./scripts/check-gosec.sh` | Fail with 299 untriaged findings | Static-analysis gate is not release-usable; gosec is also absent from `check-go` and CI. |

### 6.3 Manual source checks

- Traced authentication authority before and after proof of possession.
- Traced invite consumption, rotation, revocation, expiry, and clock-block transitions.
- Traced package-installed rotate/revoke across the local management forward and lifecycle lock.
- Traced client generation selection and server authorization snapshots.
- Reviewed SSH KEX and rekey state, session-ID handling, packet sequencing, and strict-KEX advertisement.
- Reviewed channel parsing, receive windows, channel quotas, target dialing, deadlines, cancellation, and observability.
- Reviewed effective service users, capabilities, writable paths, process-control authority, and provisioner request boundaries.
- Reviewed release candidate, artifact build, signer, evidence, CTA, package-skip, deployment-target, benchmark, and support-matrix paths.
- Freshly built and inspected macOS controller, provisioner, SSH, and ssh-keygen Mach-O minimum OS values in temporary diagnostic output.

### 6.4 Not run or not proven

- No signed or notarized release artifacts were produced or validated.
- No exact-digest package-only two-host test was run.
- No macOS 13, Intel macOS, Linux arm64, or declared Linux distribution lifecycle was exercised.
- Linux systemd and macOS launchd install, reboot, upgrade, uninstall, rotate, revoke, expiry, and incident recovery were not executed end to end.
- No live exploitation of the rsync race was attempted because it would be destructive.
- No strict-KEX active-network manipulation, forced multi-rekey, malformed protocol fuzzing, target-saturation, disk-full, power-loss, PID-reuse, or clock-rollback race test was run.
- Tag authentication was not proven because the audit keyring lacked the public signing key. This is not evidence that the signature is invalid.
- No SBOM, provenance attestation, package vulnerability scan, artifact secret scan, or published-asset readback was available.
- No manual website accessibility evaluation was performed. Website source verification is not accessibility evidence.
- Existing benchmark results were not accepted as release performance evidence.

## 7. Security architecture assessment

### 7.1 Intended trust path

```text
confidential single-use invitation
        |
        v
invite-pinned TLS enrollment
        |
        v
durable host grant + immutable client route generation
        |
        v
strict hybrid SSH KEX + composite mutual authentication
        |
        v
one authorized direct-tcpip target
        |
        v
versioned session authority for expiry, rotation, and revocation
```

The current implementation is strongest in invite transport, exact algorithms, and forwarding-surface reduction. Its weakest seams are the last two transitions:

- the native SSH transport does not yet implement the complete long-lived SSH state machine; and
- grant lifecycle facts are split among invite records, client records, authorized-key text, static in-memory snapshots, route receipts, active-generation pointers, lifecycle files, and service-manager state.

### 7.2 Required authority consolidation

The ideal design has one durable grant authority per client and target. Every derivative view must be versioned and reconstructible:

| Fact | Sole authority | Derived projections |
| --- | --- | --- |
| Client grant state | Durable host grant journal with generation and token state | Authentication snapshot, audit output, invite status |
| Active client identity | Immutable route generation plus atomic `active.json` | Runtime manifest, identity path, known-hosts path, receipt |
| Desired tunnel state | Durable route intent | systemd/launchd unit projection |
| Observed tunnel state | Service manager plus exact process/listener evidence | CLI status and telemetry |
| Live authorization | Current grant generation plus clock state | Session registration and selective teardown |
| Release identity | Signed promotion manifest | packages, cask, checksums, SBOM, provenance, evidence index, CTA |

This consolidation removes the classes of defect seen in revocation, rotation, stale status, reboot intent, and release self-attestation.

## 8. Ideal remediation and release strategy

The productivity points below measure relative movement toward the ideal release state. They are not time estimates.

### Gate A: Freeze unsafe promotion paths and restore one source identity, 3 points

- Keep the CTA dark.
- Do not republish or rebuild `v0.1.0-rc.8`.
- Remove the current rsync command from the release surface or redesign it behind its own reviewed service boundary.
- Restore `make check-go`, full Go tests, full race tests, release tests, secret scan, shell checks, and profile fixtures.
- Add gosec, `govulncheck`, dependency, secret, package, and artifact scanning as required, triaged CI gates.
- Cut only a new version from a clean detached authenticated tag.

**Exit condition:** one clean candidate commit with every required source gate green and no version-identical dirty build path.

### Gate B: Establish one grant and lifecycle authority, 13 points

- Split invitation cancellation from grant revocation.
- Add root-authoritative host revocation by client ID and consumed invite ID.
- Make rotation one immutable client/host generation transaction.
- Remove static authorization ambiguity through authoritative lookup or atomic snapshots.
- Keep management available until host operations are durable.
- Selectively terminate and prove old/revoked/expired sessions gone.
- Make the provisioner own desired intent and service projection transactionally.
- Project every supervisor state and reconcile CLI status with service-manager and listener truth.
- Repair reservation idempotency, reboot policy, upgrade, uninstall, and crash recovery.

**Exit condition:** package-only lifecycle fault matrix passes on both platform families, including interruption after every durable transition.

### Gate C: Complete and deprivilege the native SSH transport, 13 points

- Implement the full KEX/rekey state machine and immutable session ID.
- Implement strict KEX and sequence reset behavior.
- Enforce channel windows, packet limits, field widths, channel quotas, dial timeouts, and admission controls.
- Add privacy-safe rejection and saturation observability.
- Move network parsing/forwarding to an unprivileged service and isolate signing and narrow privileged mutations.
- Define explicit CPU, memory, descriptor, channel, connection, handshake, target-dial, shutdown, and recovery budgets.

**Exit condition:** OpenSSH interop, forced repeated rekey, active-network manipulation, malformed protocol, and bounded-flood tests pass against the installed service.

### Gate D: Raise cryptographic and parser assurance, 8 points

- Pin the exact upstream ML-DSA source revision and maintain a mechanical adaptation diff.
- Import NIST and upstream known-answer vectors plus malformed corpora.
- Add independent cross-implementation KEX, signature, key, and packet vectors.
- Fuzz invite, TLS control, key, KEX, packet, authentication, channel, grant, route, provisioner, and evidence parsers.
- Run race, sanitizer where applicable, static, vulnerability, dependency, secret, and artifact scans.
- Commission an external review focused on the native SSH transport, privilege boundary, and lifecycle authority.

**Exit condition:** current-revision vector, fuzz, cross-implementation, static, and independent-review evidence has no unresolved release-blocking finding.

### Gate E: Build one authenticated promotion pipeline, 8 points

- Create one fail-closed command rooted in a clean detached signed tag.
- Bind source commit, version, toolchains, upstream receipts, build environment, package inventories, SBOM, provenance, package hashes, signer identities, and support floor into a signed promotion manifest.
- Set and verify macOS deployment targets for every Mach-O.
- Complete Debian dependencies and lifecycle; either build a real RPM or remove the claim.
- Publish and pin complete WarpTweet release-signing fingerprints and rotation/revocation policy.
- Always install and hash the exact selected packages on disposable hosts. Never reuse same-version installed bytes or unkeyed caches in qualification.

**Exit condition:** extracting any package is sufficient to recover and authenticate its exact promotion identity, and installed hashes match the selected asset.

### Gate F: Produce full package and public-readback evidence, 13 points

- Run all declared client/server architecture cells on clean supported OS images.
- Exercise install, connect, forwarding, multiple clients/routes, rekey, rotate, revoke, expiry, clock rollback, manual down, reboot, upgrade, uninstall, target failure, network failure, tamper, and bounded floods.
- Sign a full release-evidence index containing every cell and required case.
- Make the website build validate exact public assets and the signed index.
- Perform manual security operations review and applicable website accessibility review.
- Enable the Homebrew CTA only after an independent readback of the published URLs, checksums, signer/notary identities, package contents, evidence index, and rendered install command passes.

**Exit condition:** the public site points to exact published assets whose full support matrix and lifecycle behavior are proven at the same revision and digest.

## 9. Distribution acceptance contract

WarpTweet should not be called ready for public distribution until all of the following are true at one immutable revision:

1. No Critical or High finding in this document remains open.
2. Full source, race, release, static, vulnerability, dependency, secret, package, and artifact gates pass.
3. The native server runs behind a justified least-privilege boundary.
4. Forced multi-rekey and strict-KEX adversarial interoperability pass.
5. Channel, KEX, connection, target, and shutdown resource budgets pass under attack and outage.
6. Host revocation removes authorization, closes live sessions, and survives restart before reporting success.
7. Rotation atomically moves both endpoints to one generation and invalidates the old generation.
8. Enrollment does not interrupt unrelated sessions.
9. Desired state, status, reboot, upgrade, uninstall, and recovery match operator intent on every supported platform.
10. Invitations are consistently treated as confidential single-use bearer capabilities.
11. ML-DSA and all network parsers have current vector, cross-implementation, malformed-input, and fuzz evidence.
12. Every package is bound to a clean authenticated tag, exact source commit, signer, SBOM, provenance, and published checksum.
13. Every claimed OS/architecture cell has exact-package evidence, including real minimum-OS testing.
14. The website's CTA validator independently reads back and authenticates the published assets and complete evidence index.
15. All unrun, unavailable, waived, or environment-dependent checks remain explicitly incomplete rather than being recorded as pass.

## 10. Final assessment

WarpTweet is not failing because post-quantum tunneling is inherently impractical. The project has already solved several difficult foundation problems. The current risks arise because the implementation recently crossed an important boundary: it now contains its own network-facing SSH server, durable grant lifecycle, privileged service management, and public promotion system. Each of those becomes security-critical at distribution scale.

The shortest safe route to the public is not more feature work. It is to freeze the release surface, consolidate authority, complete the native SSH state machine, deprivilege the parser, and make the package/evidence pipeline prove the exact bits users receive. Once those gates are satisfied, WarpTweet will have a substantially stronger first-release posture than most early open-source infrastructure projects.
