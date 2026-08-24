# Native Windows client implementation roadmap

- Status: architecture and release plan, not implementation or release evidence
- Reviewed source revision: `92f78b1261cf88220e0b92b33d6f03493b7fec18`
- Review date: 2026-08-24
- Primary scope: native Windows client against the existing Linux host
- Initial release target: supported Windows 11 on x64
- Subsequent target: Windows 11 on ARM64 only after native artifact and package proof

## Executive decision

WarpTweet should build a native Windows client product. It should not build a
kernel driver, a Windows SSH server, a WSL wrapper, or a second tunneling
protocol.

The ideal first Windows implementation is:

1. `warptweet.exe`, an unprivileged command-line client with the same public
   route lifecycle vocabulary as macOS and Linux.
2. `warptweet-service.exe`, one machine-wide, least-privileged Windows Service
   that owns all protected client state, route supervision, and privileged
   mutations.
3. A package-private, cryptographically pinned native `ssh.exe` client engine
   that implements the existing exact WarpTweet wire profile.
4. A signed per-machine MSI, discoverable through WinGet, that installs all
   immutable files, ACLs, the service, and the local operator group without
   downloading code during installation.
5. A new `windows-amd64` artifact profile and a new release-evidence contract
   whose Windows-to-Linux matrix must pass from the exact signed packages.

The Linux host data plane does not change for this project. It is already the
WarpTweet-owned Go SSH server in `internal/dataplane`; OpenSSH remains the
client engine and a host-key interoperability tool. Windows enrollment must
consume the same `.wtinvite` contract and negotiate the same immutable profile:

```text
mlkem768x25519-sha256
ssh-mldsa44-ed25519@openssh.com
chacha20-poly1305@openssh.com
```

There must be no use of Windows' in-box OpenSSH, no algorithm downgrade, and no
classical fallback when the requested WarpTweet profile cannot be established.

The principal technical uncertainty is not Go or MSI. It is whether the native
Windows OpenSSH port can be turned into an authenticated, reproducible,
statically linked equivalent of WarpTweet's pinned OpenSSH 10.4p1 and OpenSSL
3.5.7 client, including a trustworthy readiness signal. That question is an
early proof gate, not something to defer until packaging.

## What this document establishes

This document:

- assesses the pasted Windows comments against current source;
- maps the present client architecture and Unix assumptions;
- defines the proposed Windows ownership, security, lifecycle, IPC, engine,
  state, package, upgrade, observability, and evidence contracts;
- identifies exact package seams and expected new platform implementations;
- orders the work by dependency and relative productivity points;
- defines acceptance and non-release conditions.

It does not claim that a Windows binary builds, starts, connects, is signed, or
is ready for distribution. The repository was already dirty during this
review. No existing user changes were modified. The only execution performed
for this review was read-only source inspection and failed cross-compilation to
temporary output paths.

## Assessment of the supplied comments

The comments are directionally correct, but too compressed to be an
implementation plan. Several statements need material qualification.

| Supplied statement | Assessment | Current-source correction |
| --- | --- | --- |
| Windows users have the same local TCP-to-remote-loopback use case | Correct | The product contract can remain one approved local loopback listener carried to one approved host-loopback target. |
| The Linux host does not change | Correct for this project | The current host data plane is native Go in `internal/dataplane` and `internal/command/dataplane.go`. OpenSSH is not the Linux host tunnel daemon now. |
| `GOOS=windows` is the easy part | Incorrect as a present-tense statement | The controller does not currently cross-compile. `internal/lifecycle/state.go` directly uses Unix `flock` and `kill`; `internal/provisioner/uninstall.go` references a symbol defined only by supported platform files. More failures are hidden behind those first compiler errors. |
| Production preflight fails closed outside Linux and Darwin | Correct | This is deliberate in `internal/engine/client_platform_unsupported.go`, `client_state_unsupported.go`, `client_owner_unsupported.go`, and `client_linkage_unsupported.go`. Windows needs reviewed implementations, not removal of the checks. |
| Windows needs the same OpenSSH engine built for Windows | Correct in wire behavior, incomplete in source strategy | Portable upstream OpenSSH targets Unix-like systems. Native Windows support lives in Microsoft's Win32 port. Its public release and build conventions do not automatically match pinned OpenSSH 10.4p1, OpenSSL 3.5.7, static linkage, or WarpTweet's readiness design. |
| Use `C:\Program Files\WarpTweet` | Correct for immutable program files | Mutable routes, trust, receipts, and identity belong under `%ProgramData%\WarpTweet`, resolved through Windows Known Folder APIs. Runtime authority belongs in handles, named pipes, events, and job objects. |
| Use a dedicated service account | Directionally correct | The recommended baseline is `LocalService` plus a restricted per-service SID, not `LocalSystem`, not the interactive administrator, and not a logon-capable human account. The exact token and privileges require live verification. |
| Supervise through Windows Services | Correct | One service should own every route. Creating a Windows service per tunnel would enlarge configuration, upgrade, authorization, and recovery surfaces unnecessarily. |
| Use AF_UNIX or named pipes | Incomplete | A local named pipe is the recommended CLI-to-service boundary. AF_UNIX is not a substitute for the existing OpenSSH ControlMaster readiness proof, and neither primitive proves that the authenticated forward belongs to the expected process. |
| Add PE inspection and Authenticode | Correct | Runtime preflight also needs a retained executable handle, final-path and file-identity checks, import and mitigation validation, safe DLL search behavior, exact signer policy, and revalidation immediately before launch. |
| MSI/MSIX plus WinGet | Mostly correct | Start with a signed per-machine MSI and a WinGet manifest that binds its hash. MSI is the better initial fit for a Windows Service, ACLs, upgrades, and repair. MSIX is a future option only if its service and state model is proven without exceptions. |
| Add Windows-to-Linux evidence cells | Correct | The existing schema hard-codes Darwin and Linux client profiles. Windows requires a versioned v3 checklist and evidence schema, not an in-place mutation of v2. |
| WSL2 is not native Windows | Correct | WSL testing cannot satisfy any `windows-*` artifact, service, ACL, Authenticode, MSI, sleep/resume, or package-to-package release gate. |
| Windows should replace Intel Mac priority | Product opinion, not an engineering invariant | Windows x64 is an additive platform contract. Whether to retire `darwin-amd64` must be decided from support policy and evidence cost, not treated as an implementation shortcut. |

The most important correction is that this is not “almost everything around the
client process is rewritten.” The current typed route, invitation, wire
profile, supervisor state machine, evidence philosophy, and closed OpenSSH
option construction should be preserved. Platform authority and operating
system mechanics must be replaced behind explicit interfaces.

## Current architecture, as implemented

The Windows plan must preserve the observable product behavior while replacing
Unix-specific mechanics.

```text
operator
   |
   | warptweet connect/up/down/status/rotate/revoke
   v
unprivileged CLI
   |
   | typed, bounded local provisioner request
   v
privileged platform provisioner and route supervisor
   |
   | protected immutable route generation
   | exact OpenSSH arguments and sanitized environment
   v
bundled OpenSSH client process
   |
   | pinned hybrid KEX, composite authentication, one local forward
   v
WarpTweet native Go data plane on Linux
   |
   | one authorized direct-tcpip destination
   v
host-loopback service
```

### Reusable platform-neutral assets

| Concern | Current authority | Windows disposition |
| --- | --- | --- |
| Wire profile | `internal/profile/profile.go` | Reuse without changing algorithm names. Move executable format out of the wire profile because `ExecutableFormat = "ELF"` is not a wire property. |
| Artifact profile registry | `internal/artifactprofile/profile.go` | Add `WindowsAMD64`; add `WindowsARM64` only when it is independently supported. Extend the layout type for Windows-native state and signing facts instead of forcing UID/path fields onto Windows. |
| Manifest and invite parsing | `internal/config`, `internal/enrollment` | Reuse strict bounded parsing, semantic validation, single-use handling, pinned TLS, and fail-closed behavior. |
| Composite key implementation | `internal/composite` | Reuse `Generate`, public derivation, signing, verification, and interop vectors. |
| OpenSSH private-key encoding | `internal/opensshkey` | Reuse after Windows OpenSSH interop proof. This can remove the client dependency on `ssh-keygen.exe`. |
| Closed client policy | `internal/engine/client.go`, `effective.go` | Reuse option construction and exact `ssh -G` validation. Add a Windows-specific environment and executable invocation implementation. |
| Lifecycle state machine | `internal/supervisor/supervisor.go` | Preserve typed states and bounded restart semantics. Replace signal/PID-only process authority with Windows process handles and job objects. |
| Route transactions | `internal/routestate` | Preserve generation and transaction semantics. Replace POSIX ownership, modes, locks, rename, and fsync operations with a Windows storage authority. |
| Release evidence | `internal/releaseevidence`, `packaging/evidence/checklist-v2.json` | Preserve exact-byte, exact-matrix, package-only philosophy. Introduce v3 for Windows-specific fields and cases. |
| Linux host | `internal/dataplane`, `internal/command/dataplane.go` | Unchanged except for cross-platform interop fixes demonstrated by Windows evidence. |

### Unix-specific seams that cannot be papered over

The current source directly encodes these assumptions:

- `internal/lifecycle/state.go` uses `syscall.Flock`, `syscall.Kill`, POSIX mode
  bits, PID files, and `os.Rename` semantics.
- `internal/supervisor/supervisor.go` sends `SIGTERM` and treats PID as the
  public readiness identity.
- `internal/provisioner/protocol.go` dials a Unix-domain socket and uses
  `CloseWrite` on `*net.UnixConn`.
- `internal/provisioner/server_linux.go` projects desired state into systemd;
  `internal/provisioner/server.go` projects it into launchd.
- `internal/engine/readiness.go` creates a short Unix socket path, runs
  `ssh -O check`, parses a PID from a pinned diagnostic, and unlinks the socket.
- `internal/engine/client_state.go` models trust with UID, GID, POSIX modes,
  link counts, and POSIX ACL absence.
- `internal/command/lifecycle.go` contains `/proc`, `sysctl`, `systemctl`,
  `Geteuid`, `Chown`, `Chmod`, and packaged `ssh-keygen` paths.
- `internal/installlayout/layout.go` and `darwin.go` contain Unix fixed paths,
  service identities, and runtime roots.
- host and server commands in `internal/command/host.go`, `hostsign.go`, and
  related files are Linux-oriented capabilities that a Windows client build
  must not expose as if supported.

There is one partial precedent in `internal/enrollment/lock_other.go` and
`lock_owner_windows.go`, but the O_EXCL lock-file and PID-liveness approach is
not sufficient as machine-wide route authority. It should be replaced by
service serialization plus an actual Windows held-handle lock.

### Current cross-compilation result

At the reviewed revision, each of these commands failed before producing an
artifact:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/warptweet
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/warptweet
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/warptweet-provisioner
```

The first source failures were:

```text
internal/lifecycle/state.go:94:20: undefined: syscall.Flock
internal/lifecycle/state.go:94:50: undefined: syscall.LOCK_EX
internal/lifecycle/state.go:94:66: undefined: syscall.LOCK_NB
internal/lifecycle/state.go:106:14: undefined: syscall.Flock
internal/lifecycle/state.go:106:44: undefined: syscall.LOCK_UN
internal/lifecycle/state.go:204:17: undefined: syscall.Kill
internal/provisioner/uninstall.go:35:17: undefined: encodeOutput
```

The audit environment also denied Go's attempt to update a module stat cache
under the user's normal module directory. That sandbox warning is separate
from, and does not explain, the compiler errors above. A clean Windows build
remains unverified.

## Windows product contract

### Supported outcome

A non-administrator in the local WarpTweet operator group can:

```powershell
warptweet connect .\studio-mac.wtinvite
warptweet status
warptweet down studio-mac
warptweet up studio-mac
warptweet rotate studio-mac
warptweet revoke studio-mac
```

After successful readiness, a Windows application connects to the exact local
loopback endpoint shown by WarpTweet, for example `127.0.0.1:15432`. Traffic is
carried through the pinned WarpTweet profile to the one host-loopback target
authorized by the invite and server grant. The operator does not need to run
the CLI as Administrator after installation.

### Explicit support boundaries

The first native Windows release should support:

- per-machine installation;
- Windows 11 x64 on explicitly listed, vendor-supported servicing releases;
- interactive PowerShell, Command Prompt, and Windows Terminal use;
- one or more independent machine-wide routes;
- `unless-stopped` and `manual` desired intent, with distinct service-restart
  and machine-reboot behavior (see Sleep, resume, reboot, and network changes);
- exact IPv4 loopback binding initially, with IPv6 loopback added only when its
  collision and dual-stack semantics are fully tested;
- Linux `amd64` and Linux `arm64` WarpTweet hosts from the published server
  package matrix.

The first release should not claim:

- a Windows host or server data plane;
- Windows 10 support, unless a separately maintained LTSC or ESU test contract
  is explicitly adopted;
- Windows ARM64 from x64 emulation or Go compilation alone;
- WSL2 as native Windows support;
- SSH shells, remote commands, SFTP, SCP, VPN behavior, arbitrary forwarding,
  or generic OpenSSH compatibility;
- encrypted-at-rest private keys if the release merely protects a raw key file
  with a DACL;
- standardized IETF post-quantum SSH authentication. The selected composite
  authentication name remains vendor-qualified OpenSSH behavior.

Windows 10 reached normal end of support on 2025-10-14. The release baseline
must therefore be expressed as exact supported Windows 11 versions and builds,
not the vague label “Windows 10 or later.” Microsoft's current release-health
pages are the authority when a package version is cut, not this document's
snapshot. See [Windows release health](https://learn.microsoft.com/en-us/windows/release-health/release-information)
and [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information).

## Target architecture

### Component and authority map

| Component | Runs as | May do | Must not do |
| --- | --- | --- | --- |
| `warptweet.exe` | interactive user | Parse commands, read invite supplied by that user, show confirmation, send typed request, render sanitized status | Read service private keys, write protected route state, choose engine path/options, install services, or infer authorization from being elevated |
| `warptweet-service.exe` | `LocalService` with restricted `NT SERVICE\WarpTweetClient` SID | Authenticate local callers, perform enrollment, own route generations, start/stop engines, maintain desired intent, expose sanitized status | Run as `LocalSystem`, accept shell text or caller paths, expose secret state, execute while impersonating a caller, or treat PID as durable identity |
| private `ssh.exe` | child of service, in per-route job | Connect with exact closed arguments and one local forward | Read ambient config, search `PATH`, load package-external crypto DLLs, create shells, execute remote commands, forward anything beyond the manifest |
| MSI custom actions | elevated install transaction | Install signed bytes, configure DACLs/group/service/Event Log source/PATH, perform versioned upgrade transaction | Download code, retain secrets in MSI logs, create routes, consume invites, or delete identity on ordinary uninstall |
| Linux data plane | existing dedicated host service | Authenticate exact composite client, enforce grant and one target | Add Windows-specific trust or relax wire/profile policy |

### One service, not one service per route

The recommended service model is one `WarpTweetClient` Windows Service that
supervises all routes. Route state is an internal typed state machine, not an
SCM service definition.

This gives one authorization boundary, one upgrade boundary, one event source,
one recovery policy, one place to coordinate port allocation, and one process
whose health SCM can evaluate. Per-route child engines remain independently
restartable and independently confined by job objects.

SCM recovery restarts the controller service after an unexpected service
failure. It must not produce unbounded restart loops. The service itself owns
bounded per-route backoff, stable-window reset, and desired-intent restoration.
Microsoft exposes service SID configuration and failure actions through the
service APIs; use those APIs and verify the resulting configuration rather
than trusting installer exit status. See
[SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
and [ChangeServiceConfig2](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w).

### Capability separation

The Windows binary set must make unsupported host behavior structurally
unavailable. The command registry should be capability-driven:

- common client commands compile on every supported client platform;
- Windows registers native client lifecycle commands and service entrypoints;
- Linux registers host/server commands and Linux service helpers;
- unsupported commands return a typed “not part of this artifact profile”
  result only when a shared syntax requires them, otherwise they are omitted
  from help entirely;
- tests assert the exact command surface for every artifact profile.

Do not scatter `if runtime.GOOS == "windows"` around the command layer. Move
platform operations behind real interfaces and build-tagged constructors, then
make missing implementations a compilation failure.

## Local IPC and authorization

### Named pipe contract

Use a local named pipe as the CLI-to-service transport:

```text
\\.\pipe\WarpTweet\v1\control
```

The exact name is package policy, not caller input. The server creates it with:

- byte- or message-mode framing selected once and tested for partial reads;
- overlapped I/O so deadlines and cancellation are real;
- `PIPE_REJECT_REMOTE_CLIENTS`;
- an explicit SDDL security descriptor;
- bounded instances, input bytes, output bytes, and outstanding requests;
- a timeout for accept, request body, action execution, and response write;
- no inheritable pipe handles;
- immediate creation of the next listening instance without opening an
  unbounded concurrency path.

Windows' default named-pipe DACL can grant read access to Everyone and anonymous
logon. WarpTweet must never rely on that default. See
[Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

### Caller authorization

The installer creates a local `WarpTweet Operators` group. The pipe DACL admits
only:

- `SYSTEM`;
- the `WarpTweetClient` service SID;
- built-in Administrators;
- members of `WarpTweet Operators`.

The DACL is the connect gate, not the action matrix. The service performs a
second authorization check against the connected client's token **before**
decoding a mutating action.

| Principal | Mutating lifecycle (`connect`, `enroll`, `up`, `rotate`, `revoke`) | Recovery (`status`, `repair`, documented recovery `forget`) |
| --- | --- | --- |
| `WarpTweet Operators` | allowed | allowed |
| Administrators, not in Operators | **denied** (recovery-only; join Operators for lifecycle) | allowed |
| `SYSTEM` / service SID | service-internal only | service-internal only |
| anyone else | denied | denied |

The authorization contract is machine-wide: every Operators member can manage
every WarpTweet route on that machine. The UI and docs must not imply per-user
privacy or per-route ownership. If per-user route isolation is wanted later, it
requires a distinct state root, service/token model, and release contract.

Console session ID, caller PID, executable path, parent process, administrator
elevation, and pipe possession are diagnostic facts, not authorization. An
Operators member in another interactive session is **not** rejected for session
mismatch. A non-operator in another session is still denied.

For identity capture, the service may call `ImpersonateNamedPipeClient`, query
the caller token and group membership, then call `RevertToSelf` immediately.
It must check every return value. No filesystem, network, process, or policy
operation may execute while impersonating the caller. A failed impersonation
call leaves the service in its own security context, which is precisely why
unchecked use is unsafe. See
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient).

`GetNamedPipeClientProcessId` may support correlation but never replaces the
token decision.

### Protocol rules

Reuse the strict semantics in `internal/provisioner/protocol.go`, but define a
versioned Windows-capable protocol rather than overloading v1 implicitly.

Every request must contain:

- protocol version;
- random request ID;
- one enumerated action;
- only the typed fields allowed for that action;
- a **required** idempotency key for every externally mutating operation
  (`connect`, `enroll`, `up`, `rotate`, `revoke`, and any other action that
  consumes a single-use invite or changes host/client authority);
- a client deadline or cancellation intent that cannot extend server policy.

The caller generates the idempotency key **before transmission** and retains it
for retries. The service journals that identity as the first durable act of
the operation, before any invite consumption, key generation, or remote call.
A lost response or unknown remote outcome is a **hard recovery state**: retry
with the same identity; the service returns the prior outcome or in-progress
status. Do not mint a second key, consume another invite, or activate a new
local generation. Local generation activation requires an acknowledged remote
result.

Every response must contain:

- the same request ID;
- typed success or typed error code;
- sanitized human text;
- action-specific structured output;
- an explicit terminal/non-terminal state where relevant.

The decoder must reject unknown fields, duplicate keys, trailing values,
invalid Unicode, overlong strings, oversized invites, invalid route IDs, and
fields belonging to another action. Action-specific limits should be below the
current 1 MiB global ceiling wherever possible. The protocol must not accept:

- executable paths;
- arbitrary filesystem paths;
- OpenSSH flags or configuration text;
- service names or SCM definitions;
- SDDL, SIDs, usernames, owners, or modes;
- shell text or environment variables;
- arbitrary destination addresses or ports outside the validated invite and
  active route contract.

All mutating operations are serialized per route. Port reservation and route
creation also take a machine-global allocation lock. Read-only status takes an
immutable snapshot and never blocks indefinitely behind network activity.

## Filesystem and protected state

### Fixed layout

Resolve `ProgramFiles` and `ProgramData` through Known Folder APIs. Do not trust
ambient environment variables to define security-sensitive roots.

```text
%ProgramFiles%\WarpTweet\
  bin\
    warptweet.exe
    warptweet-service.exe
  libexec\openssh\
    ssh.exe
  share\
    openssh-source.txt
    openssl-source.txt
    openssh-bundle.sha256
    sbom.spdx.json
    licenses\...

%ProgramData%\WarpTweet\
  state\
    routes\<route-id>\
      active.json
      generations\<generation-id>\
        client.wt
        identity\client
        trust\known_hosts
        trust\known_hosts.empty
        enrollment-receipt.json
  journal\
  diagnostics\
  temp\
```

The exact generation layout may be adjusted to match current route
transactions, but these invariants are mandatory:

- program files are immutable at runtime;
- service state and private keys are never under an interactive user's profile;
- route generations are immutable after publication;
- one small authority selects the active generation;
- no manifest can choose any path;
- runtime objects do not become persistent configuration;
- ordinary uninstall preserves identities and route state;
- destructive purge is separate, explicit, and recoverable where practical.

### DACL and object rules

The installer creates explicit protected DACLs and disables unsafe inherited
write access. Expected owner, primary group, DACL, integrity level, reparse
state, volume, and file identity become artifact-profile facts.

| Object | Required access model |
| --- | --- |
| Program directory and binaries | Read/execute for users as needed; write, delete, `WRITE_DAC`, and `WRITE_OWNER` only for trusted installation authorities; no non-admin principal may replace an ancestor or child. |
| Service state root | `SYSTEM` and restricted service SID only for mutation; Administrators may obtain recovery access through explicit administration, not routine operator commands. |
| Private identity and management receipt | Service SID and `SYSTEM` only; no operator-group read; no backup or indexer access unless explicitly documented and tested. |
| Public trust and manifest data | Service-owned immutable generation; operator read only if a concrete UX requires it and doing so reveals no capability or sensitive endpoint beyond documented policy. |
| Named pipe | Connect permission only for the explicit caller set; no remote clients. |
| Logs | Read policy documented; never contain invite bodies, private keys, management tokens, payloads, raw command lines with secrets, or unnecessary user identifiers. |

ACL validation must use native security descriptors and SID comparison, not
POSIX mode emulation. See
[Access-control lists](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists).

### Path and replacement defense

Every security-sensitive file should be opened by handle from a previously
validated parent. Validation must reject or account for:

- reparse points and mount points on every ancestor and leaf;
- hard links where link count or file-ID aliasing can weaken replacement
  assumptions;
- alternate data streams;
- UNC and remote-volume paths;
- unsupported filesystem semantics;
- case-folding and trailing-dot/space aliases;
- 8.3 short-name aliases where enabled;
- sharing modes that allow write, delete, or rename during attestation;
- path changes between check and use.

Use `CreateFileW` with explicit sharing and `FILE_FLAG_OPEN_REPARSE_POINT` where
inspection requires it. Compare final normalized paths from retained handles,
volume serial numbers, file IDs, size, timestamps, hashes, security
descriptors, and signatures. See
[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [GetFinalPathNameByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).

Do not validate a pathname, close the handle, then execute that pathname. The
launch design must bind the verified object to the executed object. If Windows
cannot execute directly from the retained handle, hold the restrictive handle,
deny delete/write sharing, re-open immediately before `CreateProcessW`, verify
the same volume and file ID, and fail closed on any discrepancy.

### Atomic state publication

Windows state publication needs a dedicated implementation, not direct reuse of
`os.Rename` and Unix directory fsync assumptions:

1. Create a candidate within the final volume and protected parent.
2. Write all bytes with strict size bounds.
3. flush file buffers;
4. apply and read back the exact security descriptor;
5. parse and semantically validate from the candidate handle;
6. publish the selector (`active.json`) with a **create-if-absent** path on
   first publication and `ReplaceFileW` (or an equivalent proven replace) when
   the selector already exists. `ReplaceFileW` requires a destination file;
   first publication must not depend on it. Tests cover both first publication
   and replacement of an existing selector. Crash semantics of whichever
   primitive is used must be explicit;
7. flush the parent where Windows and filesystem semantics permit;
8. reopen the authoritative name and compare content, file identity, DACL, and
   expected generation;
9. record the transition in a bounded, recovery-oriented journal;
10. retain the prior generation until the new generation and route are proven
    coherent.

Antivirus and indexing software can temporarily hold files. Retries must be
bounded, classified, cancellation-aware, and safe to repeat. A sharing
violation is not permission to publish in place or loosen ACLs.

## Service identity and privilege model

### Recommended account

Install `WarpTweetClient` under the built-in `LocalService` account and enable a
restricted service SID for `NT SERVICE\WarpTweetClient`. Grant filesystem and
pipe access to the service SID, not to a broad local group. Remove every token
privilege the service does not require. Do not grant interactive logon,
administrator membership, `SeDebugPrivilege`, or blanket filesystem rights.

This is a proposed security baseline, not yet proof. A native test must capture
and retain the service token's user SID, group SIDs, restricted SIDs,
privileges, integrity level, session, and network behavior. If the service
requires a privilege not present in this model, the design must document why,
scope it narrowly, and add an abuse test.

`LocalSystem` is prohibited for normal operation. A virtual service account is
an alternative only if its machine-network identity and token are preferable
and proven. The project should not create a password-managed local user unless
Windows service APIs force it, because that adds password rotation, logon
rights, and account lifecycle without improving the product.

### Installer versus runtime authority

Only the MSI transaction is elevated to install or upgrade:

- binaries and source receipts;
- DACLs and local group;
- service registration and recovery policy;
- Event Log source or provider;
- optional machine PATH entry for the CLI;
- version and uninstall metadata.

The running service must not retain installer authority. It cannot update its
own binaries, alter its service definition, add operators, weaken DACLs, or
download an update. Upgrades occur only through a new signed MSI.

## Client-engine decision and build provenance

### Why the engine is a release-blocking design gate

WarpTweet's macOS and Linux client profile is not “whatever `ssh` is installed.”
The engine is an authenticated input with exact version, algorithms, linkage,
path, source receipts, executable structure, digest, and effective
configuration.

The portable upstream OpenSSH repository describes a port to Unix-like systems
and Cygwin. Microsoft's **active development** tree for native Windows is
[PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable).
[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) is the
**release, issue, and build-documentation** location, not the working source
tree (that README has pointed at `openssh-portable` since 2016). At review
time, the Win32-OpenSSH public release line showed 10.0.0.0, while WarpTweet
pins upstream 10.4p1. Microsoft's documented native build uses Visual Studio,
the Windows SDK, and LibreSSL conventions, while WarpTweet pins OpenSSL 3.5.7
with static linkage. These are resolvable engineering gaps, but they are not
evidence that the current engine already builds on Windows. See
[OpenSSH Portable](https://github.com/openssh/openssh-portable),
[PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable),
[Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH), and
[the Win32 native build notes](https://github.com/PowerShell/Win32-OpenSSH/wiki/Building-OpenSSH-for-Windows-%28using-LibreSSL-crypto%29).

### Required source strategy

Before production implementation proceeds past the platform abstractions, an
ADR must select one reproducible source strategy:

1. Rebase a reviewed, pinned **PowerShell/openssh-portable** compatibility
   commit or patch set onto authenticated upstream OpenSSH 10.4p1; or
2. import the necessary native Windows compatibility patch set into the
   authenticated WarpTweet OpenSSH 10.4p1 source tree.

The ADR and source receipt must record the exact active compatibility
commit/tree (from `PowerShell/openssh-portable`, not a Win32-OpenSSH release
tag unless that tag is proven identical) and the patch base used for W2
provenance.

The resulting source receipt must bind:

- the upstream OpenSSH release archive, SHA-256, and verified release
  signature;
- the exact `PowerShell/openssh-portable` compatibility commit and tree hash;
- every local patch in ordered form and its digest;
- the authenticated OpenSSL 3.5.7 source archive and digest;
- MSVC, Windows SDK, Perl/build tools, and all build-script versions;
- the exact compiler and linker flags;
- the generated configuration;
- test commands and material output;
- the final unsigned PE hashes;
- signing transformation and final signed PE hashes;
- license and SBOM outputs.

No build may silently switch to LibreSSL, a system OpenSSL DLL, a newer or older
OpenSSH feature set, or the Windows optional OpenSSH feature. A change in any
wire algorithm, engine version, cryptographic library, patch set, or build
toolchain is a new reviewed artifact contract and may require a new profile ID.

OpenSSL documents native Windows targets and `no-shared` static builds. The
engine feasibility proof must build and test both OpenSSL and the resulting
OpenSSH client on a native Windows builder, rather than calling a Unix
cross-build sufficient. See [OpenSSL build instructions](https://github.com/openssl/openssl/blob/master/INSTALL.md)
and [OpenSSL Windows notes](https://github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md).

### Minimal engine payload

The client MSI should ship the smallest proven engine surface:

- `ssh.exe`;
- no `sshd.exe`;
- no `scp.exe`, `sftp.exe`, `ssh-agent.exe`, or shell utilities;
- no crypto DLL if the static-linkage contract succeeds;
- `ssh-keygen.exe` only if Go key generation cannot pass the exact interop gate.

The repository already has `composite.Generate` and
`opensshkey.MarshalPrivate`. The preferred Windows enrollment path generates
the composite key in Go, writes it through the protected generation
transaction, derives the public key in Go, zeroes avoidable temporary buffers,
and proves that the pinned Windows `ssh.exe` accepts and uses those bytes. This
removes one executable and one subprocess from the client trust base.

This does not remove host-side interoperability checks with OpenSSH key tools.
It only removes a needless client runtime dependency after byte-for-byte and
live authentication proof.

### PE and Authenticode preflight

Add a Windows executable inspector that returns typed facts rather than a
Boolean “looks signed” result. It must verify at least:

- DOS and PE headers are well formed and bounded;
- expected machine type: AMD64 for `windows-amd64`, ARM64 for
  `windows-arm64`;
- expected PE32+ optional header;
- executable is not a DLL and has the intended subsystem;
- section table is sane, non-overlapping, within the file, and contains no
  writable-and-executable section;
- import and delay-import tables are fully bounded and match a reviewed system
  DLL allowlist;
- no unexpected crypto, runtime, or side-loaded DLL is imported;
- ASLR, DEP/NX, high-entropy VA, CFG, and supported CET compatibility flags are
  present according to the pinned toolchain contract;
- debug paths, manifests, resources, version information, and build metadata do
  not disclose builder secrets or create ambiguous product identity;
- Authenticode validation succeeds for the exact file;
- the signing certificate or public-key identity matches release policy;
- timestamp and certificate validity policy is applied consistently;
- the SHA-256 equals the package manifest and active route manifest;
- the file's final path, volume, file ID, size, write time, security descriptor,
  and hash remain stable across preflight and launch.

`WinVerifyTrust` returns zero only for success; other values are failure
statuses, not ordinary `GetLastError` results. Use it for chain and policy
validation, then enforce WarpTweet's expected publisher identity separately.
See [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).

Application code should initialize safe DLL search policy before loading any
optional library, use full paths, avoid current-directory and `PATH` lookup,
and statically link non-system cryptography. See
[Dynamic-Link Library Security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security)
and [SetDefaultDllDirectories](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories).

### Exact child environment

The current `sanitizedClientEnvironment` returns only `LANG=C` and `LC_ALL=C`.
Windows needs its own closed environment constructor. It must determine the
minimum values required by the pinned engine through native testing, likely
including an API-derived Windows directory and a service-private temporary
directory. It must explicitly exclude ambient:

- `PATH` and `PATHEXT`;
- `HOME`, interactive `USERPROFILE`, and roaming profile paths;
- `SSH_AUTH_SOCK` and OpenSSH agent/config overrides;
- `OPENSSL_CONF`, `OPENSSL_MODULES`, and provider overrides;
- loader, allocator, debugger, tracing, and compatibility shims;
- proxy variables not part of the direct WarpTweet transport;
- caller `TMP` and `TEMP`.

If the native engine requires `SYSTEMROOT`, `WINDIR`, `TMP`, or `TEMP`, derive
the values from trusted APIs and fixed protected layout, not the caller's
environment. Tests must prove behavior with hostile ambient variables and
Unicode installation paths.

### Native Go SSH client alternative

A WarpTweet-owned native Go client could eventually remove the Win32 OpenSSH
port and enable a cleaner handle-based readiness seam. It is not a safe
schedule shortcut. A secure replacement must implement and test the full
relevant SSH transport state machine, including strict KEX, first exchange,
session ID continuity, rekey, packet sequence handling, composite signatures,
channel windows, cancellation, error closure, quotas, and malformed-peer
behavior.

Therefore:

- first attempt the pinned native Win32 OpenSSH engine under the feasibility
  gate;
- if it cannot meet the exact profile, provenance, static-linkage, and
  readiness contracts, stop and write a separate native-client ADR;
- never ship a partial custom SSH client solely to make Windows packaging
  possible;
- if a native client is later built, prefer converging all client platforms on
  it only after independent interoperability, fuzzing, adversarial review, and
  package evidence.

## Process supervision and authenticated readiness

### Durable process authority

Windows supervision must own kernel handles, not rediscover processes from PID
files. For each engine launch, retain:

- process handle;
- primary thread handle until the process is safely assigned and resumed;
- process ID for display only;
- creation time;
- executable volume and file ID;
- route generation ID;
- job object handle;
- one-shot readiness object;
- exit code and observed exit time.

Create the child suspended, assign it to a fresh per-route job object, configure
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, set applicable process and memory limits,
install monitoring, then resume it. If any step fails, terminate and reap the
child before reporting failure. Windows job objects provide containment and
whole-job lifecycle notifications; see
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The service must retain and wait on the process handle. PID reuse cannot turn a
stale route record into authority over another process. Status may show a PID,
but readiness, stop, kill, and exit classification use the retained handle and
creation identity.

### Stop and shutdown

The generic supervisor contract should be changed from Unix “Terminate then
Kill” wording to platform-neutral “RequestGracefulStop then ForceStop,” with a
Windows implementation.

The Windows child protocol should support one bounded graceful stop mechanism
selected during the engine spike. Possibilities include an inherited control
event or a private control pipe added to the pinned engine. Sending console
Ctrl events is not reliable service authority and must not target a shared
console. If graceful stop is unavailable, job termination may be the only safe
mechanism, but that limitation and its state consequences must be explicit.

On service stop, upgrade, or system shutdown:

1. stop admitting mutating requests;
2. mark active operations cancelling;
3. request graceful child stop concurrently within a global deadline;
4. force-stop remaining route jobs;
5. wait for process handles and record exit outcomes;
6. flush state transitions and service diagnostics;
7. report SCM stopped only after owned work is reaped or a documented hard
   system deadline prevents it.

A failed stop is not “stopped.” It remains a distinct failure requiring job and
process evidence. Service shutdown must never delete identity or desired
intent.

### Why current readiness cannot be reused blindly

Today WarpTweet marks a route Ready only after:

1. the pinned foreground OpenSSH process exposes a Unix ControlMaster socket;
2. `ssh -O check` reports the exact foreground PID;
3. the control socket is revalidated and unlinked;
4. the child remains alive.

This is a strong Unix-specific witness. Microsoft's Win32 OpenSSH design notes
historically list ControlMaster support as constrained by Unix ancillary-data
semantics. A native Windows build must prove the current exact behavior rather
than assume it exists. See
[Win32-OpenSSH design details](https://github.com/PowerShell/Win32-OpenSSH/wiki/About-Win32-OpenSSH-and-Design-Details).

### Recommended Windows readiness seam

Patch the pinned Windows `ssh.exe` with a narrow inherited readiness event or
one-shot control handle. The service creates a non-inheritable event, duplicates
only the required child handle as inheritable, passes its opaque numeric value
through a WarpTweet-private option or environment entry, and restricts the
child's inherited handle list with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.

The engine signals the event exactly once, only after:

- server host authentication succeeds;
- composite user authentication succeeds;
- the requested local forward listener is successfully created;
- all forwarding failures that `ExitOnForwardFailure` covers have been
  resolved;
- the connection is entering its forwarding-only steady state.

The service waits on both the readiness event and process handle under a startup
deadline. Process exit wins over readiness if both are observed ambiguously.
After the signal, the service independently verifies:

- the child process handle is still live;
- the listener exists only on the exact intended loopback address and port;
- the listener belongs to the expected child process, using native connection
  table ownership data or a stronger engine-provided socket handle;
- the engine launch attestation still identifies the exact executable and route
  generation.

Then, and only then, the state may transition from `AwaitingReadiness` to
`Ready`. Target application health remains `not_checked` unless a separate,
explicit probe contract exists.

The stronger ideal is for the service to reserve the loopback listener with
exclusive address use and pass the listener handle to the engine. If the
pinned engine can be patched to accept that handle without changing SSH wire
behavior, it removes the bind race and makes listener identity direct. This
should be evaluated in the feasibility spike. Parsing log text or sleeping for
a fixed interval is never a readiness implementation.

### Route state machine

Preserve the existing states and make Windows transitions explicit:

| From | Event | To | Required durable or handle evidence |
| --- | --- | --- | --- |
| `Stopped` | operator up or desired restore | `Preparing` | authorized request or boot reconciliation, selected immutable generation |
| `Preparing` | all state and engine preflight passes | `Starting` | retained state and engine handles, exact launch contract |
| `Preparing` | validation fails | `Failed` | typed terminal integrity error, no child |
| `Starting` | suspended child assigned to job and resumed | `AwaitingReadiness` | retained process/job/event handles |
| `Starting` | create/assign/resume fails | `Failed` | child terminated and reaped, failure recorded |
| `AwaitingReadiness` | exact readiness proof | `Ready` | live process and exact listener identity |
| `AwaitingReadiness` | timeout, child exit, or integrity failure | `Backoff` or `Failed` | child reaped, bounded policy decision |
| `Ready` | unexpected child exit | `Backoff` or `Failed` | exit observed from process handle, desired intent checked |
| `Ready` | operator down, rotate, revoke, upgrade, service stop | `Stopping` | desired intent and operation journal updated before destructive effect |
| `Backoff` | timer expires and intent remains active | `Preparing` | cancellation-aware timer, bounded attempt count |
| `Backoff` | down/revoke/expiry | `Stopping` | retry cancelled, no new child |
| `Stopping` | child job fully reaped | `Stopped` | exact handle completion and durable final state |
| any active state | service crash | reconciliation on service restart | state journal plus absence/presence of owned job/process evidence; never stale Ready |

Every transition must have one owner. External CLI cancellation ends the
request wait; it does not automatically cancel a durable operation after the
service has crossed its commit boundary. The response must say whether the
operation was not started, cancelled before commit, still running, completed,
or failed.

### Sleep, resume, reboot, and network changes

Windows laptops suspend and change networks frequently. The service must:

- subscribe to service and power notifications rather than poll;
- treat suspend as an interruption, not proof of child failure or route
  success;
- reconcile child process, listener, grant expiry, wall-clock rollback, and
  network state after resume;
- never retain stale `Ready` solely because a pre-suspend PID still exists;
- use the current server-side expiry and revocation authority after reconnect;
- treat **service restart** and **machine reboot** as different events
  (boot identity changes only on reboot);
- `unless-stopped`: restore after service restart **and** after machine reboot;
- `manual`: if desired was up, restore after **service restart**; after
  **machine reboot**, remain stopped (do not start merely because the machine
  came back). Explicit `down` stays down across both;
- bound reconnection storms when many routes resume together;
- add jitter without weakening maximum delay or cancellation;
- expose degraded/retrying state without claiming the target is healthy.

Use a machine boot identity derived from a Windows API and monotonic process
facts. Do not recreate `/proc` boot IDs with a wall-clock string. The exact
algorithm must survive clock adjustment and distinguish a service restart from
a machine restart.

## Loopback networking contract

### Listener policy

The initial Windows profile should bind exactly `127.0.0.1`, never `0.0.0.0`,
an interface address, or an invite-selected arbitrary local address. If IPv6
is supported later, bind `[::1]` under a versioned policy and test dual-stack
and port-collision behavior. Do not assume that an IPv6 loopback listener
implicitly provides the intended IPv4 contract.

The service must prevent silent port reassignment. A requested occupied port is
a typed conflict, not a reason to pick another port. The ideal listener-owner
design reserves the socket with `SO_EXCLUSIVEADDRUSE` before child launch and
passes the socket handle to the engine. If OpenSSH must bind itself, tests must
prove there is no interval where another local process can steal the port
between validation and bind.

Windows Firewall is not local caller authorization for a loopback service. The
threat model must assume any local process able to connect to the selected
loopback port can send application traffic through that route. WarpTweet
protects the remote service from the public network and restricts the remote
target; it does not authenticate local database clients. This behavior must be
documented without implying per-application isolation.

### Connection failures

Network loss, DNS failure where names are supported, host refusal, expired
grant, revoked authorization, rekey failure, target refusal, and local listener
collision are distinct outcomes. Only authenticated SSH plus local listener
setup establishes route readiness. Target refusal is observed per connection
and must not rewrite cryptographic readiness as “secure tunnel failed” without
the underlying distinction.

No retry loop may be unbounded. Retries must:

- honor desired intent and cancellation;
- use exponential backoff with a cap and stable-window reset;
- classify permanent integrity/profile/signature errors as terminal;
- avoid retrying malformed invites, expired grants, revoked authorization, bad
  signatures, state tampering, or package tampering;
- re-attest the engine and active state before every launch;
- avoid synchronized resume or boot storms;
- retain last transition and sanitized error for diagnosis.

## Key and secret lifecycle

### Assets

Windows handling must classify at least:

| Asset | Classification | Persistence | Exposure rule |
| --- | --- | --- | --- |
| `.wtinvite` | confidential, short-lived, single-use bearer credential | caller-selected input; service holds only for action duration and required recovery journal | never log or copy into general diagnostics; securely delete best-effort temporary service copy after terminal consumption |
| composite private key | secret authentication key | protected active and retained rollback generation according to lifecycle policy | service SID and `SYSTEM` only; never CLI-readable |
| management token | secret capability | protected enrollment receipt until rotate/revoke lifecycle makes it obsolete | transmit only over invite-pinned TLS; server stores digest; never log |
| host key pin and public keys | integrity-sensitive public material | active immutable generation | may be displayed in deliberate diagnostics; never silently replace |
| manifest and route target | sensitive operational metadata | active immutable generation | disclose only to authorized operators; do not send telemetry |
| tunnel payload | private application data | not persisted by WarpTweet | never inspect or log |

### Baseline disk protection

The release baseline may store the unencrypted OpenSSH private-key encoding on
disk only if:

- it is inside the protected service-owned generation;
- the DACL permits only the service SID and `SYSTEM`;
- backup, indexing, crash-dump, log, and antivirus behavior is documented;
- the project states accurately that access control protects the file and does
  not call it encrypted at rest;
- key creation, rotation, rollback retention, revocation, uninstall, purge, and
  incident behavior are tested.

### Gold-standard hardening path

The stronger design keeps the raw private key out of persistent plaintext:

1. Store a service-bound protected key blob, using an appropriate Windows
   protection mechanism only after its machine/service/recovery semantics are
   fully specified.
2. Provide signing through a WarpTweet-owned private agent or an inherited,
   authenticated handle understood by the pinned engine.
3. Decrypt into locked service memory only for bounded signing use.
4. Prevent swap, dumps, child environment, command line, pipe responses, and
   diagnostic paths from receiving the raw key.
5. Define backup and machine-recovery behavior explicitly, including the
   possibility that a protected key is intentionally non-portable.

This should not be claimed by wrapping bytes in DPAPI while writing the
plaintext back to disk for OpenSSH. Windows CNG/TPM support for a custom
ML-DSA-44 plus Ed25519 composite key must not be assumed. If the engine cannot
use a service-resident signer, the honest ACL-protected baseline is preferable
to a misleading encryption claim.

### Memory handling limits

Go cannot guarantee that every secret copy is eliminated by zeroing one slice.
The implementation should still minimize lifetimes and copies, overwrite
owned mutable buffers, avoid converting secrets to strings, exclude secrets
from errors and structured logs, and document the garbage-collected memory
limit honestly. Crash dumps for the service and engine require an explicit
policy because they can contain key or payload memory.

## Reliability, concurrency, and recovery

### State ownership

There must be one durable authority for each fact:

| Fact | Authority |
| --- | --- |
| Active route generation | service-owned generation selector under protected state |
| Desired restart intent | durable route state committed before SCM or child effects |
| Current engine process | retained service process and job handles |
| Display PID | derived diagnostic fact from current process handle |
| Readiness | current-generation process plus one-shot authenticated-forward proof and listener identity |
| Host authorization | Linux host grant authority, not Windows state |
| Invite consumption | Linux host enrollment authority and bound client transaction |
| Package identity | MSI/package manifest plus runtime binary attestation |
| Operator authorization | current named-pipe client token and explicit local-group policy |
| Route expiry/revocation | server authority, reconciled into local lifecycle state |

State files must never assert that a process is currently Ready after service
restart. They may record that the last observed state was Ready, but runtime
state starts as reconciling until fresh handle/listener/transport evidence is
created.

### Concurrency rules

- One mutating operation per route may cross its validation boundary at a
  time.
- Route creation and listen-port changes also hold a machine-global port
  allocation lock.
- `status` and `routes` return an immutable snapshot and may run concurrently.
- Duplicate requests with the same idempotency key return the same committed
  outcome or resume the same transaction.
- Duplicate requests with different bodies and the same key fail as a conflict.
- Rotate and revoke cannot overlap.
- Down during enrollment, rotation, or repair becomes a typed cancellation or
  queued intent according to the operation's commit point.
- Service shutdown cancels admission first, then waits for or safely journals
  in-flight operations.
- MSI upgrade owns a global maintenance lock and prevents the old and new
  services from simultaneously mutating state.

Use `LockFileEx` on a held handle for cross-process maintenance and migration
locks. Do not use a removable PID text file as the lock authority. The normal
service path should require little cross-process locking because one service
serializes route operations in memory, but the installer, repair tools, and
recovery path still need a durable exclusion primitive.

### Transaction commit points

Enrollment, rotation, and revocation cross both local and server authorities.
Each transaction needs explicit durable phases and idempotent recovery:

```text
validated
local candidate generated
remote request prepared with stable idempotency identity
remote outcome unknown or acknowledged
local generation activated
old generation retired or retained for bounded recovery
terminal result published
```

Response loss after the host commits must not generate a new key/token or
consume a second invite. The service journals enough non-secret binding data
and protected capability state to retry the exact operation. It verifies the
host outcome before activating or retiring a generation. A CLI timeout does
not erase this journal.

### Upgrade and downgrade

The MSI upgrade transaction must:

1. verify the incoming MSI signature and product/upgrade identity;
2. acquire the global maintenance lock;
3. stop new CLI mutations;
4. drain or safely cancel route transactions;
5. stop and reap all engine jobs;
6. back up the state schema and active-generation selectors without copying
   secrets into an insecure temp directory;
7. stage new signed immutable program bytes;
8. migrate state forward with typed version checks;
9. read back DACLs, service config, binary signatures, hashes, and state;
10. start the new service and reconcile desired routes;
11. prove status and route restoration;
12. commit the installer transaction.

If a pre-commit step fails, rollback restores the prior signed program version
and state schema or leaves the service stopped with a precise recovery result.
A half-migrated service must not start. Automatic downgrade is denied unless
the target version explicitly understands every current state schema. Identity
and grants are preserved by default.

### Uninstall and purge

Ordinary uninstall:

- stops the service and child jobs;
- removes service registration, binaries, PATH entry, and package metadata;
- preserves `%ProgramData%\WarpTweet\state` and identity by default;
- leaves a concise, permission-safe explanation of preserved state and the
  exact purge command;
- verifies that no service or engine process remains.

Purge is a separate administrator action. It names the exact state root,
summarizes that identity and route recovery will be lost, requires explicit
confirmation or a purpose-built noninteractive flag, optionally writes a
recoverable backup, removes only the validated WarpTweet state, and reads back
absence. It must reject reparse points or an unexpected root before deleting
anything.

The optional purge backup may contain the composite private key and management
receipt. It is a **secret**:

- destination is service-owned, under `%ProgramData%\WarpTweet\purge-backup\`
  (or an operator path that passes the same parent/leaf reparse, volume, and
  file-ID checks as other protected state);
- DACL: service SID and `SYSTEM` for mutation; Administrators recovery read;
  no Operators-group read; no indexer/backup-operator ACE unless separately
  specified and tested;
- reject reparse points on every ancestor and leaf before create;
- retention: keep until the operator deletes it or a later purge replaces it
  under the same contract; do not write a second plaintext copy into temp,
  diagnostics, or Event Log;
- purge readback lists the backup path and whether it exists; secret-scan of
  Event Log, MSI logs, CLI output, dumps, and temp must include that tree.

A separate encrypted export is a later contract, not a first-edition
requirement. If no backup is requested, no secret-bearing copy is created.

## Observability and privacy

### Event model

Use Windows Event Log or ETW for bounded, structured operational events. Every
event needs:

- event ID and schema version;
- product and service version;
- route ID or a stable redacted correlation ID;
- operation/request ID where applicable;
- lifecycle state and transition reason;
- typed outcome code;
- retry attempt and bounded backoff when relevant;
- engine/package digest prefix only when useful and non-ambiguous;
- no secret or payload.

Recommended events include service start/stop, configuration reconciliation,
request admitted/denied, route transition, engine attestation failure,
readiness success/failure, process exit, retry exhaustion, enrollment
transaction recovery, upgrade migration, state-integrity failure, and clock
rollback handling.

### User-facing status

`warptweet status --json` should remain deterministic and typed. The human view
must distinguish:

- stopped by operator;
- preparing;
- starting;
- awaiting authenticated readiness;
- ready;
- retrying with next attempt metadata;
- failed due to integrity, profile, authorization, expiry, local port,
  networking, or target behavior;
- service unavailable;
- route transaction still recovering.

Ready means the exact authenticated transport and local forward listener were
proven for the live child. It does not mean the target application is healthy.
Do not collapse security denial into a generic network error or reveal secret
values in a detailed diagnostic mode.

### Resource budgets

Define numerical release budgets before implementation evidence is accepted:

- service idle CPU and wakeups with zero routes;
- service private working set with zero routes and per additional route;
- engine private working set per route;
- CLI cold-start and local status latency;
- connect-to-readiness latency under representative LAN and Internet paths;
- reconnect behavior after network loss and resume;
- tunnel throughput and added latency versus the same pinned engine on macOS;
- log volume per route per day and during failure storms;
- maximum concurrent routes, pending IPC requests, and child launch attempts;
- MSI installed size and upgrade temporary storage.

The exact values belong in the acceptance checklist after measurement. “Low
overhead,” “fast,” and “efficient” are not pass criteria. Prefer service and
network notifications over polling.

## Packaging, signing, and distribution

### MSI first

Use a signed per-machine MSI as the initial native package. Microsoft's
packaging guidance identifies MSI as appropriate when installation needs
system-level changes such as Windows Services; WinGet adds discovery and
install orchestration around that package. See
[Choose a Windows app distribution path](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/choose-distribution-path).

The MSI must:

- have stable product and upgrade codes under a documented version strategy;
- contain every runtime byte, source receipt, license, and SBOM;
- perform no network download;
- install only per-machine;
- install quoted, exact service image paths;
- create and read back DACLs and local-group membership changes;
- configure delayed auto-start only if boot evidence justifies it;
- configure bounded SCM failure actions;
- support unattended install, repair, and uninstall without hidden prompts;
- redact MSI property values and custom-action logs;
- leave no writable executable ancestor;
- fail and rollback if signature, ACL, service, or read-back validation fails;
- preserve state on upgrade and ordinary uninstall;
- block a second concurrent install/repair/migration path.

Avoid custom actions where declarative MSI tables can express the change.
Every unavoidable custom action needs explicit input validation, rollback,
impersonation context, logging redaction, and failure tests. The packaging
toolchain, such as WiX if selected, is a pinned supply-chain dependency with
license, provenance, maintenance, and vulnerability review.

### Code signing

Authenticode-sign:

- `warptweet.exe`;
- `warptweet-service.exe`;
- private `ssh.exe`;
- any package custom-action DLL or executable;
- the final MSI.

Use SHA-256, a protected signing identity, and a trusted timestamp service.
Separate build authority from signing authority. CI must upload immutable
unsigned artifacts and receive immutable signed artifacts; signing credentials
must not enter the repository, build logs, developer machines, prompts, or
fixtures. Record signer certificate chain, timestamp, unsigned digest, signed
digest, signing request identity, and verification output in release evidence.

Microsoft documents several signing options, including managed services and
programs suitable for open-source projects. Selecting or provisioning one is an
external organizational decision, not part of local implementation. See
[Code signing options for Windows](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options).

### WinGet

After the signed MSI passes package-only evidence, publish a versioned WinGet
manifest that binds:

- package identifier and publisher;
- exact version;
- per-architecture installer URL;
- exact SHA-256 of the signed MSI;
- machine scope;
- silent and interactive switches;
- minimum supported Windows version;
- installer type and return-code behavior;
- license and project URLs.

WinGet is a discovery and installation layer, not a trust replacement. The MSI
signature, WinGet hash, package manifest, and runtime preflight all bind the
same final bytes. Scoop and MSIX add no first-release capability and should not
be added until the MSI path is complete and maintainable.

### Supply-chain outputs

Every Windows release should publish or retain:

- source tag and full commit;
- clean-tree proof;
- authenticated source archives and signatures;
- ordered patch set and digest;
- pinned builder image or VM recipe;
- compiler, SDK, Go, OpenSSL, OpenSSH, MSI-tool, and signing-tool versions;
- complete build commands;
- SPDX or CycloneDX SBOM for the controller, service, engine, and installer;
- license inventory;
- dependency, secret, static-analysis, and artifact-scan results;
- reproducibility comparison from at least two controlled builds where
  technically achievable;
- PE and Authenticode reports;
- signed package digest and public release evidence.

## Threat model additions for Windows

The existing `docs/2026-08-09_threat-model.md` should be extended when the
architecture is accepted. The Windows-specific minimum is:

| Actor or failure | Attempt | Consequence if successful | Required control | Release proof |
| --- | --- | --- | --- | --- |
| Unprivileged local user outside operator group | Connect to service pipe and mutate routes | Unauthorized tunnel creation, stop, or secret access | explicit pipe DACL, remote rejection, caller-token authorization, no secret response | negative requests from multiple local accounts and sessions |
| Authorized operator | Read service private key or another operator's invite | Credential theft and route impersonation | machine-wide management is explicit, but secret files remain service-only; no invite persistence/logging | DACL access-denial tests and log inspection |
| Local administrator | Replace binaries or state | Complete local machine compromise of WarpTweet | package signatures and runtime attestation detect accidental or out-of-band mutation; do not claim protection from a hostile active administrator | tamper tests produce terminal integrity failure |
| Malicious named-pipe client | Oversized, malformed, duplicated, reordered, or slow request | memory exhaustion, parser confusion, stuck service | bounded framing, strict decoder, deadlines, concurrency caps, idempotency | fuzz, slowloris, boundary, duplicate-key, and cancellation tests |
| Remote pipe connection | Invoke machine management over SMB or a remote session | remote control-plane exposure | `PIPE_REJECT_REMOTE_CLIENTS`, DACL, caller-token checks | remote connection attempts rejected |
| Path attacker | Reparse, hard-link, alternate-stream, case alias, or rename executable/state | engine or key substitution | handle-relative validation, reparse rejection, file identity, restrictive share modes, DACL readback | adversarial filesystem tests |
| DLL planter | Place dependency in current directory, PATH, temp, or writable ancestor | code execution as service | static crypto, system-DLL allowlist, safe DLL directories, full paths, protected ancestors | import inspection and planted-DLL execution test |
| Malicious or corrupted engine | Signal readiness without authenticated forward | false Ready and misrouted local traffic | engine source review, signed exact bytes, one-shot event at reviewed code point, independent process/listener check | patched-code unit test plus live packet/algorithm evidence |
| PID reuse | Stale state targets unrelated process | wrong-process termination or false status | retained process handle, creation identity, job ownership | forced PID churn/reuse test |
| Port race | Bind local port between check and engine bind | denial or traffic interception | service-owned exclusive listener handle if feasible, otherwise exact bind-race proof | competing binder stress test |
| Service crash or power loss | Interrupt state mutation | split generation, stale Ready, lost intent | journaled immutable generations, atomic replace, startup reconciliation | kill and VM power-cut fault injection at every commit boundary |
| Antivirus/indexer | Hold or scan candidate/state file | partial publish or unbounded hang | restrictive share modes, bounded retry, safe failure, exclusion guidance only if necessary | controlled sharing-violation tests with Defender enabled |
| Malicious environment | Inject config, crypto provider, DLL, proxy, locale, or agent behavior | policy bypass or code loading | closed API-derived environment and full executable paths | hostile environment matrix |
| Package downgrade | Install older vulnerable code over newer state | security regression or corrupt state | versioned MSI upgrade policy, state schema checks, downgrade denial | upgrade/downgrade matrix |
| Clock rollback | Extend expired authorization | unauthorized continued access | existing server clock authority and local resume/reconnect reconciliation | live rollback closes authorization and session |
| Memory or crash-dump collector | Capture key or payload memory | confidentiality loss | secret minimization, dump policy, service ACLs, no routine dump upload | dump configuration inspection and incident procedure |
| Compromised update or signing path | Publish attacker-controlled signed-looking package | ecosystem compromise | separated build/sign/release authority, protected signing service, immutable digests, public provenance | release rehearsal and independent signature verification |

The local administrator row requires precise language. WarpTweet can detect
that installed files no longer match the signed release and fail closed. It
cannot promise to remain secure against an administrator who controls the
kernel, service configuration, trust stores, and process memory.

## Repository change map

The implementation should evolve coherent packages rather than creating a
parallel Windows application.

### Platform contracts first

| Existing area | Required change |
| --- | --- |
| `internal/profile/profile.go` | Remove platform executable format from the wire profile. Preserve algorithm and engine facts. Add a migration test proving the profile ID does not change merely because the executable container changes. |
| `internal/artifactprofile/profile.go` | Add typed Windows IDs and a Windows-native layout/attestation structure. Avoid empty or meaningless UID/GID fields. Make every profile explicit about client, host, architecture, package, format, signing, and support capabilities. |
| `internal/installlayout` | Add Windows Known Folder resolution and typed logical roots. Fixed security policy should compare canonical handle-resolved paths, not raw environment-expanded strings. |
| command registration | Separate client, host, service, and diagnostic capabilities. Build only the Windows client/service surface into Windows packages. |
| `internal/lifecycle` | Split lock, process identity, liveness, atomic state, and boot identity into platform interfaces. Add `windows` implementations using handles and native APIs. |
| `internal/supervisor` | Generalize graceful/force stop semantics and readiness identity. Add Windows process/job launcher without weakening Unix behavior. |
| `internal/routestate` | Separate domain transaction state from POSIX storage. Add Windows storage with DACL, handle, flush, replace, and recovery semantics. |

### Windows service and IPC

| New or changed area | Responsibility |
| --- | --- |
| `cmd/warptweet-service` | SCM entrypoint only; no general CLI parsing; current directory and environment ignored as authority. |
| `internal/platform/windowsservice` | service registration facts, control handler, power/session/network notifications, status checkpoints, shutdown coordination, Event Log integration |
| `internal/platform/windowsipc` | named-pipe creation, SDDL, caller-token capture, strict framing, deadline/cancellation, remote rejection |
| `internal/platform/windowsprocess` | suspended process creation, restricted handle inheritance, job assignment, exit monitoring, graceful/force stop |
| `internal/platform/windowsfs` | Known Folders, retained handles, DACL validation, reparse/file-ID checks, safe replace and flush |
| `internal/provisioner` | preserve action/domain handling, add transport-neutral service handler, version protocol for Windows caller identity and idempotency semantics |

Package names are illustrative. The final design should keep public surfaces
small and avoid a generic `platform` dumping ground. Native syscall wrappers
should expose typed WarpTweet operations, not arbitrary Windows API access to
the domain layer.

### Engine and preflight

| Existing area | Required change |
| --- | --- |
| `internal/engine/client_platform_*` | Add Windows platform support only after native engine facts are known. |
| `internal/engine/client_linkage_*` | Add PE import/linkage/mitigation inspector and exact allowed system library contract. |
| `internal/engine/client_codesign_*` | Add `WinVerifyTrust` and expected signer policy. |
| `internal/engine/client_state_*` | Implement DACL, owner SID, final-path, file-ID, reparse, stream, and sharing checks. Do not adapt POSIX modes mechanically. |
| `internal/engine/client_process.go` | Add closed Windows environment and native process launch contract. |
| `internal/engine/readiness.go` | Extract Unix ControlMaster readiness behind an interface; add the reviewed Windows one-shot readiness implementation. |
| OpenSSH patch/build scripts | Add authenticated Win32 patch-source fetch, native build, static OpenSSL proof, tests, source receipt, and bundle manifest. |
| key generation path | Prefer `composite.Generate` plus `opensshkey.MarshalPrivate`; add deterministic public-key and live OpenSSH interop tests. |

### Package and evidence

| New or changed area | Responsibility |
| --- | --- |
| `packaging/windows` | MSI source, service/group/DACL definitions, upgrade/rollback, no-download install, licenses and receipts |
| `scripts/build-windows-*` | deterministic controller/service/engine/package build orchestration on native Windows |
| `scripts/sign-windows-*` | signing request and verification workflow with no local secret keys |
| `schemas/release-evidence-v3.schema.json` | Windows-aware artifact, signer, OS-build, service, and package binding |
| `packaging/evidence/checklist-v3.json` | immutable expanded matrix and Windows positive/negative cases |
| `internal/releaseevidence/v3.go` | strict decoding, exhaustive matrix validation, final package digest binding, signer and environment validation |
| interop harness | PowerShell-native package-only client role plus Linux server role; no source-tree substitution |
| website/install docs | before W8: non-install “Windows is in development” banner only (allowed from W0); no WinGet, MSI URL, or availability claim until the exact signed MSI, WinGet manifest, and complete v3 evidence exist |

### Test discipline during refactoring

Existing Linux and Darwin tests are regression gates. Platform extraction is
not permission to loosen ownership, readiness, linkage, or process-identity
tests. Add contract tests that run the same domain lifecycle suite against
fake platform authorities, then native tests for the actual Windows boundary.

Do not delete `*_unsupported.go` fail-closed behavior. Replace it only for the
specific Windows profile with a complete implementation.

## Verification strategy

### Test layers

| Layer | Required proof | Does not prove |
| --- | --- | --- |
| Cross-compilation | every intended Windows command/package compiles for the declared GOOS/GOARCH; unsupported host commands are absent | executable launch, native API behavior, service behavior, cryptographic engine, MSI, or Windows support |
| Domain unit tests | lifecycle, transaction, protocol, profile, idempotency, and error invariants | Windows handles, DACLs, process ownership, named pipes, or package installation |
| Windows native unit/integration tests | filesystem, ACL, pipe, token, service, job, process, event, PE, signature, and state recovery against Windows APIs | remote Linux interoperability or public package behavior |
| Engine build tests | authenticated sources, OpenSSL tests, OpenSSH tests, exact queries, linkage/imports, readiness patch tests | installed package, non-admin operation, host interop, or release matrix |
| MSI tests | clean install, repair, upgrade, rollback, uninstall, DACL/service/PATH readback | a working tunnel or published WinGet artifact |
| Package-to-package tests | exact signed MSI against exact signed Linux packages on separate hosts | public CDN availability or broad user-environment compatibility |
| Manual accessibility and usability | real terminal, Narrator, keyboard, copy/paste, error recovery, installer experience | unattended automation or all locales |
| Release publication checks | public URLs, hashes, signatures, WinGet install, docs and CTA binding | future Windows versions or untested architectures |

Go lists Windows on amd64 and arm64 as supported build targets, but that is
only the controller toolchain fact. It does not establish native OpenSSH,
installer, service, or package support. See
[Go installation from source and supported ports](https://go.dev/doc/install/source).

### Native Windows test matrix

The matrix must be fixed in the v3 checklist before a release candidate is
tested. At minimum it should include:

| Dimension | Required initial cells |
| --- | --- |
| Client architecture | native `windows-amd64` |
| Client OS | each Windows 11 release explicitly promised and still supported at release cut |
| Edition | at least Pro and Home where service/group behavior is supported; Enterprise if claimed |
| Installation | clean interactive, clean silent, repair, same-version repair, upgrade from previous candidate, rollback on injected failure, uninstall-preserve, explicit purge |
| User | installing administrator, non-admin member of WarpTweet Operators, non-member local user, second operator, Unicode username/profile, standard and elevated terminals |
| Terminal | PowerShell, Command Prompt, Windows Terminal |
| Security mode | Microsoft Defender enabled, SmartScreen/reputation behavior observed, UAC default, high-contrast mode for installer/manual UI where applicable |
| Power/network | reboot, service restart, sleep/resume, Modern Standby where hardware supports it, Wi-Fi change, offline start, network loss, server restart |
| Server | signed Linux amd64 package and signed Linux arm64 package on separate machines |
| Local applications | deterministic TCP fixture plus representative PostgreSQL and one additional binary protocol client |

Virtual machines are appropriate for deterministic OS and fault-injection
coverage. At least one representative physical Windows laptop is required for
sleep/resume, network transition, terminal integration, endpoint security, and
user-experience evidence. ARM64 becomes a supported profile only with native
ARM64 engine, service, MSI, signature, and hardware evidence. Running x64 under
emulation is an x64 compatibility observation, not `windows-arm64` proof.

### Required positive package cases

The existing v2 positive cases remain applicable unless the v3 contract gives
a documented Windows-specific equivalent. Add or refine:

1. final MSI signature, PE signatures, source receipts, SBOM, and package
   manifest all bind the same bytes;
2. install creates exact files, DACLs, service account/SID, operator group,
   service recovery, PATH entry, and Event Log provider;
3. non-admin operator consumes a fresh `.wtinvite` with the public command;
4. Go-generated composite identity is accepted by the pinned Windows engine;
5. exact composite host and user authentication is captured;
6. exact hybrid KEX and approved cipher are captured;
7. at least one rekey stays on the same exact profile;
8. readiness proves the expected live process and exact loopback listener;
9. deterministic target payload crosses the tunnel;
10. two routes run simultaneously with distinct identity, state, process, job,
    and port;
11. `unless-stopped` restores after service restart and reboot; `manual`
    restores after service restart only and stays stopped across reboot;
12. sleep/resume and network transition never expose stale Ready;
13. rotate converges after injected response loss without duplicate authority;
14. revoke closes active traffic at the server authority;
15. expiry and clock rollback remove authorization and close active sessions;
16. service crash and SCM recovery restore only eligible desired routes;
17. MSI upgrade preserves identity and active intent, then proves fresh route
    readiness;
18. ordinary uninstall preserves state, leaves no process/service, and clean
    reinstall can recover according to documented policy;
19. explicit purge removes only validated WarpTweet state and readback proves
    the result;
20. WinGet installs the exact previously proven signed MSI without source-tree
    substitution.

### Required negative and adversarial cases

At minimum:

- classical-only KEX, host key, or client key;
- wrong, changed, expired, or unsupported profile;
- wrong or replaced host pin;
- malformed, truncated, overlong, trailing-data, and wrong-algorithm SSH data;
- expired, reused, altered, cross-host, and cross-target invite;
- shell, exec, subsystem, SFTP, SCP, remote, dynamic, agent, X11,
  stream-local, and TUN forwarding requests;
- local listen wildcard, interface address, silent port change, and occupied
  port;
- competing bind before and during launch;
- engine, controller, service, manifest, identity, trust, receipt, source
  receipt, and package-manifest replacement;
- invalid Authenticode chain, unexpected signer, expired policy, absent
  timestamp where required, and signed-file post-mutation;
- DLL in current directory, user PATH, service temp, package ancestor, and
  route state;
- writable executable ancestor, malicious inherited DACL, owner change,
  `WRITE_DAC`, `WRITE_OWNER`, and delete permission;
- reparse ancestor/leaf, mount point, hard link, alternate data stream, case
  alias, short-name alias, and remote volume;
- pipe connection from non-operator, anonymous/remote source, and
  Administrators-without-Operators mutating lifecycle actions; Operators
  member in another session **succeeds**;
- unknown fields, duplicate JSON keys, invalid UTF-8/Unicode, oversized body,
  slow body, no half-close, response backpressure, cancellation, and request
  flood;
- duplicate and reordered enrollment/rotation/revocation responses;
- process exit before readiness, readiness signal before listener, signal from
  wrong process, duplicated event handle, PID reuse, job escape attempt, and
  stop failure;
- service kill and VM power interruption at every local transaction boundary;
- antivirus sharing violation during write, replace, preflight, launch, and
  upgrade;
- network loss during enroll, authenticate, ready, rekey, rotate, and revoke;
- target refusal, server restart, TCP reset, half-open connection, and bounded
  flood;
- downgrade over newer state, corrupt migration, concurrent repair/upgrade,
  and rollback failure;
- uninstall with active routes, in-flight rotate, locked file, modified DACL,
  and reparse-point state root;
- secret scanning of Event Log, MSI logs, CLI output, process command line,
  environment, crash dumps, temp files, package artifacts, and the optional
  purge-backup tree.

### Fuzzing and static analysis

Add deterministic fuzz targets for:

- named-pipe frames and strict request decoding;
- invite and proof transfer through IPC;
- PE headers, sections, imports, delay imports, load configuration, certificate
  directory, and resource parsing;
- Windows path normalization and canonical identity comparison;
- state journal and generation selector recovery;
- Windows error-to-domain error classification;
- readiness messages or event metadata if the engine patch carries any bytes.

Run current Go format, vet, tests, race tests where supported, vulnerability
scan, secret scan, static analysis, dependency review, MSI validation, PE
security inspection, and installer malware scanning. A Windows race build that
cannot exercise native service tests is not a substitute for concurrency fault
injection around actual handles.

### Accessibility and CLI usability

The Windows CLI and installer are user interfaces. Before release, verify:

- every operation is possible by keyboard;
- terminal output remains understandable with color disabled and never uses
  color as the only success, warning, or failure cue;
- `NO_COLOR` and redirected-output behavior are documented and deterministic;
- progress output does not continuously rewrite lines when redirected or used
  with a screen reader;
- status and errors are announced coherently with Narrator in representative
  terminal combinations;
- visible command labels appear verbatim in accessible names for any installer
  UI;
- long paths, Unicode route labels, localization expansion, narrow terminal
  widths, 200 percent text scaling, high contrast, and light/dark terminal
  themes do not hide essential output;
- prompts preserve input and state on validation failure;
- unattended install requires no inaccessible UI;
- documentation includes copyable PowerShell commands and does not rely on a
  screenshot alone.

Automation cannot establish accessibility by itself. Retain the Windows build,
terminal, Narrator, theme, scaling, commands, evaluator, failures, and
remediations in release evidence.

## Release-evidence v3

Do not mutate `release-evidence-v2.schema.json` or
`packaging/evidence/checklist-v2.json`. They are historical contracts. Create
v3 and hash the canonical checklist exactly as v2 does.

### Required additional bindings

Each Windows client report should bind at least:

- Windows edition, version, build, servicing state, architecture, and native or
  emulated execution;
- physical/VM environment and hypervisor where applicable;
- client MSI path, SHA-256, package product/version/upgrade IDs, and
  Authenticode result;
- controller, service, engine, and custom-action final signed SHA-256 values;
- signer certificate/public-key identity and timestamp facts;
- OpenSSH upstream source, PowerShell/openssh-portable compatibility commit,
  patch-set, OpenSSL, Go, compiler, SDK, and packaging-tool receipts;
- SBOM digest;
- PE inspection report digest;
- installed file manifest and DACL readback report digest;
- service account SID, restricted service SID, token/privilege report digest,
  recovery policy, and image-path evidence;
- pipe name, SDDL, remote-rejection, and operator-authorization evidence;
- route generation, process creation identity, job identity, readiness event,
  listener owner, and exact local bind;
- exact server package, host profile, and host target;
- exact commands and whether each ran elevated or unelevated;
- reboot, sleep/resume, upgrade, uninstall, and fault-injection evidence;
- accessibility evaluator and manual matrix;
- Defender/SmartScreen state and any exclusions;
- redacted log digest plus secret-scan result;
- clean-tree, package-to-package, and no-source-substitution proof.

The v3 validator must require every declared client/server matrix cell exactly
once. `fail`, `blocked`, `not_run`, missing, duplicate, stale revision, mixed
package digest, unknown signer, or source-tree substitution cannot complete the
index. Evidence from `windows-amd64` cannot satisfy `windows-arm64`, and a VM
cannot satisfy an explicitly physical-only sleep/resume check.

### Website and public command gate

Until the W8 public-command gate, the website may show **only** a non-install
“Windows is in development” statement. That banner may appear after
architecture acceptance (W0). It is not an install CTA.

The website may show an install command such as:

```powershell
winget install WarpTweet.WarpTweet
```

only when that exact WinGet manifest resolves to the exact signed MSI whose
complete v3 matrix passed for the published version. A local MSI, a CI build,
an unsigned prerelease, a source-tree tunnel, or a manually authored evidence
JSON does not activate the public install claim. Before that gate: no WinGet
snippet, no MSI download URL, and no “Windows is available” wording.

## Implementation sequence

Points below are relative movement toward the ideal, not calendar or staffing
estimates. Order reflects dependency. A later stage may begin exploratory work
early, but it cannot close before its preceding proof gate.

| Stage | Relative points | Deliverable | Exit gate |
| --- | ---: | --- | --- |
| W0. Freeze contract and ADRs | 5 | accepted product boundary, service/account model, support baseline, engine decision criteria, threat-model delta, v3 acceptance skeleton | no unresolved contradiction between CLI, service, state, package, and release authority |
| W1. Extract platform authorities | 8 | Windows builds reach only explicit unsupported seams; wire profile no longer says ELF; domain lifecycle/storage/process interfaces; exact per-profile command surfaces | Linux and Darwin regression suites pass; Windows compile failures enumerate unimplemented native contracts rather than Unix symbols |
| W2. Prove native engine feasibility | 13 | authenticated OpenSSH 10.4p1 plus Win32 patch strategy, static OpenSSL 3.5.7, minimal `ssh.exe`, PE report, exact algorithm queries, Go key interop, reviewed readiness prototype | native x64 engine negotiates exact profile and signals readiness at the correct code point; provenance is reproducible; otherwise stop for native-client ADR |
| W3. Implement Windows state and attestation | 13 | artifact profile, Known Folder layout, DACL/reparse/file-ID storage, atomic generations, PE/import/mitigation inspection, Authenticode policy, closed environment | adversarial filesystem, signature, DLL, state crash, and key-permission suites pass on Windows |
| W4. Implement service, IPC, and process lifecycle | 21 | `warptweet-service.exe`, named-pipe protocol, token authorization, job supervision, event readiness, shutdown/recovery, Event Log | non-admin operator lifecycle works; unauthorized callers fail; PID/port/readiness/service-crash tests pass |
| W5. Integrate enrollment and route operations | 13 | connect, enroll, up, status, down, rotate, revoke, repair, forget, uninstall-preserve behavior using service-owned transactions | response-loss, cancellation, duplicate, reboot, sleep/resume, expiry, and revocation scenarios converge correctly |
| W6. Package and sign | 13 | signed MSI, upgrade/repair/uninstall, SBOM/licenses/receipts, signing workflow, draft WinGet manifest | clean VM install and package lifecycle pass with exact readback; no public publication yet |
| W7. Complete adversarial package matrix | 21 | immutable v3 checklist/schema/validator, Windows x64 to both Linux host architectures, security/reliability/performance/accessibility evidence | every required current-revision cell passes from exact final packages; no blocked, unrun, stale, or substituted result |
| W8. Publish through controlled release | 5 | final repository release metadata, public signed MSI, WinGet manifest, docs/site install command, incident and rollback procedure | public URLs and WinGet resolve to proven bytes; independent install/readback succeeds; external publication is separately authorized |

Total scope indicator: 112 relative points. The number is useful only for
comparing remaining dependency-weighted work. It must not be translated into
hours, weeks, or a release date.

## Stage acceptance details

### W0: decisions to freeze

- Windows is a client-only platform.
- First architecture is x64; ARM64 has its own later profile and evidence.
- First supported OS list contains only vendor-supported Windows 11 releases.
- One machine-wide service owns all routes.
- Local management is machine-wide for explicit operator-group members.
- Runtime service identity is `LocalService` plus restricted service SID unless
  native token proof rejects that model.
- MSI is the canonical package and WinGet is its discovery layer.
- The engine must be exact OpenSSH 10.4p1 behavior with static OpenSSL 3.5.7,
  or a separate native-client decision is required.
- No in-box SSH, WSL, algorithm fallback, or classical-only mode.
- Baseline key-at-rest language is ACL protection unless service-resident
  signing is actually implemented and proven.

### W1: extraction invariants

- No regression in Linux pidfd/process or Darwin ownership/readiness behavior.
- Unsupported platforms continue to fail closed.
- Platform interfaces describe WarpTweet needs, not raw syscall collections.
- Host commands remain Linux capabilities.
- Domain tests use exhaustive typed states and errors.
- A Windows compile does not include dead Unix service files.

### W2: engine go/no-go

Proceed only if all are true:

- authenticated source chain is complete;
- build is native and reproducible enough to investigate drift;
- final engine is PE for the declared architecture;
- OpenSSL 3.5.7 is statically linked by positive evidence, not absence of an
  obvious DLL name alone;
- `ssh -V` and `ssh -Q` produce exact pinned facts under the closed environment;
- Go-generated private key authenticates against the current Linux data plane;
- classical-only and wrong-profile peers fail;
- rekey remains on the pinned profile;
- readiness code point and inherited-handle security are reviewed and tested;
- engine process can be stopped and reaped without PID ambiguity;
- license and redistribution requirements are satisfied.

If any item fails, W2 is blocked. Packaging the Windows in-box OpenSSH or
changing the profile is not an allowed workaround.

### W3 through W6: native boundary proof

Each stage needs source tests plus native API readback. Mocked SIDs, DACLs,
service states, signatures, jobs, and named pipes prove only the mock contract.
The test report must state Windows version/build, filesystem, Defender state,
toolchain, commit, and exact artifact hashes. W3 must prove both first
publication of `active.json` (selector absent) and replacement of an existing
selector.

### W7: release candidate proof

Freeze the v3 checklist and hash before executing the final matrix. If a test
definition changes, create a new checklist hash and rerun affected cells. Do
not edit result JSON to make it conform. Harness-generated, artifact-bound
evidence is the authority.

### W8: publication authority

Repository preparation does not authorize external release, signing-account
creation, WinGet submission, DNS/CDN mutation, or website deployment. Those
actions require explicit owner authorization. Publication is complete only
after public readback from a clean machine.

## Definition of done

Native Windows support is complete only when:

- the public CLI behavior is coherent with existing WarpTweet client behavior;
- the Windows x64 artifact profile is explicit and fail closed;
- the service, pipe, caller authorization, state, engine, listener, process,
  key, installer, signing, upgrade, recovery, and logging contracts are
  implemented;
- the exact pinned hybrid and composite profile is proven end to end;
- no unprivileged caller can mutate routes or read private state;
- no verified path allows engine/DLL/state substitution;
- lifecycle states survive cancellation, duplication, restart, reboot,
  sleep/resume, network loss, response loss, and power interruption without
  false Ready or false completion;
- signed package install, repair, upgrade, rollback, uninstall-preserve, and
  purge behavior pass on supported Windows versions;
- security scans and adversarial tests have no unresolved applicable release
  finding;
- accessibility manual and automated checks pass for affected flows;
- numerical performance and resource budgets pass;
- the immutable v3 package-to-package matrix is complete for Windows x64
  against Linux amd64 and arm64;
- public documentation names exact supported versions, limitations, key-at-rest
  posture, local-loopback trust, and recovery behavior;
- the public WinGet command installs the same signed MSI bound by evidence;
- every unrun, blocked, failed, waived, physical, external, and production-only
  check is reported accurately.

Until then, the accurate status is “native Windows client in development.” A
cross-compiled EXE, a working WSL demo, a successful OpenSSH handshake, a green
unit suite, or a locally installed MSI is valuable progress but not native
Windows distribution readiness.

## Recommended immediate next action

Execute W0 and W2 as a paired decision package before broad implementation:

1. write the engine-source/readiness ADR with the exact acceptance gate above;
2. create a clean native Windows x64 builder recipe pinned to the selected
   toolchain;
3. prove or disprove OpenSSH 10.4p1 plus the PowerShell/openssh-portable
   compatibility patch set,
   static OpenSSL 3.5.7, exact algorithms, Go-generated key interop, and the
   one-shot readiness event;
4. in parallel only at the code-organization level, extract the Unix lifecycle
   and storage calls until Windows fails at named unimplemented interfaces;
5. do not begin MSI polish or public Windows copy until the engine gate passes.

This sequence attacks the highest-risk unknown first while preserving the
existing protocol and host implementation. It avoids investing in an installer
around an engine that cannot yet satisfy WarpTweet's security contract.

## Authoritative external references

- [OpenSSH Portable repository](https://github.com/openssh/openssh-portable)
- [Microsoft Win32-OpenSSH repository and releases](https://github.com/PowerShell/Win32-OpenSSH)
- [Win32-OpenSSH design details](https://github.com/PowerShell/Win32-OpenSSH/wiki/About-Win32-OpenSSH-and-Design-Details)
- [Win32-OpenSSH native build notes](https://github.com/PowerShell/Win32-OpenSSH/wiki/Building-OpenSSH-for-Windows-%28using-LibreSSL-crypto%29)
- [OpenSSL build instructions](https://github.com/openssl/openssl/blob/master/INSTALL.md)
- [OpenSSL Windows notes](https://github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md)
- [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew)
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [Windows service SID information](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Windows service configuration and failure actions](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Windows ACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [GetFinalPathNameByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [Dynamic-Link Library Security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security)
- [SetDefaultDllDirectories](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories)
- [Windows packaging and distribution guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/choose-distribution-path)
- [Windows code-signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Windows release health](https://learn.microsoft.com/en-us/windows/release-health/release-information)
- [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information)
- [Go supported ports](https://go.dev/doc/install/source)

## Repository evidence reviewed

- `AGENTS.md`
- `go.mod`
- `internal/artifactprofile/profile.go`
- `internal/profile/profile.go`
- `internal/installlayout/layout.go`
- `internal/installlayout/darwin.go`
- `internal/engine/client.go`
- `internal/engine/client_process.go`
- `internal/engine/client_state.go`
- `internal/engine/launch.go`
- `internal/engine/readiness.go`
- `internal/engine/client_*_unsupported.go`
- `internal/command/lifecycle.go`
- `internal/command/host.go`
- `internal/command/dataplane.go`
- `internal/provisioner/protocol.go`
- `internal/provisioner/server.go`
- `internal/provisioner/server_linux.go`
- `internal/provisioner/intent.go`
- `internal/provisioner/uninstall.go`
- `internal/lifecycle/state.go`
- `internal/supervisor/supervisor.go`
- `internal/routestate/route.go`
- `internal/composite/composite.go`
- `internal/opensshkey/opensshkey.go`
- `internal/releaseevidence/index.go`
- `internal/releaseevidence/v2.go`
- `schemas/release-evidence-v2.schema.json`
- `packaging/evidence/checklist-v2.json`
- `docs/2026-08-09_architecture.md`
- `docs/2026-08-09_crypto-profile.md`
- `docs/2026-08-09_threat-model.md`
- `docs/2026-08-10_client-layout.md`
- `docs/2026-08-10_client-readiness.md`
- `docs/2026-08-12_client-lifecycle.md`
- `docs/2026-08-12_package-interop-evidence.md`
- `docs/2026-08-20_dataplane-daemon.md`
- `docs/2026-08-22_security-reliability-distribution-audit.md`
