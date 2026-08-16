# Homebrew delivery

## Objective

Deliver a public, reproducible path in which a macOS user can visit
`warptweet.com`, install WarpTweet with Homebrew, enroll into a managed Linux
host, and open one declared loopback TCP tunnel without hand-editing SSH
configuration or weakening the WarpTweet cryptographic profile.

The target experience is:

```sh
brew install --cask warptweet/tap/warptweet
warptweet connect <single-use-invite.wtinvite>
```

The final command reports the local application endpoint, for example
`127.0.0.1:15432`. WarpTweet is a TCP tunnel, not an interactive terminal.
`warptweet up` MUST NOT open a shell, run a remote command, enable SOCKS, or
expose a non-loopback listener.

This document is the implementation contract. Do not publish the installation
command on the website until every release gate in this document passes against
the exact downloadable artifacts.

## Current blockers

The controller, Darwin artifact inspection, authenticated Darwin engine build,
client state policy, lifecycle commands, typed provisioner, package assembler,
cask renderer, Linux `host`, and pinned-TLS enrollment path are implemented in
source. The public path remains blocked by release evidence and external
publication state:

- no signed release tag or published source/artifact URLs are bound in the
  repository;
- no current clean-host proof exists for signed and notarized arm64 and amd64
  packages, the zero-password-after-install flow, or upgrade/uninstall;
- no signed Linux package repository or completed server package matrix exists;
- no complete package-to-package dual-host evidence document exists for exact
  published digests;
- no published tap/cask, release SBOM, provenance attestation, or verified
  update channel exists;
- the CLI version remains `0.1.0-dev` and the website CTA remains dark.

A formula that installs only the current controller is not the product. The
website CTA becomes active only when the installed client can complete the
full enrollment and tunnel lifecycle.

## Product and standards status

Do not brand WarpTweet itself as experimental. WarpTweet is implemented
software. Keep status axes separate and typed:

| Axis | Value for the first release |
| --- | --- |
| Product | Open-source managed-endpoint tunnelling |
| Support | Supported only on the published platform and evidence matrix |
| Key exchange | `mlkem768x25519-sha256` |
| Authentication binding | OpenSSH vendor-qualified |
| Profile policy | Immutable and fail closed |

The word `experimental` may appear only in the scoped upstream disclosure:
OpenSSH 10.4p1 labels its opt-in
`ssh-mldsa44-ed25519@openssh.com` composite authentication binding
experimental. It is vendor-qualified and not an IETF-standardized SSH
authentication binding. This disclosure MUST NOT become WarpTweet's product
badge, hero message, service description, CLI identity, or generic status.

Replace the ambiguous boolean `Profile.Experimental` and emitted
`"experimental": true` values with typed fields:

```go
type AuthenticationBindingStatus string

const AuthenticationBindingOpenSSHVendor AuthenticationBindingStatus =
	"openssh-vendor-qualified"

type SupportStatus string

const SupportStatusPublishedMatrix SupportStatus = "published-matrix"
```

Profile, validate, doctor, doctor-server, and structured launch events MUST
emit `authentication_binding_status` and `support_status`. The profile registry
MUST compare these typed values as immutable profile attributes. There is no
compatibility alias for the ambiguous boolean because no release has shipped.

## Architecture

Keep the SSH wire profile separate from platform artifact attestation.

```text
WireProfile
  profile ID
  OpenSSH version
  KEX, authentication, cipher names
  raw key and signature sizes
  no-fallback policy

PlatformArtifactProfile
  platform and architecture
  executable format and linkage rules
  code-signing and notarization rules
  fixed filesystem layout
  owner, group, mode, ACL, and link rules
  service-manager and readiness integration
  authenticated artifact manifest
```

Do not mutate the Linux ELF contract to admit macOS. Add separately versioned
artifact profiles for:

- `linux-amd64`;
- `linux-arm64`;
- `darwin-arm64`;
- `darwin-amd64`.

One wire profile may reference multiple reviewed artifact profiles. Changing an
engine version, wire name, encoding, policy rule, platform linkage rule, fixed
path, signing authority, or artifact inventory creates a new immutable profile
or artifact-profile ID.

## Work packages

Implement in the following ideal order. Points measure progress toward the
complete solution, not elapsed time.

### 1. Status contract and present-tense public identity, 3 points

- Replace `Profile.Experimental` with the typed status fields above.
- Update all JSON outputs, tests, structured logs, CLI usage, systemd
  descriptions, README, SECURITY, architecture documents, and website copy.
- Use present-tense copy: `Open-source post-quantum tunnelling`, `Profile v1`,
  and `Implemented and reviewable`.
- Preserve one narrowly scoped OpenSSH authentication-binding disclosure.
- Preserve exact evidence and support boundaries without describing the whole
  product as experimental.
- Add a repository-wide test that forbids product-level phrases such as
  `WarpTweet is experimental`, `Experimental WarpTweet`, and an
  `Experimental` website badge.

Acceptance:

- no public or operator-facing surface conflates product maturity, standards
  status, and support status;
- every machine-readable status has a typed, documented meaning;
- all Go, race, release-copy, Astro, and website tests pass.

### 2. Platform-neutral client seams, 5 points

- Introduce interfaces for executable inspection, client-state inspection,
  platform layout, service identity, ACL validation, and runtime-directory
  management.
- Keep dependency injection per invocation. Do not introduce mutable global test
  hooks.
- Move Linux ELF and fixed-state behavior behind a Linux artifact profile with
  no semantic change.
- Add an explicit artifact-profile ID to preflight evidence and release
  manifests.
- Ensure the `.wt` schema selects the wire profile, not caller-controlled
  executable, identity, trust, or runtime paths.
- Preserve the exact closed OpenSSH argument policy and PID-bound
  authenticated-forward readiness semantics.

Acceptance:

- Linux behavior remains byte-for-byte and policy-equivalent;
- platform-specific code cannot silently relax wire policy;
- unsupported platform or artifact-profile combinations fail before network
  activity;
- Linux unit, race, cross-compile, fixed-layout, and live-tunnel gates remain
  green.

### 3. Authenticated macOS OpenSSH engine, 8 points

Status: recipe and CI matrix present. Full hosted-suite evidence remains a
release gate rather than a local-workspace claim.

- Build OpenSSL 3.5.7 from authenticated upstream source for macOS arm64 and
  amd64 with static libcrypto, no shared crypto libraries, no loadable provider
  modules, and tests enabled.
- Build OpenSSH 10.4p1 from authenticated upstream source against that private
  OpenSSL for both architectures.
- Run OpenSSL and complete OpenSSH upstream test suites on clean native macOS
  runners. Do not cross-compile release binaries.
- Stage only the client inventory: `ssh`, `ssh-keygen`, both source receipts,
  both upstream license files, and one exact bundle manifest. Do not ship server
  helpers in the macOS client package.
- Record source URLs, source hashes, exact signer fingerprints, target tuple,
  architecture, configure flags, test result, static libcrypto hash, compiler
  identity, minimum macOS version, and artifact hashes.
- Inspect every staged Mach-O. Reject dynamic `libcrypto` or `libssl`, absolute
  non-system dependencies, `LC_RPATH`, unsafe load commands, unexpected slices,
  and mismatched deployment targets.
- Produce separate architecture artifacts first. Create a universal binary only
  if both slices are independently authenticated and the final universal binary
  is re-signed, rehashed, and re-inspected.

Acceptance:

- both native architectures pass upstream tests;
- every release engine reports exactly `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun
  2026`;
- exact required KEX and authentication algorithms are present;
- staged binaries have no dynamic OpenSSL dependency or RPATH;
- receipts and manifest reproduce the exact downloadable package contents.

### 4. macOS artifact and state attestation, 8 points

Status: layout, Mach-O inspector, Darwin production seams, and fail-closed
unprovisioned-host gates are implemented. Live package-owned readiness remains
a later package evidence gate.

Define a macOS layout independent of the Homebrew prefix. The recommended
package-owned paths are:

| Path | Policy |
| --- | --- |
| `/Library/Application Support/WarpTweet/bin/warptweet` | root-owned executable |
| `/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh` | root-owned pinned engine |
| `/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen` | root-owned key tool |
| `/Library/Application Support/WarpTweet/state/client.wt` | root-owned active policy |
| `/Library/Application Support/WarpTweet/state/identity/client` | protected composite private key |
| `/Library/Application Support/WarpTweet/state/trust/known_hosts` | root-owned exact host pin |
| `/Library/Application Support/WarpTweet/state/trust/known_hosts.empty` | exactly empty ambient trust |
| `/Library/Caches/wt/<id>` | short, bounded readiness runtime directory |

The final choice of service identity MUST be explicit:

- preferred: a dedicated `_warptweet` user and group created by the signed
  installer, with root-owned group-readable active state and no supplementary
  members;
- acceptable only after equivalent proof: a per-user LaunchAgent design whose
  state is owned by that user and whose threat model explicitly excludes
  same-user mutation.

Implement:

- Mach-O parser and immutable artifact manifest verification;
- code-signature validation against the exact WarpTweet Team ID and designated
  requirement;
- notarization and stapling verification for the installer and executable
  inventory;
- retained descriptor traversal for all fixed ancestors and files;
- exact UID/GID, mode, file type, link count, flags, ACL, and extended-attribute
  policies;
- protection against symlink, hardlink, directory replacement, in-place trust
  mutation, and time-of-check/time-of-use substitution;
- readiness socket ownership and anchored-unlink behavior on Darwin;
- a sanitised child environment and the same complete `-F none` plus `-o`
  invocation used on Linux.

Do not treat `/proc`, ELF, Linux shadow databases, systemd, or Linux-only
ownership APIs as portable abstractions.

Acceptance:

- an unprivileged user cannot write, replace, rename, chmod, relink, or add ACLs
  to active engine, identity, trust, or manifest state;
- preflight revalidates the exact opened artifacts immediately before launch;
- OpenSSH can read the protected identity as the selected service account;
- authenticated-forward readiness passes on both macOS architectures;
- all mutation and race tests fail closed without deleting attacker
  replacements.

### 5. Signed macOS installer and Homebrew cask, 8 points

Status: package assembly recipe, installer scripts, provisioner surface, and
cask template are present. Signed/notarized hosted package evidence remains a
release gate.

Use a dedicated public Homebrew tap, for example `warptweet/homebrew-tap`.
The primary artifact is a signed and notarized `.pkg`, installed by a cask. A
source formula that installs only the Go controller MAY exist as
`warptweet-cli`, but MUST NOT be the website's primary installation path.

The `.pkg` MUST:

- install the controller, client-only OpenSSH bundle, receipts, licenses,
  artifact manifest, service definition, and privileged provisioner;
- create and validate the dedicated identity and fixed directories;
- install no server daemon on macOS;
- make no network connection during package installation;
- provide exact, idempotent uninstall behavior that stops services before
  removing executables;
- preserve user confirmation before destroying identity material;
- carry Developer ID Installer signing and Apple notarization with a stapled
  ticket;
- contain no install-time download or mutable URL.

The cask MUST pin version, architecture-specific URL, SHA-256, package ID, and
uninstall stanza. Avoid `latest`, floating branches, branch archives, and
`version :latest`. Generate the cask from release metadata, but review and test
the rendered Ruby before publication.

Release both architecture packages from clean, ephemeral native runners. Sign
and notarize after deterministic assembly. Publish SHA-256 and an independent
signed release manifest. Generate an SBOM and provenance attestation for each
artifact.

Acceptance:

- `brew install --cask warptweet/tap/warptweet` succeeds on clean supported
  arm64 and amd64 macOS systems;
- `spctl`, `pkgutil`, code-signature, notarization, artifact-manifest, ownership,
  and preflight checks pass after installation;
- uninstall and reinstall are idempotent;
- an altered package, executable, receipt, cask SHA, signature, or fixed path
  fails before connection;
- the Homebrew-installed package can complete the two-endpoint live gate.

### 6. Linux server packages and bootstrap, 8 points

Status: package assembly recipe, maintainer scripts, and the public `host`
bootstrap are present. Hosted signed package install
evidence remains a release gate.

Build native signed `.deb` and `.rpm` packages for Linux amd64 and arm64. The
packages install the existing fixed `/opt/warptweet` and `/etc/warptweet`
layout, exact OpenSSH server bundle, system users, privilege-separation jail,
systemd units, licenses, receipts, and bundle manifest.

Public bootstrap:

```text
warptweet host --to <port|numeric-ip:port> --name <name>
warptweet server revoke <client-id>
warptweet server status
```

`host` MUST generate or reuse the composite host key locally, establish the
restricted SSH listener and pinned-TLS enrollment listener, and print the
public fingerprint without exporting private bytes. It MUST create one
single-use, short-lived enrollment authorization bound to:

- server identity and exact composite host public-key blob;
- numeric server address and WarpTweet SSH port;
- declared numeric target and port;
- dedicated principal;
- wire and platform artifact profile IDs;
- issuance time, expiry, nonce, and one-use status;
- the exact TLS 1.3 enrollment SPKI pin carried by the invite.

Do not put a private key, bearer credential suitable for repeated use, password,
or classical recovery path in the invite. A QR or compact text encoding MAY be
added only after the canonical signed binary or JSON representation is defined.

Server activation MUST be transactional: stage complete candidate state, set
metadata, fsync, preflight, atomically publish, fsync the parent, then start or
reload the service. A failed preflight leaves the prior active generation
unchanged.

Acceptance:

- clean Ubuntu and supported RPM-family systems install and remove correctly;
- server package preflight and systemd confinement gates pass;
- the host rejects shell, exec, subsystem, SFTP, SCP, remote, dynamic,
  agent, X11, stream-local, and TUN forwarding;
- server firewall and `PermitOpen` restrict egress to the exact target;
- invite reuse, expiry, mutation, wrong server, wrong target, and wrong profile
  all fail closed.

### 7. Enrollment and lifecycle CLI, 13 points

Status: connect/enroll/up/status/down/rotate/revoke/uninstall command surface,
local lifecycle state machine, and typed macOS provisioner are present. Network
enroll/rotate/revoke use the invite-pinned HTTPS endpoint (port 29722) with
client-generated management capabilities. Live
package-to-package evidence remains WP8.

Add the following user commands with strict, typed outputs:

```text
warptweet enroll <invite>
warptweet up <tunnel-id> [--once]
warptweet status [<tunnel-id>] [--json]
warptweet down <tunnel-id>
warptweet rotate <tunnel-id>
warptweet revoke <tunnel-id>
warptweet uninstall --preserve-identity
```

`enroll` MUST:

1. Parse and authenticate the invite before network activity.
2. Display the server identity, address, exact target, local bind, and profile
   for explicit user confirmation when enrollment is interactive.
3. Generate a distinct composite client key locally with the bundled
   `ssh-keygen`; never accept a private key from the invite or server.
4. Submit only the canonical public-key blob and enrollment proof.
5. Require server proof that binds the accepted client key, exact host key,
   target, principal, profile, and enrollment nonce.
6. Render canonical `known_hosts`, `.wt`, and local identity state.
7. Ask the privileged provisioner to activate one complete generation
   atomically.
8. Run local preflight, establish the tunnel, pass PID-bound authenticated
   readiness, and report the loopback endpoint.
9. Consume the invite durably so a retry cannot create an ambiguous second
   identity.

Separate local-forward readiness from target health. `up` MAY offer an explicit
application probe, but it MUST label the result separately and MUST NOT perform
an application request by default.

Lifecycle behavior:

- `up` is idempotent and fails if another identity owns the listener;
- `status` distinguishes Preparing, Starting, AwaitingReadiness, Ready,
  Backoff, Stopping, Stopped, Failed, and target health `not_checked`;
- `down` terminates and reaps the exact process and removes no trust or identity;
- rotation activates the new composite identity before revoking the old one;
- revocation is durable on the host before local state reports completion;
- recovery issues a new composite identity and never falls back to a classical
  credential;
- diagnostic output never includes key bytes, invite secrets, passphrases, or
  target credentials.

Acceptance:

- first enrollment from a clean Homebrew installation opens a working tunnel;
- interruption at every durable step resumes safely or rolls back cleanly;
- concurrent enroll/up/down/rotate operations have deterministic locking and
  state transitions;
- logs are structured and non-secret;
- every command has JSON output for automation and concise human output.

### 8. End-to-end release evidence, 13 points

Status: immutable checklist, evidence schema, validator, and package-interop
harness are present. Dual-host complete pass evidence remains a hosted release
gate and is not claimed by this repository state.

Run the exact downloadable macOS client packages against the exact downloadable
Linux server packages on separate managed hosts. Test both client architectures
against both server architectures where runner availability permits.

Positive evidence:

- package signature, manifest, source receipt, engine, identity, trust, and
  manifest preflight;
- invite enrollment and single-use consumption;
- exact composite host and client authentication;
- exact `mlkem768x25519-sha256` KEX and approved AEAD cipher;
- at least one rekey with the same exact profile;
- PID-bound authenticated readiness before application transit;
- deterministic target payload through the loopback listener;
- clean stop, restart, host-key rotation, client-key rotation, revocation, and
  package upgrade.

Negative evidence:

- classical-only KEX, host key, and client key;
- wrong or replaced host pin;
- malformed, truncated, overlong, trailing-data, and wrong-algorithm keys and
  messages;
- expired, reused, altered, cross-server, and cross-target invites;
- shell, exec, subsystem, SFTP, SCP, remote, dynamic, agent, X11, stream-local,
  and TUN forwarding requests;
- listener collision, process substitution, runtime-directory replacement, and
  state-file mutation;
- failed rekey, engine replacement, receipt drift, code-signature failure, and
  package tampering;
- bounded connection, authentication, channel, and oversized-packet floods;
- loss of network, server restart, target refusal, and interrupted enrollment.

Evidence artifacts MUST bind release version, source commit, package hashes,
artifact-profile IDs, engine manifest hashes, platform versions, architectures,
test identities, exact commands, timestamps, and complete redacted logs.
Same-container or source-tree tests do not substitute for package-to-package,
host-to-host evidence.

### 9. Public release and website installation path, 5 points

Status: public-release gate document, website install panel, and CTA
verification are present. The Homebrew command remains dark until complete
package-to-package evidence is linked.

Publish, in order:

1. source repository with signed release tag;
2. immutable release artifacts and signed checksums;
3. SBOM and provenance attestations;
4. Linux package repository metadata;
5. Homebrew tap and reviewed cask;
6. canonical v1 schemas and release notes;
7. website install experience.

The website hero MUST expose the working command only after the release gate:

```sh
brew install --cask warptweet/tap/warptweet
```

The page MUST then show the real next action:

```sh
warptweet connect <single-use-invite.wtinvite>
```

Add architecture-aware download metadata but do not use browser fingerprinting
or analytics. Keep a copy button accessible, retain the command as selectable
text, and link the cask, signed checksums, source tag, release evidence, SBOM,
security policy, and uninstall instructions.

Before artifacts exist, the website MUST say `Homebrew package in release
qualification` and MUST NOT display a command that resolves to a nonexistent or
controller-only package.

Acceptance:

- the website command installs the exact artifact tested by release CI;
- a clean visitor can proceed from install to enrollment without consulting the
  source tree;
- all links are immutable or versioned where appropriate;
- no product-level `experimental` branding remains;
- standards and support claims remain scoped and evidence-backed.

## API and repository shape

Recommended additions:

```text
internal/artifactprofile/
internal/enrollment/
internal/generation/
internal/platform/darwin/
internal/platform/linux/
internal/provisioner/
internal/releasemetadata/
cmd/warptweet-provisioner/
packaging/macos/
packaging/deb/
packaging/rpm/
homebrew/Casks/warptweet.rb.tmpl
scripts/build-openssh-darwin.sh
scripts/build-macos-pkg.sh
scripts/build-linux-packages.sh
scripts/test-package-interop.sh
```

Keep crypto policy, manifest parsing, renderer, SSH argument construction, and
supervision in shared packages. Platform packages own only artifact
attestation, filesystem policy, service integration, and privileged activation.
The privileged provisioner MUST expose a small typed request surface and MUST
NOT accept arbitrary paths, shell commands, OpenSSH options, configuration
fragments, owners, modes, launch labels, or service definitions.

## Non-negotiable invariants

- No classical-only compatibility or recovery mode.
- No trust on first use.
- No ambient SSH config, agent, identity search, DNS trust, ProxyCommand, or
  ProxyJump.
- No manifest-selected key, trust, engine, or runtime paths.
- No private key leaves its endpoint.
- No install-time network downloads from package scripts.
- No mutable or unpinned release URL.
- No root daemon parses unauthenticated network protocol messages when a narrow
  unprivileged process can do so.
- No website install command before an exact working package exists.
- No claim that readiness proves target health.
- No claim of IETF-standardized SSH authentication, FIPS validation, or
  absolute protection against every quantum attack.
- No product-level `experimental` branding. Scope that term only to OpenSSH's
  description of its vendor-qualified authentication binding.

## Definition of done

This work is complete only when a new supported macOS machine can:

1. install the signed WarpTweet cask;
2. authenticate and consume a single-use invite from a packaged managed Linux
   host;
3. generate its composite identity locally;
4. atomically activate exact host trust and tunnel policy;
5. pass platform and engine preflight;
6. open the declared loopback listener;
7. prove authenticated-forward readiness;
8. carry deterministic application traffic to the one server-approved target;
9. reject every weaker or alternate SSH path;
10. stop, restart, rotate, revoke, upgrade, and uninstall without orphaned
    processes, ambiguous state, secret disclosure, or policy downgrade.

Until all ten statements are demonstrated against the published artifacts, the
site may describe the implementation and evidence honestly, but the Homebrew
install CTA remains inactive.
