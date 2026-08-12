# macOS OpenSSH client engine

Status: build recipe and contract tests, 2026-08-12

## Objective

Produce architecture-specific, authenticated macOS client OpenSSH bundles that
satisfy the Homebrew delivery engine gate without shipping server helpers or
weakening the wire profile.

## Script

```sh
./scripts/fetch-openssh.sh "$HOME/warptweet-openssh-source"
./scripts/fetch-openssl.sh "$HOME/warptweet-openssl-source"
./scripts/build-openssh-darwin.sh \
  "$HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
  "$HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
  "$HOME/warptweet-openssh-darwin-stage"
```

Caller paths must be clean absolute paths using the same safe ASCII path rules
as the Linux release scripts. The stage destination must not already exist. Work
occurs under a private mode-0700 sibling directory and publishes with BSD
`mv -hn`.

## Native-only contract

- Host OS must be Darwin.
- Architecture must be native `arm64` or `x86_64`.
- Release binaries are never cross-compiled.
- The build account must be non-root.
- OpenSSL Configure selects `darwin64-arm64-cc` or `darwin64-x86_64-cc`.
- OpenSSH `config.guess` must match the native architecture.
- Default minimum deployment target is `13.0`, overridable only through
  `WARPTWEET_MACOS_DEPLOYMENT_TARGET` with a dotted numeric value.

## Authenticated inputs

Both archives are copied into the private build root, hashed there, and compared
to the pinned SHA-256 values from `third_party/openssh/source.env` and
`third_party/openssl/source.env`. Extraction uses only the private copies.

OpenSSL is built with:

```text
no-shared no-module no-dso no-pinshared
```

OpenSSL tests run before OpenSSH is configured. The private install must produce
`libcrypto.a` and must not produce shared crypto libraries, engines, or provider
modules. The logical OpenSSL prefix remains the DESTDIR-only path
`/opt/warptweet/libexec/openssl-static`.

OpenSSH is configured against that private OpenSSL tree with hardening, PIE, and
without Kerberos, LDNS, libedit, PAM, RPATH, SELinux, or zlib. The complete
upstream `make tests` suite must pass on the native host.

## Client-only staged inventory

The published tree is the package-owned layout:

```text
Library/Application Support/WarpTweet/libexec/openssh/bin/ssh
Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen
Library/Application Support/WarpTweet/share/licenses/openssh/LICENCE
Library/Application Support/WarpTweet/share/licenses/openssl/LICENSE.txt
Library/Application Support/WarpTweet/share/openssh-source.txt
Library/Application Support/WarpTweet/share/openssl-source.txt
Library/Application Support/WarpTweet/share/openssh-bundle.sha256
```

The authenticated bundle manifest contains exactly those six files. Server
helpers (`sshd`, `sshd-auth`, `sshd-session`) and unused clients (`scp`,
`sftp-server`, `ssh-agent`, and similar) are not staged.

## Mach-O attestation

Every staged executable must:

- be a regular non-symlink file;
- be a Mach-O 64-bit executable for the native architecture only;
- have no dynamic `libcrypto` or `libssl` dependency;
- have no `@rpath`, `@loader_path`, or `@executable_path` dependency;
- depend only on absolute system paths under `/usr/lib/` or `/System/Library/`;
- contain no `LC_RPATH` load command.

The staged `ssh` binary must report exactly:

```text
OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026
```

and must expose the required KEX, authentication, and cipher names.

## Receipts

Both receipts record platform `darwin`, architecture, artifact-profile ID
(`darwin-arm64` or `darwin-amd64`), source URLs and hashes, signer fingerprint,
static `libcrypto` hash, deployment target, compiler identity, and
`tests=passed`. The OpenSSH receipt is labeled `role=macos-client` and
`server_helpers=no`.

## Relationship to later work packages

- WP4 consumes this stage for ownership, code-signature, notarization, and
  readiness attestation under the fixed Application Support layout.
- WP5 packages the stage into a signed notarized `.pkg` and Homebrew cask.
- Universal binaries are out of scope until both architecture stages are
  independently authenticated and the combined binary is re-signed, rehashed,
  and re-inspected.

## CI

`.github/workflows/ci.yml` defines an `openssh-darwin` job on native
`macos-15` (arm64) and `macos-14` (x86_64) runners. It fetches the pinned
sources, runs `scripts/build-openssh-darwin.sh`, and verifies the six-path
client inventory, Mach-O dependency policy, receipts, and exact `ssh -V` line.

## Evidence boundary

Presence of this script, its contract tests, and the CI job definition is not
by itself evidence that a hosted runner completed the full upstream suites
against the downloadable package. Passing CI logs and package hashes remain
required before the website Homebrew CTA may activate.
