# macOS client attestation

Status: platform seams and fail-closed production gates, 2026-08-12

## Scope

WP4 adds Darwin production attestation for the fixed package-owned client layout
without weakening the wire profile or Linux ELF gates.

## Layout

| Role | Path |
| --- | --- |
| Controller | `/Library/Application Support/WarpTweet/bin/warptweet` |
| Engine | `/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh` |
| Keygen | `/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen` |
| Manifest | `/Library/Application Support/WarpTweet/state/client.wt` |
| Identity | `/Library/Application Support/WarpTweet/state/identity/client` |
| Host pin | `/Library/Application Support/WarpTweet/state/trust/known_hosts` |
| Empty trust | `/Library/Application Support/WarpTweet/state/trust/known_hosts.empty` |
| Runtime root | `/Library/Caches/wt` |
| Service identity | `_warptweet` / `_warptweet` |

The runtime root is intentionally short. Authenticated-forward readiness keeps
the control socket within the fixed Unix-domain path budget used on Linux.

## Artifact profiles

`darwin-arm64` and `darwin-amd64` are supported production artifact profiles.
They require:

- executable format `Mach-O`;
- OpenSSL linkage `static`;
- the fixed Application Support layout above.

Wire cryptography remains in `internal/profile`. Production preflight compares
executable format to the artifact profile and OpenSSL linkage to the wire
profile.

## Mach-O policy

The pure Go inspector rejects:

- universal/fat binaries;
- non-`MH_EXECUTE` types;
- non-native CPU types;
- `LC_RPATH`;
- dynamic `libcrypto` / `libssl`;
- `@rpath`, `@loader_path`, and `@executable_path` dependencies;
- absolute dependencies outside `/usr/lib/` and `/System/Library/`.

## Ownership and state

Darwin production uses root ownership checks via `syscall.Stat_t`, the fixed
state walk shared with Linux, and Directory Services lookup for `_warptweet`.
The dedicated account must use home `/var/empty` and shell `/usr/bin/false`.

## Code signature

Production Darwin preflight calls `verifyProductionClientCodeSignature`. Until
the release Team ID is configured, that gate fails closed with
`production client code-signing Team ID is not configured`. Unsigned or
wrong-team binaries remain rejected after the Team ID is published.

## Evidence boundary

macOS CI must prove that production entrypoints fail closed on an unprovisioned
host and that Mach-O/layout unit tests pass. A live authenticated-forward proof
against an installed package remains a WP5 package gate.
