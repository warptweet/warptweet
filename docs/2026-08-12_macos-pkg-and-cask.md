# macOS package and Homebrew cask

Status: assembly recipe and contract tests, 2026-08-12

## Objective

Produce architecture-specific WarpTweet client `.pkg` artifacts and a pinned
Homebrew cask definition without install-time network downloads, server helpers,
or floating version URLs.

## Package assembly

```sh
make build
go build -trimpath -o bin/warptweet-provisioner ./cmd/warptweet-provisioner
./scripts/build-macos-pkg.sh \
  "$HOME/warptweet-openssh-darwin-stage" \
  "$PWD/bin/warptweet" \
  "$PWD/bin/warptweet-provisioner" \
  "$HOME/warptweet-client-darwin-arm64.pkg"
```

Inputs:

1. Authenticated Darwin OpenSSH client stage from
   `scripts/build-openssh-darwin.sh`
2. Built `warptweet` controller
3. Built `warptweet-provisioner`
4. Non-existent absolute output `.pkg` path

The script stages:

- `/Library/Application Support/WarpTweet/bin/warptweet`
- `/Library/Application Support/WarpTweet/bin/warptweet-provisioner`
- client-only OpenSSH inventory and receipts
- LaunchDaemon template `com.warptweet.client`
- `share/uninstall.sh`

It refuses server helpers (`sshd`, `sshd-auth`, `sshd-session`).

## Installer behavior

| Script | Behavior |
| --- | --- |
| `preinstall` | Darwin/root checks; refuse existing server helper path |
| `postinstall` | Create `_warptweet` user/group, fixed directories, empty ambient trust file, harden ownership |
| `uninstall.sh` | Stop services, remove executables, preserve identity unless `--destroy-identity` with typed confirmation |

Install scripts never call `curl`, `wget`, or any URL.

## Signing and notarization

Optional release environment:

| Variable | Purpose |
| --- | --- |
| `WARPTWEET_VERSION` | Package version string |
| `WARPTWEET_INSTALLER_IDENTITY` | Developer ID Installer identity for `productsign` |
| `WARPTWEET_NOTARY_PROFILE` | `notarytool` keychain profile |
| `WARPTWEET_REQUIRE_SIGNED_PKG=1` | Fail closed when installer identity is absent |

Release publication requires signed packages. Local development may emit an
unsigned package for layout validation only.

## Homebrew cask

Template: `homebrew/Casks/warptweet.rb.tmpl`

Render with `internal/releasemetadata.RenderCask` using exact version and both
architecture SHA-256 digests. The rendered cask:

- pins version and architecture-specific URLs/digests;
- installs the `.pkg`;
- uninstalls through `pkgutil` and the package uninstall script;
- never uses `version :latest` or plain HTTP.

Primary tap path remains `warptweet/tap/warptweet`. A controller-only formula is
not the website CTA.

## Privileged provisioner

`warptweet-provisioner` currently exposes:

- `version`
- `verify-layout` (root-only layout attestation)

It rejects every other request. Enrollment activation commands arrive in the
enrollment work package and must remain a typed surface with no shell, path, or
OpenSSH-option injection.

## Evidence boundary

Presence of these scripts is not evidence that a signed notarized package was
produced or that `brew install --cask` succeeded on clean hosts. Hosted release
runners must publish signed packages, checksums, SBOM/provenance, and package
install verification before the website Homebrew CTA activates.
