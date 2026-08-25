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
- root provisioner LaunchDaemon `com.warptweet.provisioner`
- `share/uninstall.sh`

It refuses server helpers (`sshd`, `sshd-auth`, `sshd-session`).

## Installer behavior

| Script | Behavior |
| --- | --- |
| `preinstall` | Darwin/root checks; refuse existing server helper path; stop only fixed WarpTweet launchd labels before payload replacement |
| `postinstall` | Create and validate `_warptweet`, normalize fixed ownership, modes, and ACLs, create empty ambient trust, start the typed root provisioner, and require its `root:admin` mode-0660 socket |
| `uninstall.sh` | Stop only WarpTweet launchd labels, remove package executables and receipts, preserve identity unless `--destroy-identity` receives typed confirmation |

Install scripts never call `curl`, `wget`, or any URL.

## Signing and notarization

Optional release environment:

| Variable | Purpose |
| --- | --- |
| `WARPTWEET_VERSION` | Package version string |
| `WARPTWEET_INSTALLER_IDENTITY` | Developer ID Installer identity for `productsign` |
| `WARPTWEET_NOTARY_PROFILE` | `notarytool` keychain profile |
| `WARPTWEET_REQUIRE_SIGNED_PKG=1` | Fail closed when installer identity is absent |
| `WARPTWEET_REQUIRE_NOTARIZED_PKG=1` | Fail closed when the notary profile is absent |

Release mode verifies the controller, provisioner, `ssh`, and `ssh-keygen`
signatures against Team ID `CP4268Q8UF` before assembly and requires the
installer identity to belong to that same team. Release publication requires
signed and notarized packages. Local development may emit an unsigned package
for layout validation only.

## Homebrew cask

Template: `homebrew/Casks/warptweet.rb.tmpl`

Render with `internal/releasemetadata.RenderCask` using exact version and the
darwin-arm64 SHA-256 digest. The rendered cask:

- pins version and the Apple Silicon URL/digest;
- depends on `arch: :arm64`;
- installs the `.pkg`;
- uninstalls through `pkgutil` and the package uninstall script;
- never uses `version :latest` or plain HTTP;
- does not ship an Intel Mac package.

Primary tap path remains `warptweet/tap/warptweet`. A controller-only formula is
not the website CTA.

## Privileged provisioner

The installed `warptweet-provisioner serve` owns the narrow privilege boundary.
The public CLI is run normally by a member of macOS `admin` and sends one
strict, size-bounded request over `/var/run/warptweet/provisioner.sock`.
Supported actions are `enroll`, `up`, `status`, `down`, `rotate`, and `revoke`.
The protocol rejects unknown fields, trailing JSON, arbitrary paths, shell
text, OpenSSH options, owners, modes, labels, and plist fragments.

The provisioner atomically activates protected client state, generates a
closed per-tunnel LaunchDaemon from a validated tunnel id, runs the tunnel as
the dedicated `_warptweet` identity, and binds Ready state to the PID reported
by launchd. Package installation is the interactive administrator boundary;
normal lifecycle commands must not ask again for `sudo` or AppleScript
authorization.

## Evidence boundary

Presence of these scripts is not evidence that a signed notarized package was
produced or that `brew install --cask` succeeded on clean hosts. Hosted release
runners must publish signed packages, checksums, SBOM/provenance, and package
install verification before the website Homebrew CTA activates.
