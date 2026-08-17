# Private first-party tap invited install

Channel: private `warptweet/homebrew-tap`
Command: `brew install --cask warptweet/tap/warptweet`
Website Homebrew CTA: remains dark

This is not Homebrew endorsement and not a public release.

## Preconditions

1. A non-`dev` version on a clean tagged commit
2. Developer ID signed, notarized, stapled macOS packages for arm64 and amd64
3. Signed Linux host packages for every declared host architecture
4. Rendered cask with immutable SHA-256 values
5. Invited testers install the fully qualified cask name with trust enabled

## Invited command

```sh
brew install --cask warptweet/tap/warptweet
```

Do not pass `--no-quarantine` or otherwise disable Homebrew trust.

## Current blocker

This machine has Developer ID Application `CP4268Q8UF`, but no Developer ID
Installer identity, no `notarytool` keychain profile, and no Linux GPG signing
key. `scripts/release-candidate.sh` fail-closes until those are present.

Ordinary `brew uninstall` preserves identity. `brew uninstall --zap` is the
destructive authorization.
