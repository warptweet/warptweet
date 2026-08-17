# Official Homebrew submission readiness

Contract ID referenced: `warptweet.adoption-release.v1`.
Milestone name: `official-submission-ready`.
This document does not claim official Homebrew acceptance.

## Classification

The working macOS product is a signed `.pkg` that establishes a fixed
root-owned layout, dedicated identity, and privileged helper. That is
cask-shaped. Homebrew currently prefers open-source command-line-only
software in `homebrew/core`. A controller-only formula is not the complete
WarpTweet security product.

Do not weaken the fixed package and privilege model merely to fit a
repository.

## In-tree assumptions

- Package token: `warptweet`
- First-party tap command: `brew install --cask warptweet/tap/warptweet`
- Destructive identity removal: `brew uninstall --zap`
- Private tap repository: `warptweet/homebrew-tap`
- Public communication and the website CTA stay closed until v2 evidence is complete

## Policies to re-read immediately before submission

- https://docs.brew.sh/Acceptable-Casks
- https://docs.brew.sh/Acceptable-Formulae
- https://docs.brew.sh/Package-Acceptance-Policy
- https://docs.brew.sh/Taps
- https://docs.brew.sh/Cask-Cookbook

Acceptance is controlled by Homebrew maintainers and must be recorded
separately from this internal milestone.
