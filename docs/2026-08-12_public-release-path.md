# Public release and website installation path

Status: v3 qualification complete; public distribution gate closed, 2026-08-25

## Do you need WP8 evidence before WP9?

Yes for package qualification. Public installation additionally requires proof
that the published command installs the same qualified artifact.

| Work | Allowed now? |
| --- | --- |
| Product website and two-machine quickstart | Yes |
| Record the complete package and networking matrix | Complete |
| Show `brew install --cask warptweet/tap/warptweet` | Only after public distribution evidence |

WP8 delivered the checklist and harness. The first-edition Apple Silicon index
at `packaging/evidence/release-evidence-index-v3.json` covers the required
architecture matrix and networking cells. That index qualifies the product. It
does not prove that a GitHub release or Homebrew tap exists, and its
development-version artifacts cannot serve as public distribution evidence.

## Release order

1. Signed source tag
2. Immutable artifacts and signed checksums
3. SBOM and provenance attestations
4. Linux package repository metadata
5. Homebrew tap and reviewed cask
6. Canonical public schemas (client-tunnels v2, server-gateway v2, invite v3, evidence v3), Profile v1 crypto contract, and release notes
7. Clean Apple Silicon Homebrew installation through the public command
8. Distribution evidence binding the tap, cask, package digest, release version,
   source commit, Homebrew version, and observed installed version
9. Website install command activation

## Gate document

`packaging/evidence/public-release.json`

```json
{
  "schema_version": 2,
  "qualification_complete": true,
  "public_distribution_ready": false,
  "homebrew_command": "brew install --cask warptweet/tap/warptweet",
  "next_command": "warptweet connect <invite-file>",
  "qualification_message": "First-edition package matrix complete",
  "distribution_message": "Public packages are being prepared",
  "required_evidence_document": "packaging/evidence/release-evidence-index-v3.json",
  "required_distribution_evidence_document": ""
}
```

To enable public installation:

1. Produce a complete v3 package-interop evidence index for the exact
   non-development release version and source commit.
2. Publish the signed release artifacts and a rendered
   `Casks/warptweet.rb` whose client digest matches that index.
3. Run the exact Homebrew command on a clean supported Apple Silicon Mac.
4. Record `warptweet.public-distribution-evidence` with the release URL, tap
   URL and commit, cask path and digest, client package digest, Homebrew
   version, installed version, and clean-install observation.
5. Set `required_distribution_evidence_document` to that repository-relative
   document and set `public_distribution_ready` to `true`.
6. Run `internal/publicrelease.ValidatePublicDistribution` and
   `pnpm run verify`.

## Website behavior

- Qualified, not distributed: show the supported two-machine setup and
  qualification milestone, but no install command.
- Distributed: show the selectable Homebrew command, accessible copy result,
  Linux release-package path, connect action, and links to release and security
  evidence.

## Verification

- Go: `internal/publicrelease` validates qualification and distribution as
  separate states and binds clean-install evidence to the qualified artifacts.
- Website: `src/scripts/verify-site-output.mjs` fails if the built site exposes
  the Homebrew command before public distribution is ready.
