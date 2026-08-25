# Public release and website installation path

Status: CTA gate and website install panel, 2026-08-12

## Do you need WP8 evidence before WP9?

Yes for **activating** the Homebrew command.

| Work | Allowed now? |
| --- | --- |
| WP9 scaffolding: dark CTA, release order docs, gate validator | Yes |
| Flip website to `brew install --cask warptweet/tap/warptweet` | Only after complete package-to-package evidence |

WP8 delivered the checklist and harness. Hosted dual-host runners must still
produce a complete v3 `warptweet.release-evidence-index` covering the
architecture matrix and required networking cells. Until that exists, the
website must say `Homebrew package in release qualification`.

## Release order

1. Signed source tag
2. Immutable artifacts and signed checksums
3. SBOM and provenance attestations
4. Linux package repository metadata
5. Homebrew tap and reviewed cask
6. Canonical public schemas (client-tunnels v2, server-gateway v2, invite v3, evidence v3), Profile v1 crypto contract, and release notes
7. Website install experience (CTA on only after evidence)

## Gate document

`packaging/evidence/public-release.json`

```json
{
  "homebrew_cta_enabled": false,
  "homebrew_command": "brew install --cask warptweet/tap/warptweet",
  "next_command": "warptweet connect <invite-file>",
  "qualification_message": "Homebrew package in release qualification",
  "required_evidence_document": ""
}
```

To enable the CTA:

1. Produce a complete v3 package-interop evidence index for the published digests.
2. Commit the index under the repository (or release branch).
3. Set `required_evidence_document` to that path.
4. Set `homebrew_cta_enabled` to `true`.
5. Run `internal/publicrelease.ValidateEnabledCTA` and website `pnpm run verify`.

## Website behavior

- Dark: qualification message, planned connect next action
  (`warptweet connect <invite-file>`), no install command.
- Light: selectable Homebrew command, copy control, connect next action
  (`warptweet connect <invite-file>`), links to artifacts/evidence/security.

## Verification

- Go: `internal/publicrelease` keeps the repository gate dark by default and
  rejects an enabled CTA without complete evidence.
- Website: `src/scripts/verify-site-output.mjs` fails if the built site exposes
  the Homebrew command while the gate is dark.
