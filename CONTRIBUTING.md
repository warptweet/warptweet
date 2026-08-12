# Contributing to WarpTweet

WarpTweet welcomes focused contributions that preserve its managed-endpoint, fail-closed security model. Read the architecture, threat model, and cryptographic profile before changing a security boundary:

- [Managed local-forward architecture](docs/2026-08-09_architecture.md)
- [Fixed client layout](docs/2026-08-10_client-layout.md)
- [Client readiness](docs/2026-08-10_client-readiness.md)
- [Installed server gate](docs/2026-08-10_server-gate.md)
- [Static OpenSSL boundary](docs/2026-08-10_static-openssl.md)
- [Threat model](docs/2026-08-09_threat-model.md)
- [Cryptographic profile v1](docs/2026-08-09_crypto-profile.md)
- [Client tunnels manifest v1 schema](schemas/client-tunnels-v1.schema.json)
- [Server gateway manifest v1 schema](schemas/server-gateway-v1.schema.json)

## Non-negotiable invariants

Changes must preserve all of the following:

- Never add a classical fallback to a PQ-required profile.
- An unsupported peer or algorithm is a hard failure.
- A released profile ID is immutable. Any change to an engine, name, encoding, primitive, parameter, cipher list, or verification rule needs a new profile ID and migration design.
- Both ML-DSA-44 and Ed25519 verifications must succeed for the current composite key.
- Host identity is preprovisioned and pinned. Trust on first use is not allowed.
- The client launches OpenSSH with `-F none`, a closed ordered argument policy, exact algorithm lists, and no ambient SSH configuration or agent.
- The Linux client uses only the fixed root-owned installed `ssh`, requires the profile's exact statically linked OpenSSL version and ELF linkage contract, and launches with the deterministic `LANG=C`, `LC_ALL=C` environment.
- The MVP remains local TCP forwarding to one exact numeric target. It does not grow shells, commands, file transfer, SOCKS, remote forwarding, or arbitrary destinations.
- `.wt` remains the strict JSON WarpTweet Tunnel Manifest family with media type `application/vnd.warptweet.tunnel+json`; each kind has an explicit independently versioned schema.
- A `.wt` manifest contains policy metadata only. Client filesystem paths are fixed installation invariants. A manifest never contains private keys, seeds, passphrases, credentials, or tunneled content.
- Keep product maturity, support status, and authentication-binding standards status separate. Do not brand WarpTweet itself as experimental. Scope that term only to OpenSSH's description of its vendor-qualified authentication binding. Do not claim standardization, quantum-proof security, or FIPS validation.

A proposal that needs to change an invariant should begin with a threat-model and profile-migration update rather than silently weakening validation.

## Development setup

WarpTweet currently uses Go 1.26. The static website additionally uses the pinned Node.js and npm versions declared by `.node-version` and the Docker build. Install its locked dependencies before running the whole-repository gate:

```sh
npm ci --ignore-scripts --no-audit --no-fund
go test ./...
```

Before submitting a change:

```sh
make check
make test-race
```

Use `gofmt` only on files you changed. Do not perform unrelated rewrites, dependency updates, or generated-file changes in the same contribution.

The repository has a controller CLI and a verified-source OpenSSH build recipe, but no supported release. The default suite validates packages, policy rendering, engine preflight, trust inputs, supervision, and a fake-engine process boundary. The opt-in real-engine harness accepts `WARPTWEET_OPENSSH_PREFIX` for staged cryptographic and rendering checks:

```sh
WARPTWEET_OPENSSH_PREFIX=/absolute/stage/opt/warptweet/libexec/openssh \
  make test-openssh-integration
```

Its client `doctor` phase cannot satisfy the current production contract from an arbitrary staged prefix. A valid current client gate requires the exact root-owned `/opt/warptweet/libexec/openssh/bin/ssh` path. The integration harness and CI ordering must install and attest that fixed layout before a full real-engine client result may be reported as passing.

The Ubuntu OpenSSH CI job is also configured to assemble the fixed root-owned layout on an ephemeral runner and run `doctor-server` without starting a listener. That hosted gate validates installed-server provenance and effective policy when it passes, but it has not yet been observed from this workspace.

None of these suites proves an authenticated client-to-server tunnel. Any change that claims end-to-end behavior must add live two-endpoint integration fixtures, negotiated-algorithm and rekey observation, Linux service confinement evidence, and negative interoperability tests.

## Change requirements

Each contribution should include:

- a narrowly stated problem and security impact;
- the invariant or trust boundary affected;
- tests for the intended behavior and important failure cases;
- strict rejection tests for malformed and adversarial input;
- documentation updates for user-visible or protocol-visible behavior;
- a migration plan when stored state, manifests, keys, or profiles change;
- primary-source links for standards and cryptographic claims.

For `.wt` changes, test unknown and duplicate object fields, trailing values, invalid UTF-8, size limits, schema versions, numeric bounds, duplicate identities or listeners, path validation, and attempts to introduce secret-bearing fields.

For OpenSSH boundary changes, test executable provenance, version and algorithm queries, exact rendered configuration, closed command arguments, host-key pinning, authentication restrictions, local bind and target restrictions, rekey behavior, cleanup, and denial-of-service bounds.

## Code and documentation style

- Prefer explicit types, errors, and validation over coercion or implicit defaults.
- Keep security-sensitive construction deterministic and reviewable.
- Reject unknown input rather than preserving it for later interpretation.
- Do not invoke OpenSSH through a shell or admit caller-supplied arguments or configuration fragments.
- Avoid logging commands, manifests, keys, credentials, or tunneled content.
- Put dated design documentation in `docs/` using `YYYY-MM-DD_short-title.md`.
- Use primary NIST, IETF, IANA, RFC Editor, OpenSSH, and source-code references for protocol facts.
- Describe Internet-Drafts as work in progress and record the exact revision used.
- Express roadmap sizing in productivity points, not calendar estimates.
- Avoid em dashes in user-facing copy unless necessary.

## Pull requests

Keep pull requests reviewable and single-purpose. Explain what was verified and what remains unverified. Call out any dependency on network access, a packaged OpenSSH engine, Linux systemd, physical hardware, or privileged integration that was not exercised.

Do not combine a cryptographic profile change with unrelated product work. Do not update a draft binding in place. Add the new profile, interoperability evidence, managed migration, and explicit retirement conditions.

## Security reports

Do not submit suspected vulnerabilities through a public issue or pull request. Follow [SECURITY.md](SECURITY.md), including its warning that the placeholder reporting mailbox must be confirmed before publication.

## Licensing

By submitting a contribution, you agree that it may be distributed under the [Apache License 2.0](LICENSE). Do not copy code or assets with incompatible terms. Identify all third-party material and preserve its copyright, license, and notice requirements.

The intended OpenSSH bundle is not vendored yet and will remain under its own upstream license when added. A contribution that vendors or packages it must include the exact corresponding upstream license and notices without implying that Apache-2.0 relicenses OpenSSH.
