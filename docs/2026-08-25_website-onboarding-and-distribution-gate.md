# Website onboarding and distribution gate

- Status: implemented source direction, pending final verification
- Date: 2026-08-25
- Scope: public homepage, first-edition onboarding, and install-command authority
- Deployment: not authorized and not performed

## Purpose

The WarpTweet homepage must answer four questions in order:

1. What does it give me?
2. Will it work on my machines and network?
3. How do I start?
4. What authority does it grant and how is that enforced?

The primary outcome is one exact remote TCP service on localhost. Hybrid
post-quantum cryptography is a defining product property, but the homepage must
connect that property to the recognizable service-access job instead of making
the reader reconstruct the product from protocol vocabulary.

## Product statement

WarpTweet gives an Apple Silicon Mac a loopback TCP port to one exact service
on a Linux machine controlled by the operator. The first edition does not give
the client a shell, subnet, dynamic proxy, file transfer surface, hosted relay,
or WarpTweet account.

The canonical example is querying Postgres in remote Docker Compose at
`127.0.0.1:15432`. The target service continues to own its own credentials and
application authorization.

## Information architecture

The homepage order is:

1. Outcome-first hero with the Postgres example and first-edition support facts.
2. Two-machine setup with the Linux `host` command and Mac `connect` command.
3. Concrete use cases for databases, private APIs, dashboards, and agent tools.
4. Product features covering destination authority, enrollment, loopback,
   lifecycle, restart behavior, and open-source operation.
5. Security boundaries and lifecycle semantics.
6. Qualified compatibility and explicit first-edition exclusions.
7. Exact Profile v1 contract and claim boundary.
8. Open-source repository and contribution path.

The site must not lead with defensive statements about what WarpTweet is not.
Limits remain visible at the decision points where they help a user understand
authority, compatibility, or cryptographic claims.

## First-edition onboarding

The host example is:

```sh
warptweet host --to 127.0.0.1:5432 --name staging-db
```

The client example is:

```sh
warptweet connect --listen-port 15432 staging-db.wtinvite
```

Flags precede the invite path in public examples. The resulting application
endpoint is `127.0.0.1:15432`.

The setup surface must distinguish installed-product use from public package
availability. When public distribution is unavailable, the host and client
workflow remains visible, but the site must not expose a command that cannot
install WarpTweet.

## Support boundary

The first-edition website may represent only the qualified matrix:

- Apple Silicon Mac client on macOS 13 or newer;
- Ubuntu Linux host packages for AMD64 and ARM64;
- direct public IPv4 and IPv6;
- one-to-one NAT where the guest bind differs from the published dial address;
- independently mapped public data and enrollment ports;
- lowercase ASCII DNS locators.

Windows clients, Intel Mac support, outbound-only NAT, TLS-terminating load
balancers, and PROXY protocol are not first-edition capabilities. Future work
must not appear as implied parity.

## Install-command authority

`packaging/evidence/public-release.json` is a schema 2 state document with two
independent milestones:

```text
qualification incomplete
  -> qualification complete, distribution unavailable
  -> qualification complete, public distribution ready
```

`qualification_complete` is authoritative only when the required v3 evidence
index authenticates the checklist, contains every required matrix and
networking report, binds present artifacts where applicable, and passes the v3
completeness rules.

`public_distribution_ready` additionally requires a separate
`warptweet.public-distribution-evidence` document. That document must bind:

- a non-development release version;
- the source commit used by every qualified report;
- a first-party `warptweet/warptweet` GitHub release URL;
- the first-party `warptweet/homebrew-tap` URL and exact tap commit;
- `Casks/warptweet.rb` and its SHA-256;
- the qualified client package SHA-256;
- the exact public Homebrew command;
- a passing clean installation on a supported Apple Silicon Mac;
- the Homebrew version, installed WarpTweet version, observed package digest,
  and RFC 3339 observation time.

The observed clean-install digest must equal the distribution digest and the
qualified client-package digest. The release version and source commit must
match every report in the qualification index. Repository-relative evidence
paths must be canonical and may not escape the repository.

The public Homebrew command is:

```sh
brew install --cask warptweet/tap/warptweet
```

The command must be absent from built HTML while
`public_distribution_ready` is false. It may appear only after the Go
validator accepts both evidence layers.

## Security and reliability invariants

- Website copy must not expand the product beyond one exact target and one
  loopback listener.
- Profile v1 values must be exact. The site must not advertise an alternative
  cipher or classical-only fallback.
- The site must call the OpenSSH composite authentication binding
  vendor-qualified, not IETF-standardized, FIPS validated, or quantum-proof.
- An install CTA must never be inferred from package qualification alone.
- Evidence documents and their paths are untrusted input and must be strictly
  decoded, versioned, bounded by repository-relative paths, and digest-bound.
- Copy controls must report success and failure through an accessible live
  region and leave the command selectable when clipboard access fails.
- Local preview, build success, and container health do not prove public
  deployment or public package availability.

## Accessibility requirements

The affected homepage must retain:

- a skip link and a single programmatically associated main landmark;
- semantic headings, lists, tables, navigation, buttons, and status output;
- visible keyboard focus that is not obscured;
- horizontal table overflow that remains keyboard reachable;
- text and layouts that reflow at narrow widths and remain usable at 200% zoom;
- non-color labels for qualification and support state;
- reduced-motion behavior for decorative transitions;
- an `aria-live` result for install-command copying;
- target sizes meeting the project accessibility requirements.

Automated structure checks do not establish WCAG conformance. A public release
still requires current manual keyboard, screen-reader, zoom, reflow, contrast,
forced-color, reduced-motion, and supported-viewport evidence.

## Verification contract

Before this direction is accepted, run at the current revision:

```sh
gofmt -w internal/publicrelease/gate.go internal/publicrelease/gate_test.go
go test ./internal/publicrelease ./internal/enrollment
go test ./...
go test -race ./...
make fmt-check
make script-check
make vet
pnpm run verify
docker compose config --quiet
docker compose build website
docker compose up --detach --wait website
curl --fail --silent --show-error http://127.0.0.1:4322/
docker compose down
```

`pnpm run verify` must build the site, validate the authoritative release gate,
reject an early install command, check exact Profile v1 copy, and verify the
brand outputs. It also calculates the contrast of the authored foreground,
background, focus, boundary, and graphic pairs used by the affected homepage.
This calculation does not replace browser and assistive-technology evaluation.
The container build compiles a minimal, statically linked copy of
the authoritative Go release validator in a separate pinned builder stage and
runs that binary against the evidence copied into the Node build stage. The
runtime Caddy image does not contain Go, Node, pnpm, source files, or the
validator. The container check proves only that the local Caddy image serves the
generated site.

Record anything blocked, skipped, sandbox-constrained, or dependent on a public
release as incomplete. Do not deploy or publish from this implementation task.
