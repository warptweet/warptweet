# WarpTweet

WarpTweet makes one TCP service on a Linux machine appear on localhost on an
Apple Silicon Mac. It provides hybrid post-quantum tunneling without giving the
client a shell, a subnet, or a general-purpose SSH credential.

The first-edition path is deliberately small:

```text
Mac application -> 127.0.0.1:<local-port> -> WarpTweet -> one host-approved service
```

For example, query Postgres in remote Docker Compose through
`127.0.0.1:15432` without publishing Postgres to the internet or maintaining a
VPN mesh.

## Current status

The first-edition package and networking qualification matrix is complete for:

- Apple Silicon Mac client on macOS 13 or newer;
- Ubuntu Linux host packages for AMD64 and ARM64;
- direct IPv4 and IPv6, one-to-one NAT, mapped public ports, and DNS locators.

Public distribution is not ready. There is no published Homebrew tap or
non-development GitHub release bound to the qualified artifacts. The website
therefore does not display an install command yet.

This repository separates those two facts in
[`packaging/evidence/public-release.json`](packaging/evidence/public-release.json):

- `qualification_complete` means the required package and topology evidence is
  complete;
- `public_distribution_ready` means a clean supported Mac installed the same
  qualified client artifact through the advertised public Homebrew command.

See the [product quickstart](docs/2026-08-16_product-quickstart.md),
[qualification evidence](packaging/evidence/release-evidence-index-v3.json),
and [public release contract](docs/2026-08-12_public-release-path.md).

## Two-machine workflow

After the signed packages are installed, run this on the Linux machine that can
reach the service:

```sh
warptweet host --to 127.0.0.1:5432 --name staging-db --access-for 30d
```

`host` applies the restricted host policy, starts and verifies the data and
enrollment listeners, then writes `staging-db.wtinvite`. The invite is a
confidential, single-use bearer authorization with a 15-minute lifetime. Send
it over an authenticated channel and delete it after use.

On the Apple Silicon Mac:

```sh
warptweet connect --listen-port 15432 --restart unless-stopped staging-db.wtinvite
psql "host=127.0.0.1 port=15432 dbname=app"
```

WarpTweet generates the client identity locally, pins the host during
enrollment, and binds the local listener to loopback. Target-service
credentials remain separate from WarpTweet.

The route lifecycle is explicit:

```sh
warptweet routes --json
warptweet status staging-db --json
warptweet down staging-db
warptweet up staging-db
warptweet rotate staging-db
warptweet revoke staging-db
```

`down` stops the local route but does not revoke host authorization. `revoke`
removes authorization at the host. Grants expire and do not silently renew.

## Security contract

WarpTweet is a managed two-endpoint product, not a general SSH client or VPN.
Its current contract includes:

- one exact remote TCP destination;
- one loopback-only local listener;
- no shell, remote command, SFTP, SCP, SOCKS, agent forwarding, X11, or TUN;
- pinned host identity and a locally generated client identity;
- single-use enrollment, finite authorization, rotation, revocation, and
  supervised restart behavior;
- strict, versioned `.wt` and `.wtinvite` inputs;
- fail-closed package, executable, policy, and cryptographic-profile checks.

Local loopback is a host boundary, not per-process authentication. Machines
with mutually untrusted local users need an operating-system control that
restricts access to the listener. WarpTweet does not constrain what a database
credential can do after connection, protect a compromised endpoint, hide
traffic flow, or guarantee availability.

Read the [threat model](docs/2026-08-09_threat-model.md) and
[security policy](SECURITY.md) before deploying it around sensitive services.

## Exact cryptographic profile

Profile v1 is immutable and has no classical-only fallback.

| Field | Exact value |
| --- | --- |
| Profile ID | `warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20` |
| Engine | `OpenSSH_10.4p1` |
| OpenSSL | `OpenSSL 3.5.7 9 Jun 2026` |
| Key exchange | `mlkem768x25519-sha256` |
| Host and client identity | `ssh-mldsa44-ed25519@openssh.com` |
| Cipher | `chacha20-poly1305@openssh.com` |
| Engine boundary | Exact Linux ELF and macOS package contracts with authenticated files |

The key exchange combines ML-KEM-768 with X25519. Authentication combines
ML-DSA-44 with Ed25519 and requires both component verifications to succeed. A
missing algorithm, wrong host key, altered executable, malformed message, or
profile mismatch is a hard failure.

ML-KEM and ML-DSA are NIST standards. OpenSSH labels the composite
`ssh-mldsa44-ed25519@openssh.com` authentication binding experimental. It is a
vendor-qualified binding, not an IETF-standardized SSH authentication name.
WarpTweet does not claim FIPS validation, quantum-proof security, or arbitrary
OpenSSH interoperability.

## Manifests and invites

`.wt` is the strict JSON WarpTweet Tunnel Manifest family with media type
`application/vnd.warptweet.tunnel+json`.

| Kind | Schema | Purpose |
| --- | --- | --- |
| `warptweet.client-tunnels` | [v2](schemas/client-tunnels-v2.schema.json) | Declares the pinned engine, published host locator, supervision policy, and selected route. |
| `warptweet.server-gateway` | [v2](schemas/server-gateway-v2.schema.json) | Declares bind and published endpoints, endpoint generation, one target, one account, and installed-engine pins. |
| WarpTweet invite | v3 | Carries published endpoints and single-use enrollment authority. Use the `.wtinvite` extension. |

Unknown fields, duplicate JSON names at any depth, trailing values, invalid
UTF-8, unsupported versions, and oversized inputs are rejected. `.wt` files do
not contain private keys. `.wtinvite` files contain no private key, but they are
confidential until consumed or expired.

## Networking model

The listener address and published client address are separate facts. This
allows a host to bind its private guest address while the invite publishes a
public address, DNS name, or independently mapped ports. The locator is not
identity: enrollment SPKI and the data-plane host key remain authoritative.

Outbound-only NAT without inbound publication is not supported in the first
edition. WarpTweet does not provide a hosted relay and does not query cloud
instance metadata to guess a public address. See the
[bind and advertise contract](docs/2026-08-24_host-bind-and-advertise.md).

## Build and verification

The controller and static website use the repository toolchains and lockfiles:

```sh
make check-go
make build
./bin/warptweet profile

pnpm install --frozen-lockfile
pnpm run verify
```

Useful source-level commands:

```sh
./bin/warptweet validate --config client.wt
./bin/warptweet render-client --config client.wt --tunnel database-primary
./bin/warptweet render-server --config server.wt
./bin/warptweet render-authorized-key --config server.wt --public-key client.pub --not-after 2026-09-17T00:00:00Z
./bin/warptweet doctor --config /etc/warptweet/client.wt --tunnel database-primary
./bin/warptweet doctor-server --config /etc/warptweet/server.wt
```

`doctor` and `doctor-server` prove their documented local preflight boundaries.
They do not by themselves prove a live connection, forwarding-target health,
rekey behavior, public package availability, or production readiness.

For live-forward readiness, WarpTweet validates the control socket and
remembers its inode. Its checks require the exact `ssh -O check` PID to match
the foreground child, revalidate the same remembered socket inode, unlink the
pathname relative to the retained directory descriptor, and confirm the child
remains alive before Ready. Close the retained directory descriptor only after
the pathname is absent. This retirement does not send OpenSSH a mux request and
does not signal the process. WarpTweet never invokes `ssh -O stop` for
retirement. Target health is not checked by this readiness boundary.

The local website uses Astro and Caddy:

```sh
docker compose up --build website
```

Then open `http://127.0.0.1:4322/`.

## Repository map

- [`cmd/warptweet`](cmd/warptweet): public CLI entry point
- [`internal`](internal): controller, policy, enrollment, lifecycle, evidence,
  and platform boundaries
- [`schemas`](schemas): canonical external JSON contracts
- [`packaging`](packaging): fixed layouts, package recipes, and release evidence
- [`scripts`](scripts): build, verification, and package interop harnesses
- [`src`](src): Astro website source
- [`docs`](docs): architecture, threat model, operations, release contracts, and
  reviewer records

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Report
suspected vulnerabilities privately to `security@warptweet.com` using
[SECURITY.md](SECURITY.md).

WarpTweet is licensed under the [Apache License 2.0](LICENSE). The authenticated
OpenSSH bundle retains its upstream licenses; see [NOTICE](NOTICE).
