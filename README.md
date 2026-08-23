# WarpTweet

WarpTweet is open-source managed-endpoint TCP tunneling built around a tightly constrained OpenSSH data plane. It is designed for deployments that manage both endpoints, both identities, the exact destination, and the exact OpenSSH build.

WarpTweet is not a general-purpose SSH client or VPN. It permits one declared local TCP listener to reach one declared target through standard SSH `direct-tcpip` forwarding. The listener is fixed to `127.0.0.1`, server forwarding is destination-restricted, and interactive SSH features are disabled.

## Current status

This repository contains a working WarpTweet controller and tested local process boundary, but it is not yet a supported end-to-end release. The current implementation and release contract is [`docs/2026-08-16_adoption-and-release-strategy.md`](docs/2026-08-16_adoption-and-release-strategy.md). The product quickstart is [`docs/2026-08-16_product-quickstart.md`](docs/2026-08-16_product-quickstart.md). The public Homebrew CTA stays dark until v2 package evidence passes.

- The public CLI path is `host` on the service machine and `connect <label>.wtinvite` on the client. `host` installs policy, starts and verifies the restricted SSH and pinned-TLS enrollment listeners, and writes the invite. The old `gateway`, `server init`, and `server invite` surfaces are rejected rather than aliased.
- Enrollment, rotation, and revocation use TLS 1.3 with hybrid `X25519MLKEM768` key agreement and an Ed25519 SPKI pinned by the invite. The client generates its management capability locally; the server stores only its digest and journals authorization changes for exact retry and restart recovery.
- The `warptweet` CLI strictly validates both manifest kinds, renders isolated client and server policy, renders managed host and client public-key entries, performs client and installed-server preflight, and supervises one selected local forward.
- The repository contains a pinned recipe intended to authenticate, build, test, and stage OpenSSH 10.4p1 from upstream source. It does not distribute or install an OpenSSH source tree or binary bundle, and the full upstream regression suite has not completed in this workspace sandbox.
- Earlier macOS work proved OpenSSH 10.4p1 composite key generation, composite SSHSIG sign and verify, algorithm queries, and the then-current client `doctor` integration. That evidence predates the current Linux-only static OpenSSL, ELF, fixed-path, and root-ownership gates. The current client gate has not yet passed against an installed Linux bundle, and neither result proves a client-to-server tunnel.
- The systemd units (`warptweet-sshd`, `warptweet-enroll`, `warptweet-tunnel@`) establish the intended Linux packaging contract and fail startup or reload unless installed-server preflight passes. Two-endpoint package-to-package interoperability evidence (WP8) has not been completed; the public Homebrew CTA stays dark until it is.
- A system `ssh` binary is not a substitute. Client preflight requires `/opt/warptweet/libexec/openssh/bin/ssh`, root-owned non-symlink ancestry that is not group or world writable, the manifest-pinned executable SHA-256, the exact OpenSSH and OpenSSL version line, an ELF executable with no dynamic libcrypto or libssl dependency and no RPATH or RUNPATH, the required algorithms, trust inputs, and effective configuration.

Until a reviewed OpenSSH 10.4p1 bundle with the required composite signature support is installed, WarpTweet must remain unavailable rather than weaken its profile.

## Exact cryptographic profile

The only current profile is Profile v1. It is immutable and fail closed:

| Field | Exact value |
| --- | --- |
| Profile ID | `warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20` |
| Engine | `OpenSSH_10.4p1` |
| OpenSSL | `3.5.7`; exact version text `OpenSSL 3.5.7 9 Jun 2026` |
| Executable contract | Linux ELF with static OpenSSL linkage, no RPATH or RUNPATH |
| Key exchange | `mlkem768x25519-sha256` |
| Host and client authentication key | `ssh-mldsa44-ed25519@openssh.com` |
| Cipher | `chacha20-poly1305@openssh.com` |
| Authentication binding status | `openssh-vendor-qualified` |
| Support status | `published-matrix` |

The key exchange combines ML-KEM-768 with X25519. Authentication combines ML-DSA-44 with Ed25519 and requires both component verifications to succeed.

There is no classical fallback. A missing algorithm, unsupported peer, wrong host key, unusable client key, altered executable, malformed message, or profile mismatch is a hard failure. WarpTweet does not retry with classical-only SSH.

ML-KEM and ML-DSA are NIST standards. OpenSSH 10.4p1 labels its `ssh-mldsa44-ed25519@openssh.com` composite authentication binding experimental; that binding is vendor-qualified and not an IETF-standardized SSH authentication name. WarpTweet is not represented as an IETF-standard PQ SSH authentication product, quantum-proof, or FIPS validated. Support is limited to the published platform and evidence matrix.

## `.wt` tunnel manifests

A `.wt` file belongs to the strict JSON WarpTweet Tunnel Manifest family with media type:

```text
application/vnd.warptweet.tunnel+json
```

Every manifest has a `kind`, kind-specific `schema_version`, and exact `profile_id`. The current family has two schemas:

| Kind | Schema | Purpose and kind-specific metadata |
| --- | --- | --- |
| `warptweet.client-tunnels` | [v1](schemas/client-tunnels-v1.schema.json) | Pins the fixed installed client `ssh` digest and declares the server endpoint, supervision policy, and one or more tunnels. Key and trust paths are installation invariants and cannot be supplied by a manifest. Each `run --tunnel` invocation selects exactly one declaration and binds exactly `127.0.0.1`. |
| `warptweet.server-gateway` | [v1](schemas/server-gateway-v1.schema.json) | Selects one server listener, one authorized target, one dedicated account, fixed host-key and authorized-keys paths, and exact SHA-256 pins for the installed `sshd` and authenticated OpenSSH plus OpenSSL bundle manifest. |

Unknown fields, duplicate JSON member names at any nesting depth, trailing JSON values, invalid UTF-8, invalid types, unsupported kind-specific schema versions, and oversized inputs are rejected.

A `.wt` manifest contains policy metadata but never private-key material. Client filesystem paths are fixed installation invariants and are absent from the client schema. The server-only `host_key_path` is fixed by the server schema. ML-DSA or Ed25519 seeds, expanded keys, OpenSSH private-key bytes, passphrases, agent credentials, and target-service credentials must never be embedded in, logged from, or exported with a manifest.

## What can be run now

Build and verify the controller:

```sh
make check-go
make build
./bin/warptweet profile
```

Product verbs (require a packaged engine and fixed layout for a live tunnel):

```sh
# On the host that can reach the service
./bin/warptweet host --to 5432 --name laptop-1
# writes ./laptop-1.wtinvite after both host listeners are ready

# On the client
./bin/warptweet connect laptop-1.wtinvite --yes
./bin/warptweet status laptop-1 --json
```

Validate or render a manifest without opening a connection:

```sh
./bin/warptweet validate --config client.wt
./bin/warptweet render-client --config client.wt --tunnel database-primary
./bin/warptweet render-server --config server.wt
./bin/warptweet render-authorized-key --config server.wt --public-key client.pub --not-after 2026-09-17T00:00:00Z
./bin/warptweet render-known-host --config client.wt --tunnel database-primary --public-key host.pub
```

The selected client engine and trust inputs must pass local preflight before `doctor` or `run` can succeed. The fixed Linux server installation must pass its separate gate before `sshd` starts or reloads:

```sh
./bin/warptweet doctor --config /etc/warptweet/client.wt --tunnel database-primary
./bin/warptweet doctor-server --config server.wt
./bin/warptweet run --config /etc/warptweet/client.wt --tunnel database-primary
```

Successful Linux `doctor` output uses `"status":"preflight_ready"`. It proves the fixed root-owned client executable path and ancestry, stable executable digest and metadata, exact stderr line `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026`, empty version stdout, static OpenSSL linkage, ELF format, absence of RPATH and RUNPATH, the sorted dynamic-library inventory, required algorithm availability, fixed identity and trust-file constraints, composite host pin, and effective closed OpenSSH argument policy. Client subprocesses and the launched tunnel receive only `LANG=C` and `LC_ALL=C`. Doctor does not open a connection or prove server identity, client authentication, forwarding readiness, negotiated algorithms, or rekey behavior.

Successful `doctor-server` output also uses `"status":"preflight_ready"`, with `"role":"server"`. On Linux it proves the root-owned fixed-layout `sshd`, helper, `ssh-keygen`, source receipt, exact authenticated bundle membership, dedicated tunnel account with the exact public-key-only `*NP*` sentinel, privilege-separation account with OpenSSH's Linux `!` lock prefix, host-key metadata and derived composite public key, one canonical client authorization, byte-for-byte rendered configuration, and effective `sshd -T` policy. Shadow password-field values are never reported. The WarpTweet controller never reads, hashes, serializes, or logs host private-key bytes; the bundled `ssh-keygen -y` subprocess reads the key only to derive its public key. The command does not start a listener or prove a live handshake.

`run` launches the closed OpenSSH invocation after the same preflight. WarpTweet validates the Unix-domain control socket and remembers its inode, executes the exact pinned `ssh -O check`, requires the reported master PID to equal the foreground child PID, revalidates the same socket inode and pathname through a retained directory descriptor, unlinks that exact pathname relative to the descriptor, verifies its absence, closes the descriptor anchor, and confirms that the child remains alive before reporting Ready. Unlinking the pathname externally does not send OpenSSH a mux request or a process signal. The master keeps its already-open listener descriptor and the SSH transport and local forward remain alive, while new mux clients can no longer reach the retired pathname. This proves authentication and local-listener creation, not forwarding-target health. With restart enabled, the controller stops after ten consecutive failed launches; a stable run resets the count and exponential backoff bounds retry frequency. Packaged service managers use `--once` and own service-level restart policy.

The intended release flow is:

1. Install the reviewed, pinned OpenSSH 10.4p1 bundle, source receipt, and authenticated file manifest in the fixed root-owned layout.
2. On the service host: `host` to start the restricted data and enrollment planes and mint a single-use confidential `.wtinvite`. That file contains no private keys or long-lived credentials. It is a confidential bearer authorization: transfer it over an authenticated channel and delete it after use.
3. On the client: `connect` to generate a composite client key locally, enroll, pin the host, and open the loopback forward.
4. Use `status` / `down` / `rotate` / `revoke` for lifecycle; rotate and revoke require host acknowledgment via the management token.
5. Before a supported release, complete package-to-package dual-host evidence (WP8): authentication, forwarding readiness, negotiated algorithms, rekey, classical-only denial, confinement, invite fail-closed, and cleanup.

Do not use the packaged systemd units as evidence of a supported installation until Linux package assembly and two-endpoint positive and negative interoperability verification are complete.

## Security boundaries

WarpTweet's MVP intentionally excludes:

- unmanaged peers or arbitrary SSH interoperability;
- interactive shells, commands, SFTP, and SCP;
- dynamic SOCKS, remote, agent, X11, stream-local, or TUN/TAP forwarding;
- wildcard or LAN-facing local listeners;
- arbitrary target hosts or ports;
- passwords, keyboard-interactive, GSSAPI, host-based authentication, and trust on first use;
- private keys or credentials inside `.wt` manifests or `.wtinvite` files;
- anonymity, traffic-flow confidentiality, endpoint compromise protection, and availability guarantees;
- claims of standardization, FIPS validation, or quantum-proof security.

Local loopback is a host boundary, not per-process authentication. A deployment with mutually untrusted local users needs an operating-system control that restricts access to the listener.

## Design documents

- [Development quickstart](docs/2026-08-09_quickstart.md)
- [Managed local-forward architecture](docs/2026-08-09_architecture.md)
- [Fixed client layout](docs/2026-08-10_client-layout.md)
- [Client readiness](docs/2026-08-10_client-readiness.md)
- [Installed server gate](docs/2026-08-10_server-gate.md)
- [Static OpenSSL boundary](docs/2026-08-10_static-openssl.md)
- [Threat model](docs/2026-08-09_threat-model.md)
- [Cryptographic profile v1](docs/2026-08-09_crypto-profile.md)
- [Homebrew delivery](docs/2026-08-12_homebrew-delivery.md)
- [macOS OpenSSH client engine](docs/2026-08-12_macos-openssh-engine.md)
- [macOS client attestation](docs/2026-08-12_macos-client-attestation.md)
- [macOS package and Homebrew cask](docs/2026-08-12_macos-pkg-and-cask.md)
- [Linux server packages and bootstrap](docs/2026-08-12_linux-server-packages.md)
- [Client enrollment and lifecycle CLI](docs/2026-08-12_client-lifecycle.md)
- [Package-to-package release evidence](docs/2026-08-12_package-interop-evidence.md)
- [Public release and website install path](docs/2026-08-12_public-release-path.md)
- [CLI host and connect strategy](docs/2026-08-12_cli-host-connect.md)
- [Reviewer catch-up: CLI, invites, architecture](docs/2026-08-14_reviewer-catchup-cli-invites-architecture.md)
- [Dual-host interop orchestrator (Phase A)](docs/2026-08-14_dual-host-interop-orchestrator.md)
- [Local Caddy website](docs/2026-08-12_website-local.md)
- [Logo: The Declared Route](docs/2026-08-12_logo.md)

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Report suspected vulnerabilities privately to `security@warptweet.com` using the process in [SECURITY.md](SECURITY.md).

WarpTweet is licensed under the [Apache License 2.0](LICENSE). The intended OpenSSH bundle remains under its upstream licenses; see [NOTICE](NOTICE).
