# Development quickstart

This guide exercises WarpTweet's controller, manifest, trust-rendering, client-preflight, and installed-server-preflight boundaries. It is not a production deployment guide or evidence of an authenticated two-endpoint tunnel.

## Controller

Build and test the Go control plane:

```sh
make check-go
make build
./bin/warptweet profile
```

The profile command must report `authentication_binding_status: "openssh-vendor-qualified"`, `support_status: "published-matrix"`, the exact profile ID `warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519`, OpenSSL version `3.5.7`, exact version text `OpenSSL 3.5.7 9 Jun 2026`, static linkage, and ELF executable format.

## Authenticated Linux engine build

The production build is intentionally restricted to a disposable native Linux `x86_64` or `aarch64` runner. It does not consume system OpenSSL development files. Install the prerequisites listed in the CI workflow, including `acl`, `binutils`, a C toolchain, `curl`, GnuPG with `gpg-agent`, Perl, `libtext-template-perl`, and `sudo`. Then provision the exact non-root regression identity:

```sh
sudo env WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 \
  ./scripts/provision-openssh-build-account.sh
```

This account receives a broad root-or-`nobody` regression-only sudo policy because the full upstream OpenSSH suite exercises privileged fixtures. Never run this provisioner on a persistent build host or production endpoint. See [`2026-08-10_openssh-build-account.md`](2026-08-10_openssh-build-account.md) for the exact boundary.

Authenticate and fetch both pinned source archives as that account:

```sh
WT_BUILD_HOME=/var/lib/warptweet-build

sudo -u warptweet-build -H env \
  HOME="$WT_BUILD_HOME" \
  TMPDIR="$WT_BUILD_HOME/tmp" \
  ./scripts/fetch-openssh.sh \
  "$WT_BUILD_HOME/warptweet-openssh-source"

sudo -u warptweet-build -H env \
  HOME="$WT_BUILD_HOME" \
  TMPDIR="$WT_BUILD_HOME/tmp" \
  ./scripts/fetch-openssl.sh \
  "$WT_BUILD_HOME/warptweet-openssl-source"
```

The OpenSSH gate requires the pinned SHA-256 `ef6026dd2aea8d56059638d5d3262902c892ceba9f88395835e0d06d3fb63238` and exact release-key signer and primary fingerprint `7168B983815A5EEF59A4ADFD2A3F414E736060BA`. The OpenSSL gate requires SHA-256 `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8` and exact artifact signer and primary fingerprint `BA5473A2B0587B07FB27CF2D216094DFD0CB81EF`. HTTPS alone is not source authentication.

Build OpenSSL 3.5.7 with shared libraries, modules, and DSO loading disabled, run its complete test suite, link OpenSSH 10.4p1 against that private static libcrypto, and run the complete upstream OpenSSH regression suite:

```sh
. ./third_party/openssh/source.env
. ./third_party/openssl/source.env
WT_BUILD_HOME=/var/lib/warptweet-build

sudo -u warptweet-build -H env \
  HOME="$WT_BUILD_HOME" \
  TMPDIR="$WT_BUILD_HOME/tmp" \
  SUDO=sudo \
  ./scripts/build-openssh.sh \
  "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
  "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
  "$WT_BUILD_HOME/warptweet-openssh-stage"
```

The script rejects root execution, an existing stage directory, unsafe identities or paths, skipped tests, and dynamic crypto linkage. A successful stage authenticates exactly nine manifest members: `ssh`, `ssh-keygen`, `sshd`, `sshd-auth`, `sshd-session`, both source receipts, and both upstream license files. The manifest itself and privilege-separation jail are also staged. Unused tools, setuid helpers, and a runtime OpenSSL library tree are excluded. Staging does not install `/opt/warptweet` or create a distributable package.

## Verified local OpenSSH evidence

On 2026-08-10, OpenSSH 10.4p1 configured and compiled in this macOS workspace against Homebrew OpenSSL 3.6.3. Upstream file and unit tests passed. The following real-engine boundaries also passed:

- distinct composite host and client key generation with `ssh-keygen -t mldsa44-ed25519`;
- composite SSHSIG signing and verification, including rejection of a modified payload;
- OpenSSH algorithm queries for `mlkem768x25519-sha256`, `ssh-mldsa44-ed25519@openssh.com`, `chacha20-poly1305@openssh.com`, and `aes256-gcm@openssh.com`;
- managed host-pin and authorized-client rendering from the real composite public keys;
- the then-current WarpTweet client integration in [`tests/integration/openssh_test.go`](../tests/integration/openssh_test.go), including real executable hashing, version and capability checks, effective client configuration, and `doctor` output with `"status":"preflight_ready"`.

That client result predates the current profile's static OpenSSL 3.5.7, Linux ELF, fixed installed path, and root-ownership gates, so it is not evidence that the current client preflight passes. The upstream network regression harness could not start its test `sshd` because the workspace sandbox denied binding `127.0.0.1:4242`. The full upstream regression suite therefore remains unverified in this environment. This macOS evidence does not verify the current Linux client gate, Linux package assembly, Linux service confinement, the installed server runtime, or client-to-server interoperability.

## Manifests

WarpTweet Tunnel Manifest is one strict JSON family with media type `application/vnd.warptweet.tunnel+json` and independently versioned kinds. `examples/client.example.wt` is `warptweet.client-tunnels` v1; it pins the fixed installed client engine digest and may contain multiple tunnel declarations, but contains no caller-selected filesystem paths. `examples/server.example.wt` is `warptweet.server-gateway` v1; it selects restricted server policy and pins the installed `sshd` plus the authenticated OpenSSH and OpenSSL bundle manifest.

Client and server manifests begin at `schema_version: 1` and require the current exact profile ID. The exact client executable SHA-256 remains the manifest's binary pin. The executable, identity, trust, and production manifest paths are fixed installation invariants.

Copy the examples to deployment-specific candidate `.wt` files and replace every documentation address and placeholder. The client example must fail validation until the exact installed `/opt/warptweet/libexec/openssh/bin/ssh` SHA-256 is inserted. The server example must fail until both the installed `sshd` digest and the installed `openssh-bundle.sha256` file digest are inserted. Neither kind may contain private-key material. The server-only `host_key_path` is a fixed filesystem reference.

```sh
cp examples/client.example.wt /absolute/private/path/client.wt
cp examples/server.example.wt /absolute/private/path/server.wt
./bin/warptweet validate --config /absolute/private/path/client.wt
./bin/warptweet validate --config /absolute/private/path/server.wt
```

Render reviewable OpenSSH policy:

```sh
./bin/warptweet render-client \
  --config /absolute/private/path/client.wt \
  --tunnel database-primary

./bin/warptweet render-server \
  --config /absolute/private/path/server.wt
```

`render-client` selects one declaration from the client manifest. The v1 declaration is valid only when its listener address is exactly `127.0.0.1`. Rendering and validation may inspect a candidate manifest anywhere; production `doctor` and `run` require the installed manifest at `/etc/warptweet/client.wt`.

## Trust inputs

Generate distinct composite host and client keys locally with the reviewed OpenSSH 10.4p1 `ssh-keygen`. Never copy sample or production private-key material into documentation or a `.wt` manifest:

```sh
/absolute/path/to/openssh-prefix/bin/ssh-keygen \
  -t mldsa44-ed25519 -N '' -f /absolute/private/path/host

/absolute/path/to/openssh-prefix/bin/ssh-keygen \
  -t mldsa44-ed25519 -N '' -f /absolute/private/path/client
```

Render the exact managed public-key entries to standard output for review:

```sh
./bin/warptweet render-known-host \
  --config /absolute/private/path/client.wt \
  --tunnel database-primary \
  --public-key /absolute/private/path/host.pub

./bin/warptweet render-authorized-key \
  --config /absolute/private/path/server.wt \
  --public-key /absolute/private/path/client.pub
```

The first command renders the composite host-key pin under alias `warptweet-<tunnel-id>`. For the example tunnel, the per-tunnel known-hosts entry begins:

```text
warptweet-database-primary ssh-mldsa44-ed25519@openssh.com <base64-public-key-blob> warptweet-managed-host
```

The second command renders a restricted `authorized_keys` line bound to the server manifest's exact target. Neither command installs or appends a file. Provision the reviewed output atomically through an authenticated channel and with restrictive permissions.

The configured global known-hosts file at `/etc/warptweet/trust/known_hosts.empty` must exist and be exactly zero bytes. The client identity is fixed at `/etc/warptweet/identity/client`, and managed host pins are fixed at `/etc/warptweet/trust/known_hosts`. Production files are root-owned, group-readable only by the dedicated `warptweet-client` group, and not mutable by the service account. This prevents ambient system trust or a manifest-selected path from changing host identity.

## Preflight and execution

On Linux, the client doctor gate verifies the exact fixed `ssh` path; root ownership and non-symlink, non-group-writable, non-world-writable ancestry; stable size, modification time, and SHA-256 around held-file ELF inspection; ET_EXEC or ET_DYN format; no `DT_NEEDED` libcrypto or libssl; no RPATH or RUNPATH; exact empty version stdout and stderr `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026\n`; required algorithms; identity and trust-file constraints; exact composite pin structure; exact local-forward arguments; and the effective configuration resolved by that engine. Every client subprocess and final launch receives only `LANG=C` and `LC_ALL=C`:

```sh
./bin/warptweet doctor \
  --config /etc/warptweet/client.wt \
  --tunnel database-primary
```

Successful output reports `"status":"preflight_ready"` plus `openssl_version`, `openssl_version_text`, `openssl_linkage`, `executable_format`, and the sorted `elf_needed` list. This means local client preflight passed. Production client preflight fails closed on non-Linux platforms. Doctor does not open a network connection and does not prove server identity, client authentication, forwarding readiness, negotiated algorithms, or rekey behavior.

On a provisioned Linux server, validate the fixed root-owned engine, helper, receipt, host-key metadata, managed authorization, rendered configuration, and effective server policy before starting or reloading `sshd`:

```sh
./bin/warptweet doctor-server \
  --config /etc/warptweet/server.wt
```

Successful output includes `"status":"preflight_ready"` and `"role":"server"`. The WarpTweet controller never reads, hashes, serializes, or logs host private-key bytes; the bundled `ssh-keygen -y` subprocess reads the key only to derive its public key. The command starts no listener. It fails closed on non-Linux platforms and when the fixed `/opt/warptweet` installation contract is absent.

Only after doctor succeeds may the local forward start:

```sh
./bin/warptweet run \
  --config /etc/warptweet/client.wt \
  --tunnel database-primary \
  --once
```

`--once` disables controller-level restart. Packaged service managers require this mode and own service restart policy. Direct use without it stops after ten consecutive failed launches; a stable run resets the count and exponential backoff caps retry frequency at the manifest's `max_backoff`. WarpTweet reports Ready only after PID-bound host and client authentication plus exact local-listener creation. Target health remains `not_checked`.

The Ready event does not by itself prove target reachability, negotiated algorithm observation, rekey, key rotation, negative interoperability, server confinement, or two-endpoint behavior. Those remain separate release evidence.

## Publication boundary

Report suspected vulnerabilities privately to `security@warptweet.com`. See [`SECURITY.md`](../SECURITY.md).
