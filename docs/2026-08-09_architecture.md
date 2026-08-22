# Managed local-forward architecture

Status: MVP design, 2026-08-09

## Purpose

WarpTweet provides one narrow capability: a managed client opens an authenticated SSH connection to a managed server and exposes an explicitly configured TCP service on a loopback-only local port. The data path is an SSH `direct-tcpip` channel, the standard channel used by local port forwarding in [RFC 4254, section 7.2](https://www.rfc-editor.org/rfc/rfc4254.html#section-7.2).

This is not a general-purpose SSH client or VPN. Both endpoints, their OpenSSH engine version, their identities, and the allowed forwarding tuple are managed as one deployment.

The cryptographic profile is specified in [2026-08-09_crypto-profile.md](2026-08-09_crypto-profile.md). The security analysis is specified in [2026-08-09_threat-model.md](2026-08-09_threat-model.md). Homebrew delivery and multi-platform packaging are specified in [2026-08-12_homebrew-delivery.md](2026-08-12_homebrew-delivery.md).

## Wire profile versus platform artifact profile

Keep the SSH wire contract separate from platform artifact attestation.

```text
WireProfile (internal/profile)
  profile ID, OpenSSH version, KEX, authentication, ciphers
  raw key and signature sizes, no-fallback policy
  authentication_binding_status, support_status

PlatformArtifactProfile (internal/artifactprofile)
  platform and architecture ID
  executable format and linkage rules
  fixed filesystem layout and service identity names
  code-signing and notarization rules when applicable
```

A `.wt` manifest selects only the wire `profile_id`. Production preflight resolves the running GOOS/GOARCH to an artifact-profile ID, fails closed when that combination is unsupported, and records `artifact_profile_id` in doctor and launch evidence. Supported client artifact profiles are `linux-amd64`, `linux-arm64`, `darwin-arm64`, and `darwin-amd64`. Darwin uses the package-owned Application Support layout, Mach-O static-OpenSSL inspection, and the `_warptweet` service identity; production still fails closed on unprovisioned hosts until the signed package and Team ID are present.

## MVP boundary

One tunnel declaration maps:

```text
127.0.0.1:<local-port>
        -> managed WarpTweet client
        -> authenticated SSH transport
        -> managed WarpTweet server
        -> <authorized-target>:<authorized-port>
```

The current client-manifest local listener MUST bind exactly to the IPv4 loopback address `127.0.0.1`. IPv6 loopback, wildcard, and non-loopback binds MUST be rejected. The server MUST authorize the destination host and port exactly. An attacker-controlled DNS name MUST NOT be used as an authorized target.

The client starts the connection without a remote command, requests only the configured local forward, and treats failure to establish the forward as connection failure. The server accepts only the required `direct-tcpip` channels for that principal and configured destination.

## WarpTweet Tunnel Manifest family

A file ending in `.wt` belongs to the strict JSON WarpTweet Tunnel Manifest family. Its media type is `application/vnd.warptweet.tunnel+json`. The file contains exactly one UTF-8 JSON object with a `kind`, kind-specific `schema_version`, and exact `profile_id`. The tuple of media type, kind, and schema version identifies the schema. Unknown or non-canonical field names, duplicate JSON member names at any nesting depth, a second or trailing top-level JSON value, invalid field types, invalid UTF-8, and inputs beyond the configured size limit MUST be rejected rather than ignored.

The current family contains two kinds:

| Kind | Schema | Declarative policy metadata |
| --- | --- | --- |
| `warptweet.client-tunnels` | v1 | Exact fixed client `ssh` digest, managed server, supervision policy, and one or more tunnel declarations. Executable, manifest, identity, and trust paths are fixed installation invariants. One controller process selects exactly one declaration by ID. |
| `warptweet.server-gateway` | v1 | One server listener, one authorized target, one dedicated account, fixed host-key and authorized-keys paths, and SHA-256 pins for the installed `sshd` and authenticated OpenSSH plus OpenSSL bundle manifest. |

A `.wt` manifest MUST NEVER contain private-key material. In particular, it MUST NOT embed ML-DSA or Ed25519 seeds, expanded private keys, OpenSSH private-key files, passphrases, agent credentials, target-service credentials, or other secrets. Client private-key and trust paths are absent from v1. The fixed server `host_key_path` names state managed outside the manifest and does not authorize reading, copying, logging, serializing, or returning its contents. Import, export, diagnostic, and error paths MUST preserve this boundary.

Although a manifest is not a private-key container, its topology, account, filesystem paths, hashes, and policy can be operationally sensitive. Its integrity and access permissions MUST be protected, and activation MUST use an authenticated desired-state process.

## Components and trust boundaries

| Component | Responsibility | Security boundary |
| --- | --- | --- |
| Managed `.wt` manifest | Select one immutable cryptographic profile and kind-specific endpoint, tunnel, and protected-path policy | The manifest is policy input, not a secret-key container or merely a convenience |
| Controller and supervisor | Render exact OpenSSH policy, attest every client launch, preflight the fixed server installation, start and stop one selected client engine, and publish PID-bound authenticated-forward readiness | Target health and negotiated-algorithm observation remain separate evidence gates |
| OpenSSH client engine | Negotiate the pinned transport, verify the host, authenticate the client, and create the local forward | Only the pinned OpenSSH release is in profile scope |
| OpenSSH server engine | Authenticate the client and enforce destination and channel restrictions | It handles untrusted network input before authentication |
| Key store | Hold distinct composite client and host private keys | Private material never crosses to the other endpoint or control plane |
| Local application | Connect to the loopback listener | It is outside SSH authentication; loopback restricts access to the host, not to one user or process |
| Target service | Receive plaintext after SSH termination | It is outside the tunnel's confidentiality boundary |

The supervisor is not permitted to infer a weaker configuration from peer capabilities. The OpenSSH process is not permitted to read ambient user SSH configuration, use a system agent with unrelated identities, or search default identity and host-key locations. Every security-relevant input is supplied by the managed configuration.

## Current implementation boundary

The controller currently implements and tests:

- strict, bounded decoding of both manifest kinds, including duplicate-member rejection and exact `127.0.0.1` client binding;
- deterministic diagnostic client-policy and restricted server configuration rendering;
- deterministic composite client authorization and host-pin rendering from validated public-key lines;
- verification before every client launch of the fixed Linux `ssh` path and root-owned protected ancestry, stable SHA-256 and metadata around held-file inspection, ELF format, static OpenSSL linkage without RPATH or RUNPATH, exact `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026` version output, required algorithm availability, fixed root-owned manifest, identity, and trust state, composite host pin, exact local-forward arguments, and effective closed argument policy;
- Linux installed-server preflight for root ownership and permissions, exact bundle membership and hashes, pinned source receipt, fixed helpers, host-key metadata and derived composite public key, canonical authorization, byte-for-byte rendered configuration, and effective server policy;
- a closed client invocation using `-F none` that selects one tunnel declaration, admits no caller-supplied OpenSSH options, and receives only `LANG=C` and `LC_ALL=C` in its process environment;
- PID-bound authenticated-forward readiness that validates and remembers the one-shot control-socket inode, requires an exact `ssh -O check` PID match, revalidates the same inode and pathname, unlinks it relative to the retained directory descriptor, verifies absence, closes the descriptor anchor, and confirms that the child remains alive before Ready;
- direct process supervision with an exponential delay capped by `max_backoff`.

Successful `doctor` output reports `"status":"preflight_ready"`. It means the local client preflight passed. Successful `doctor-server` output adds `"role":"server"` and means the fixed Linux server installation passed. Neither command opens a network connection, and neither proves server identity to a remote client, client authentication, local-forward readiness, negotiated KEX, host key, client key, cipher, or rekey behavior.

The readiness witness removes only the verified control-socket directory entry. A descriptor-relative external unlink does not send a mux request to OpenSSH and does not signal the process. OpenSSH retains its already-open listener descriptor, transport, and local forward, but the retired pathname is no longer available to a new mux client. Readiness remains an authentication and local-listener claim. Target health is not checked.

With restart enabled, the controller stops after ten consecutive failed launches; a stable run resets the count. Backoff bounds retry frequency. Packaged service managers use `run --once` and own the operational restart policy; the systemd unit publishes readiness with `Type=notify`.

## Required release lifecycle

1. Strictly decode the selected `.wt` kind and validate its profile, fixed installed state, ownership, key types, local bind or server listener, and exact destination.
2. Verify that both installed engines report `OpenSSH_10.4p1`, match approved release provenance, and support every exact algorithm in the selected profile.
3. Build the closed client argument policy and restricted server configuration from allow-lists. Additive OpenSSH syntax such as `+algorithm` is forbidden.
4. Start the server with password, keyboard-interactive, host-based, GSSAPI, and ambient CA trust unavailable. Enable public-key authentication only for the managed composite key type. The authenticated build compiles PAM, Kerberos, and GSSAPI out; do not emit unsupported runtime directives merely to restate that build invariant.
5. Start the client with the managed identity, managed known-hosts file, strict host-key checking, no remote command, and the one configured local forward.
6. Require the SSH negotiation to select the profile's exact key exchange, composite host-key type, composite client-key type, and one profile cipher. Any mismatch terminates the process and closes the listener.
7. Mark the tunnel ready only after authentication has completed and the local forwarding listener has been created. Process existence alone is not readiness.
8. On engine exit, authentication failure, forwarding failure, configuration drift, or profile mismatch, close the listener and report a stable failure reason. Never retry with a weaker profile.

## Fail-closed invariants

These invariants apply to initial key exchange and every rekey:

- The only accepted profile ID is an ID returned by the profile registry. An unknown, unversioned, or partially specified profile is invalid.
- The engine version MUST equal the profile engine version. A newer or older engine requires a separately reviewed profile.
- The negotiated key exchange MUST be `mlkem768x25519-sha256`.
- Host authentication MUST use `ssh-mldsa44-ed25519@openssh.com` and a preprovisioned exact host key. Trust on first use is forbidden.
- Client authentication MUST use public-key authentication with `ssh-mldsa44-ed25519@openssh.com`. Password, keyboard-interactive, GSSAPI, host-based, and classical-only public keys are forbidden.
- Both ML-DSA-44 and Ed25519 verification operations MUST succeed for a composite signature to succeed.
- The negotiated cipher MUST be `chacha20-poly1305@openssh.com`. No `none`, CBC, CTR, or AES-GCM cipher is accepted. A protocol-level MAC selection is not used by this AEAD cipher and cannot expand the profile.
- Compression MUST be disabled for the MVP.
- The effective algorithm lists MUST be exact replacements, not additions to OpenSSH defaults.
- A peer with no mutually supported required algorithm is incompatible. Compatibility fallback is forbidden.
- A failed PQ operation, missing key, unknown profile, malformed packet, or unverifiable effective configuration is a hard failure.

SSH includes both parties' `SSH_MSG_KEXINIT` payloads in the exchange hash, as defined by [RFC 4253, section 8](https://www.rfc-editor.org/rfc/rfc4253.html#section-8). This authenticates the negotiated transcript after host verification. It does not protect against locally configured fallback, so the product must still enforce the exact policy before and after negotiation.

## Identity lifecycle

The MVP uses raw, pinned composite keys. It does not depend on a new certificate format. The current controller renders validated host-pin and authorized-client lines, but it does not generate, install, rotate, revoke, destroy, or audit endpoint keys. The following lifecycle remains required deployment and release behavior:

- Host and client identities are separate key pairs. Their ML-DSA and Ed25519 components MUST NOT be reused independently or in another composite key.
- Keys are generated on the endpoint from the operating system CSPRNG. The control plane receives only the public-key blob and lifecycle metadata.
- The identity record binds the exact SSH public-key blob and its SHA-256 digest to an immutable endpoint or principal ID, role, profile ID, issuance event, status, and activation generation.
- Private key files are owned by the engine account, are not group or world accessible, and are never accepted from an ambient `ssh-agent`.
- Authorization and known-hosts state are written atomically from a versioned desired-state record. Stale or partially written state is not usable.
- Rotation first provisions a newly generated composite key, then activates its exact public blob, confirms connectivity, and finally revokes the prior key. Every key in the overlap remains composite and profile-approved.
- Revocation removes authorization and trust pins through an authenticated desired-state update. Recovery issues a new composite identity. There is no classical recovery credential.
- Decommissioning stops the tunnel, removes authorization, destroys local private material where the platform permits, and retains only non-secret audit evidence.

[RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html) permits additional SSH agent key types but requires vendor-specific types to remain domain-qualified until IANA allocation. The MVP avoids agent forwarding and shared ambient agents even though the OpenSSH engine can serialize the vendor-qualified composite key type.

## Interoperability and release gates

Interoperability means exact wire compatibility, not merely use of the same NIST primitives. A release candidate MUST demonstrate:

- managed client to managed server operation with the exact profile and OpenSSH 10.4p1;
- rejection of every classical-only KEX, host key, and client key;
- rejection of malformed, truncated, overlong, trailing-data, and wrong-algorithm encodings;
- successful and failed rekey behavior under the same exact policy;
- exact host-key pinning and atomic key rotation;
- enforcement of the exact `127.0.0.1` client binding and exact destination authorization;
- refusal of shell, exec, subsystem, SFTP, SCP, remote forwarding, dynamic forwarding, agent forwarding, X11 forwarding, and TUN/TAP requests;
- bounded behavior under connection floods, authentication floods, channel floods, and oversized packet declarations;
- transcript and test-vector interoperability with an independently maintained implementation before any profile is called stable.

The [SSHM charter](https://datatracker.ietf.org/group/sshm/about/) expects interoperable implementations for standards work. WarpTweet should contribute reusable encoding tests, negative vectors, parser fixes, and algorithm integration upstream. The `.wt` manifest, managed enrollment, tunnel policy, supervision, audit, and rollout remain product-specific.

## Standards and migration boundary

ML-KEM and ML-DSA themselves are NIST standards. OpenSSH 10.4 explicitly describes its composite authentication support as experimental and disabled by default in the [OpenSSH 10.4 release notes](https://www.openssh.com/txt/release-10.4). WarpTweet records that authentication binding as `openssh-vendor-qualified` and does not brand the product itself as experimental.

No draft revision, engine update, algorithm rename, encoding change, security-rule change, or IANA registration mutates an existing profile. Each creates a new profile ID. Migration rules are normative in [2026-08-09_crypto-profile.md](2026-08-09_crypto-profile.md).

## Explicit non-goals

The MVP does not provide:

- arbitrary or unmanaged SSH interoperability;
- interactive shells, remote command execution, SFTP, or SCP;
- dynamic SOCKS forwarding, remote forwarding, agent forwarding, X11 forwarding, or layer-3 tunnels;
- wildcard, LAN-facing, or public local listeners;
- arbitrary destination hosts or ports;
- password, keyboard-interactive, GSSAPI, host-based, classical-only, or trust-on-first-use authentication;
- a general PKI, SSH CA service, DNS SSHFP deployment, hardware-token integration, or private-key escrow;
- a private-key, credential, or secret bundle inside a `.wt` manifest;
- application-layer authentication for programs that can reach the local loopback listener;
- anonymity, traffic-flow confidentiality, endpoint compromise protection, or availability guarantees;
- support for SLH-DSA, pure ML-DSA SSH keys, or alternative hybrid/composite schemes;
- a claim of standardization, FIPS validation, or being quantum-proof.
