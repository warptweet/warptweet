# Cryptographic profile v1

Status axes: authentication binding `openssh-vendor-qualified`; support `published-matrix`; 2026-08-09

## Normative source

The product's normative profile registry is `internal/profile/profile.go`. This document explains that profile but does not override it. If code and documentation differ, the implementation MUST fail validation until a reviewed change makes them agree.

A `.wt` file belongs to the strict JSON WarpTweet Tunnel Manifest family, with media type `application/vnd.warptweet.tunnel+json`. Every kind and schema version selects a profile by exact `profile_id`. The path-free `warptweet.client-tunnels` v1 kind carries the fixed client-engine digest, supervision, server, and one-or-more-tunnel policy. The `warptweet.server-gateway` v1 kind carries restricted server policy plus installed-engine and authenticated OpenSSH plus OpenSSL bundle-manifest digest pins. Neither kind may carry private-key material or executable bytes. Client key and trust paths are fixed installation invariants. The server `host_key_path` is a fixed reference to separately protected key state; a manifest cannot embed ML-DSA or Ed25519 seeds, expanded keys, OpenSSH private-key bytes, passphrases, or agent credentials.

The current immutable profile is:

| Field | Exact value |
| --- | --- |
| Profile ID | `warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519` |
| Engine version | `OpenSSH_10.4p1` |
| OpenSSL version | `3.5.7` |
| Exact OpenSSL version text | `OpenSSL 3.5.7 9 Jun 2026` |
| OpenSSL linkage | `static` |
| Executable format | `ELF` |
| Key exchange | `mlkem768x25519-sha256` |
| Authentication key type | `ssh-mldsa44-ed25519@openssh.com` |
| Cipher preference 1 | `chacha20-poly1305@openssh.com` |
| Cipher preference 2 | `aes256-gcm@openssh.com` |
| Authentication binding status | `openssh-vendor-qualified` |
| Support status | `published-matrix` |

No abbreviation, wildcard, alias, OpenSSH default, or semantically similar algorithm is part of this profile. The authentication key type applies to both server host authentication and managed client public-key authentication in the MVP.

The Go profile registry encodes the immutable engine, OpenSSL, executable-format, linkage, and cryptographic tuple. Product enforcement renders and validates exact client and server algorithm lists, disables compression and alternate authentication, constrains forwarding, validates composite public-key blobs, isolates client trust and identity inputs, re-attests every client launch, and preflights fixed Linux installations and effective configuration. Live KEX and rekey behavior, authenticated-forward readiness, and direct observation of negotiated results remain mandatory release gates rather than profile fields.

## Key exchange

`mlkem768x25519-sha256` combines ephemeral ML-KEM-768 and X25519 results:

```text
K_PQ = ML-KEM-768 shared secret
K_CL = X25519 shared secret
K    = SHA-256(K_PQ || K_CL)
```

The exact SSH construction, fixed-length encoding, transcript inputs, and failure behavior are defined by the IETF SSHM working-group document [draft-ietf-sshm-mlkem-hybrid-kex-10](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-10). ML-KEM itself is standardized in [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203), and X25519 is defined in [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html).

Exact raw sizes are:

| Value | Size |
| --- | ---: |
| ML-KEM-768 public key | 1,184 bytes |
| X25519 public key | 32 bytes |
| Client `C_INIT` | 1,216 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| Server `S_REPLY` | 1,120 bytes |
| ML-KEM-768 shared secret | 32 bytes |
| X25519 shared secret | 32 bytes |
| Combined `K` | 32 bytes |

As of 2026-08-09, the SSHM document is in the RFC Editor queue and the method name appears in the [IANA SSH Key Exchange Method Names registry](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16). It is further advanced than the authentication binding. Support remains limited to the published platform and evidence matrix until every required layer has a stable binding and package-to-package release gates complete.

## Composite authentication

`ssh-mldsa44-ed25519@openssh.com` is a composite signature key. Its components are ML-DSA-44 from [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) and Ed25519 from [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

The OpenSSH 10.4p1 implementation constructs:

```text
public key  = mldsa44_public_key || ed25519_public_key
private key = mldsa44_seed       || ed25519_seed
signature   = mldsa44_signature  || ed25519_signature
```

Exact raw sizes are:

| Value | ML-DSA-44 | Ed25519 | Composite |
| --- | ---: | ---: | ---: |
| Public key | 1,312 bytes | 32 bytes | 1,344 bytes |
| Stored private seed material | 32 bytes | 32 bytes | 64 bytes |
| Signature | 2,420 bytes | 64 bytes | 2,484 bytes |

SSH string framing and the exact type name surround these raw values. OpenSSH 10.4p1 prehashes the SSH message with SHA-512 and applies the composite prefix and `COMPSIG-MLDSA44-Ed25519-SHA512` label before both component signatures. Its ML-DSA signing path uses fresh 32-byte randomness. The exact deployed behavior is visible in the tagged [OpenSSH composite implementation](https://github.com/openssh/openssh-portable/blob/V_10_4_P1/ssh-mldsa-eddsa.c) and [cryptographic constants](https://github.com/openssh/openssh-portable/blob/V_10_4_P1/crypto_api.h).

A signature is valid only when both component verifications succeed. Host and client identities MUST use independently generated composite pairs. Component material MUST NOT be reused as a standalone key or in another composite identity.

The product uses the raw key type only. The OpenSSH certificate variant, classical certificates, standalone ML-DSA keys, and classical-only keys are outside this profile.

## Transport encryption

Both permitted ciphers are authenticated-encryption constructions. A separately selected SSH MAC is not part of the data protection when either is negotiated.

| SSH name | Construction | Standards position |
| --- | --- | --- |
| `chacha20-poly1305@openssh.com` | OpenSSH ChaCha20-Poly1305 with encrypted packet length | Widely deployed vendor-qualified name; the equivalent unqualified binding is an SSHM working-group draft in last call: [draft-ietf-sshm-chacha20-poly1305-04](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-chacha20-poly1305-04) |
| `aes256-gcm@openssh.com` | AES-256-GCM for SSH | OpenSSH name for the AES-256-GCM construction in [RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html); [RFC 9212](https://www.rfc-editor.org/rfc/rfc9212.html) explicitly identifies the OpenSSH name and adds counter guidance |

The listed order is the product preference order. Negotiation of either is acceptable. Negotiation of any other encryption algorithm is a profile violation.

## Authentication binding and support status

The NIST primitive standards do not define SSH authentication key blobs, signature wrappers, negotiation names, agent serialization, OpenSSH certificates, or migration semantics. Implementing FIPS 203 or FIPS 204 does not make an SSH binding standardized and does not make a product FIPS validated.

Keep status axes separate:

| Axis | Profile v1 value | Meaning |
| --- | --- | --- |
| Product | Open-source managed-endpoint tunnelling | Implemented software, not a product-level experimental badge |
| Support status | `published-matrix` | Supported only on the published platform and evidence matrix |
| Authentication binding status | `openssh-vendor-qualified` | OpenSSH vendor-qualified composite authentication name |

The current authentication-binding state is:

- [OpenSSH 10.4 release notes](https://www.openssh.com/txt/release-10.4) call ML-DSA-44 plus Ed25519 support experimental and state that it is disabled by default. That upstream wording is the only permitted product-facing use of the word experimental.
- The deployed name contains `@openssh.com`, which is a locally extensible name under [RFC 4250, section 4.6.1](https://www.rfc-editor.org/rfc/rfc4250.html#section-4.6.1). This is the correct namespace for an unallocated algorithm name.
- The active successor [draft-miller-sshm-composite-sigs-00](https://datatracker.ietf.org/doc/html/draft-miller-sshm-composite-sigs-00) is an individual Internet-Draft. It requests unqualified names including `ssh-mldsa44-ed25519`, but it is not an SSHM working-group document or RFC.
- The [IANA SSH Public Key Algorithm Names registry](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19) does not list an ML-DSA, SLH-DSA, or composite PQ authentication key as of the registry update available on this date.
- Internet-Drafts may change, be replaced, or expire. WarpTweet v1 follows the OpenSSH 10.4p1 implementation identified by the profile, not an automatically moving draft target.

Machine-readable outputs MUST emit `authentication_binding_status` and `support_status`. They MUST NOT emit an ambiguous boolean `experimental` field. WarpTweet MUST NOT be branded experimental as a product. It MUST NOT be marketed as an IETF standard, widely interoperable PQ SSH authentication, quantum-proof, or FIPS validated.

## Fail-closed configuration

Both managed endpoints MUST replace OpenSSH algorithm defaults with exact lists equivalent to:

```text
KexAlgorithms mlkem768x25519-sha256
HostKeyAlgorithms ssh-mldsa44-ed25519@openssh.com
PubkeyAcceptedAlgorithms ssh-mldsa44-ed25519@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
Compression no
```

The server MUST load only the managed composite host key for this service and authorize only managed composite client keys. The client MUST load only its managed composite identity and the exact preprovisioned composite host-key pin. Ambient config, default identity discovery, trust on first use, `UpdateHostKeys`, DNS-based trust, and shared agents are disabled.

Policy rendering is not sufficient proof. Client `doctor` checks the fixed root-owned Linux executable and state ancestry, stable digest and metadata, ELF linkage without dynamic libcrypto or libssl and without RPATH or RUNPATH, exact `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026` version output, required algorithms, fixed trust inputs, exact local-forward arguments, effective closed arguments, and the deterministic `LANG=C`, `LC_ALL=C` process environment. Linux `doctor-server` checks the fixed installed bundle, source receipt, keys, authorization, rendered bytes, and effective server configuration. Both report `preflight_ready` without connecting. `run` adds a PID-bound authenticated-forward readiness witness. A supported release MUST still prove that negotiated KEX, host key, client key, cipher, and every rekey match the profile across both managed endpoints.

## Packet and resource rules

The profile's KEX, public keys, and signatures fit within the minimum SSH packet sizes required by [RFC 4253, section 6.1](https://www.rfc-editor.org/rfc/rfc4253.html#section-6.1). This does not authorize generic large packets.

- Parse every fixed-size value at its exact size.
- Check the complete hybrid input length before KEM work.
- Reject wrong inner algorithm names, truncated components, overlong components, and trailing bytes.
- Bound pre-authentication connections, authentication attempts, packet buffers, channels, rekeys, and logs.
- Preserve strict KEX behavior for initial exchange and rekey.
- Treat resource-limit exhaustion as connection failure, never as a reason to choose a cheaper classical algorithm.

[SLH-DSA SSH proposals](https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-sphincs-02) and any future algorithm with signatures near or above SSH's 32,768-byte mandatory payload floor require a new profile and denial-of-service analysis.

## Profile and key migration

An immutable profile is a compatibility and security contract. Any change to an engine version, OpenSSL version or version text, executable format, linkage rule, SSH name, component algorithm, parameter set, encoding, domain separation, signature context, hash, cipher list, verification rule, or required product invariant creates a new profile ID.

Migration follows these rules:

1. Never edit the meaning of a released profile ID.
2. Never enable an unallocated bare algorithm name merely because it appears in an Internet-Draft.
3. Treat a future IANA-allocated authentication name and final RFC encoding as a new profile, even if they resemble the current OpenSSH vendor-qualified form.
4. Generate new host and client composite key pairs for the new profile. Do not relabel or reuse old component seeds.
5. Remember that the SSH public-key blob contains the algorithm name. A name change changes the blob and its SHA-256 digest, so trust and authorization must be rebound explicitly.
6. Stage the new engine and profile on both managed endpoints, publish new host pins and client authorization, and prove exact interoperability before activation.
7. During a managed overlap, every accepted profile must independently require approved PQ/classical hybrid KEX and composite authentication. A classical-only bridge is forbidden.
8. Prefer the new profile only after both endpoints and desired state are ready. There is no opportunistic per-connection downgrade.
9. Confirm successful operation under the new profile, then revoke the old key blobs and remove the old profile from accepted policy.
10. Rollback, if required, returns to a still-approved immutable PQ-required profile and its distinct keys. It never returns to classical-only SSH.

The v1 registry currently exposes only one profile. Supporting a transition window is future functionality and must be explicit, bounded, tested, and auditable rather than implemented through OpenSSH defaults. A `.wt` migration changes profile and path policy references only; private keys remain separate endpoint-managed files throughout the migration.

## New-profile acceptance gates

A proposed successor profile is not accepted until it has:

- a stable primary specification and correctly allocated names where applicable;
- exact encodings, limits, domain separation, contexts, and error behavior;
- a reviewed, constant-time cryptographic implementation from an accountable source;
- deterministic and randomized test vectors plus malformed-input vectors;
- two independently maintained interoperable SSH implementations;
- client, server, keygen, agent or key-store, known-hosts, authorization, rekey, and forwarding tests;
- fuzzing and denial-of-service results for all new parsers and maximum-size paths;
- an endpoint key migration and revocation procedure;
- product claim review that preserves typed authentication-binding and support status without product-level experimental branding.
