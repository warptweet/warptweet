# Managed local-forward threat model

Status: MVP threat model, 2026-08-09

## Security objective

WarpTweet's release objective is to protect the confidentiality and integrity of traffic between two managed endpoints against passive and active network attackers, while mutually authenticating those endpoints with the exact Profile v1 cryptographic contract. It exposes only one authorized TCP local-forward path. The current local preflight evidence does not yet demonstrate this end-to-end objective.

The objective is conditional on the security of both endpoints, their key lifecycle, the OpenSSH 10.4p1 implementation, the configured target service, and the component cryptographic assumptions. Support is limited to the published platform and evidence matrix. WarpTweet is not described as quantum-proof or FIPS validated.

## Protected assets

- Application data crossing the SSH transport.
- Integrity and destination binding of each forwarded connection.
- Managed server host identity.
- Managed client or device identity.
- ML-DSA-44 and Ed25519 private signing seeds.
- Configuration, authorization, trust pins, profile ID, and rollout state.
- Kind-versioned WarpTweet Tunnel Manifest policy and engine provenance pins.
- Audit evidence for issuance, activation, rotation, revocation, connection, and policy failure.
- Service availability, as a best-effort operational property rather than a cryptographic guarantee.

## Trust boundaries and assumptions

The model assumes:

- Client and server operating systems, privileged supervisors, and installed WarpTweet/OpenSSH artifacts are not compromised.
- Enrollment authenticates the endpoint and delivers public-key pins and policy without substitution.
- The operating system CSPRNG is sound.
- ML-KEM-768, X25519, ML-DSA-44, Ed25519, SHA-256, SHA-512, ChaCha20-Poly1305, and AES-256-GCM meet their intended security properties.
- The hybrid and composite constructions and their OpenSSH implementations are correct and do not leak private material through side channels.
- The configured target service is the intended service and the server-to-target plaintext path is within the trusted deployment boundary.
- All local users and processes able to reach the loopback listener are trusted, unless a platform firewall or equivalent control isolates the listener to the service identity.
- Operators can revoke and replace endpoint keys through an authenticated, durable desired-state mechanism.

If any of these assumptions fails, the tunnel may no longer meet its confidentiality or authentication objective.

## Manifest trust boundary

A `.wt` file belongs to the strict JSON WarpTweet Tunnel Manifest family with media type `application/vnd.warptweet.tunnel+json`. It is untrusted input until its UTF-8, size, single-object shape, `kind`, kind-specific `schema_version`, complete field set, canonical field names, value constraints, profile ID, path policy, and endpoints have been validated. Unknown or non-canonical fields, duplicate object member names, and trailing JSON values are errors.

The `warptweet.client-tunnels` v1 kind validates the fixed client executable digest, managed server, supervision policy, and one or more tunnel declarations. It contains no filesystem paths. The `warptweet.server-gateway` v1 kind validates one server listener, target, dedicated user, fixed `host_key_path` and authorized-keys path, installed `sshd` digest, and authenticated OpenSSH plus OpenSSL bundle-manifest digest. Neither manifest embeds an executable or private key.

Both kinds contain policy metadata only. They MUST NEVER contain private-key bytes, ML-DSA or Ed25519 seeds, passphrases, agent credentials, or other secret material. Client identity and trust paths are fixed installation invariants. The server `host_key_path` is a fixed reference to separately permissioned local key state, not inline key material and not permission to disclose it. Logs, validation errors, diagnostics, support bundles, and manifest export MUST NOT read or reproduce private-key contents.

The manifest is not secret-key material, but it reveals operational metadata and controls security behavior. Unauthorized read access can disclose topology. Unauthorized write access can redirect a listener or target, select a path, or alter supervision. The file therefore requires authenticated distribution, restrictive permissions, atomic activation, rollback protection, and audit by content digest and activation generation.

## Current evidence boundary

The implemented controller proves strict manifest decoding, exact profile selection, deterministic policy and public-key-entry rendering, the fixed Linux client executable and state layout with root-owned protected ancestry, stable executable digest and metadata, held-file ELF inspection, static OpenSSL linkage without RPATH or RUNPATH, exact OpenSSH and OpenSSL version output, required client algorithm availability, fixed identity and trust-file constraints, composite host-pin structure, effective closed client arguments, and a two-variable deterministic process environment. Client `doctor` reports this state as `preflight_ready`.

On Linux, installed-server `doctor-server` additionally proves the fixed root-owned `sshd`, helper and `ssh-keygen` files, authenticated bundle membership and source receipt, exact engine version, host-key metadata and derived composite public key, one canonical target-bound client authorization, byte-for-byte rendered server configuration, and effective `sshd -T` policy. The WarpTweet controller never reads, hashes, serializes, or logs host private-key bytes; the bundled `ssh-keygen -y` subprocess reads the key only to derive its public key.

Neither preflight status proves a network connection, server host authentication by a remote client, client authentication by the server, negotiated algorithms, rekey behavior, Linux service confinement, or resistance to live network and resource attacks. `run` has a separate PID-bound witness for authenticated transport and local-listener creation, but that implementation still requires live Linux release evidence and never claims target health. A process being alive is not evidence that the security objective is met.

## Adversaries

The model includes:

- A passive network observer recording traffic for later cryptanalysis.
- An active network attacker who intercepts, injects, reorders, truncates, replays, or drops SSH packets.
- A malicious or misconfigured peer offering weaker algorithms.
- An unauthenticated remote attacker consuming pre-authentication CPU, memory, sockets, or bandwidth.
- An authenticated but constrained client attempting unauthorized destinations or SSH channel types.
- A local unprivileged process attempting to use or disrupt the loopback listener.
- An attacker who steals a private-key file or stale authorization snapshot.
- A supply-chain attacker attempting to substitute the engine, configuration, or cryptographic profile.

## Threats and controls

| Threat | Required control | Residual risk |
| --- | --- | --- |
| Harvest now, decrypt later | Require `mlkem768x25519-sha256` for initial KEX and every rekey | A future break in both ML-KEM-768 and X25519, or an implementation failure, defeats the hybrid assumption |
| Active man-in-the-middle | Pin the exact composite host-key blob; require both ML-DSA-44 and Ed25519 verification; authenticate the KEX transcript | Compromised provisioning or host private keys defeat server authentication |
| Client impersonation | Authorize only the exact managed composite client key; disable all other authentication methods | Theft of both component seeds, or signing access to the managed key, enables impersonation until revocation |
| Algorithm downgrade | Replace algorithm lists with exact allow-lists, verify effective configuration and negotiated results, and never retry with a weaker profile | An enforcement bug in the wrapper or engine can violate the invariant |
| Component substitution | Parse fixed lengths, reject trailing data and wrong inner names, and bind the full SSH key blob to the principal | Draft churn can introduce incompatible encodings, which requires a new profile |
| Signature-component failure | Composite verification succeeds only if both component verifications succeed; component keys are never reused | The security argument depends on the composite construction and its implementation |
| Replay | Rely on the SSH session identifier, exchange hash, sequence numbers, and signed user-auth request defined by [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html) and [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) | Replay inside a compromised endpoint is outside the network model |
| Unauthorized forwarding | Bind each principal to exact `direct-tcpip` destination values; reject all other channel and forwarding types | The target can expose additional capability after the authorized TCP connection is established |
| Local listener exposure | Bind exactly `127.0.0.1`, add a platform firewall where local users are not mutually trusted, and close the listener on loss of SSH policy | Loopback TCP does not identify the calling process; without an OS control, any local process may connect |
| Key theft at rest | Restrictive ownership and modes, isolated key paths, no ambient agent, atomic provisioning, and rapid revocation | File protection does not resist a compromised privileged account or live memory capture |
| Malicious `.wt` manifest | Strictly decode one bounded JSON object, reject unknown fields, authenticate desired state, validate every field, pin the profile ID and engine version, and record activation generations | A compromised management authority remains authoritative |
| Secret smuggling through manifest | Define `.wt` as policy metadata only; remove client key and trust paths; reject secret-bearing fields; never dereference fixed key paths for logging, export, or diagnostics | A compromised endpoint can still read its local key according to OS permissions |
| Engine substitution | On Linux, require fixed root-owned protected paths for both engines; retain and reverify client ancestry; hash, inspect, and rehash the held client executable; require exact OpenSSH and OpenSSL version output and static ELF linkage; re-attest before every launch; verify the server bundle, receipts, helpers, and effective policy before start or reload | The final path-to-exec interval still relies on root-owned protected production paths; a compromised build, root account, kernel, or privileged runtime can falsify checks |
| Client-state substitution | Remove caller-selected paths and generated configuration; execute with `-F none`; require fixed root-owned manifest, identity, and trust files with descriptor-anchored ancestry, exact metadata, no ACLs, and content rechecks | A compromised root account, kernel, or service credential can still use or replace endpoint state |
| Readiness spoofing | Validate and remember the one-shot control-socket inode, require the exact `ssh -O check` PID to match the foreground child, revalidate the same inode and pathname through the retained directory descriptor, unlink it relative to that descriptor, verify absence, close the descriptor anchor, and require the child to remain alive before Ready | A compromised service UID can interfere with its own transient runtime directory and is treated as endpoint compromise |
| Traffic analysis | None in the MVP beyond normal SSH packet encryption | Addresses, connection timing, duration, direction, and approximate volume remain observable |
| Availability attack | Apply bounded parsing, rate limits, connection and channel caps, authentication limits, deadlines, and backoff | A network attacker can always drop traffic or saturate upstream capacity |

## Fail-closed threat cases

The following events are required to terminate connection establishment or an active tunnel in a supported release. The controller prevents locally configured fallback and observes authenticated local-forward readiness, but it does not yet observe negotiated results or rekey directly:

- the peer does not offer the exact required hybrid KEX;
- the server does not present the pinned composite host-key type and blob;
- either component of a host or client signature fails verification;
- the client cannot authenticate with the managed composite key;
- negotiation selects a cipher outside the profile;
- the engine version or effective configuration differs from the profile;
- the `.wt` manifest is oversized, malformed, has unknown or duplicate fields or trailing values, selects an unsupported kind/schema/profile, or attempts to contain private-key material;
- the local bind is not exactly `127.0.0.1` or the requested destination differs from policy;
- the authenticated-forward witness fails, cannot bind the reported PID to the child, cannot revalidate the same socket inode and pathname, cannot unlink that pathname through the retained descriptor, cannot prove its absence, cannot close the descriptor anchor, or observes that the child exited before Ready;
- rekey does not preserve the same KEX, authentication, and cipher requirements;
- a packet is malformed, has an unexpected length, contains trailing data, or creates unreasonable resource demand;
- authorization state is missing, stale beyond policy, revoked, or only partially installed.

The implementation MUST NOT reconnect using a classical-only algorithm after any such failure. Direct controller supervision can retry the same profile without a count limit and caps retry frequency with bounded exponential backoff. The packaged service uses `run --once`; systemd restart limits own the operational circuit breaker and alert boundary.

## Packet and denial-of-service analysis

[RFC 4253, section 6.1](https://www.rfc-editor.org/rfc/rfc4253.html#section-6.1) requires SSH implementations to process uncompressed payloads through 32,768 bytes and total packets through 35,000 bytes. The current profile remains below that interoperability floor:

- ML-KEM-768 contributes a 1,184-byte public key and 1,088-byte ciphertext. With X25519, the hybrid `C_INIT` and `S_REPLY` values are 1,216 and 1,120 bytes respectively.
- The composite authentication key has a 1,344-byte raw public key.
- The composite signature is 2,484 bytes: 2,420 bytes for ML-DSA-44 and 64 bytes for Ed25519.

These values come from the [OpenSSH 10.4p1 cryptographic constants](https://github.com/openssh/openssh-portable/blob/V_10_4_P1/crypto_api.h) and the [ML-KEM SSH specification](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-10). SSH string and packet framing add overhead but do not approach the mandatory floor for this profile.

Being below the packet limit does not make parsing cheap or safe. The implementation MUST:

- reject a hybrid KEX input unless its length is exactly the sum required by the negotiated method before encapsulation or decapsulation, as required by the ML-KEM SSH draft;
- reject a composite key or signature unless every fixed-length component and inner algorithm name is exact;
- reject trailing bytes rather than ignoring them;
- cap identification lines, packets, pending output, unauthenticated connections, authentication attempts, channels, forwarding requests, and log volume;
- place deadlines around version exchange, KEX, authentication, forwarding setup, idle policy, and shutdown;
- rate-limit by source and principal while preserving global capacity;
- perform cheap structural and authorization checks before expensive cryptographic work where protocol ordering permits;
- keep pre-authentication processes sandboxed and least-privileged;
- require strict KEX behavior and reject non-KEX traffic during key exchange;
- close a connection that attempts repeated rekeys or channel creation outside policy;
- bound restart frequency and resource use; the current controller does not bound total restart count, so deployment policy must supply a circuit breaker where required.

OpenSSH 10.4 includes additional handling for non-KEX messages during post-authentication rekey and several denial-of-service fixes, documented in its [release notes](https://www.openssh.com/txt/release-10.4). Pinning the release does not replace deployment-level resource controls.

SLH-DSA is outside the profile. The parameter sets in the individual [SLH-DSA SSH proposal](https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-sphincs-02) include signatures larger than the SSH mandatory packet floor, which creates a materially different packet and denial-of-service problem. Adding it requires a new threat review and profile.

## Key compromise and recovery

Compromise is defined at the composite identity level. Either component being exposed is a security incident even though forging the composite normally requires both.

On suspected exposure:

1. Stop new connections for the affected identity.
2. Revoke the exact public-key blob and activation generation.
3. Generate an entirely new ML-DSA-44 and Ed25519 component pair on the endpoint.
4. Provision new authorization and pins atomically.
5. Re-establish the tunnel under the same or a newly approved profile.
6. Destroy superseded private material where the platform permits and retain audit evidence.

The product MUST NOT keep one uncompromised component and combine it with a new component. Component reuse across composite identities is forbidden by the current [composite SSH draft](https://datatracker.ietf.org/doc/html/draft-miller-sshm-composite-sigs-00#section-5).

## Out-of-scope threats

The MVP does not protect against:

- a compromised client, server, supervisor, root account, kernel, or target service;
- malicious application data accepted by the target protocol;
- theft of plaintext before tunnel entry or after tunnel exit;
- traffic analysis or endpoint discovery;
- denial of service through packet dropping, route withdrawal, or capacity exhaustion;
- a malicious management authority or compromised release-signing process;
- coercion, physical attacks, or side channels not addressed by the packaged cryptographic implementation;
- local process-level authorization on a shared loopback interface;
- future cryptanalytic breaks in the required primitives or composite/hybrid constructions.

These exclusions must remain visible in product claims and operational guidance.
