# Public release convergence

This document defines the implementation contract for moving WarpTweet from
reviewable source and lab artifacts to the first supported package release. It
does not itself establish release evidence.

## Public product contract

The public two-command path is:

```text
warptweet host --to <port|ip:port> --name <client-label>
warptweet connect <label>.wtinvite
```

`host` is the only public server bootstrap verb. The unreleased `gateway` verb
is removed rather than retained as an alias. Operator commands under `server`
remain available for diagnostics and recovery.

The server manifest kind remains `warptweet.server-gateway` v1. That value is a
versioned machine contract and is not the public CLI noun. Renaming it would add
an unrelated manifest migration without improving the product workflow.

Invite basenames remain human labels with type in the extension:

```text
studio-mac.wtinvite
studio-mac-a13f.wtinvite   # collision only
```

## Trust boundaries

The SSH data plane remains the immutable Profile v1 contract.

Enrollment, rotation, and revocation MUST use TLS 1.3 with the exact hybrid
`X25519MLKEM768` key exchange and a server enrollment identity pinned by the
invite. Plain HTTP and redirect following are forbidden. The TLS certificate
may use Ed25519 because the out-of-band invite pins its exact SPKI. This control
plane does not replace or weaken the composite SSH host and client identity
contract.

The invite is a short-lived confidential capability. It contains no private
key, but possession authorizes one enrollment and therefore it MUST be handled
like a secret until consumed or expired.

The network listener and privileged authorization writer SHOULD be separate
processes. If the first supported package retains one process, it MUST remain
root-confined, bounded, deny by default, and tracked as an explicit remaining
privilege-separation release gap rather than silently described as least
privilege.

## Enrollment and access authority

The durable client registry and the effective OpenSSH authorization file are
one logical authority. Mutations MUST be serialized and restart-recoverable.

Enrollment states:

```text
issued -> enrollment_pending -> active
```

Rotation states:

```text
active -> rotation_pending -> active
```

Revocation states:

```text
active -> revocation_pending -> revoked
```

The client generates its management capability locally and sends it only over
the pinned TLS channel. The server stores only its digest. An exact retry of an
interrupted request MUST be idempotent and return the same committed outcome.
A conflicting retry MUST fail closed.

Recovery MUST reconcile every pending state before the enrollment service is
ready. Revocation MUST remove effective SSH authorization before it reports
success. No state may say `revoked` while the corresponding key remains
authorized.

## Readiness authority

Only the PID-bound authenticated-forward event produced by `run` establishes
client readiness. `up`, `connect`, lifecycle state, interop evidence, and
service-manager notification MUST all derive from that event. Elapsed time and
process survival are never readiness evidence.

`host` is ready only after:

1. fixed server identity and policy are installed;
2. the pinned TLS enrollment listener is accepting connections;
3. the confined OpenSSH listener has passed preflight and is listening;
4. the invite was durably written, unless `--no-invite` was selected.

An empty managed `authorized_keys` file is a valid bootstrap state: public-key
authentication remains required and therefore no client can authenticate.

## Platform ownership

Linux packages own system files as root and provision the exact service
accounts and units. Package assembly MUST normalize archive ownership and the
installed package database MUST be verified.

The macOS installer performs the only interactive administrator authorization.
After installation, a typed privileged helper activates root-owned client state
and manages the `_warptweet` LaunchDaemon. It MUST accept no shell text,
arbitrary destination path, OpenSSH option, or service fragment. Runtime
`connect`, `up`, `status`, and `down` MUST not require repeated administrator
password entry.

## Release evidence

The website install command remains disabled until evidence is bound to the
published source commit and exact package digests. Required evidence includes:

- signed and notarized macOS package installation on a clean supported Mac;
- signed Linux package or signed repository metadata installation on a clean
  supported server;
- package-only `host -> invite -> connect` with no source-tree substitution;
- pinned encrypted enrollment and exact invite retry/failure behavior;
- actual PID-bound readiness before deterministic payload transit;
- restart, interruption, rotation, revocation, and upgrade recovery;
- the positive and negative Profile v1 checklist for the declared support
  matrix;
- SBOM, provenance, checksums, signatures, uninstall, and rollback evidence.

No skipped, suppressed, `not_run`, lab-elevated, direct-`sshd`, or manually
repaired package case can enable the public Homebrew CTA.
