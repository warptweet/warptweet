# Linux host packages and bootstrap

Status: package and `host` contracts implemented in source, 2026-08-15

## Package assembly

```sh
./scripts/build-linux-packages.sh \
  /absolute/path/to/openssh-stage \
  /absolute/path/to/warptweet \
  /absolute/path/to/new-output-directory
```

The output tree contains the fixed `/opt/warptweet` engine, controller,
authenticated receipts, systemd units, and maintainer scripts. Debian assembly
uses `dpkg-deb --root-owner-group`; installed package verification must still
prove the package database, file ownership, modes, signatures, and exact
artifact digests on a clean host.

System-account creation is an installation-time contract: maintainer scripts
create `warptweet`, `warptweet-client`, and `warptweet-sshd` system identities
and reload systemd. They do not contact the network. Package installation alone
does not open a WarpTweet listener.

## Public bootstrap

The only public host bootstrap is:

```text
warptweet host --to <port|numeric-ip:port> [--name <client-label>]
```

`host` performs one convergent operation:

1. generates or reuses the composite host identity through the bundled
   `ssh-keygen -t mldsa44-ed25519`;
2. creates the pinned TLS 1.3 enrollment identity (no invite MAC key);
3. writes the fixed server manifest and an initially empty managed
   `authorized_keys` file;
4. reconciles pending client authorization state;
5. renders and preflights the restricted `sshd` configuration;
6. starts the packaged `warptweet-sshd.service` and requires the declared TCP
   listener, or uses the same pinned direct process only in an unpackaged lab;
7. starts `warptweet-enroll.service` and requires its pinned-TLS endpoint; and
8. writes one single-use `<label>.wtinvite`, unless `--no-invite` was selected.

Host output reports `local_listener_ready`, `published_endpoint_configured`,
and `external_reachability_unverified` after both bind listeners accept. There is no
public flag that bypasses enrollment readiness. A port-only target is local to
the host, so `--to 5432` means `127.0.0.1:5432`.

## Invite and enrollment contract

The `.wtinvite` binds the exact host public key, enrollment TLS SPKI pin,
server endpoint, target, principal, wire profile, artifact profile, expiry,
nonce, and single-use MAC. It contains no private key or reusable management
capability and is mode 0600 because possession authorizes one enrollment.

Enrollment, rotation, and revocation use TLS 1.3 with the invite-pinned Ed25519
SPKI and hybrid `X25519MLKEM768` key agreement. The client generates the
management capability locally; the server stores only its SHA-256 digest.

The packaged enrollment listener is an internal service surface:

```text
warptweet server enroll-listen [--listen numeric-ip:port]
warptweet server accept-enrollment --request <request.json>
warptweet server revoke <client-or-invite-id>
warptweet server status
```

It implements `POST /v1/enroll`, `/v1/rotate`, and `/v1/revoke`. Client and
authorization mutations are journaled as pending before effective
`authorized_keys` changes, reconciled on restart, and idempotent for exact
retries. Empty `authorized_keys` is a valid pre-enrollment state while
public-key authentication remains mandatory.

`server enroll-listen` exists for the packaged unit. `server init` and
`server invite` are deliberately rejected; callers use `warptweet host` so
identity, policy, both listeners, and invite output cannot drift into separate
operator steps.

## Evidence boundary

Source assembly does not prove a published package. Release evidence must bind
signed repository metadata or package signatures, exact package digests,
root-owned installed files, both systemd listeners, package-only
`host -> connect`, encrypted enrollment, readiness, payload, lifecycle
recovery, negative policy cases, uninstall, and rollback on clean amd64 and
arm64 hosts in the declared matrix.
