# Linux server packages and bootstrap

Status: package recipes and server admin CLI, 2026-08-12

## Package assembly

```sh
./scripts/build-linux-packages.sh \
  /absolute/path/to/openssh-stage \
  /absolute/path/to/warptweet \
  /absolute/path/to/new-output-directory
```

The output tree contains:

- fixed `/opt/warptweet` inventory from the authenticated OpenSSH stage
- controller at `/opt/warptweet/bin/warptweet`
- systemd units `warptweet-sshd.service`, `warptweet-enroll.service`, and
  `warptweet-tunnel@.service`
- empty invite/client/state directories under `/var/lib/warptweet`
- `control` metadata for `dpkg-deb`
- `warptweet.spec` for RPM-family release automation
- `postinst` / `prerm` maintainer scripts

When `dpkg-deb` is available, a `.deb` is produced. Maintainer scripts create
`warptweet`, `warptweet-client`, and `warptweet-sshd` system accounts, lock the
tunnel account with the public-key-only `*NP*` sentinel where supported, and
reload systemd units. Scripts never download packages or contact the network.

## Server bootstrap CLI

```text
warptweet server init --listen <ip:port> --target <ip:port>
warptweet server invite --target <ip:port> --name <name>
warptweet server enroll-listen [--listen ip:port]
warptweet server accept-enrollment --request <request.json>
warptweet server revoke <client-or-invite-id>
warptweet server status
warptweet gateway --to <port|ip:port>
```

### `server init`

- Generates a composite host key with the bundled `ssh-keygen -t mldsa44-ed25519`
- Writes the public key beside the private key
- Creates a server-local invite MAC secret at `/etc/warptweet/invite.mac-key`
- Writes `/etc/warptweet/server.wt` for the fixed layout
- Prints host public-key SHA-256 without exporting private bytes

### `server invite`

Creates one single-use, short-lived invite bound to:

- server listen endpoint
- exact authorized target
- dedicated principal
- wire `profile_id` and platform `artifact_profile_id`
- host public key line
- issuance time, expiry, nonce, and HMAC

Invites never contain private keys, passwords, or reusable bearer tokens. Server
state is stored under `/var/lib/warptweet/invites`.

### `server revoke`

Revokes an invite by id when present; otherwise clears the managed
`authorized_keys` file transactionally.

### `server status`

Reports manifest presence, host-key presence, listen/target, enroll URL/port,
invite counts by status, and enrolled client counts by status.

### `server enroll-listen` / `warptweet-enroll.service`

HTTP control plane on the invite `enroll_port` (default **29722**):

- `POST /v1/enroll` — consume single-use invite, install `authorized_keys`
- `POST /v1/rotate` — replace client key with management-token auth
- `POST /v1/revoke` — clear authorization with management-token auth

Package install enables `warptweet-enroll.service`. It starts successfully only
after `server init` (or `gateway`) has written `server.wt`, the host key, and
`invite.mac-key`. Operators may also run `systemctl start warptweet-enroll`
after bootstrap. `gateway` can start a detached listener for unpackaged labs;
packaged hosts should prefer the unit.

### `server accept-enrollment`

One-shot offline accept for air-gapped operators (writes proof JSON to stdout).

## Activation invariant

Authorized-key and invite state updates use temp file, fsync, rename, parent
fsync. A failed preflight leaves the prior active generation unchanged when
service reload is gated by `doctor-server` in the systemd unit.

## Evidence boundary

These recipes and commands are not evidence that a signed `.deb`/`.rpm` was
published or that two-endpoint package install succeeded. Hosted package
interop remains a later release gate.
