# Use cases, operator quickstart, and product roadmap

This note is product and design guidance. It is not package-to-package release
evidence. The five-minute command path remains
`docs/2026-08-16_product-quickstart.md`. The release contract remains
`docs/2026-08-16_adoption-and-release-strategy.md`.

WarpTweet's job is one named local TCP socket to one exact remote TCP
service, with both endpoints, both identities, and the engine under the same
operator. It is not a VPN, a mesh, or a general SSH login.

## Ideal use cases

These are the jobs WarpTweet should win. Each one needs a single destination,
not a network.

### Remote Compose Postgres

Publish Postgres only on the host loopback. Developers and agents query
`localhost:15432` on a laptop. The database never listens on a public NIC.
Database credentials stay in the app or secret store. WarpTweet only carries
the socket.

### Private TCP API or admin port

Reach an internal HTTP API, Redis, or admin UI that must not be published.
The client gets one port. There is no SOCKS, no subnet, and no shell on the
host.

### Agent-scoped access

Give an agent or CI job a database or API socket, not SSH to the box.
WarpTweet restricts the tunnel destination and does not grant an SSH shell
or host filesystem access. The agent can still break the app credential.
The exposed service's own network or authorization behavior may permit
SSRF or other pivot paths.

### Durable staging route

Enroll once. `unless-stopped` restores the listener after reboot until the
host grant expires. `manual` and `down` stay down. Expired grants do not
renew themselves.

### Second independent client to the same target

A second laptop or agent gets its own invite, identity, and listen port. No
shared private key. Revoking one client does not revoke the other.

### Break-glass host access stays outside WarpTweet

If someone still has root or unrestricted SSH on the host, that is a
separate, logged, human path. WarpTweet must not become that path. Mixing
them collapses the boundary.

## What WarpTweet is not

- A replacement for Tailscale, WireGuard, or a site VPN
- A jump host, bastion shell, or `ssh user@host`
- Ingress from the public internet to a service
- Automatic grant renewal or silent port reassignment
- A place to store database passwords

## Quickstart for a developer

Goal: query a remote loopback service as if it were local.

1. Ask the host operator for a `.wtinvite` and the intended local port.
2. Install the client package for your Mac architecture. After install,
   `warptweet` is on `PATH` via `/usr/local/bin`.
3. Connect with flags first:

```sh
warptweet connect --yes --listen-port 15432 --restart unless-stopped staging-db.wtinvite
warptweet status --json staging-db
```

4. Point the app at `127.0.0.1:15432`. Example:

```sh
psql "host=127.0.0.1 port=15432 dbname=app"
```

5. Day to day:

```sh
warptweet routes --json
warptweet down staging-db
warptweet up staging-db
warptweet revoke staging-db
```

Invites last 15 minutes and are single-use. The grant is a separate default
of 30 days. Stopping a route is not revocation. If `connect` says the invite
expired, ask for a new invite. Do not reuse a consumed invite.

## Quickstart for a network or systems administrator

Goal: publish one service on host loopback and grant named clients access.

### Host layout

| Tree | Role |
| --- | --- |
| `/opt/warptweet` | immutable package |
| `/etc/warptweet` | `server.wt`, `sshd_config`, policy, enrollment TLS |
| `/var/lib/warptweet` | host keys, `authorized_keys`, grants, invites, sessions |
| `/run/warptweet` | sockets and pid |

### First host

On Linux, after the host package is installed:

```sh
# Compose or the service must bind only loopback
#   ports: ["127.0.0.1:5432:5432"]

warptweet host --to 127.0.0.1:5432 --name staging-db --access-for 30d
```

That starts the data-plane listener (default 2222) and enrollment TLS.
Use the exact enrollment port printed by `warptweet host`, or configure a
fixed enrollment port first and open that value. Copy the invite to the
client out of band.

Open only those two host ports plus whatever you already use for package
and SSH administration. Restrict both listeners to known client or
administrator source networks. Do not publish 5432. If either listener
must face the Internet, require matching source ACLs and monitoring on
the upstream security group or equivalent. Do not treat an unrestricted
allow as the default.

```sh
ufw allow from 192.0.2.0/24 to any port 2222 proto tcp comment 'warptweet data plane'
ufw allow from 192.0.2.0/24 to any port "$ENROLL_PORT" proto tcp comment 'warptweet enroll'
```

Replace `192.0.2.0/24` with the client or administrator networks. Set
`ENROLL_PORT` to the printed enrollment TLS port.

Confirm with `ss -lntp` and a cloud security group if one exists.

### Ongoing host work

```sh
warptweet host --to 127.0.0.1:5432 --name other-client --access-for 30d
systemctl status warptweet-sshd warptweet-enroll
journalctl -u warptweet-sshd -u warptweet-enroll -n 50
```

A target change is refused while any invite or grant exists. That is
intentional. Revoke every affected grant before retargeting.

`doctor-server` is read-only. enroll owns grant writes. sshd must be able to
read `authorized_keys` and drop to the privsep user. Do not re-enable
`NoNewPrivileges` on `warptweet-sshd`.

Ordinary package uninstall keeps identity. On macOS, `brew uninstall --zap`
is the destructive path once the tap exists.

### Prove a socket without Postgres

On the host:

```sh
printf 'warptweet-ok\n' | ncat -l 127.0.0.1 5432
```

On the client:

```sh
nc -v 127.0.0.1 15432
```

## Shell on the host: do not put it in WarpTweet

A full machine-management platform is a real product. It is a different
product.

WarpTweet's value is that the client is not a user on the host. Adding
shell, exec, SFTP, or a multiplexed control channel to the same grant would
undo that. An agent that only has `localhost:15432` cannot become an agent
that also has a root shell without a new, explicit authority.

Preferred shape:

| Product | What it grants | How it attaches |
| --- | --- | --- |
| WarpTweet | one TCP destination | current protocol and packages |
| A later control product | shell, files, or inventory | its own identity, audit, and install; may reuse the invite/enrollment *idea*, not the data-plane grant |

If the control product needs a socket to the host, it should be a second
named WarpTweet route to a dedicated, narrowly bound local service, not
OpenSSH `session` on the WarpTweet sshd. Do not open `ForceCommand`, a
shell, or SFTP on the WarpTweet data plane.

A single "do everything" binary is easier to demo and harder to trust.

## Roadmap ideas that stay inside the product

Sizing is productivity points, not calendar time. 1 is a small, isolated
change. 8 is a full subsystem.

### Finish the first supported release (8)

Close the remaining package matrix, signed artifacts, and v2 evidence.
Until that is `pass`, keep the public CTA dark. This is the current critical
path.

### Operator polish on the existing verbs (3)

Flags after the invite path. `warptweet` on `PATH` from every package.
Clearer `status` when the job never reached sshd. Tunnel logs on by
default. These do not change the security model.

### Host package and unit contract (5)

Ship `/etc` vs `/var/lib` layout, grant socket lifetime, `CAP_SYS_PTRACE`
on enroll, readable `authorized_keys` ancestry, and sshd config path in the
`.deb` itself so operators do not need drop-ins. This is still WarpTweet,
just packaged as designed.

### Grant and session authority (5)

Terminate every generation on revoke and expire. Reap crashed session
records. Make RuntimeDirectory ownership so sshd restart cannot delete the
grant socket. Keep the post-auth hook fail-closed.

### Second client and second route as first-class demos (3)

Documented Compose plus two invites, two listen ports, independent
revoke. This is already the intended product. It needs evidence and copy,
not a new protocol.

### Read-only host status for operators (2)

A `warptweet server status` that shows grant count, clock state, listener
ports, and whether the grant socket is live, without opening a shell.

### Invite and grant UX (2)

Printed remaining invite TTL. Explicit "consumed, ask for a new invite"
copy. Optional `--proof` path for air-gapped enroll. No silent retry.

## Roadmap ideas that should stay out, or stay adjacent

- **In-process shell or exec.** Reject for WarpTweet. Consider only as a
  separate product.
- **Subnet, wildcard, or SOCKS.** Reject. That is a VPN.
- **Automatic grant renewal.** Reject. New invite, new generation.
- **Windows client or extra host OS.** Possible later. Each platform is a
  new package matrix, not a flag.
- **Multi-target host.** Possible later as multiple named host instances or
  multiple grants with distinct targets after an explicit migration. Do not
  reinterpret existing grants.
- **Public Homebrew core.** Only after the first-party tap and v2 evidence.

## Suggested sequence

See `docs/2026-08-18_hardening-sequence.md` for the four hardening steps.
rc.2 is step 1 (designed host package).

1. First supported pair (darwin-arm64 client, linux-amd64 host) with
   honest evidence. (8)
2. Host package matches the designed units and paths. (5)
3. Session revoke across generations and durable grant socket. (5)
4. Operator CLI and status polish. (3)
5. Second-arch clients and hosts only when 1 is real. (8)

Do not start a management-plane product until WarpTweet can grant and
revoke one socket without drop-ins or hotfixed binaries.

## Related notes

- `docs/2026-08-16_product-quickstart.md`
- `docs/2026-08-16_adoption-and-release-strategy.md`
- `docs/2026-08-17_host-state-layout.md`
- `docs/2026-08-17_ubuntu-builder.md`
- `skills/warptweet-service-access/SKILL.md`
