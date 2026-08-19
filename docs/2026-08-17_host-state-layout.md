# Host filesystem ownership

`/opt/warptweet` is immutable package payload. Generated machine state
does not live there.

| Tree | Owner | Contents |
| --- | --- | --- |
| `/opt/warptweet` | package | controller, OpenSSH engine, licenses |
| `/etc/warptweet` | `host` | `server.wt`, `sshd_config`, authorization policy, enrollment TLS |
| `/var/lib/warptweet` | grant authority | host keys, `authorized_keys`, clients, invites, sessions, clock |
| `/run/warptweet` | services | grant socket under `server/`, sshd pid under `sshd/` |

`doctor-server` is read-only preflight. It does not take locks or rewrite
keys. `sshd` reads host keys and `authorized_keys` and writes only under
`/run/warptweet/server`. enroll writes `/var/lib/warptweet` and
`/etc/warptweet/enrollment`.
