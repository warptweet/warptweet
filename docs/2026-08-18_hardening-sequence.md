# Hardening sequence

Four steps, in order. Do not start the next until the current one is in a
shipped package, not only in a hotfix or drop-in. Sizing is productivity
points, not calendar time.

This is the sequence from the 2026-08-18 surface-area discussion. It does
not replace `docs/2026-08-16_adoption-and-release-strategy.md`.

## 1. Package the designed host (0.1.0-rc.2)

Points: 5

Ship the Linux host package so a clean `dpkg -i` matches the layout and
units we already designed. Operators should not need systemd drop-ins or a
hand-copied controller.

Must be in the `.deb`:

- `/opt/warptweet` immutable. Host keys under `/var/lib/warptweet/ssh`.
  `authorized_keys` under `/var/lib/warptweet/authorized_keys`.
  `sshd_config` under `/etc/warptweet/sshd_config`.
- `/usr/bin/warptweet` symlink to `/opt/warptweet/bin/warptweet`.
- `doctor-server` read-only. enroll writes grants. sshd writes only `/run`.
- `warptweet-sshd`: no `NoNewPrivileges` (privsep `setuid` must work).
  Own `RuntimeDirectory=warptweet/sshd` so restart cannot delete the grant
  socket.
- `warptweet-enroll`: `CAP_SYS_PTRACE` so grant register can read
  `/proc/<sshd-session>/exe`. Owns `RuntimeDirectory=warptweet/server`
  (grant socket). No `ProtectProc=invisible`.
- `/var/lib/warptweet` mode `0755` so `sshd-auth` can reach
  `authorized_keys`. Invite, client, and session dirs stay `0700`.
- Grant hook linked into packaged `sshd-session`.

rc.2 is this step. Tag only from a clean tree whose `Version` is
`0.1.0-rc.2`.

## 2. Forward-only OpenSSH build

Points: 5

Keep OpenSSH 10.4p1 and the same wire profile. Compile out code WarpTweet
must never run: shell/session, SFTP, agent, remote and dynamic forwarding,
X11, tun. Keep `direct-tcpip` and the grant hook in the privileged monitor.

A config mistake must not be able to turn those features back on.

Do this only after rc.2 is installable without drop-ins.

## 3. Enroll not always on

Points: 5

29722 is a permanent TLS server today. After a client is enrolled, the
data plane only needs 2222.

- Listen for enrollment when minting an invite or when the operator starts
  enroll explicitly.
- Move rotate and revoke onto a tiny framed RPC inside the already
  authenticated tunnel. That is not a shell.
- Daily operation can close 29722.

Do this only after the forward-only engine is what the package runs.

## 4. WarpTweet-only daemon, same SSH profile

Points: 8

A daemon that speaks only the pinned KEX, auth, and ciphers, and only
`direct-tcpip` to one `permitopen`. No session code in the tree.

The client may stay packaged `ssh` at first. A matching tiny client is a
later increment.

Do not start this until steps 1 to 3 are real packages. Do not replace
OpenSSL until this daemon exists and the current pair has v2 evidence.

## Out of scope for this sequence

- Shell, exec, or SFTP on the WarpTweet data plane
- Classical KEX or host-key fallback
- A greenfield non-SSH tunnel
- Public Homebrew CTA

## Related

- `docs/2026-08-18_use-cases-and-roadmap.md`
- `docs/2026-08-17_host-state-layout.md`
- `docs/2026-08-16_adoption-and-release-strategy.md`
