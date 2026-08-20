# Forward-only OpenSSH

Hardening sequence step 2. The Linux host still runs OpenSSH 10.4p1 on the
same wire profile. After upstream `make tests`, WarpTweet rewrites
`serverloop.c` so `sshd-session` cannot open anything except `direct-tcpip`.

Allowed after authentication:

- channel type `direct-tcpip`
- global requests `keepalive@openssh.com` and `no-more-sessions@openssh.com`

Everything else, including `session`, `tun@openssh.com`,
`direct-streamlocal@openssh.com`, `tcpip-forward`, and SFTP, disconnects the
client. A mistaken `sshd_config` cannot turn those features back on.

The rewrite is applied only on the Linux engine build, after the grant hook,
and the `sshd` / `sshd-session` binaries are rebuilt before staging. The
macOS client stage is unchanged: it does not ship `sshd`.

Shipped in `0.1.0-rc.3`. The Ubuntu builder does not reuse the rc.2 OpenSSH
stage, because `scripts/apply-openssh-forward-only.sh` is a stage input.
