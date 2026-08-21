# WarpTweet data-plane daemon

Hardening sequence step 4, first increment.

`internal/dataplane` is the WarpTweet-owned host data plane. It advertises only
the pinned profile (mlkem768x25519-sha256, ssh-mldsa44-ed25519@openssh.com)
and `aes256-gcm@openssh.com`. It does not advertise
`chacha20-poly1305@openssh.com` until that cipher is implemented. It allows
only `direct-tcpip` to the manifest target and `127.0.0.1:29723`. Session,
tun, streamlocal, and `tcpip-forward` are protocol errors.

Composite host-key signing is implemented in `internal/composite` using
FIPS 204 ML-DSA-44 (adapted from Go's `crypto/internal/fips140/mldsa`) plus
Ed25519, matching OpenSSH's `ssh-mldsa44-ed25519@openssh.com` construction.

Hybrid KEX `mlkem768x25519-sha256` is implemented with `crypto/mlkem` and
`crypto/ecdh`. Composite signing uses FIPS 204 ML-DSA-44 plus Ed25519.
`warptweet-sshd.service` now starts `warptweet server data-plane`. After
authentication it registers a grant-session record. Revoke drops those
connections through `/run/warptweet/sshd/control.sock` and does not kill the
daemon. Packaged `sshd` remains in the tree only as the client engine and
host-key generator. OpenSSL is not replaced in this increment.
