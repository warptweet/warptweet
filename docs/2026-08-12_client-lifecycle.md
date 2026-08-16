# Client enrollment and lifecycle CLI

Status: command surface, durable transactions, and macOS provisioner path,
2026-08-15

## Commands

```text
warptweet enroll <invite.wtinvite> [--yes] [--prepare-only] [--proof <proof.json>] [--listen-port N]
warptweet connect <invite.wtinvite> [--yes] [--proof <proof.json>] [--once]
warptweet up <tunnel-id> [--once]
warptweet status [<tunnel-id>] [--json]
warptweet down <tunnel-id>
warptweet rotate <tunnel-id>
warptweet revoke <tunnel-id>
warptweet uninstall --preserve-identity
```

## enroll

1. Parse invite JSON and reject private-key material before network activity.
2. Validate shape, profile id, expiry, and numeric endpoints.
3. Show server, target, principal, profile, local bind, and host key for confirmation unless `--yes`.
4. Generate a composite client key with the packaged `ssh-keygen -t mldsa44-ed25519`.
5. Generate a 256-bit management capability locally and emit an enrollment
   request containing the public key, capability, and invite binding.
6. Submit the request to the host enrollment endpoint
   (`https://<server>:<enroll_port>/v1/enroll` from the invite’s `enroll_port`,
   default **29722** when unset, via `warptweet server enroll-listen`), using
   TLS 1.3, hybrid `X25519MLKEM768`, and the exact Ed25519 SPKI pin carried in
   the invite; or
   accept an offline proof with `--proof`. The proof binds invite id, nonce, host
   key, client key, target, principal, and profile.
7. Render `client.wt`, `known_hosts`, empty ambient trust, and identity files.
8. Activate the generation into the fixed client layout, or stop after staging with `--prepare-only`.

MAC verification of invites remains server-side because the invite MAC key never leaves the host. Client parsing still fails closed on malformed, expired, or secret-bearing documents. Operator one-shot accept without the listener: `warptweet server accept-enrollment --request <request.json>`.

Target health is never implied by enrollment success.

## Lifecycle state

Per-tunnel state lives under the artifact-profile runtime root:

```text
<runtime-root>/<tunnel-id>/state.json
<runtime-root>/<tunnel-id>/lock
<runtime-root>/<tunnel-id>/pid
```

Phases: Preparing, Starting, AwaitingReadiness, Ready, Backoff, Stopping,
Stopped, Failed. Target health defaults to `not_checked`.

`up` is idempotent when Ready with a live PID. It starts `warptweet run --once`
by default so package supervisors own restart policy. `down` signals the exact
PID and never deletes identity or trust. `status` reports typed JSON by default.

On an installed Mac, the login administrator invokes these same public
commands without `sudo`. The fixed-path controller sends one typed request to
the package provisioner over a `root:admin` mode-0660 Unix socket. The helper
owns protected-state activation and generates one closed per-tunnel
LaunchDaemon running as `_warptweet`; caller-selected paths, commands, owners,
modes, labels, plists, and OpenSSH options are not part of the protocol.

## rotate / revoke

Both require a local mode-0600 enrollment receipt holding the client-generated
`management_token` written at successful `enroll` / `connect`. The raw
capability is transmitted only over the invite-pinned TLS channel. The server
stores only its digest.

| Command | Behavior |
| --- | --- |
| `rotate <tunnel-id>` | Stop local tunnel, durably stage a new composite key and client-generated next token, `POST /v1/rotate`, then activate only after host acknowledgment |
| `revoke <tunnel-id>` | Stop local tunnel, `POST /v1/revoke` with management token (host removes that client’s `authorized_keys` line and burns token), preserve local identity files |

Host acknowledgment is required before local completion. Pending enrollment,
rotation, and revocation states survive response loss or restart; exact retries
reuse the same key and capability and converge authorization before final
state publication. Offline `--proof` enrollment without a management
token cannot rotate/revoke over the network; use
`server revoke` on the host or re-enroll. No classical recovery path.

## uninstall

`warptweet uninstall --preserve-identity` stops local tunnels and preserves
identity. Package removal remains the platform package manager / uninstall
script responsibility.

## Evidence boundary

This work package does not prove end-to-end enroll against a live packaged
host. Package-to-package enrollment and readiness remain WP8 evidence.
