# Client enrollment and lifecycle CLI

Status: command surface and local state machine, 2026-08-12

## Commands

```text
warptweet enroll <invite.wtinvite> [--yes] [--prepare-only] [--proof <proof.json>] [--listen-port N]
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
5. Emit an enrollment request containing only the public key and invite binding.
6. Submit the request to the gateway enrollment endpoint
   (`http://<server>:<enroll_port>/v1/enroll` from the invite’s `enroll_port`,
   default **29722** when unset, via `warptweet server enroll-listen`), or
   accept an offline proof with `--proof`. The proof binds invite id, nonce, host
   key, client key, target, principal, and profile.
7. Render `client.wt`, `known_hosts`, empty ambient trust, and identity files.
8. Activate the generation into the fixed client layout, or stop after staging with `--prepare-only`.

MAC verification of invites remains server-side because the invite MAC key never leaves the gateway. Client parsing still fails closed on malformed, expired, or secret-bearing documents. Operator one-shot accept without the listener: `warptweet server accept-enrollment --request <request.json>`.

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

## rotate / revoke

Both require a local enrollment receipt that holds the gateway-issued
`management_token` (written at successful `enroll` / `connect`). The token is
long-lived and is transmitted in cleartext over plain HTTP on the invite’s
`enroll_port`; use only a trusted, firewall-restricted management segment until
pinned TLS or mTLS protects the endpoint.

| Command | Behavior |
| --- | --- |
| `rotate <tunnel-id>` | Stop local tunnel, generate new composite client key, `POST /v1/rotate` with management token, activate new identity, store new token |
| `revoke <tunnel-id>` | Stop local tunnel, `POST /v1/revoke` with management token (gateway removes that client’s `authorized_keys` line and burns token), preserve local identity files |

Gateway acknowledgment is required before local completion. Offline `--proof`
enroll without a management token cannot rotate/revoke over the network; use
`server revoke` on the gateway or re-enroll. No classical recovery path.

## uninstall

`warptweet uninstall --preserve-identity` stops local tunnels and preserves
identity. Package removal remains the platform package manager / uninstall
script responsibility.

## Evidence boundary

This work package does not prove end-to-end enroll against a live packaged
gateway. Package-to-package enrollment and readiness remain WP8 evidence.
