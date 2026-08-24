# CLI strategy: host, connect, and named invites

Status: product CLI design, 2026-08-12  
Invite naming revised 2026-08-14: human basename + `.wtinvite` (no `wt-invite-` prefix).

## Product verbs

Average path is two commands. Everything else is advanced or operational.

```text
warptweet host --to <port|ip:port> [--name <client-label>]
warptweet connect <invite-file>
```

| Verb | Machine | Meaning |
| --- | --- | --- |
| `host` | Host that can reach the service | Ensure host identity, write server policy, start host, mint one invite file |
| `connect` | Laptop / client | Consume invite, create client identity, pin host, activate route, bring tunnel up |

Private keys are always generated on the machine that will hold them. `host` never mints a client private key. `connect` never mints a host private key.

## Invite files: human basename, typed extension

Do not default to a generic `invite.json`. Put **type in the extension** and keep
the **basename human-oriented** (who/what the invite is for). Do not repeat brand
or type in the basename (`wt-invite-…` + `.wtinvite` is redundant).

Keep timestamps out of the filename. Issued/expiry live only in invite contents;
duplicating them in the path is noise.

### Default path pattern

```text
<label>.wtinvite
```

Examples:

```text
db-1.wtinvite
studio-mac.wtinvite
curtis-macbook.wtinvite
postgres-prod.wtinvite
```

| Part | Rule |
| --- | --- |
| basename | sanitized label: default server hostname, or `--name` |
| extension | `.wtinvite` (document kind; not a `.wt` tunnel manifest) |

Invites are deliberately **not** `.wt` manifests. `.wt` is the versioned tunnel
policy family; `.wtinvite` is a single-use enrollment artifact with its own
semantics.

Connect stays clean:

```text
warptweet connect studio-mac.wtinvite
```

### Label sanitization (hostname or `--name`)

- lowercase
- allow `a-z`, `0-9`, `-`
- collapse other runs to a single `-`
- trim leading/trailing `-`
- max 48 characters after sanitize
- empty or unusable hostname → `host`

### Write rules

- default directory: current working directory
- mode `0600` on Unix
- create-new only (`O_EXCL`); never overwrite an existing path
- print the absolute path on success
- never put private keys in the invite file

### Uniqueness (deliberate, not global-by-default)

Do not force every default name to be globally unique with timestamps or long
prefixes. Prefer a readable name; handle collisions deliberately.

1. Try `<label>.wtinvite` with exclusive create.
2. If that path already exists, try `<label>-<id4>.wtinvite` where `<id4>` is the
   first four lowercase hex characters of `invite_id` (implementations may use
   four to six characters from the same prefix if four collides again).
3. If the disambiguated path also collides, fail with a clear message to pass
   `--out` or remove the old file.

Example after a prior `studio-mac.wtinvite` still on disk:

```text
studio-mac-a81f.wtinvite
```

`--out` is exact-path exclusive: collision always fails (operator chose the path).
Do not auto-suffix when `--out` is set.

### Overrides

```text
# default: <this-machine-hostname>.wtinvite
warptweet host --to 5432

# label only: studio-mac.wtinvite
warptweet host --to 5432 --name studio-mac

# full path / basename override (exact; no auto-suffix)
warptweet host --to 5432 --out ./studio-mac.wtinvite
warptweet host --to 5432 --out /tmp/alice.wtinvite

# advanced: invite JSON on stdout, no file
warptweet host --to 5432 --stdout
```

| Flag | Effect |
| --- | --- |
| (none) | `<sanitized-hostname>.wtinvite`, with invite-id suffix on collision |
| `--name <label>` | `<sanitized-label>.wtinvite`, with invite-id suffix on collision |
| `--out <path>` | exact path ending in `.wtinvite` (other extensions rejected); directories must already exist; fail on collision |
| `--stdout` | no file; print invite JSON only |

## `host` behavior

```text
warptweet host --to 5432
warptweet host --to 127.0.0.1:5432
warptweet host --to 127.0.0.1:5432 --listen 10.168.0.2:2222 --advertise 34.20.174.226:2222
```

### Defaults

| Input | Default |
| --- | --- |
| `--to PORT` | target `127.0.0.1:PORT` |
| `--to IP:PORT` | target exact address |
| `--listen` | package default listen (documented fixed port, all suitable interfaces or package bind policy) |
| host key | generate once into fixed install path if missing; refuse clobber without `--rotate-host-key` |
| invite | mint one named invite file unless `--no-invite` or `--stdout` |

### Steps (internal)

1. Preflight packaged engine and layout.
2. Ensure host identity at fixed path.
3. Write or update the server policy manifest for the listener and target.
4. Ensure the pinned enrollment TLS identity exists. Invites are unsigned bearer documents; there is no invite MAC key.
5. Enable/start host service unit when packaged that way.
6. Mint an invite schema 3 document bound to the published data and enrollment dials, host public key, profile, artifact profile, principal, expiry, nonce, and enrollment SPKI. Connect uses the enrollment locator for HTTPS (HTTP/1.1 over the pinned TLS channel).
7. Write named invite file; print path + host fingerprint + local target summary.

### Human output (concise)

```text
local_listener_ready
published_endpoint_configured
external_reachability_unverified
target   127.0.0.1:5432
listen   10.168.0.2:2222
host     SHA256:ab:cd:...
invite   /home/you/db-1.wtinvite
```

JSON available via `--json` for automation.

## `connect` behavior

```text
warptweet connect db-1.wtinvite
warptweet connect ./studio-mac.wtinvite --yes
```

### Steps (internal)

1. Read invite file; reject private-key markers and expired/malformed invites before network.
2. Show confirmation summary unless `--yes`.
3. Generate client composite identity locally (fixed client path on activate).
4. Complete enrollment with host (proof binding).
5. Write client manifest, known_hosts pin, empty ambient trust.
6. Start tunnel (`up`) until Ready.
7. Print local open endpoint only.

### Defaults

| Input | Default |
| --- | --- |
| tunnel id | sanitized invite `client_name` / label |
| local listen | `127.0.0.1` + stable default port (or next free in a small range) |
| confirmation | interactive unless `--yes` |

### Human output

```text
connected
open     127.0.0.1:15432
service  127.0.0.1:5432
tunnel   studio-mac
```

## Advanced commands (keep; demote in docs)

These remain for operators and recovery. They are not the homepage story.

```text
warptweet server revoke | status | doctor-server
warptweet enroll | up | down | status | rotate | revoke
warptweet gen host | gen client
warptweet doctor | profile | validate | render-*
```

Mapping:

| Friendly | Composes |
| --- | --- |
| `host` | ensure identity + manifest + both listeners + invite mint |
| `connect` | enroll + activate + up |

## Identity generation naming

When `gen` is used explicitly:

```text
warptweet gen host
warptweet gen client --name studio-mac
```

- Default **label** (comment / receipt): `<hostname>-<utc-date>`
- Production **paths** stay fixed install invariants
- Never default operator-facing artifacts to OpenSSH’s `id_*` names

## Non-negotiables

- No DNS for authorized targets in v1 (exact IP:port under the hood).
- Port-only `--to 5432` is sugar for `127.0.0.1:5432` on the server machine.
- Invites are single-use, short-lived confidential bearers. Transfer them authenticated and delete them after use.
- Fail closed on profile, path, ownership, and algorithm mismatch.
- Target health is never implied by Ready.

## Implementation order

1. Invite filename helper + exclusive write + tests. **Done (2026-08-14).**
2. `host` thin orchestration over existing server bootstrap/invite. **Done (2026-08-14).**
3. `connect` thin orchestration over enroll + up. **Done (2026-08-14)**.
3b. Packaged enrollment accept endpoint (`server enroll-listen`, `Accept`, client
    auto-submit). **Done (2026-08-14)**. `host` requires the pinned TLS listener
    on port 29722 before reporting ready. Offline `--proof` remains for
    air-gapped ops.
3c. Client `rotate` / `revoke` via management token + `POST /v1/rotate|revoke`.
    **Done (2026-08-14)**.
4. Website and docs already show the friendly verbs; keep them aligned as flags stabilize.
5. Remove the public `server init` / `server invite` split so bootstrap cannot
   bypass the `host` readiness contract. **Done (2026-08-15).**

## Acceptance

- New user path is two commands without typing documentation IPs.
- Invite files default to `<label>.wtinvite` (type in extension, human basename).
- No brand/type prefix and no timestamps in the default basename.
- Default/named writes use exclusive create; collision auto-suffixes
  `-<invite_id prefix>` once, then fails; `--out` never auto-suffixes.
- Power users can still pass exact listen/target and custom `--out`.
- Automated tests cover sanitize, exclusive create, collision suffix, port sugar,
  and end-to-end composition dry-runs.
