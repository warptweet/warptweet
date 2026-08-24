# Published endpoints for `warptweet host`

- Status: **Frozen implementation contract**
- Date: 2026-08-24
- Audience: WarpTweet maintainers and external reviewers
- Scope: inbound publication of WarpTweet’s data-plane SSH and enrollment HTTPS across real cloud locator models. Not a reverse-relay product. Not a distributed endpoint-migration protocol in the first ship.
- Greenfield: no mixed-version rollout, no old-binary compatibility, no iptables in the package. Historical schema numbers stay historically numbered; this edition **rejects** them at runtime.

This is the consensus of the original bind/dial split, the gold-standard passthrough review, the 2026-08-24 adjudication (`docs/reviews/2026-08-24_claude-review-adjudication.md`), the Darwin/enrollment follow-up, and the crash-safety / authority / DNS / LB / evidence-v3 review. Do not implement product code against a prior draft.

## Overview

`warptweet host` today uses one concrete IP:port for bind, client dial, and enrollment TLS naming. That is correct when a public address sits on the guest NIC. It is wrong on cloud 1:1 NAT, incomplete for independently mapped passthrough-LB ports, and unnamed as a locator (not an identity).

This edition:

- Splits **bind** (local sockets) from **dial** (published locators) from **identity** (enrollment SPKI and SSH host key).
- Models data-plane SSH and enrollment HTTPS as independent published services.
- Accepts DNS names as locators, authenticated only by existing pins, as one vertical slice with the client.
- Diagnoses outbound-only NAT as unsupported.
- Treats first-ship locator stability as an operator requirement, with `published_endpoint_generation` in the schema so relocation is not a later break.

The 2026-08-24 GCE run proved linux-arm64 packages can interoperate. It did not prove this model (lab DNAT helper) and is not valid release evidence (dirty tree, duplicate result IDs, two `not_run`).

## Consensus with the passthrough reviews

| Claim | Verdict |
| --- | --- |
| Bind ≠ dial | Accept. `--listen` binds. `--advertise` publishes the data dial. |
| Dial is not a security pin | Accept. Identity is SPKI + host key + invite/grant records. |
| Independent data and enrollment endpoints | Accept. CLI derives enrollment dial from data dial unless overridden. |
| DNS as locator | Accept, as one vertical slice with client-tunnels v2 and resolve-once launch. |
| Schema 2 / invite 3 | Accept. Reject prior schema numbers. Client-tunnels also becomes v2. |
| No private bind IPs on the cert | Accept, and go further: **no SANs in this edition**. Identity is the Ed25519 key and SPKI. Locator changes never renew. |
| No silent IMDS | Accept. Kernel routing only for bind. Future explicit `--advertise-from=…` may return an operator-confirmed *candidate*. |
| Coarse `host ready` | Accept. Local / configured / unverified vs timestamped observation. |
| Outbound-only NAT | Accept. Unsupported. Diagnose. |
| Overlap relocation in first ship | Defer implementation. Keep `published_endpoint_generation` in the schema. First ship refuses locator change while live grants exist. DNS or a reserved static IP covers ordinary movement. |
| Relay / rendezvous | Defer forever as this product. Different availability authority. |

**Public `host` is Linux-only (deliberate).** `host.go` has no build tag and `command.go` `case "host":` has no GOOS guard; Darwin auto-listen via `net.Interfaces()` works today. That is **accidental exposure**, not a supported host product. Server packaging, `/opt/warptweet`, `/etc/warptweet/server.wt`, systemd, and `inspectProductionServerAccounts` are Linux (`internal/installlayout/layout.go`, `internal/engine/server_account_other.go`). First edition: **public `host` fails closed on non-Linux** with an error that names Linux and `--listen` is irrelevant because the command is the server. Bind-discovery helpers (`inspect-network` / `nonLoopbackIPv4Addresses`) remain **unit-testable** on Darwin; they are not a Darwin host. No PF_ROUTE parser. `--listen-interface` is Linux-only.

**Enrollment HTTPS vs SSH dial.** OpenSSH owns the data connection. Enrollment already uses `http.Transport{Proxy: nil}` (`submit.go` ~110–120). First edition: both legs consume a `ResolvedDialPlan`. Canonicalize at `parseHostForURL`. Enrollment dials the selected candidate with `Proxy: nil` and must not call the default resolver again. SSH: one immutable `ClientSpec` per attempted candidate. `HostName=<selected candidate IP>`, `HostKeyAlias=warptweet-<tunnelID>`.

## Locator versus identity

```go
type BindEndpoint struct {
    Address netip.Addr
    Port    uint16
}

// DialHost is a locator: a canonical IP literal or a DNS name.
// It is not an authentication authority.
type DialHost struct {
    IP   netip.Addr // set XOR Name
    Name string     // absolute DNS, JSON without trailing dot
}

type DialEndpoint struct {
    Host DialHost
    Port uint16
}

// PublishedEndpointSet is the atomic published locator the invite, proof,
// ClientRecord, enrollment receipt, and route receipt must carry together.
type PublishedEndpointSet struct {
    Generation  uint64 // JSON: published_endpoint_generation
    Data        DialEndpoint
    Enrollment  DialEndpoint
}

type HostIdentity struct {
    EnrollmentSPKISHA256 string
    SSHHostKey           []byte
}
```

`--advertise` is the operator flag. Code, JSON, docs, and logs say **dial** or **published endpoint**, never “pin.”

A wrong locator fails TCP, TLS SPKI (`PinnedClientTLSConfig`), or SSH host-key check. It does not mint grants by itself.

`HostName` and `HostKeyAlias` are already independent closed `-o` options in `internal/engine/client.go`. `HostKeyAlias` is `warptweet-<tunnelID>` (not route ID). Locator and SSH identity are already decoupled in the launch path. DNS work is the type change (`netip.Addr` → host-or-name) plus resolve-once, not a redesign of OpenSSH option layout.

**Name collision:** `internal/routestate/route.go` already has `Generation string` (timestamp-shaped, `ValidateGenerationID`). The published-locator revision is **`published_endpoint_generation`** (uint64) everywhere — schema, invite, receipts, logs. Do not call it `generation`. Bind-only changes do not increment it.

## Cloud environment boundary

| Environment | This edition |
| --- | --- |
| Public address on the guest NIC | Bind = dial. Omit `--advertise`. |
| 1:1 NAT, same ports | `--listen <nic>:2222 --advertise <public>:2222`. Enrollment dial defaults to `<public>:29722`. |
| Independent passthrough-LB / inbound-NAT ports | `--enroll-listen` / `--enroll-advertise`. |
| DNS in front of any of the above | Dial `host` is a DNS name. Resolve once per launch into `ResolvedDialPlan`; authenticate with pins. |
| Outbound-only NAT / Cloud Public NAT with no inbound mapping | **Unsupported.** No flag pair creates unsolicited inbound. Diagnose. Recommend public/static address, inbound NAT, **passthrough** TCP LB, reachable private address, or a different environment. |
| Proxy TCP LB / TLS termination / PROXY protocol | **Unsupported** this edition (see Publication transport). |

Guest routing cannot see 1:1 NAT or a load-balancer frontend. inspect-network must say published endpoints are **not derivable portably from guest interface and routing state** (not merely “not discoverable locally”).

## Endpoint model

### Server-gateway schema 2

`internal/server/manifest.go` `CurrentSchemaVersion` becomes **2**. Reject `schema_version != 2`. Keep `schemas/server-gateway-v1.schema.json` as historical unused. Add `schemas/server-gateway-v2.schema.json`. No v1 decoder.

Abridged (omits required `profile_id`, digests, `dedicated_user`, key paths; implementers use the schema file, not this snippet):

```json
{
  "kind": "warptweet.server-gateway",
  "schema_version": 2,
  "network": {
    "published_endpoint_generation": 1,
    "data": {
      "listen": { "address": "10.168.0.2", "port": 2222 },
      "dial":   { "host": "34.20.174.226", "port": 2222 }
    },
    "enrollment": {
      "listen": { "address": "10.168.0.2", "port": 29722 },
      "dial":   { "host": "34.20.174.226", "port": 29722 }
    }
  },
  "target": { "address": "127.0.0.1", "port": 5432 }
}
```

Always write the full `network` object. `dial.host` is an IP literal or DNS name. `listen.address` is always a numeric IP.

**Generation ownership:** `published_endpoint_generation` is **server-generated only**. Start at **1**. Increment **exactly once** when the **canonical published set** (data dial + enrollment dial, after canonicalization) changes. Bind-only edits do not increment. Never decrement. Detect overflow (uint64 max) and fail closed. First edition: it is **binding and evidence metadata**, not rollback protection. Do not “reject stale update messages” until such messages exist (overlap relocation is PR 5).

**Crash-atomic commit (no journal in this edition).** Under the host-operation lock, which also excludes enrollment accept for the duration:

1. Load invite and grant inventory.
2. Refuse a published-set change if any issued invite or non-terminal grant exists.
3. Compute the next generation (or keep the current one).
4. Write `server.wt` (generation + `network` + desired revision) as **one atomic replace** (temp file, fsync, rename). This is the only durable generation commit.
5. Apply / reconcile services, then mint.

Crash before step 4: no generation bump. Crash after step 4: the new generation is durable and matches the written set; next `host` reconciles applied receipts and does not mint against a stale inventory that was supposed to block the write (the refuse happened before the write, and accept could not interleave). Do not introduce a multi-record generation journal in the first edition. Interruption tests must recover and assert generation, `network`, and inventory together.

### Invite schema 3

`enrollment.CurrentSchemaVersion` becomes **3**. Reject invite schema 2. No decoder.

Abridged (omits nonce, durations, host public key, client name; use the schema):

```json
{
  "kind": "warptweet.invite",
  "schema_version": 3,
  "data": { "host": "tunnel.example.com", "port": 443 },
  "enrollment": { "host": "enroll.example.com", "port": 8443, "tls_spki_sha256": "…" },
  "published_endpoint_generation": 1
}
```

No bind addresses. HMAC stays gone (WT-SR-020). **Delete the dead secret:** `ensureInviteSecret` / `ReadSecret` of `/etc/warptweet/invite.mac-key`, enroll unit `AssertPathExists` for that path (`warptweet-enroll.service:9`), tests and docs that still mention a client-verifiable MAC. First edition does not create a key it does not use.

**Do not mint or accept a DNS `host` until the client resolver and client-tunnels v2 land in the same release.** `runEnroll` calls `SubmitEnrollment` **before** `BuildClientManifest` (`internal/command/lifecycle.go`). Today `BuildClientManifest` does `netip.ParseAddr(invite.ServerAddress)`. A DNS-bearing invite that passes schema 3 and enrolls, then fails ParseAddr, **consumes the single-use invite** and leaves no `client.wt`. Shipping schema-before-resolver is not a slice; it is a footgun. Either one vertical slice (schema + mint + client) or the schema rejects DNS names until that slice.

### Client-tunnels schema 2

`internal/config.CurrentSchemaVersion` becomes **2**. Reject v1. `Server.Address netip.Addr` cannot hold a DNS locator.

```go
type Server struct {
    Host string `json:"host"` // IP literal or DNS name (the persisted locator)
    Port Port   `json:"port"`
    User string `json:"user"`
}
```

Enrollment dial lives on the invite and on receipts (`PublishedEndpointSet`). After enroll, `up` uses data dial only; rotate/revoke stay on the tunnel-local management forward (`127.0.0.1:29723`).

One `ClientSpec.ServerAddress` cannot mean “resolve once, then try candidates.” Introduce `ResolvedDialPlan`:

```go
type ResolvedDialPlan struct {
    Host       DialHost
    Candidates []netip.Addr // canonical, deduped, bounded, ordered
}
```

Resolve once into the plan. Construct **one immutable `ClientSpec` per attempted candidate** (`ServerAddress` = that candidate). Policy construction and readiness use only the selected candidate. Never re-resolve inside `newClientPolicy` or `readiness.go`.

### Atomic propagation

Carriers of today’s `ServerAddress` that are **server or verified-client state** must carry the whole `PublishedEndpointSet`. The **client enrollment request is not such a carrier.**

| Site | First edition |
| --- | --- |
| `EnrollmentRequest` | **Does not carry** the set. Identifies the invite (id, nonce, client key, listen). |
| Validated `server.wt` | Authoritative set. |
| Server invite record + transferred invite | Set copied from the manifest. |
| Server-generated `EnrollmentProof` | Set copied from the manifest, never from the request. |
| `ValidateEnrollmentProof` | Proof set **equals** invite set (canonical, including generation). |
| enrollment receipt / `ClientRecord` / `routestate.Route` | The verified set. |
| `enroll_server.go` accept path / `AcceptInput` | Set from the manifest, not from listen IP alone. |

**Idempotency:** `storeOrResumePendingClient` (`internal/enrollment/accept.go`) compares `existing.ServerAddress != want.ServerAddress`. After this change it must compare the **entire** `PublishedEndpointSet`, including `published_endpoint_generation`. Comparing only a host string silently changes re-accept: a new generation would be treated as identical or as conflict incorrectly. This is the highest-risk migration line. It is a named item in PR 3.

**Authority direction.** The client `EnrollmentRequest` identifies the invite (invite id, nonce, client key, listen port). It is **not** an authority for publication data. Do not add `PublishedEndpointSet` to the request. Flow:

```text
operator flags
  → validated server.wt (schema 2)
  → server invite record + transferred invite (schema 3, set copied from manifest)
  → server-generated enrollment proof (set copied from manifest)
  → ValidateEnrollmentProof: proof set == invite set (canonical, including generation)
  → client receipt and route
```

Today `ValidateEnrollmentProof` (`internal/enrollment/client.go` ~193) does **not** compare server address or enroll port. Later `runEnroll` prefers proof `EnrollPort` (`lifecycle.go` ~243). First edition **requires** equality of the complete canonical `PublishedEndpointSet` (and generation) between invite and proof. A proof must not silently replace the invite locator. Lifecycle then uses that verified set, not “proof wins.”

Management RPC stays `127.0.0.1:29723`.

## Everyday CLI

```sh
# Public IP on NIC, or local-only.
warptweet host --to 127.0.0.1:5432

# 1:1 NAT, same ports.
warptweet host --to 127.0.0.1:5432 \
  --listen 10.168.0.2:2222 \
  --advertise 34.20.174.226:2222

# DNS locator.
warptweet host --to 127.0.0.1:5432 \
  --listen 10.168.0.2:2222 \
  --advertise tunnel.example.com:2222

# Independent publication.
warptweet host --to 127.0.0.1:5432 \
  --listen 10.168.0.2:2222 \
  --advertise tunnel.example.com:443 \
  --enroll-listen 10.168.0.2:29722 \
  --enroll-advertise enroll.example.com:8443
```

| Omitted | Default |
| --- | --- |
| `--listen` | Public `host` is Linux-only. If set, that address. If omitted and a stored data **bind** exists, **keep it** (do not re-run inspect-network). Else inspect-network. Ambiguity → fail closed and name `--listen`. |
| `--advertise` | Distinct stored data dial if present (even when `--listen` is re-supplied). Else data dial := listen IP:port. |
| `--enroll-listen` | Data listen IP, port 29722. |
| `--enroll-advertise` | Data dial **host**, port 29722. |

Empty `--advertise` restores. `--advertise` equal to resolved data listen is an **explicit reset**. Never pre-fill the flag with listen.

`--listen-interface ens4` (Linux) resolves that interface to a concrete address and persists the address, not the name.

Unspecified bind stays rejected.

## DNS locators (one vertical slice)

**Canonical form (ASCII A-labels only).** One function used by `parseHostForURL`, invite schema 3, and server-gateway dial `host`. It **lowercases** the name (`TUNNEL.EXAMPLE.COM` and `tunnel.example.com` are the same result) and returns that form. JSON, generation hashing, invite/proof equality, and URL construction all consume the lowercase form **without** a trailing dot. Tests cover both casings. Reject:

- empty string, empty labels, labels > 63 octets, total > 253 octets
- non-ASCII / U-labels (no IDNA ToASCII in this edition)
- control characters, space, URI metacharacters (`/ ? # @ : [ ]`), wildcards (`*`)
- leading/trailing hyphens in a label, consecutive dots
- names that parse as IP literals (those belong in the IP arm of `DialHost`)
- IPv6 zones

**Resolve:** query `canonicalName + "."` (absolute). Do not use resolver search/`ndots`. Timeout: 5s aggregate.

**Answers:** unmap IPv4-mapped IPv6. Reject unspecified, multicast, link-local. Reject loopback unless the whole host is local-only (bind loopback). Deduplicate by canonical `netip.Addr`. Cap **4 per family**, total at most 8. Extra answers after the cap are dropped, not an error.

**Sequential walk, interleaved families.** Do not concatenate all IPv6 then all IPv4: four timed-out IPv6 candidates would consume the 8s aggregate and starve IPv4. Walk `IPv6[0], IPv4[0], IPv6[1], IPv4[1], …`. Per-candidate connect timeout 2s; aggregate 8s; no extra retry; **no parallel happy-eyeballs**. With both families present, at least one IPv4 attempt remains inside the aggregate. Go’s default `net.Dialer` is **not** used for this path: custom resolve is required so answers are validated and the selected address is recorded without re-resolving.

**Enrollment HTTPS:** controller-owned. Custom resolve into a plan, then dial the selected candidate with `http.Transport{Proxy: nil}` **without** calling the default resolver again. Record `enrollment_resolved_addr`.

**SSH:** `ResolvedDialPlan` → one `ClientSpec` per attempted candidate → `HostName=<that IP>`, `HostKeyAlias=warptweet-<tunnelID>`. Sequential candidates, not `net.Dialer` happy-eyeballs. Record `data_resolved_addr`.

**Same logical host.** Multi-address DNS is safe only if every enrollment address presents the **same** invite-pinned SPKI and grant authority, and every data address presents the **same** host key and equivalent grant/target state. WarpTweet’s file-backed host is not active-active independent machines. Round-robin onto two different WarpTweet hosts is unsupported.

Split resolution (enroll IP ≠ SSH IP for one name) is allowed **when both addresses are that same logical host**. Evidence records both addresses. It is not an impersonation hole; it is not “anycast two independent authorities.”

## inspect-network (Linux host only)

Public `host` fails closed on non-Linux: *WarpTweet host requires Linux; this is the server command.* Discovery helpers may still be unit-tested on Darwin with fake routes / `Interfaces()` fixtures; that is not a supported Darwin host.

Do not query IMDS. Do not use `net.Route` (not in the stdlib) or `golang.org/x/net/route` (not Linux).

**Lookup, not dump.** Per family, issue `RTM_GETROUTE` with `NLM_F_REQUEST` **without** `NLM_F_DUMP`, via `golang.org/x/sys/unix`:

- `rtm_family` = `AF_INET` or `AF_INET6`
- `rtm_dst_len` = 32 or 128 (not 0)
- `RTA_DST` = `192.0.2.1` or `2001:db8::1` (documentation prefixes; this is a route lookup, not a reachability probe)
- `rtm_table` = `RT_TABLE_MAIN` (254)

A zero-length destination (`rtm_dst_len = 0` and no `RTA_DST`) dumps routes and is not the contract. The response must contain **exactly one** `RTM_NEWROUTE`. Zero or several → fail closed and print the kernel evidence. PR 1 includes a bounded Linux probe that asserts that cardinality.

`RTA_PREFSRC` is **optional**. If the kernel returns it, use it. If not, take the selected output interface (`RTA_OIF`) and the single unicast address of that family on that interface. If that interface has zero or several unicast addresses of the family, fail closed and print the kernel evidence. Policy routing / extra tables → fail closed, name `--listen`.

Then:

1. Exclude loopback, down, link-local-only.
2. Interface names are **diagnostic hints**, never exclusion authority.
3. Exactly one remaining candidate **for that family** → keep it.
4. **One bind address per service this edition.** If only one family has exactly one candidate, use it. If **both** IPv4 and IPv6 have exactly one candidate, fail closed, print both, and name `--listen`. Do not expand `BindEndpoint` or the listen schema to two sockets. DNS **dial** may still be dual-stack at resolve time.
5. Several defaults or other ambiguity → fail closed, name `--listen`.
6. Never invent a published locator.

```text
Local bind candidate
  ens4        10.168.0.2       default-route source  table 254  inet

Ignored (not the default-route source)
  docker0     172.17.0.1       not selected by RTM_GETROUTE default

Published data endpoint
  not derivable portably from guest interface and routing state

Suggested command
  warptweet host --listen 10.168.0.2:2222 \
    --advertise <client-reachable-host>:2222 \
    --to 127.0.0.1:5432
```

## Port collision

Today `invite.go` rejects `EnrollPort == ServerPort` because both share one `server_address`. Independent hosts make `tunnel.example.com:443` and `enroll.example.com:443` legitimate.

| Layer | Reject | Allow |
| --- | --- | --- |
| Bind | Canonical listen `address:port` (unmap IPv4-mapped) equal for data and enrollment | Same port on different bind addresses |
| Dial | Canonical locator `host:port` equal (lowercase A-label or canonical IP) | Same port on different **canonical** locators |

WarpTweet ships no protocol demultiplex on one socket. Equal full locators are invalid.

**Mint-time DNS is not a collision oracle.** First edition does **not** resolve published DNS names at `host` in order to compare candidate address sets. The guest often cannot see the public answer (split-horizon, no recursive resolver), and any answer is TOCTOU. Collision of two DNS locators is canonical name+port equality only. Operators must not publish two names for the same address:port; the client fails closed at connect (`tcp_connect` / `tls_spki` / `ssh_host_key`). There is no “external mapping proves separate listeners” exception: first edition cannot authenticate that mapping.

**IP-literal dials** compare as canonical `netip.Addr` after unmapping. `--advertise 34.20.174.226:443 --enroll-advertise 34.20.174.226:443` rejects. `--advertise 34.20.174.226:443 --enroll-advertise [::ffff:34.20.174.226]:443` also rejects.

## Enrollment TLS

`PinnedClientTLSConfig` uses `InsecureSkipVerify` plus manual SPKI checks. Go does **no** hostname verification. A certificate with **no SANs** is valid for this protocol.

Today `EnsureTLSIdentity(..., addresses []net.IP, ...)` and `writeEnrollmentCertificate` copy `addresses` into `IPAddresses`. First edition **stops that**. Generated certificates leave **both** `IPAddresses` and `DNSNames` empty. The `addresses` argument is ignored (and should be removed in PR 3). Adding published-name SANs later would mean a new signature, template fields, canonical compare, and a renewal trigger.

First edition: **no SANs**. No bind addresses. No DNS names on the cert. Identity is the Ed25519 key and SPKI. Bind and dial changes **never** renew. Time-based renewal reuses the key and still emits empty SAN slices. `doctor-server` need not compare SAN to dial. Certificate tests assert both SAN fields are empty and that pin/renewal behavior is unchanged.

This deletes work the previous draft invented and strengthens identity (topology is not in the cert). Published-name SANs are a later change if an interoperability need appears.

Restart the **enrollment process** when **any** field of the `PublishedEndpointSet` or its generation changes (including **data dial**). `runServerEnrollListen` loads and captures the whole manifest at start (`enroll_server.go` ~47, ~85). A data-dial-only change still changes the set the daemon would mint and prove. Restart the **data-plane service** (`warptweet-sshd.service` runs `warptweet server data-plane`, not OpenSSH `sshd`) when data **listen** changes, or when reconcile finds desired ≠ applied. Time-based cert renewal still restarts enrollment so it loads the new leaf.

## Endpoint relocation

Durable identity is host key + enrollment TLS key.

`published_endpoint_generation` is configuration-version metadata on the published locator set. WarpTweet **cannot** revoke an external locator (NAT, DNS, firewall, LB). The operator withdraws the old locator in that infrastructure. First edition binds receipts and evidence to a generation. It cannot know which external locator delivered an authenticated SSH connection. Do not write “revoke the old generation” as if SSH enforced it. Do not “reject stale update messages” until overlap-relocation messages exist (PR 5).

**First ship:** refuse published-locator change while issued invites or non-terminal grants exist (reuse `refuseHostTargetChange` inventory in `host.go`). Require a stable locator (DNS name or reserved static IP). Warning when bind is non-global and data dial is a raw IP. Bind-only changes do not increment the generation and are not this refusal.

**Overlap serving** (old+new locators at once, in-band client update) is **aspirational** until authorization and external-withdrawal semantics are a separate design. Not a blocker for GCE 1:1 NAT with a stable `--advertise`.

## Readiness and observations

Do not print a single `host ready` that only means a local listen.

| Host-observable state | Meaning |
| --- | --- |
| `local_listener_ready` | Data and enrollment sockets accept on **bind** from the guest. |
| `published_endpoint_configured` | Manifest has a complete `PublishedEndpointSet`. |
| `external_reachability_unverified` | No successful client observation stored. Default after `host` on NAT. |

**`end_to_end_verified` is not a current state.** It is a timestamped observation: `last_verified_at`, `published_endpoint_generation`, `data_dial`, `enrollment_dial`, `client_artifact`, `server_artifact`, `verification_scope`. Never render “currently reachable” from a past observation. Guest-originated probes of the published address are not this observation (hairpin is not guaranteed).

Error classes **on the client** (logs, client status, **package evidence**):

- `dns_resolution`, `tcp_connect`, `tls_negotiate`, `tls_spki`, `invite_authorization`, `ssh_host_key`, `forward_target`

There is no authenticated client-to-host reporting channel in this edition. Those classes **do not** appear on host `status`. Host-observable failures are local bind, config validation, and unit health.

Outbound-only NAT: local listeners ready, published endpoint configured, internet clients `tcp_connect`, doctor notes WarpTweet cannot create inbound.

## Fail-closed validation

| Rule | Action |
| --- | --- |
| Bind unspecified, zoned, multicast, broadcast, port 0 | reject |
| Dial host empty or DNS malformed | reject (and do not mint DNS until the client slice exists) |
| Dial IP unspecified, multicast, or IPv4 broadcast | reject (same as DNS-answer validation; before mint) |
| Dial loopback while bind is non-loopback | reject |
| Bind loopback, dial loopback | allow |
| Bind loopback, dial non-loopback | reject |
| Bind: canonical data listen `address:port` == enrollment listen `address:port` | reject |
| Dial: canonical data `host:port` == enrollment `host:port` | reject |
| Equal ports on **different** canonical bind addresses or dial locators | allow (no mint-time DNS resolve for this check) |
| Link-local dial | reject |
| RFC1918 / CGNAT / ULA dial | allow (VPC-only); warn when equal to bind and not loopback |

Warnings are JSON-only on `doctor-server`. Exit 0 / `preflight_ready` when preflight succeeds so enroll/mgmt `ExecStartPre` survives GCE NAT. Private-pin warning excludes loopback pin=bind.

## Persistence of bind and published locators

**Dial restore** (unchanged): omitted `--advertise` keeps a distinct stored data dial even when `--listen` is passed. Passing `--advertise` equal to listen is an explicit reset.

**Bind restore** (same shape as today’s `resolveHostListen`, and the symmetric hole the dial side already closed):

`resolveHostListen` today returns stored `manifest.Listen` **before** `nonLoopbackIPv4Addresses` (`host.go` ~617–619). Keep that precedence.

| `--listen` | Stored data bind | Result |
| --- | --- | --- |
| Set | any | Use the flag. If it differs from stored bind, that is a listen change → restart the **data-plane service** after write. |
| Omitted | present | **Keep stored bind.** Do not re-run inspect-network. Re-evaluating every run can silently move the socket and fire the restart table. |
| Omitted | none | Linux inspect-network. Zero candidates → `127.0.0.1:2222`. Several → fail closed, error names `--listen`. Non-Linux: `host` does not run. |

`--listen-interface` is an explicit bind source (Linux), equivalent to passing `--listen` of the resolved address, and may restart the data-plane service if the address changed.

## `runHost` operation: crash-safe apply then mint

Today `withHostStateLock` covers identity/manifest write, then unlocks; `ensureSSHDStarted` and enroll start run **after** (`host.go` ~114 then ~160). Two `host` processes can interleave: A writes set A and unlocks; B writes set B; A restarts or mints against stale A. A crash after write and before restart leaves durable desired state ahead of listeners; the next compare-against-written-manifest can skip restart.

**First edition:** a **host-operation lock** spans the entire configuration: resolve → refuse → write desired → apply services → verify listeners → mint. `withHostStateLock` may be that lock or a nested lock; implementers must not release it before mint-or-error.

Persist **one desired revision** and **one applied receipt** covering every host-managed input those processes load, not only `network`:

- Desired: canonical hash of schema-2 `network` (binds + published set + generation) **and** the enrollment certificate leaf digest (and any other host-managed file the services load). Cert-only renewal changes the cert digest without bumping `published_endpoint_generation`.
- Applied: the same hash of what the running data-plane and enrollment processes have actually loaded (or “none”).

On **every** `host` invocation, **reconcile**: if desired ≠ applied, restart/apply even if flags match the already-written manifest. Certificate renewal therefore sets desired ≠ applied until enrollment has loaded the new leaf.

Mint an invite **only after** both bind listeners are demonstrated for the current desired revision (data listen and enrollment listen from the guest). First-edition “demonstrated” means: the process has been restarted or confirmed running against the desired config, a guest-originated TCP accept succeeds on each bind, and the **applied receipt is written only after that**. It is not a protocol-level generation handshake on the wire.

**Restart the data-plane service** (`warptweet server data-plane`) when data listen changed or reconcile requires it. **Restart enrollment** when any published-set field or generation changed, when enrollment listen changed, or when the cert leaf digest changed.

**Invite mint is atomic with the invite record.** Write the server invite record and the transferable invite bytes in one durable transaction (same temp directory, fsync, atomic publish). Do not mint a second invite to recover. On rerun after a crash past record creation: if an unused issued invite exists for the current generation, **resume that blob** (same `invite_id` and bytes). If it was already accepted, the normal consume path applies. Do not invent an invalidation-and-replace protocol in this edition.

Tests: interrupt after manifest write, after certificate write, after each service restart, after readiness verification, after invite-record creation (rerun yields exactly one usable invite, same id, no duplicate record); plus concurrent two-`host` (second waits on the operation lock; exactly one mint for one successful apply). Recovered state after a generation write must show matching generation, `network`, and inventory.

## Interop and evidence

`scripts/interop/work/evidence-20260824T050658Z.json` is laboratory only: dirty tree, two `not_run`, duplicate `engine-identity-trust-preflight`. `internal/releaseevidence/v2.go` rejects duplicate IDs. The generator must `Validate` before write.

Networking evidence fields: binds, dials, observed listeners, **absence** of test DNAT/lo aliases, client dial results and error class, SPKI and host-key results, `published_endpoint_generation`, **`enrollment_resolved_addr` and `data_resolved_addr` (may differ for the same DNS name)**, operator-stated firewall/LB assumptions, package-only, clean tree.

Those fields **do not fit evidence schema v2** (`ReportV2` has no such members; `schemas/release-evidence-v2.schema.json` has `additionalProperties: false`). PR 4 introduces immutable **release-evidence-v3** + **checklist-v3** + Go types + `Validate` before write + public-index integration. The current v2 checklist still cartesian-products darwin-arm64/amd64 × linux-amd64/arm64; a GCE arm64 cell is **one** cell, not the matrix.

Acceptance cells for *this networking contract* (v3): darwin-arm64 × linux-arm64 on GCE **without** DNAT helper; bind ≠ data dial; invite schema 3 matches dial; guest listeners match bind. Additional v3 cells: port-mapped (including equal ports on different hosts), DNS dial, IPv6 bind=dial, passthrough NLB if available. **Proxy** load balancers are not a first-edition evidence cell.

Interop env: `LISTEN` = bind; `ADVERTISE` unset by default; pass `--advertise` only when explicitly set; optional enroll advertise; Mac TCP (including bounded floods) uses published dials; never default `ADVERTISE=LISTEN`.

## Publication transport (what “load balancer” means)

First edition supports:

- Direct bindable public IP
- 1:1 inbound NAT (GCE access-config, AWS EIP, Azure public IP)
- **Passthrough** TCP load balancing (backend terminates TLS/SSH; client bytes unchanged)

**Unsupported** until specified with evidence:

- **TLS/SSL termination.** The client must see the WarpTweet enrollment certificate whose SPKI is in the invite.
- **PROXY protocol v1/v2** unless WarpTweet implements and authenticates it (it does not).
- **Proxy** TCP load balancers that open a new backend connection (GCP proxy NLB, similar Azure/AWS modes).

The native data plane allows **four connections per observed source** (`defaultMaxConnsPerSource = 4` in `internal/dataplane/conn.go`). Enrollment rate limits by `RemoteAddr`. A proxy that NATs every client to one backend source collapses those buckets: availability failure or cheap DoS. First edition does not pretend to fix that.

Passthrough LB may still replace the observed client address with the LB’s. Document that source quotas then apply per-LB, not per-client. Idle timeouts must be tested against durable tunnels (`sessionIdleTimeout` is 5 minutes in the dataplane).

## Systemd and packaging

No new units. Forbidden: `iptables`, `nft`, `ip addr`, cloud-named units, `CAP_NET_ADMIN`/`CAP_NET_RAW`, metadata curl in maintainer scripts.

**Delete `invite.mac-key`.** `ensureInviteSecret` still creates it (`host.go`) and `warptweet-enroll.service` `AssertPathExists` it. HMAC is gone (WT-SR-020). First edition must not create, assert, document, or test that file.

## Alternatives (rejected for this edition)

- Single Listen forever (old option 1): coherent freeze, not this edition.
- IPv6-only publication: valid when both ends have IPv6; 2026-08-24 VM had none.
- Unspecified bind: rejected.
- Silent IMDS: rejected. Future explicit candidate fetch may exist; it never implies reachability or stability.
- Reverse relay: different product.

## Security

| Threat | Mitigation |
| --- | --- |
| Wrong dial locator | TCP or SPKI / host-key failure. Locator ≠ identity. |
| Client as publication authority | `EnrollmentRequest` does not carry the set. Proof must equal invite. |
| DNS rotation during launch | Resolve once into `ResolvedDialPlan`; one `ClientSpec` per candidate. Never re-resolve in policy or readiness. |
| Crash after manifest write / two `host` | Host-operation lock spans write+apply+verify+mint. Desired vs applied reconcile. |
| Re-accept after generation bump | Compare entire `PublishedEndpointSet` at `accept.go` idempotency. |
| DNS invite before client resolver | Do not mint; schema+client land together. Enroll-then-ParseAddr would consume the invite. |
| docker0 as auto-bind | Kernel default-route **lookup** source, not name blacklist. |
| Private bind on cert | No SANs. |
| doctor warnings vs ExecStartPre | JSON-only, exit 0. |
| Stored dial clobber | Restore independent of `--listen`. |
| Stored bind clobber / silent socket move | Stored Listen short-circuits inspect-network when `--listen` is omitted. |
| Round-robin DNS onto two hosts | Unsupported. Same logical host + same pins only. Split enroll/SSH IPs for one name are allowed when both are that host. |
| Uncanonical DNS in `EnrollmentURL` | Canonicalize in `parseHostForURL`; both legs consume that form. |
| Proxy LB / TLS terminate / PROXY proto | Unsupported. Source quotas (`defaultMaxConnsPerSource=4`) collapse. |
| Outbound-only NAT | Explicit unsupported. |
| Dead `invite.mac-key` | Delete create/assert/tests/docs. |

## Open questions

Closed: bind/dial/identity, independent enrollment, DNS as a slice with `ResolvedDialPlan` and lowercase A-labels, schema numbers, no SANs (empty `IPAddresses` and `DNSNames`), port collision as canonical locators (no mint-time DNS), public `host` **Linux-only**, inspect-network as `RTM_GETROUTE` **lookup** with `RTA_DST`/`rtm_dst_len`, **one bind address per service** (both-families unique → `--listen`), bind-restore precedence, interleaved enroll/SSH candidate walk, `parseHostForURL` canonicalization, readiness as observation, outbound-only, generation ownership with atomic `server.wt` replace, host-operation lock + desired/applied including cert digest, invite resume after mint-record crash, authority direction (request is not a carrier), passthrough-only LB, evidence v3, HMAC-file deletion, resolve-once, accept idempotency.

Still open:

1. Human output when bind equals dial (JSON always full `network`).
2. Weaken locator-change refusal on `active` grants? Default is full inventory.
3. `--allow-private-dial` hard error vs warning.
4. Whether to add explicit `--advertise-from=gcp-metadata` later (candidate only).

## Key decisions

1. Bind ≠ dial ≠ identity. `--advertise` is the everyday data dial flag.
2. Data and enrollment are independent endpoint pairs; CLI derives enroll dial unless overridden.
3. Server-gateway schema 2. Reject 1. Always write `network`.
4. Invite schema 3 and client-tunnels schema 2. Reject prior numbers.
5. DNS locators only in the same release as the client resolver. Canonical lowercase ASCII A-labels; absolute resolve; `ResolvedDialPlan`; one immutable `ClientSpec` per candidate; sequential **interleaved** IPv6/IPv4 walk (no happy-eyeballs); evidence records both resolved IPs. Canonicalize in `parseHostForURL`. `HostName` = selected candidate IP; `HostKeyAlias` = `warptweet-<tunnelID>`.
6. `published_endpoint_generation` (uint64) is server-generated only: start 1, increment once on canonical published-set change via atomic `server.wt` replace after inventory refuse, never decrement, overflow fail-closed. Binding and evidence metadata, not rollback protection. Bind-only changes do not increment it. No generation journal in this edition.
7. Atomic `PublishedEndpointSet` on invite, proof, receipts, routes. **Not** on `EnrollmentRequest`. `ValidateEnrollmentProof` requires equality with the invite set. `accept.go` re-accept compares the entire set.
8. Port collision is canonical `address:port` / `host:port`, not port-only and not mint-time DNS disjointness.
9. No certificate SANs this edition. Generated certs have empty `IPAddresses` and `DNSNames`. SPKI only. No locator-driven renewal.
10. Public `host` is Linux-only (fail closed on other GOOS). inspect-network is a Linux `RTM_GETROUTE` **lookup** (`NLM_F_REQUEST`, `RTA_DST`, `rtm_dst_len` 32/128, exactly one `RTM_NEWROUTE`). `RTA_PREFSRC` optional. One bind address per service; both-families unique → `--listen`. Discovery helpers remain unit-testable on Darwin; they are not a Darwin host. `--listen-interface` is Linux-only.
11. First ship refuses published-locator change while grants exist. Overlap relocation is a later design. DNS/static IP cover ordinary movement.
12. `end_to_end_verified` is a timestamped observation. Client error classes stay on the client and in evidence.
13. No NAT/lo/cloud units. No silent IMDS. No proxy TCP LB, TLS termination, or PROXY protocol.
14. Omitted `--advertise` restores stored distinct data dial. Omitted `--listen` restores stored data bind (short-circuits inspect-network). Passing `--listen` is an explicit bind change and may restart the data-plane service.
15. `doctor-server` warnings never fail `ExecStartPre`.
16. Host-operation lock spans resolve → inventory refuse → atomic `server.wt` write → apply → verify → mint (and excludes enrollment accept). Desired/applied hashes include `network` **and** cert leaf digest. Reconcile on every `host`. Restart enrollment on **any** published-set or generation change, including data dial, and on cert-leaf change. Restart the data-plane service on data-listen change or reconcile miss. Unused invite after a mint-record crash is resumed, not reminted.
17. Release evidence for this contract is **v3** (new schema, checklist, Go types, `additionalProperties: false`). v2 cannot grow these fields. GCE arm64 is one cell, not the matrix.
18. Delete `invite.mac-key` create/assert/tests/docs.
19. 2026-08-24 JSON is not release evidence. Validate before write. Re-run GCE without DNAT.

## Risks

| Risk | Mitigation |
| --- | --- |
| Schema 2/3 + client v2 fixture churn | Expected. PR 1–2 update every in-tree document. |
| DNS mint without client | Forbidden. Same release. |
| Resolve twice per launch | Contract: once into `ResolvedDialPlan`. |
| Crash / concurrent `host` | Operation lock + desired/applied + interruption tests. |
| Generation field clash | `published_endpoint_generation` only. |
| Port-equal-on-same-host allowed by mistake | Full-pair comparison. |
| Operators think `--advertise` creates inbound | States + outbound-only copy. |
| “TCP load balancer” overclaim | Passthrough only; proxy/TLS-term/PROXY proto out. |
| v2 evidence fields | New immutable v3; do not loosen v2 `additionalProperties`. |

## References

- `internal/command/host.go`, `enroll_server.go`, `lifecycle.go` (`SubmitEnrollment` then `BuildClientManifest`), `server_admin.go`
- `internal/server/manifest.go`, `internal/server/server.go`
- `internal/config/config.go` (`Endpoint`, `Server`, schema 1), `internal/config/validate.go`
- `internal/enrollment/invite.go` (`EnrollPort == ServerPort`), `client.go` (`ParseAddr`), `accept.go` (idempotency), `tls.go` (`InsecureSkipVerify`; today still copies `IPAddresses`), `clients.go`
- `internal/engine/client.go` (`HostName`, `HostKeyAlias=warptweet-<tunnelID>`), `internal/engine/readiness.go` (`hostAlias`)
- `internal/routestate/route.go` (`Generation string`)
- `internal/releaseevidence/v2.go` (duplicate IDs)
- `golang.org/x/sys v0.47.0` in `go.mod`
- `docs/reviews/2026-08-24_claude-review-adjudication.md`
- Evidence: `scripts/interop/work/evidence-20260824T050658Z.json`

## PR plan

Greenfield: no PR exists to keep schema 1 loading.

### PR 1 — Server-gateway v2 types, Linux-only host, bind discovery

- Types, `network`, generation ownership (start 1, server-only, increment via atomic `server.wt` replace after inventory refuse). Fail-closed bind/dial (canonical full-pair port collision; IP unspecified/multicast/broadcast dial rejected). Reject schema 1. Public `host` fails closed on non-Linux. Linux inspect-network via `RTM_GETROUTE` **lookup** (`NLM_F_REQUEST`, `RTA_DST`, `rtm_dst_len` 32/128, exactly one `RTM_NEWROUTE`; `RTA_PREFSRC` optional). One bind address per service; both-families unique → `--listen`. Discovery helpers unit-testable on Darwin with fixtures; no Darwin host. **Stored-bind precedence:** omitted `--listen` does not re-discover. No `--advertise` yet. `Render` uses data listen only. Tests: non-Linux `host` errors; lookup vs dump; prefsrc-absent interface with 0/1/N addresses; exactly one IPv4 and one IPv6 candidate fails closed; Linux probe of lookup cardinality.

### PR 2 — Invite v3, client-tunnels v2, host-operation lock, DNS vertical slice, dead HMAC

- `--listen-interface` (Linux), `--advertise`, `--enroll-*`. Restore stored dial **and** stored bind. Explicit dial reset. Locator refusal. **Host-operation lock** spanning write+apply+verify+mint and excluding enrollment accept; desired vs applied receipts **including cert leaf digest**; reconcile on every invocation. Invite schema 3. Client-tunnels v2 (`Server.Host`). `ResolvedDialPlan`; one `ClientSpec` per candidate; lowercase A-label canonicalization in `parseHostForURL` (`TUNNEL.EXAMPLE.COM` ≡ `tunnel.example.com`). Interleaved IPv6/IPv4 sequential walk. DNS enroll + launch in **this** PR if DNS names are minted. Restart enrollment on any published-set/generation change (including data dial) and on cert-leaf change. Restart the **data-plane service**, not “sshd.” Delete `invite.mac-key` create/assert/tests/docs. Invite record + transferable blob are one atomic publish; crash after record creation resumes that invite. Interruption tests after manifest write, cert write, each service restart, readiness verify, invite-record create (exactly one usable invite); plus concurrent two-`host`. Readiness states (not e2e-as-current).

NAT: do not deploy without PR 3.

### PR 3 — Accept set, authority direction, TLS without SAN, doctor/status

- Propagate `PublishedEndpointSet` through **invite, proof, `ClientRecord`, receipts, `routestate`**. Do **not** add it to `EnrollmentRequest`. `ValidateEnrollmentProof` compares the complete canonical set and generation; lifecycle uses the verified set, not “proof wins.” `accept.go` compares the entire set. SPKI-only certs: `EnsureTLSIdentity` / `writeEnrollmentCertificate` emit empty `IPAddresses` and `DNSNames`; tests assert both SAN fields empty; pin and time-based renewal unchanged. No locator-driven renewal. doctor exit 0 with warnings. enroll-listen bind vs URL. Client error classes on client/evidence only.

### PR 4 — Release-evidence v3, interop split, GCE without DNAT

- Immutable `release-evidence-v3` + `checklist-v3` + Go types + strict `additionalProperties: false` + `Validate` before write + public-index integration. Unique result IDs. Env split. GCE acceptance **without** DNAT helper (one networking cell, not the full matrix). Port-mapped and DNS cells when the slice exists. Passthrough NLB optional; **no** proxy-LB cell. Delete lab DNAT unit. Docs: remove `0.0.0.0` and MAC sentences.

### PR 5 — Overlap relocation (separate design)

- Not a schema break. Not in the first GCE-without-DNAT train. This is where stale-update messages, if any, would be specified.

PR 1 mergeable with tests. PR 2+3 release together. PR 4 is proof. PR 5 is later.
