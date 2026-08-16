# WarpTweet adoption and release strategy

- Contract ID: `warptweet.adoption-release.v1`
- Status: implementation and review contract
- Assessment date: 2026-08-16
- Assessment baseline: repository `HEAD` `2bb0e2ac6053fc171b6c1a0d5dc29456dee1770f` plus the existing dirty working tree
- Audience: product owners, implementers, security reviewers, release reviewers, website authors, and AI agents
- Release evidence: none. This document defines work and gates; it does not prove a release.

## 1. Decision summary

WarpTweet has a credible product-market-fit wedge:

> Give a developer or agent one local service socket, not a shell and not a network.

The narrowness is the product. WarpTweet should make one exact remote TCP
service feel local, while avoiding an ongoing general-purpose SSH credential,
a mesh network, a hosted control plane, and a WarpTweet subscription. The
initial problem to solve exceptionally well is querying a private database,
especially Postgres in remote Docker Compose, from ordinary local tools.

Hybrid post-quantum tunnelling is valuable differentiation and a strong trust
signal, but it is not the first customer problem. The first customer problem is
the recurring setup and excess authority involved in reaching one private
service. Product copy SHOULD lead with that outcome and use the cryptographic
profile to explain how WarpTweet protects the path.

The current working tree is not release-ready. It contains substantial source
implementation for finite grants, desired route state, reconciliation commands,
and an Agent Skill, and the current source gates pass. Independent inspection
found release-critical gaps at the package and authority boundaries. In
particular, several retained routes still collapse into one global client
identity and manifest, packaged macOS `connect` attempts a protected mutation
outside the provisioner, active-session expiry has no producer for its session
ownership records, and the new Linux reconciler is neither packaged nor safe to
run as written.

The recommended path is:

1. Converge the implementation on the existing narrow service-access contract.
2. Prove signed package-to-package behavior, including real reboot and live
   expiry, before describing the new lifecycle as released.
3. Distribute a signed macOS client through a final-named private first-party
   Homebrew tap to invited testers.
4. Make the same tap public after the release evidence and website gates pass.
5. Treat the first-party tap as a valid durable channel while building public
   adoption.
6. Seek a Homebrew maintainer classification decision before promising an
   official `homebrew/core` or `homebrew/cask` destination.

The preferred product namespace is `warptweet`. `baldwinson` MAY be the GitHub
publisher or tap owner, but the package token MUST remain `warptweet`.

## 2. Contract authority and checklist immutability

This document is a normative v1 implementation and release contract. The
requirements ledger in section 16 is immutable after human approval.

Implementers and reviewers MUST NOT:

- edit a requirement ID, requirement, evidence condition, or scope condition
  in the v1 ledger;
- delete, reorder, merge, split, weaken, or reinterpret a requirement to obtain
  a pass;
- mark completion by editing this document;
- treat a failed, skipped, blocked, unrun, waived, or unobserved item as passed;
- use a newer implementation assumption to silently change what v1 requires.

Review results MUST live in a separate evidence document that references the
contract ID, checklist digest, source revision, artifact digests, environment,
and each requirement ID. The only permitted result values are `pass`, `fail`,
`blocked`, and `not_run`. Every `pass` MUST cite current-revision evidence.

If product direction genuinely changes, a human owner MUST approve a successor
contract with a new ID such as `warptweet.adoption-release.v2`. The v1 contract
and all v1 results remain historical evidence. A successor does not rewrite a
v1 result.

The canonical checklist block is delimited by exact HTML comments. Its SHA-256
is recorded after the ledger. Review automation SHOULD verify that digest
before accepting a result document.

## 3. Product thesis

### 3.1 Initial customer

The initial customer is an AI-heavy solo developer or small engineering team
that:

- manages a macOS workstation and one or more Linux staging or production
  hosts;
- occasionally needs one private TCP service from ordinary local tooling;
- currently uses `ssh -L`, a general SSH key, a VPN or mesh, a public database
  port, or an improvised tunnel;
- values open source, local control, explicit authority, and finite access;
- does not need a workforce identity platform or broad private network.

### 3.2 Primary job to be done

The primary job is:

> Query Postgres in a remote Docker Compose deployment at a stable localhost
> port, without exposing the Postgres port, maintaining a VPN mesh, or retaining
> general SSH access for ordinary use.

The same mechanism applies to other exact TCP services, but the release should
not dilute the message by starting with a generic networking taxonomy.

### 3.3 Defensible promise

The defensible promise is the combination of:

- one exact numeric remote target;
- one loopback-only local listener;
- no shell, remote command, file transfer, dynamic proxy, or subnet reach;
- a short-lived, single-use enrollment invite;
- a separate finite host-authoritative grant, 30 days by default;
- durable client intent with `unless-stopped` and `manual` restart policies;
- no silent authorization renewal;
- endpoint-generated identities and fail-closed Profile v1;
- open-source implementation with no required WarpTweet account or
  subscription.

No single element is unique. The wedge is making all of them the default
product contract for one service, with a two-machine workflow that is easier
than assembling the same controls manually.

### 3.4 Honest limits

WarpTweet narrows network and host authority. It does not constrain what a
database credential can do after connecting. It does not contain an AI process
that still holds root, Docker socket, cloud administration, or unrestricted SSH
credentials. It does not provide per-process isolation to mutually untrusted
local users who share the loopback listener.

The words `free` and `zero cost` SHOULD NOT be used as unqualified promises.
The accurate claims are `open source`, `no WarpTweet account`, and `no
WarpTweet subscription`. Users still provide machines, network reach,
operations, and target-service credentials.

### 3.5 Initial non-customers

WarpTweet is not the initial answer for users who need:

- mesh or subnet connectivity;
- arbitrary remote commands, file transfer, or a shell;
- team SSO, device posture, central workforce policy, or approval workflows;
- service discovery across many changing targets;
- public ingress, webhooks, or arbitrary outside clients;
- database query authorization, SQL safety, or session recording;
- a hosted control plane with no host administration.

Clear non-customer language protects the wedge and reduces support load.

## 4. Release scope lock

### 4.1 Required first release

The first supported release MUST provide:

- a signed and notarized macOS client package for every declared architecture;
- a signed Linux host package for every declared host architecture and
  distribution in the support matrix;
- one exact target per host installation under server manifest v1;
- several independent client grants to that same host target;
- several independent routes on one client, each with its own identity,
  receipt, trust, local port, desired state, and authorization lifecycle;
- host-controlled access duration with a 30-day installed default and a finite
  configurable maximum;
- active-session termination at expiry and revocation;
- `connect`, `routes`, `status`, `up`, `down`, `rotate`, and `revoke` with
  stable human and JSON contracts;
- reboot-safe `unless-stopped` behavior and reboot-safe `manual` behavior;
- the checked-in Agent Skill and an AI-readable documentation entry point;
- package-only positive and negative interoperability evidence;
- an accessible website with a truthful, evidence-gated install path.

### 4.2 Explicitly deferred

The following are outside the first release and MUST NOT enter its critical
path without a human-approved successor decision:

- multiple different targets behind one host installation;
- server manifest v2;
- automatic grant renewal;
- perpetual grants;
- a hosted WarpTweet control plane or account system;
- a WarpTweet-specific MCP server;
- browser administration UI;
- team RBAC, SSO, device posture, or approval queues;
- subnet, mesh, SOCKS, remote-forward, or public-ingress modes;
- Linux desktop-client support unless it receives its own package and evidence
  matrix.

### 4.3 Multi-target decision

The server manifest v1 owns one global target. That is the supported release
boundary, not an accidental limitation to hide.

Multiple clients to the one target are in scope. Multiple retained routes on a
client are in scope. Multiple different targets behind one host are deferred.
An implementer who adds a target list to v1, derives a global allow-set without
per-key isolation, or markets one host as a service gateway is off scope.

Future multi-target work requires a versioned server policy, cross-grant denial
tests, atomic policy projection, and an explicit product decision based on
observed demand. It must preserve one exact target per grant.

## 5. Market map and positioning

This table compares the job and operating model, not a universal security rank.

| Alternative | Primary job | Overlap with WarpTweet | Honest difference |
| --- | --- | --- | --- |
| OpenSSH `ssh -L` | Direct local forwarding to a remote target | Same underlying local-forward mechanism | Usually leaves key distribution, shell restriction, target policy, expiry, restart, and evidence to the operator. WarpTweet productizes those boundaries. |
| [Tailscale](https://tailscale.com/docs/features/access-control/grants) | Identity-aware connectivity across a tailnet | Device identity and port-level grants can reach a private service | Tailscale is a broader network and policy system with a control plane. WarpTweet is one service route with no WarpTweet account. Tailscale also has a generous [free Personal plan](https://tailscale.com/pricing), so WarpTweet should not position itself only as cheaper. |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/) | Connect private networks and services to Cloudflare Zero Trust | Can expose private TCP services to enrolled clients | It uses Cloudflare connectors, clients, routes, and a hosted network. WarpTweet manages both endpoints directly and has no hosted intermediary. |
| [ngrok](https://ngrok.com/docs/guides/share-localhost/tunnels) | Publish a local service through ngrok's cloud | Simple TCP tunnel and developer-friendly onboarding | The common direction is public or managed ingress to localhost. WarpTweet's primary direction is a private local socket to one remote managed service. |
| [Teleport](https://goteleport.com/docs/enroll-resources/database-access/enrollment/self-hosted/postgres-self-hosted/) | Organization-wide audited access to databases, SSH, Kubernetes, and applications | Local database proxy, expiring identity, and access policy | Teleport is a much broader access platform with cluster services, users, RBAC, and auditing. WarpTweet is intentionally smaller and does not replace database authorization or workforce governance. |
| [OpenZiti](https://openziti.io/docs/learn/quickstarts/services/) | Open-source zero-trust overlay and service identity | Named service access without changing an application | OpenZiti uses an overlay, controller, routers, identities, and optional SDK integration. WarpTweet is a fixed two-endpoint route over a pinned OpenSSH engine. |

### 5.1 Closest substitute: constrained SSH

The closest mechanical substitute is not a VPN. It is a carefully configured
OpenSSH local forward. That is useful positioning because developers already
understand `localhost`, SSH, and database clients.

WarpTweet should not claim to invent local forwarding. It should explain that
it removes the recurring security and lifecycle assembly work:

- no ongoing shell credential;
- host-generated exact destination policy;
- single-use enrollment;
- finite authorization distinct from invite expiry;
- managed client identity and host pin;
- restart-safe route state;
- package attestation and fail-closed cryptographic profile;
- one command surface for status, stop, rotation, and revocation.

### 5.2 Strongest commercial substitute: Tailscale

Tailscale solves more problems and may be the right answer when a user wants a
tailnet. Its grants support source, destination, and port policy, and its
Personal plan is free for many individual users. WarpTweet wins only when the
user actively values a narrower object:

> I do not want a private network. I want this one service at localhost.

That distinction is more durable than a pricing comparison.

### 5.3 Enterprise substitute: Teleport

Teleport offers capabilities WarpTweet intentionally lacks, including broader
resource enrollment, identity governance, audit, and database-aware access.
WarpTweet should not compete on a feature checklist. It should be the small,
self-hosted tool a developer can understand end to end.

### 5.4 Market conclusion

WarpTweet's wedge is credible if it remains easier than securely constraining
SSH and materially smaller than deploying a network or access platform. The
release should optimize installation, first successful payload, durable
reconnection, and clear failure recovery before adding targets, control planes,
or team features.

## 6. Current implementation assessment

### 6.1 What is materially present

The dirty working tree contains source implementation for:

- invite schema v2 with MAC-bound `authorization_duration_seconds`;
- 30-day default and 365-day installed maximum authorization policy;
- host `--access-for` duration parsing and policy enforcement;
- host-computed `authorization_not_after` copied into proof and client state;
- managed `authorized_keys` entries with exact `permitopen` and `expiry-time`;
- durable host client records and explicit pending states;
- durable route intent with `running`, `stopped`, `unless-stopped`, and
  `manual` values;
- `routes` and `reconcile` command surfaces;
- `connect --restart` and truthful `enrolled_not_ready` output;
- a macOS LaunchDaemon `RunAtLoad` decision based on desired state;
- a Linux reconciliation unit source file;
- the `skills/warptweet-service-access/SKILL.md` Agent Skill.

These are meaningful implementation advances. They are not package or release
evidence.

### 6.2 Current verification snapshot

At the assessed working tree:

| Check | Result | Exact boundary |
| --- | --- | --- |
| `make check` | Pass outside the filesystem/network sandbox | Go format, shell syntax, `go vet`, Go tests, enrollment control-plane tests, Astro typecheck, static build, and site output verification |
| `make test-race` | Pass outside the sandbox | Race-enabled Go package tests |
| Initial sandboxed `make check` | Expected bind failures | The sandbox denied Unix and loopback socket binds in engine and enrollment tests; the unrestricted rerun passed |
| Git release state | Incomplete | `HEAD` is `2bb0e2a`, version is `0.1.0-dev`, the feature work is dirty and partly untracked, and no Git tag is present |
| Package-to-package evidence | Not run for this revision | No current signed artifact matrix, real reboot, live expiry, or published digest proof |
| Website release gate | Closed | `homebrew_cta_enabled` is `false` and no evidence document is bound |

Source gates prove only the source-tested contracts. They do not prove clean
installation, privilege boundaries, service-manager behavior, live session
expiry, artifact signatures, notarization, Homebrew, a real reboot, or a public
deployment.

### 6.3 Release-critical findings

#### FINDING-001: per-route state still activates globally

`enrollment.BuildClientManifest` produces one tunnel. `runEnroll` then calls
`activateGeneration` with the fixed global `ClientManifestPath`,
`ClientIdentityPath`, and trust paths. A second enrollment overwrites those
global files. `runUp`, systemd, and launchd continue to load the same global
manifest.

The new route directory currently retains metadata and desired state, not a
complete independent route generation. Several routes cannot coexist safely or
operate independently. This fails the core client-route requirement.

#### FINDING-002: packaged macOS `connect` crosses the authority boundary

On macOS, `runEnroll` can be handled by the root provisioner. After that call
returns, `runConnect` calls `persistConnectDesiredState` in the unprivileged
CLI process. The route root is under the root-owned package state directory.
The default and `manual` paths therefore are not one typed privileged
transaction and can fail after the server has already consumed the invite.

The restart policy and local port MUST enter the typed provisioner request and
be committed in the same recoverable enrollment transaction.

#### FINDING-003: active-session ownership has consumers but no producer

`grantSessionStore` implements lookup, clear, and read. No production path
writes a record to `GrantSessionsDirectory`, and the sshd configuration has no
equivalent authenticated-session attribution mechanism. At expiry, the code
can remove the key but cannot prove which active sshd child belongs to the
grant. Aggregate `/proc` counting deliberately fails when ownership is unknown,
so an existing session can remain active while the grant is stuck pending.

Revocation removes authorization and may report `revoked` without terminating
or verifying an already authenticated session. Both expiry and revocation are
incomplete until they close active access.

#### FINDING-004: clock rollback does not close the data plane

Startup clock observation can fail the enrollment listener, but a later
rollback in the reconciliation loop is logged and retried. The separate sshd
service and already active sessions are not necessarily stopped. A secure
rollback response must remove effective authorization, terminate sessions, and
place the host in a visible blocked-clock state until recovery is authorized.

#### FINDING-005: Linux reconciliation is not packaged and would run tunnels as root

`warptweet-reconcile.service` is present as an untracked source file, but the
Linux package builder copies only the sshd, enrollment, and tunnel template
units. The new unit is not installed or enabled.

If installed as written, its `User=root` `ExecStart=warptweet reconcile` path
calls `runUp` directly, and that path starts the tunnel child without dropping
privileges. Linux reconciliation must project validated desired state to fixed
`warptweet-tunnel@<route>` instances, which run as the dedicated client user.

#### FINDING-006: local-port and route reservation are not complete

`connect` does not expose the existing enrollment listen-port choice, and the
default is `15432`. Multiple routes therefore collide even before the global
state issue is fixed. Existing route directories may be reused and overwritten
instead of requiring an explicit replacement or reauthorization operation.

The route ID and local port must be reserved atomically before consuming the
invite. A collision must fail with a clear action and must never silently pick
a different port.

#### FINDING-007: manual macOS policy is projected incorrectly

An explicitly started `manual` route can cause a LaunchDaemon to be written
with static `RunAtLoad=true`. That plist survives into the next boot, while the
provisioner has no boot reconciliation pass that rewrites it from the new boot
identity. The current implementation can therefore auto-start a manual route
after reboot.

#### FINDING-008: host target mutation can reinterpret existing grants

Re-running `host --to` writes a new global server target before reconciling
existing grant records. Reconciliation renders active keys from the new
manifest rather than refusing to change the immutable target stored in each
grant. A later sshd reload can redirect every old grant to a service that was
never approved for it.

Target changes must fail while grants exist or require an explicit
revoke-and-migrate transaction. Existing grants must never be reinterpreted.

#### FINDING-009: local stop uses a raw PID and can report a false terminal state

`down` signals a recorded PID without binding it to process start identity,
generation, executable, or a pidfd. After SIGKILL it can publish `stopped`
without proving the exact process exited. PID reuse can signal an unrelated
process, and stop failure can be reported as success.

#### FINDING-010: route validation and status are incomplete

A route with a missing or malformed receipt may be listed as valid, receipt
semantic validation is incomplete, and the runtime lifecycle lacks the required
blocked-expired, blocked-revoked, and blocked-policy states. Client status can
label access `expired` using local wall time without host enforcement
acknowledgment. Exact UTC parsing also accepts non-UTC offsets and normalizes
them silently.

#### FINDING-011: lifecycle integration coverage is incomplete

The new grant and route packages have useful deterministic tests. Direct tests
for the complete `connect`, `routes`, `reconcile`, packaged privilege, second
route, real reboot, live active-session expiry and revocation, target mutation,
PID reuse, rollback, and migration flows are absent or not package-backed.

#### FINDING-012: release evidence has not been versioned for the new product contract

`packaging/evidence/checklist-v1.json` predates finite grants, route desired
state, live expiry, reboot reconciliation, and Agent Skill delivery. It must
remain historical. A v2 release-evidence contract must add the new gates rather
than silently changing the meaning of v1 evidence.

The newest local interop evidence predates this dirty revision and is
incomplete. The Homebrew CTA correctly remains disabled.

#### FINDING-013: website and documentation are stale

The README and status brief still describe earlier behavior. The website does
not explain finite grants, durable routes, remote Compose, or AI-scoped access.
Its information order puts installation qualification and protocol mechanics
before the concrete problem.

The inactive install panel is a conversion dead end. If activated, it links to
an unimplemented `/docs/package-interop` route, and its inline copy script is
incompatible with the current production content-security policy. Command
examples also omit the label needed to make the shown invite filename
deterministic.

#### FINDING-014: uninstall semantics need one authority

The package uninstall script preserves identity unless the operator gives typed
destructive confirmation. The cask `zap` stanza removes the whole state
directory. The product must decide and document whether explicit `brew uninstall
--zap` is the destructive authorization, then test that exact lifecycle. Copy,
scripts, and evidence must agree.

#### FINDING-015: the Agent Skill is a draft, not a released integration

The Skill describes the narrow authority boundary well, but it currently states
reboot restoration and expiry blocking as facts that package evidence has not
proved. No package or website publishes it, and it lacks a complete cleanup and
revocation sequence. It must be corrected, evaluated, and shipped only with the
matching product behavior.

## 7. Required target architecture

### 7.1 Authority flow

```text
host operator
  -> exact target + finite duration
  -> host grant authority
  -> short-lived single-use invite
  -> client package authority
  -> immutable per-route generation + desired state
  -> native service manager
  -> loopback socket -> one remote service

host clock / expiry / revocation
  -> exact authenticated session ownership
  -> remove key + terminate connection + verify
```

### 7.2 Host target boundary

Server manifest v1 remains the sole host target authority. It contains one
canonical numeric IP address and one nonzero TCP port. Every active client key
on that host independently binds the same target with `permitopen`.

The host may grant several clients access to that target. It may not grant a
client a different target without a future versioned server policy. A target
change while any invite or grant exists must fail unless an explicit migration
first revokes every affected authorization.

### 7.3 Host grant and session ownership

Each grant must bind:

```text
grant_id
client_id
route_id
invite_id
client public key and SHA-256 digest
server manifest identity and exact target
principal
wire and artifact profile IDs
accepted_at
authorization_not_after
management-token digest
generation
status and pending-operation facts
```

The pinned data-plane implementation MUST create an authenticated session
record after successful key authentication and before forwarding is considered
available. The record must bind the grant and generation to a process identity
that cannot be confused by PID reuse. Acceptable designs include a reviewed
OpenSSH integration that emits the record or per-grant process isolation that
makes the service manager authoritative. Aggregate process counting, log text
parsing, timing inference, and an unwritten planned record are not sufficient.

On Linux, termination SHOULD use a pidfd or an equivalently strong process
identity, revalidate the expected WarpTweet sshd ancestry and grant binding,
signal the exact process, and verify exit. If attribution is missing or
corrupt, the host must fail closed. Stopping all WarpTweet data-plane sessions
is a safe recovery action, but it is not evidence of exact per-client expiry.

### 7.4 Expiry and revocation transaction

The host terminal-access transaction is:

1. serialize the grant mutation;
2. persist `expiration_pending` or `revocation_pending`;
3. remove the exact effective key authorization;
4. read back and prove that authorization is absent;
5. terminate every active process bound to the grant generation;
6. prove the processes and forwards are gone;
7. burn the management capability;
8. persist the requested terminal state with an exact UTC time;
9. expose the terminal state to client status without implying renewal.

A failure at any step remains pending and is resumed idempotently. It is never
reported terminal while effective access remains.

### 7.5 Clock failure

The host persists the last accepted wall-clock observation. A material
rollback, implausible time, unreadable observation, or incompatible state MUST:

- block new enrollment and authorization;
- remove active managed authorizations;
- terminate existing WarpTweet data-plane sessions;
- expose a `blocked_clock` or equivalent typed state and diagnostic;
- require documented operator recovery after clock trust is restored.

Merely logging the event while sshd continues is forbidden. Small tolerated
clock movements must never move the durable high-water mark backward.

### 7.6 Per-route client generations

The client package authority owns a fixed route root. A logical layout is:

```text
routes/<route-id>/
  desired.json
  active.json
  receipt.json
  generations/<generation-id>/
    client.wt
    identity
    identity.pub
    known_hosts
    known_hosts.empty
    metadata.json
  pending/<operation-id>/...
```

This shape is illustrative, but the invariants are mandatory:

- every route has a distinct private identity and management capability;
- `active.json` or its equivalent names one immutable generation;
- activation is atomic and crash recoverable;
- runtime processes never select caller-provided paths;
- the tunnel service identity can read only the files needed for its route;
- management capabilities remain available only to the package authority;
- route and generation names are validated before any filesystem or service
  manager use;
- no symlink, hard-link, ownership, mode, or path substitution can cross routes;
- a second enrollment cannot overwrite an unrelated route;
- an older binary cannot ignore expiry or desired state on downgrade.

The fixed global `client.wt`, identity, and trust layout must be migrated to a
per-route authority or rejected with a recoverable migration instruction. It
must not remain the active authority for several routes.

### 7.7 Connect transaction

The public target interface SHOULD be:

```text
warptweet connect <invite.wtinvite> \
  [--listen-port <port>] \
  [--restart unless-stopped|manual] \
  [--yes]
```

`connect` must perform one recoverable package-authority transaction:

1. strictly read and validate the invite by path;
2. show server, target, local port, duration, expected expiry, profile,
   fingerprint, restart policy, and broader-authority warning;
3. atomically reserve a unique route ID and stable local port;
4. stage an immutable route generation and local secrets;
5. enroll over invite-pinned hybrid TLS;
6. persist the exact host proof and authorization expiry;
7. activate the generation and desired state;
8. project the route to launchd or systemd as the dedicated service identity;
9. wait for PID-bound authenticated-forward readiness;
10. report `connected` only after readiness.

The restart policy and local port must be included in the typed macOS
provisioner request. No unprivileged post-enrollment write may be required.

If enrollment succeeds but activation or start fails, the route remains
recoverable and the result is `enrolled_not_ready` with a safe next action.

### 7.8 Native reconciliation

On Linux, a root-owned reconciler may validate route records and enable,
disable, start, or stop only fixed `warptweet-tunnel@<validated-route-id>`
instances. The actual tunnel unit runs as `warptweet-client`. The reconciler
must be included in package manifests, installed, enabled, hardened, and tested.

On macOS, the existing typed root provisioner projects validated per-route
LaunchDaemons. Each tunnel runs as `_warptweet`. `RunAtLoad` and service loading
must derive from durable desired state, current boot identity, and authorization
validity at every boot. A static prior-boot value is not authoritative.

Neither platform may accept arbitrary unit names, labels, plist fragments,
paths, users, groups, executable options, or environment values.

### 7.9 Truthful status and stop

Actual state remains separate from desired state and host authorization state.
The machine contract must represent stopped, starting, awaiting readiness,
ready, backoff, stop pending, blocked expired, blocked revoked, blocked policy,
blocked clock, and failed where applicable.

`down` must bind the recorded process to its generation and process-start
identity, signal safely, verify exit, and only then report `stopped`. Local
clock inference may report `expiry_expected`, but only host acknowledgment or
observed enforcement may report host access terminal.

## 8. Golden paths and common use cases

### 8.1 Remote Docker Compose Postgres

Compose should publish Postgres only on host loopback:

```yaml
services:
  db:
    image: postgres:17
    ports:
      - "127.0.0.1:5432:5432"
```

The host operator then runs:

```sh
warptweet host --to 127.0.0.1:5432 --name staging-db --access-for 30d
```

On the client:

```sh
warptweet connect staging-db.wtinvite --listen-port 15432 --restart unless-stopped
psql "host=127.0.0.1 port=15432 dbname=app"
```

The `--listen-port` form is target interface direction and is not evidence that
the assessed implementation already supports it through `connect`.

WarpTweet must never change Compose, publish Postgres on `0.0.0.0`, invent a
container IP, restart the database, or claim tunnel readiness proves database
health.

### 8.2 Agent-scoped investigation

A human or separately authorized host automation creates a route to one exact
service for a finite period. The agent receives the local socket and the
minimum service credential needed for its task. It does not retain the host SSH
credential used for bootstrap.

The website phrasing may be:

> Give the agent a database socket, not SSH access to the host.

The adjacent qualification is mandatory:

> WarpTweet narrows host and network authority. The database credential still
> controls what the agent can do, and any retained root or SSH access remains
> outside this boundary.

### 8.3 Durable staging route

The developer enrolls once, leaves the route `unless-stopped`, and uses the same
local port after restart or transient network loss until the host grant expires.
`down` persists stopped. `manual` does not start merely because the machine
rebooted. No policy silently renews the 30-day grant.

### 8.4 Private API or admin TCP service

An internal API, Redis instance, or TCP administration service remains
unpublished on its target port. WarpTweet exposes only a loopback listener to
the authorized client. The application protocol and credentials remain the
service's responsibility.

### 8.5 Bootstrap boundary

Installing the host package and creating the first invite may require broad
operator authority. That is a bootstrap event, not evidence that WarpTweet
constrains the bootstrap session. Documentation must tell an AI operator to
return, remove, or separately retain any broad credential before ordinary
service work.

## 9. Website and documentation direction

### 9.1 Information order

The public site SHOULD use this order:

1. outcome-led hero;
2. top concrete use cases;
3. exact host, invite, connect, localhost flow;
4. why this is narrower than SSH or a VPN;
5. client and host installation paths;
6. finite grant and durable route lifecycle;
7. AI use and its limits;
8. protocol and cryptographic detail;
9. open-source, security, evidence, and contribution links.

The `.wt` format is an advanced verifiability detail. The first customer mental
model is `enroll once; WarpTweet remembers the route`, once reboot behavior has
package evidence.

### 9.2 Recommended hero

Kicker:

> One service. One local port.

Heading:

> Hybrid post-quantum tunnelling.

Deck:

> Reach Postgres, a private API, or another TCP service on a remote machine
> through localhost. No exposed target-service port, VPN mesh, or
> general-purpose SSH access for the ongoing client.

Concrete line:

> Query Postgres in remote Docker Compose at `localhost:15432`.

Trust strip:

> Open source · No account · No subscription

The dark-gate primary action should be `See how it works`, with `View source`
as a secondary action. After release evidence activates installation, the
primary action may become `Install WarpTweet`, with `Quickstart` secondary.

### 9.3 Top use cases

The first use-case group should be:

1. Remote Docker Compose Postgres through localhost.
2. Task-scoped service access for an AI agent.
3. A staging route that restores after reboot until grant expiry.
4. A private API or admin TCP service without publishing its target port or
   building a mesh.

Generic labels such as `development services` may follow. They should not
replace the concrete jobs.

### 9.4 Install story

Every working route has two installations. The site must show them separately:

- macOS client through the signed Homebrew cask;
- supported Linux host through the exact signed package and bootstrap command.

Each path is independently gated by its declared platform and package evidence.
The site must not offer a working client install while leaving the required host
package undiscoverable.

While the public gate is closed, source, quickstart, security, release status,
and evidence links remain available. A disabled install CTA must not be a dead
end.

### 9.5 Command fixtures and links

Website command/output examples must execute against the current CLI or derive
from tested fixtures. The host example must include `--name staging-db` if it
shows `staging-db.wtinvite`. New host output must include invite expiry and
authorization duration accurately.

Every emitted local and external link must be checked during the site build.
No link may be activated before its route or destination exists.

### 9.6 Web security and accessibility

If the copy button remains, move its behavior to a CSP-compatible same-origin
asset, expose success and failure through an accessible status message, and
test clipboard unavailability. Alternatively, remove the button and keep the
command selectable.

The duplicate nested install `section` and accessible-name relationship must be
corrected. WCAG 2.2 AA verification must combine automation with manual
keyboard, focus, screen-reader, zoom, reflow, spacing, contrast-state, theme,
forced-color, reduced-motion, and target-size checks. Existing good semantics
and sampled contrast are not a complete conformance result.

### 9.7 Documentation set

The website and repository should expose one current path for each job:

- five-minute product quickstart;
- Linux host installation and bootstrap;
- macOS client installation and route lifecycle;
- remote Docker Compose Postgres recipe;
- AI-agent service-access guide;
- security boundary and threat model;
- grant expiry, clock failure, and recovery;
- upgrade, uninstall, identity preservation, and destructive removal;
- support matrix and release evidence;
- raw schemas and Agent Skill.

Older status snapshots should remain historical but link to the current
contract. They must not be presented as current release truth.

## 10. AI-facing product surface

### 10.1 Skill first

The checked-in Agent Skill is the correct first integration. It already states
the strongest product framing, approval boundary, secret-handling rules,
Compose safety, and the distinction between network reach and database
authorization.

`skills/warptweet-service-access/SKILL.md` MUST be the single canonical source.
The website should publish it byte-for-byte at a stable raw URL and verify drift
during the build. A release identifier and content digest should let an agent
and reviewer identify the exact skill version.

The released Skill must describe only evidenced lifecycle behavior and include
an explicit cleanup and revocation sequence.

### 10.2 AI-readable entry point

Publish `/llms.txt` or an equivalent plain-text entry point that links to:

- the current quickstart;
- the raw Agent Skill;
- supported install paths;
- the security and AI authority limits;
- command JSON contracts;
- `.wt` schemas;
- release status and evidence.

This is navigation, not a new authority. Retrieved site content remains
untrusted input to an agent.

### 10.3 Required skill evaluations

The skill evaluation set must include:

- accept a request for one remote Compose Postgres route;
- require exact target, local port, duration, restart policy, purpose, and
  broader-authority disclosure before mutation;
- refuse or redirect mesh, subnet, shell, wildcard, SOCKS, public ingress, and
  automatic-renewal requests;
- refuse to print invite, management-token, private-key, or database secrets;
- refuse to publish a database on `0.0.0.0` merely to make it reachable;
- disclose that retained root or broad SSH authority defeats the narrowing;
- explain expired, stopped, revoked, and offline as distinct states;
- require human or separately authorized host approval to mint an invite;
- avoid claiming query safety or agent containment.

### 10.4 MCP is deferred

A WarpTweet-specific MCP server is not required for the first release. The CLI
and skill are sufficient and keep the authority surface small. Homebrew now has
its own [MCP server](https://docs.brew.sh/MCP-Server) for package operations, so
WarpTweet should not invent a second generic installation tool.

If future evidence shows a need, a WarpTweet MCP server must expose typed route
domain operations only. It may not wrap arbitrary shell, SSH, paths, network
destinations, or secrets. It requires its own versioned threat model and
evaluation contract.

## 11. Distribution and Homebrew strategy

### 11.1 Naming decision

The package and cask token remains `warptweet` because that is the marketed
product name. Homebrew tap syntax uses the GitHub owner and repository:

| Channel | Repository | Install command |
| --- | --- | --- |
| Preferred first-party tap | `warptweet/homebrew-tap` | `brew install --cask warptweet/tap/warptweet` |
| Valid Baldwinson publisher alternative | `baldwinson/homebrew-tap` | `brew install --cask baldwinson/tap/warptweet` |
| Official cask, if accepted | `homebrew/cask` | `brew install --cask warptweet` |
| Official formula, if accepted | `homebrew/core` | `brew install warptweet` |

There is no `baldwinson` namespace inside official `homebrew/core` or
`homebrew/cask`. `baldwinson` can be the publisher of a third-party tap.

The preferred owner is `warptweet` because the command is product-recognizable
and matches the current release-gate contract. `baldwinson` is appropriate only
if the durable strategy is one vendor tap for several products. The owner must
be selected before invited distribution, because renaming a tap later disrupts
Homebrew [supply-chain trust](https://docs.brew.sh/Supply-Chain-Security) and
user instructions.

### 11.2 Private alpha tap

Create the final-named tap as a private Git repository. Publish only signed,
notarized, immutable, checksummed release-candidate packages. Use the fully
qualified cask name so testers trust that item rather than the whole tap.

The private alpha is not permission to lower the security contract. It may
declare a smaller test support matrix, but every distributed artifact must be
bound to its exact source, signature, notarization result, provenance, and
tested platform. The public website CTA remains closed.

### 11.3 Public first-party tap

After the full public-release evidence passes, change the same repository to
public and preserve the same command. The first-party tap is upstream-supported
and is not Homebrew endorsement. It may remain the durable distribution channel
even if official inclusion is delayed or declined.

### 11.4 Official Homebrew destination

WarpTweet has a real classification tension:

- the working macOS product is a signed `.pkg` that establishes a fixed,
  root-owned layout, dedicated identity, and privileged helper, which is
  technically cask-shaped;
- current Homebrew policy says open-source command-line-only software normally
  belongs in `homebrew/core`;
- `homebrew/core` requires a stable source build, while a controller-only build
  is not the complete WarpTweet security product.

Do not weaken the fixed package and privilege model merely to fit a repository.
After public usage exists, ask Homebrew maintainers for a package-classification
decision, with the exact signed package design, uninstall lifecycle, and reason
a controller-only formula is incomplete.

The deterministic project milestone is `official-submission-ready`. Acceptance
is controlled by Homebrew maintainers and must be recorded separately. Current
Homebrew requirements include a stable release, active public maintenance,
latest-macOS operation for declared casks, and public interest beyond the
author. These policies must be re-read at submission time:

- [acceptable casks](https://docs.brew.sh/Acceptable-Casks);
- [acceptable formulae](https://docs.brew.sh/Acceptable-Formulae);
- [package acceptance policy](https://docs.brew.sh/Package-Acceptance-Policy);
- [third-party taps](https://docs.brew.sh/Taps);
- [cask cookbook](https://docs.brew.sh/Cask-Cookbook).

## 12. Release and deployment architecture

### 12.1 Artifact promotion

One immutable release version must bind:

- source commit and clean-tree state;
- Go, Node, pnpm, OpenSSH, OpenSSL, and build-environment versions;
- authenticated upstream source receipts;
- client and host engine manifests;
- macOS arm64 and amd64 package digests;
- every declared Linux host package digest;
- Developer ID signature, notarization, and stapling evidence;
- Linux package signature or repository metadata signature;
- SBOM and provenance;
- rendered cask and its architecture digests;
- package-to-package evidence;
- website release-gate document.

Promotion is one-way and digest-based. Rebuilding the same version with
different bytes is forbidden. A failed candidate receives a new version.

### 12.2 Linux host distribution

Homebrew solves only the macOS client install. The release must provide an
equally clear Linux host path. The initial public path may use signed packages
attached to an immutable release, followed by a package repository when its
metadata, key rotation, rollback, and incident operations are defined.

The site must name exact supported distributions and architectures from the
evidence matrix. `Linux` alone is not a support claim.

### 12.3 Website deployment

Before public deployment, verify the production build behind the actual Caddy
or equivalent configuration:

- canonical HTTPS redirect and certificate behavior;
- CSP, HSTS, content-type, framing, referrer, and permissions headers;
- correct 404 behavior and no broken internal links;
- cache policy for HTML, versioned assets, schemas, skill, and `llms.txt`;
- health endpoint behavior;
- canonical, description, Open Graph, robots, and sitemap metadata;
- responsive and accessibility state matrix;
- release-gate behavior with install disabled and enabled;
- privacy behavior with no analytics, cookies, or third-party scripts unless a
  separate approved contract adds them.

This strategy authorizes local documentation only. It does not authorize
creating repositories, tags, releases, taps, packages, deployments, or public
communications.

## 13. Evidence model

### 13.1 Versioned release evidence

Create a new release-evidence checklist and schema version for the finite-grant
and durable-route product. Do not edit v1 evidence to imply it covered behavior
that did not exist.

The v2 result must bind at least:

```text
contract_id
contract_checklist_sha256
release_version
source_commit
clean_tree_proof
client and host package digests
client and host engine manifest digests
platform, architecture, and OS versions
host target and authorization policy
route count and restart policies
commands and exit codes
started_at and finished_at
evaluator identity
redacted logs and artifacts
per-requirement results
failures, blocked items, and unrun items
```

### 13.2 Package test matrix

The public release matrix must cover every declared macOS client architecture
against every declared Linux host architecture. Missing runner pairs are
`not_run`, never pass. Representative flows include:

- clean install on both machines;
- host bootstrap and deterministic invite output;
- encrypted enrollment and single-use denial;
- authenticated readiness and deterministic payload;
- exact negotiated profile and rekey;
- neighboring target denial and prohibited SSH surface denial;
- a second client grant to the same target;
- two independent client routes without overwrite or port collision;
- `unless-stopped`, `down`, and `manual` across real reboot;
- transient network failure and bounded reconnection;
- active tunnel at grant expiry, exact termination, and no reconnection;
- clock rollback fail-closed behavior;
- rotation, revocation, reauthorization, and response-loss recovery;
- host target-change denial while any invite or grant exists;
- PID reuse and stop-failure truthfulness;
- upgrade, downgrade rejection, uninstall, zap or destroy, and reinstall;
- remote Docker Compose Postgres bound only to host loopback;
- agent-like use under a dedicated local identity without retained host SSH.

### 13.3 Claim derivation

Every website and README feature claim must map to one or more passed evidence
IDs for the exact published artifacts. Source tests may support implementation
confidence but may not activate a package, platform, reboot, accessibility,
security, or deployment claim.

## 14. Ordered implementation strategy

Points measure relative movement toward the ideal. They are not calendar or
staffing estimates.

| Order | Work package | Points | Exit condition |
| ---: | --- | ---: | --- |
| 1 | Scope lock, current-truth docs, contract/result format, and v2 evidence schema | 3 | One authority for release requirements and no stale current-status claims |
| 2 | Complete per-route immutable client generations and migration | 8 | Two routes operate independently without shared secrets or global overwrite |
| 3 | Make `connect` one typed privileged transaction with port reservation | 5 | Packaged macOS default and manual connect paths succeed without a second elevation or partial unauthorized write |
| 4 | Implement exact host session attribution, live expiry, revocation, clock fail-close, and target immutability | 13 | Active matching sessions terminate and are observed gone at the authority boundary |
| 5 | Project durable state through native launchd and systemd services | 8 | Dedicated identities own data-plane processes and real reboot semantics pass |
| 6 | Close lifecycle, migration, security, and recovery tests | 8 | Deterministic and package-backed negative paths pass at the current revision |
| 7 | Produce signed release candidates and private final-named tap | 8 | Invited testers install exact attested artifacts through the qualified cask |
| 8 | Reframe website, publish docs and Skill, and complete accessibility verification | 8 | Outcome-led public surface is useful while dark and evidence-derived while active |
| 9 | Complete full package matrix and public first-party tap release | 13 | Release gate binds complete evidence and public install works from clean machines |
| 10 | Build adoption evidence and become official-submission-ready | 5 | Current Homebrew policy, classification, cask or formula checks, and upstream support obligations are satisfied |

Multi-target host work and a WarpTweet MCP server have zero points in this
sequence because they are deferred, not because they are free.

## 15. Review result format

A reviewer should create a separate file such as:

```text
packaging/evidence/adoption-release-v1/<source-commit>.json
```

Minimum conceptual shape:

```json
{
  "kind": "warptweet.adoption-release-result",
  "schema_version": 1,
  "contract_id": "warptweet.adoption-release.v1",
  "contract_checklist_sha256": "<exact digest below>",
  "source_commit": "<40 lowercase hex>",
  "release_version": "<candidate version>",
  "results": [
    {
      "id": "SCOPE-001",
      "status": "pass",
      "evidence": ["<repository-relative or immutable evidence reference>"],
      "notes": "<scope and limits>"
    }
  ]
}
```

A result schema must reject unknown IDs, duplicate IDs, missing IDs, unknown
statuses, duplicate JSON member names, trailing values, oversized input, and a
contract digest mismatch. Review tooling may compare results to the ledger. It
may not edit the ledger.

## 16. Immutable acceptance ledger

<!-- BEGIN WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->

### Product and scope

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| SCOPE-001 | The supported product grants one loopback local port to one exact numeric remote TCP service. | Package-backed positive payload plus neighboring host and port denial. |
| SCOPE-002 | Server manifest v1 supports exactly one target per host installation. | Schema, config, CLI, rendered sshd policy, tests, docs, and site contain no target list, wildcard, DNS target, or gateway claim. |
| SCOPE-003 | Several clients may hold independent grants to the host's one target. | Package test with at least two clients, independent keys, expiry, rotation, and revocation. |
| SCOPE-004 | Several routes coexist on one client without shared identity, shared management capability, overwrite, or local-port collision. | Package test with at least two different hosts or grants and concurrent deterministic payloads. |
| SCOPE-005 | Shell, exec, SCP, SFTP, SOCKS, subnet, mesh, remote forwarding, agent forwarding, X11, TUN/TAP, wildcard, and alternate target access remain unavailable. | Negative package matrix against every prohibited surface. |
| SCOPE-006 | Product copy does not claim agent containment, database query safety, anonymity, quantum-proof security, IETF-standardized composite authentication, FIPS validation, or availability guarantees. | Repository-wide copy scan and human security review. |
| SCOPE-007 | Multi-target host, automatic renewal, hosted control plane, and WarpTweet MCP remain out of first-release scope. | Public APIs, packages, docs, site, skill, and release notes contain no such behavior or claim. |
| SCOPE-008 | The package token and product name are `warptweet`; publisher namespace is represented separately. | Cask, tap, release metadata, website, and docs read-back. |

### Client route architecture

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| CLIENT-001 | Every route has a complete protected generation containing or securely referencing its own manifest, identity, trust, receipt, expiry, desired state, and recovery state. | Filesystem read-back with owner, group, mode, ACL, inode, and content assertions on clean packages. |
| CLIENT-002 | A second enrollment cannot overwrite or invalidate an unrelated active route. | Crash-injected and ordinary second-route package tests with first-route payload before and after. |
| CLIENT-003 | Route and generation activation is atomic and restart recoverable. | Fault injection at every durable boundary proves old valid or recoverable new state, never a mixed generation. |
| CLIENT-004 | Route IDs are validated before filesystem, service label, unit, plist, log, or socket use. | Traversal, separator, Unicode, case, length, collision, symlink, hard-link, and service-escaping negative tests. |
| CLIENT-005 | Route IDs and local ports are reserved before invite consumption and conflicts fail without silent replacement or reassignment. | Concurrent connect, existing route, and occupied-port tests with invite and prior-state read-back. |
| CLIENT-006 | `connect` exposes a stable local-port choice and defaults only when the default is available. | CLI contract tests and package tests for default, explicit, invalid, duplicate, and occupied ports. |
| CLIENT-007 | `connect` defaults to desired `running` and restart `unless-stopped`. | Human and JSON output plus durable desired-state read-back. |
| CLIENT-008 | `down` persists `stopped` before process stop and remains stopped after real reboot. | Package process identity, durable record, stop read-back, and real reboot evidence. |
| CLIENT-009 | `manual` starts only after explicit `up` in the current boot and does not start merely because of reboot. | Current-boot and stale-boot package tests across real reboot. |
| CLIENT-010 | `up` and `down` act on the exact route process and never signal an unrelated or PID-reused process. | PID identity or pidfd tests with substitution and reuse attempts. |
| CLIENT-011 | `down` reports `stopped` only after verified exact-process exit; failures remain stop-pending or failed. | Injected SIGTERM and SIGKILL failure tests with process read-back. |
| CLIENT-012 | Runtime state is observation only and never silently changes desired state. | State-loss, stale-state, and reconstruction tests. |
| CLIENT-013 | One malformed route remains visible as invalid without hiding or blocking valid routes. | Multi-route listing and lifecycle tests with malformed, missing, unreadable, and incompatible receipts and intents. |
| CLIENT-014 | Expired and revoked routes enter distinct terminal blocked states and do not busy-retry or self-renew. | Clock-controlled package tests plus bounded log and process observations. |
| CLIENT-015 | Client status distinguishes local expiry expectation from host-acknowledged enforcement. | Disconnected, skewed-clock, active, pending, enforced-expired, and revoked machine-contract tests. |
| CLIENT-016 | Upgrade, downgrade rejection, rollback or recovery, uninstall, identity preservation, destructive removal, and reinstall preserve the documented per-route lifecycle. | Package lifecycle matrix with exact state read-back. |

### Privilege and native supervision

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| PRIV-001 | macOS `connect` sends invite, local port, restart policy, and required route facts through one typed provisioner transaction. | Protocol schema tests and installed unprivileged CLI flow with no post-provisioner protected write. |
| PRIV-002 | The macOS provisioner accepts no arbitrary shell, path, OpenSSH option, plist, label, owner, group, mode, user, or environment input. | Protocol fuzz and negative tests against the installed socket. |
| PRIV-003 | Every macOS tunnel process runs as `_warptweet`, never root or the interactive administrator. | launchd PID, UID, GID, executable, arguments, environment, and file-access read-back. |
| PRIV-004 | Every boot reconciles macOS desired state and current boot identity before any manual route can load. | Real reboot evidence for manual running, manual stopped, unless-stopped running, and explicit down. |
| PRIV-005 | Linux reconciliation projects only validated route IDs to fixed `warptweet-tunnel@` units. | Unit tests, package inventory, service-manager audit, and injection negatives. |
| PRIV-006 | Every Linux client tunnel process runs as `warptweet-client`, never root. | systemd cgroup, UID, GID, executable, arguments, environment, and capability read-back. |
| PRIV-007 | Reconciliation units are included, hardened, enabled or triggered as designed, and removed safely by the package. | Package database, unit file, enablement, boot, upgrade, and uninstall evidence. |
| PRIV-008 | launchd and systemd are projections of durable desired state, not independent authorities. | Drift injection followed by deterministic reconciliation and state read-back. |
| PRIV-009 | Service-manager restart and in-process retry are bounded and do not create duplicate tunnel processes. | Network-fault, crash, wake, and restart-limit tests with process counts and log budgets. |

### Authorization lease and host authority

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| LEASE-001 | Invite lifetime and authorization lifetime are distinct typed values and user-visible concepts. | Invite, proof, host record, receipt, status, docs, and CLI fixture assertions. |
| LEASE-002 | Installed authorization default is exactly 30 days and installed maximum is finite. | Policy read-back and clock-controlled tests. |
| LEASE-003 | Host accepts shorter and longer finite per-invite durations within policy and rejects values above maximum without clamping. | Duration boundary, overflow, syntax, and policy package tests. |
| LEASE-004 | The client cannot alter, extend, or silently renew the host-authoritative duration or expiry. | Tampered invite, proof, receipt, replay, rotation, and expired-token negative tests. |
| LEASE-005 | Every effective key line binds the exact key, principal context, target, and expiry with canonical `restrict`, `port-forwarding`, `permitopen`, and `expiry-time` policy. | Installed authorized_keys byte comparison plus `sshd -T` and authentication tests. |
| LEASE-006 | Existing invitations and grants cannot be reinterpreted by changing the host's global target. | Active-grant and issued-invite target-change denial plus explicit migration test. |
| LEASE-007 | New authentication fails at and after expiry. | Clock-controlled packaged OpenSSH authentication test at before, exact, and after boundaries. |
| LEASE-008 | The host creates an authoritative, durable, authenticated mapping from grant generation to each active data-plane process. | Post-auth process record and process-identity read-back from the packaged engine. |
| LEASE-009 | Expiry of a live route terminates every matching active session and proves the exact processes and local forward are gone. | Observed live payload, expiry, process exit, listener failure, and terminal record at the authority boundary. |
| LEASE-010 | Revocation of a live route terminates every matching active session before terminal success. | Same evidence shape as LEASE-009 under explicit revocation. |
| LEASE-011 | Expiry and revocation remove effective authorization and read back absence before terminal success. | File and authentication read-back with injected write and verification failures. |
| LEASE-012 | Expiry burns the management capability, and expired access requires a new host-approved invite and generation. | Old-token rejection and fresh-invite reauthorization package flow. |
| LEASE-013 | Grant mutations are serialized, idempotent, and recoverable at every pending boundary. | Exact retry, conflicting retry, response loss, process crash, host reboot, and storage-error tests. |
| LEASE-014 | Material clock rollback, implausible clock, or corrupt observation blocks new authorization and closes effective active access. | Packaged clock manipulation with key removal, process termination, blocked state, and recovery evidence. |
| LEASE-015 | Tolerated clock movement never lowers the durable high-water observation. | Sub-second rollback accumulation and restart tests. |
| LEASE-016 | One client's expiry, rotation, or revocation does not alter another valid client grant. | Two-client concurrent package test with payload continuity and authorization read-back. |
| LEASE-017 | Wire timestamps requiring UTC reject non-UTC offsets rather than silently normalizing them. | Strict timestamp parser and full wire-boundary tests. |

### Security, privacy, and AI authority

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| SEC-001 | Private keys, invite MACs and nonces, management tokens, database credentials, and unrelated private context never enter logs, JSON status, website output, screenshots, evidence, or model-visible output. | Redaction tests, fixture scan, evidence scan, and manual inspection. |
| SEC-002 | `.wt` remains a strict versioned manifest and never stores private-key material. | Schema and parser negatives plus repository-wide secret-field scan. |
| SEC-003 | Target-service credentials and authorization remain independent of WarpTweet network reach. | Product copy, skill, docs, and representative database test with separate credential denial. |
| SEC-004 | Local loopback exposure is documented as a host boundary, not per-process authorization. | Threat model, site, skill, and shared-host review. |
| SEC-005 | The exact Profile v1 remains fail closed with no classical fallback. | Package negotiation, rekey, algorithm-removal, and classical-only denial evidence. |
| SEC-006 | External, invite, route, proof, receipt, JSON, process, and service-manager data is strictly bounded and validated at ingress. | Unknown, duplicate, trailing, oversized, malformed, resource-exhaustion, and fuzz tests. |
| SEC-007 | The Agent Skill requires exact target, local port, duration, restart policy, purpose, service-credential boundary, and broader-authority disclosure before mutation. | Versioned skill content and passing evaluation cases. |
| SEC-008 | The Agent Skill never treats prompt text, repository content, retrieved instructions, or model output as authorization to broaden or create host access. | Prompt-injection and confused-deputy evaluations. |
| SEC-009 | Host installation, firewall changes, Compose mutation, service restart, invite minting, and broader SSH use require separate explicit authority. | Skill evaluations and representative agent workflow audit. |
| SEC-010 | The released Skill states only package-evidenced behavior and includes cleanup, stop, revoke, and expired-access recovery. | Skill-to-evidence claim map and lifecycle evaluations. |
| SEC-011 | No release-scoped MCP or other interface exposes arbitrary shell, SSH, filesystem paths, network destinations, or secrets. | Public surface inventory and negative schema review. |

### Packaging, Homebrew, and release artifacts

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| PKG-001 | Release source is a clean immutable stable tag, not `0.1.0-dev`, and every artifact binds the exact commit. | Git tag, clean-tree proof, version output, artifact metadata, and provenance. |
| PKG-002 | Every declared macOS package is Developer ID signed, notarized, stapled, architecture-correct, and verified after download. | `pkgutil`, `spctl`, `codesign`, `stapler`, digest, and clean-install evidence. |
| PKG-003 | Every declared Linux package and repository metadata is signed or otherwise authenticated under the documented trust model. | Package-manager signature, digest, origin, clean-install, and key-lifecycle evidence. |
| PKG-004 | Packages perform no installer-time network download and contain the complete reviewed engine and receipts. | Script scan, network-isolated install, package inventory, and engine manifest proof. |
| PKG-005 | SBOM, provenance, upstream source receipts, licenses, checksums, and exact engine manifests are published for every artifact. | Immutable release asset inventory and validator output. |
| PKG-006 | Install, upgrade, failed upgrade recovery, downgrade rejection, uninstall, destructive removal, reinstall, and package rollback or recovery are tested on every declared platform family. | Package lifecycle result matrix. |
| PKG-007 | Identity preservation and `brew uninstall --zap` semantics have one documented authority and require an explicit destructive user action. | Cask, script, copy, manual action, and filesystem read-back. |
| PKG-008 | The cask token is `warptweet`, uses immutable architecture URLs and SHA-256 values, installs the full `.pkg`, and defines complete uninstall behavior. | Rendered cask review, audit, style, install, operation, and uninstall. |
| PKG-009 | The final-named private tap is used before public distribution and the fully qualified item is installed without disabling trust. | Tap repository identity and invited clean-machine install transcript. |
| PKG-010 | Public first-party tap activation occurs only after complete public-release evidence for the published digests. | Release-gate validation and public clean-machine install. |
| PKG-011 | Official Homebrew acceptance is not claimed as a deterministic internal pass; official-submission readiness and external acceptance are recorded separately. | Strategy, release report, and submission record review. |
| PKG-012 | Current Homebrew cask or formula classification and acceptance policies are revalidated immediately before submission. | Dated official-source review and maintainer classification discussion. |

### Website, documentation, and accessibility

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| WEB-001 | The first viewport states the exact one-service job and the no-shell/no-network boundary in outcome language. | Rendered desktop, mobile, zoomed, and text-only review. |
| WEB-002 | The top four use cases are remote Compose Postgres, agent-scoped access, durable staging route, and private TCP API or admin service, with required security qualifications. | Rendered content review and copy-to-evidence mapping. |
| WEB-003 | Host and client installation paths are distinct and independently support-matrix gated. | Dark and active state builds plus clean-machine path tests. |
| WEB-004 | The dark release gate has no misleading or dead primary CTA and always exposes source, quickstart, security, status, and evidence. | Rendered dark-state link and action test. |
| WEB-005 | Every feature and status claim derives from current published package evidence. | Automated claim map plus human release review. |
| WEB-006 | Every command and output example executes or fixture-tests against the released CLI. | Site build fixture test with exact output normalization rules. |
| WEB-007 | The canonical Agent Skill is published byte-for-byte from one source with version and digest, and drift fails the build. | HTTP bytes, repository bytes, digest, and build-negative test. |
| WEB-008 | An AI-readable index links quickstart, Skill, security limits, machine contracts, schemas, and release status. | Production HTTP and content review. |
| WEB-009 | Every internal and external link is checked; no enabled link returns an unexpected error or nonexistent route. | Build link checker and production crawl. |
| WEB-010 | Any copy interaction works under production CSP and announces success and failure accessibly. | Production-header browser test with clipboard allowed and unavailable. |
| WEB-011 | The complete affected web flow passes WCAG 2.2 AA automation and knowledgeable manual evaluation. | Retained semantic scan, contrast matrix, keyboard, focus, screen-reader, 200% zoom, 320px reflow, spacing, theme, forced-color, reduced-motion, and target-size evidence. |
| WEB-012 | Website analytics, cookies, trackers, and third-party scripts remain absent unless separately approved and disclosed. | Production network, storage, header, and source audit. |
| WEB-013 | Tap-era and official-era commands and namespaces derive from versioned release configuration, not component hardcoding. | Source review plus dark, tap, and official fixture builds. |
| WEB-014 | `Open source`, `no account`, and `no subscription` claims remain true, while unqualified `free` or `zero cost` claims are absent. | Product, code, dependency, network, and copy review. |
| WEB-015 | Production deployment validates HTTPS, security headers, CSP, 404s, cache policy, health, responsive states, canonical metadata, Open Graph, robots, and sitemap. | Production HTTP and browser evidence bound to deployment revision. |
| WEB-016 | README, quickstart, status brief, lifecycle docs, website, CLI help, and Skill agree on current commands, defaults, expiry, restart, support, and release state. | Cross-document contract test and human review. |

### Verification and completion

| ID | Requirement | Required evidence for pass |
| --- | --- | --- |
| VERIFY-001 | Required format, shell syntax, vet, deterministic Go tests, enrollment control-plane tests, Astro checks, static build, and site verification pass at the release revision. | Exact `make check` command, full result, environment, and source commit. |
| VERIFY-002 | Race-enabled Go tests pass at the release revision. | Exact `make test-race` command, full result, environment, and source commit. |
| VERIFY-003 | Authorization, isolation, malformed input, replay, expiry, revocation, recovery, clock, process substitution, target mutation, and prohibited forwarding security tests pass. | Current package-backed security result set. |
| VERIFY-004 | Real reboot tests pass for `unless-stopped`, explicit `down`, and `manual` on every declared client platform family. | Boot identity, before and after desired and actual state, service-manager state, PID, and payload evidence. |
| VERIFY-005 | Exact package-to-package positive and negative matrix passes for every declared client and host architecture pair. | Validated v2 release-evidence document bound to artifact digests. |
| VERIFY-006 | Live active-session expiry and revocation are observed at the authority boundary, not inferred from key text or status. | Process, connection, listener, authorization, and terminal-state evidence. |
| VERIFY-007 | Accessibility, security, privacy, reliability, and package manual checks are completed by qualified reviewers for their exact scope. | Named evaluator, method, states, findings, remediations, and limitations. |
| VERIFY-008 | Idle CPU, memory, wakeups, retry rate, and log volume meet stated budgets for stopped, ready, offline, expired, and malformed routes. | Representative measurements and regression thresholds. |
| VERIFY-009 | Release evidence records every failed, blocked, skipped, and unrun gate without converting it to pass. | Schema-valid complete result document and independent review. |
| VERIFY-010 | The public Homebrew CTA activates only when its referenced evidence validates against the exact checklist digest and published artifact digests. | Gate validator, negative tamper tests, production build, and clean public install. |
| VERIFY-011 | Security contact, vulnerability process, release rollback, key rotation, incident response, and support ownership are operational before publication. | Externally reachable contact test and reviewed operational runbooks. |
| VERIFY-012 | No task reports WarpTweet fixed, secure, accessible, production-ready, deployed, or fully tested beyond the exact evidence scope. | Completion report audit against repository and artifact evidence. |

<!-- END WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->

Checklist SHA-256: `5fa66b60627b8cf2dc4720d14719c8368f6749cbd0ebc262d1990ebd4b95b2e3`

Canonical verification command, run from the repository root:

```sh
sed -n '/^<!-- BEGIN WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->$/,/^<!-- END WARPTWEET-ADOPTION-RELEASE-V1-CHECKLIST -->$/p' \
  docs/2026-08-16_adoption-and-release-strategy.md | shasum -a 256
```

## 17. Release boundary and immediate next action

This strategy is complete only as a direction and immutable comparison
contract. WarpTweet is not ready for private package distribution merely
because source tests pass, and it is not ready for public deployment merely
because the website builds.

The immediate implementation priority is not website polish or multi-target
scope. It is to close FINDING-001 through FINDING-010 with package-aware designs
and tests. Exact session attribution and per-route client generations are the
two architectural anchors. Native supervision, package evidence, Homebrew, and
public copy depend on them.

After those anchors pass deterministic tests, build signed release candidates
and run the package matrix before opening the private tap to invited users. The
website can be reframed in parallel, but finite-grant and reboot claims remain
gated until the exact published packages prove them.
