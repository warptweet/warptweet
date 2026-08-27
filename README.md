# WarpTweet

**A local port to one private service.**

WarpTweet makes a TCP service on a Linux machine you control appear on your
Mac as `127.0.0.1`. Open Postgres, an internal API, or any other single port
with the tools you already use — without a VPN, a shared SSH login, or
publishing that service to the internet.

Your app talks to localhost. WarpTweet carries the bytes to the one service
the Linux host approved. The client never gets a shell, a subnet, or a
general-purpose key.

```text
psql, curl, your SDK  →  127.0.0.1:15432  →  WarpTweet  →  that one service
```

## Use it

You need WarpTweet on both machines: an Apple Silicon Mac (macOS 13 or newer)
and an Ubuntu Linux host (AMD64 or ARM64).

**1. On Linux**, point WarpTweet at the service. Postgres on this machine is a
typical case; keep it on loopback so the internet cannot reach it:

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:17
    ports:
      - "127.0.0.1:5432:5432"
```

```sh
warptweet host --to 127.0.0.1:5432 --name staging-db --access-for 30d
```

That writes `staging-db.wtinvite`. Treat the file like a password: send it
over a channel you already trust, use it once, then delete it. It expires in
15 minutes.

**2. On the Mac**, enroll and open a local port:

```sh
warptweet connect --listen-port 15432 staging-db.wtinvite
```

**3. Use the service as if it were local:**

```sh
psql "host=127.0.0.1 port=15432 dbname=app"
```

Database users and passwords stay with Postgres. WarpTweet only opens the
path.

If the Linux box has a private address and a separate public IP (common on
cloud VMs), tell the Mac how to dial. See
[bind and advertise](docs/2026-08-24_host-bind-and-advertise.md).

## Everyday commands

```sh
warptweet routes --json          # list routes on this Mac
warptweet status staging-db --json
warptweet down staging-db        # stop locally; the host still trusts you
warptweet up staging-db          # start again
warptweet rotate staging-db      # replace the client identity, with the host
warptweet revoke staging-db      # remove access on the host
```

`down` is “not right now.” `revoke` is “this grant is over.” Access lasts 30
days unless you chose a different `--access-for`, and it does not renew in the
background.

## Why not a VPN or SSH?

A VPN usually joins you to a network. That is more than a database port, and
it is easy to get the blast radius wrong.

SSH can do anything a login can do: a shell, file copy, extra forwards, a key
that outlives the task. Sharing a host key with a laptop or an agent is a
habit that does not age well.

WarpTweet is the smaller thing:

- one destination, chosen on the Linux host
- one listener on the Mac, bound to localhost only
- no shell, SFTP, SCP, SOCKS, agent forwarding, or VPN tunnel
- a fresh client identity generated on the Mac
- the host identity pinned at enrollment — not “trust whatever answers first”
- a single-use invite and a grant that expires

It does not replace the database password, hide that a connection exists, or
protect a machine that is already compromised. People who share a Mac still
need OS controls around localhost. Read the
[threat model](docs/2026-08-09_threat-model.md) and
[security policy](SECURITY.md) before you put this in front of something
sensitive.

Report vulnerabilities to `security@warptweet.com`.

## Install

Public packages are not on Homebrew yet. When they are, Apple Silicon install
will be:

```sh
brew install --cask warptweet/tap/warptweet
```

Do not add `--no-quarantine`. Until that command is published, this repository
is the source tree and the place signed releases will appear.

Today WarpTweet supports:

- **Your Mac:** Apple Silicon, macOS 13 or newer
- **The host:** Ubuntu Linux, AMD64 or ARM64

Windows and Intel Mac clients are later work, not a silent promise.

Lab testing of the signed Mac client against signed Linux hosts is recorded in
[`packaging/evidence/release-evidence-index-v3.json`](packaging/evidence/release-evidence-index-v3.json).
You do not need that file to use the product; it is there if you want proof.

## Cryptography

Every connection uses the same profile. There is no “fall back to ordinary
SSH” mode. If a peer is missing an algorithm, the host key is wrong, or a
binary does not match, WarpTweet stops.

| Layer | Exact value |
| --- | --- |
| Engine | OpenSSH 10.4p1, OpenSSL 3.5.7 (static) |
| Key exchange | `mlkem768x25519-sha256` (ML-KEM-768 + X25519) |
| Host and client identity | `ssh-mldsa44-ed25519@openssh.com` (ML-DSA-44 + Ed25519) |
| Cipher | `chacha20-poly1305@openssh.com` |
| Profile ID | `warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20` |

Both halves of the hybrid key exchange and both halves of the identity have to
succeed. ML-KEM and ML-DSA are NIST standards. OpenSSH still labels this
composite identity binding experimental; WarpTweet treats it as a
vendor-qualified engine, not an IETF standard, a FIPS module, or a claim of
quantum-proof security.

Policy lives in `.wt` files. Invites are `.wtinvite`. Neither file contains
private keys. The invite is still confidential until it is used or it expires.
Schemas: [client](schemas/client-tunnels-v2.schema.json),
[host](schemas/server-gateway-v2.schema.json).

## Developers

```sh
make check-go
make build
./bin/warptweet profile

pnpm install --frozen-lockfile
pnpm run verify
```

Useful local checks (these inspect policy; they are not a live tunnel):

```sh
./bin/warptweet validate --config client.wt
./bin/warptweet render-client --config client.wt --tunnel database-primary
./bin/warptweet render-server --config server.wt
./bin/warptweet render-authorized-key --config server.wt --public-key client.pub --not-after 2026-09-17T00:00:00Z
./bin/warptweet doctor --config /etc/warptweet/client.wt --tunnel database-primary
./bin/warptweet doctor-server --config /etc/warptweet/server.wt
```

Preview the website with `make site-up`, or `docker compose up --build website`
at `http://127.0.0.1:4322/`.

Layout: [`cmd/warptweet`](cmd/warptweet) CLI, [`internal`](internal) controller,
[`schemas`](schemas) contracts, [`packaging`](packaging) packages and evidence,
[`scripts`](scripts) build and lab harnesses, [`src`](src) website, [`docs`](docs)
design notes.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.

Apache License 2.0. The bundled OpenSSH/OpenSSL licenses are in [NOTICE](NOTICE).
