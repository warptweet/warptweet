# WarpTweet product quickstart

This is the five-minute product path. It is not package-to-package release evidence.

## What you get

One loopback local port to one exact numeric remote TCP service. No shell, VPN mesh, or general SSH credential for ordinary use.

## Host

On the Linux machine that can reach the service:

```sh
warptweet host --to 127.0.0.1:5432 --name staging-db --access-for 30d
```

Compose should publish the service only on host loopback:

```yaml
services:
  db:
    image: postgres:17
    ports:
      - "127.0.0.1:5432:5432"
```

## Client

On the macOS workstation:

```sh
warptweet connect staging-db.wtinvite --listen-port 15432 --restart unless-stopped
psql "host=127.0.0.1 port=15432 dbname=app"
```

`connect` defaults to desired `running` and restart `unless-stopped`. `down` persists stopped. Expired grants do not self-renew.

## Lifecycle

```sh
warptweet routes --json
warptweet status staging-db --json
warptweet down staging-db
warptweet up staging-db
warptweet revoke staging-db
```

Invite lifetime is 15 minutes and single-use. Authorization is a separate 30-day default grant. A stopped route is not revoked. Local expiry expectation is not host-acknowledged enforcement.

## Limits

WarpTweet narrows host and network authority. Database credentials remain independent. Retained root or unrestricted SSH remains outside this boundary. Public install stays dark until v2 package evidence passes.

Current contract: `docs/2026-08-16_adoption-and-release-strategy.md`.
