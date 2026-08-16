# Dual-host interop orchestrator (Phase A)

Status: Phase A scaffold, 2026-08-14

## Goal

Drive package-to-package confidence from a Mac client against a remote Linux
server without treating source-tree binaries as evidence.

Phase A implements the spine:

1. Install **pinned** client and server packages from an artifacts directory  
2. Start a **deterministic TCP echo** fixture on the server loopback  
3. Run `host` on the server and pull the newly minted `.wtinvite` home
4. Run `connect` on the local Mac package controller  
5. Prove echo payload through `127.0.0.1`  
6. Write a `warptweet.release-evidence` JSON (remaining checklist ids stay `not_run`)

This is **not** a complete WP8 matrix. Algorithm observation, rekey, floods, and
most negatives remain for later phases. The public Homebrew CTA must stay dark
until every checklist id is `pass`.

## Decisions

| Topic | Choice |
| --- | --- |
| Client | Local Mac (orchestrator = client) |
| Server | Remote Linux over SSH |
| Remote auth | `ssh-agent` (optional `IdentityFile`; no passphrase on CLI) |
| Package source | Option B: install from pinned artifact files |
| Default fixture | Deterministic TCP echo on server `127.0.0.1` |
| Forward path | Later: remote client role without rewriting cases |

## Layout

```text
scripts/interop/
  orchestrate.sh           # entrypoint
  config.example.env       # copy to config.env (do not commit secrets)
  fixtures/echo_target.py
  lib/
    common.sh
    ssh.sh
    package.sh
    fixture.sh
    evidence.sh
```

## Prerequisites

- Remote Linux host with sudo, `python3`, and `dpkg` or `rpm`
- Local Mac with administrator authorization for the `.pkg` install,
  `python3`, `ssh`, and `scp`. Client commands after installation run without
  `sudo` through the package provisioner.
- Key loaded in `ssh-agent` (`ssh-add -l` shows it)
- Artifacts directory containing the exact pinned server `.deb`/`.rpm` and client `.pkg`
- Digests in config matching those files and post-install engine manifests

## Configure

```sh
cp scripts/interop/config.example.env scripts/interop/config.env
# edit pins, host, artifact filenames, server listen IP:port
```

`WARPTWEET_INTEROP_SERVER_LISTEN` must be a **concrete** address the Mac can
reach for both SSH product port and enroll port (default 29722), e.g.
`203.0.113.10:2222`.

## Run (local-dev happy path, zero make args)

```sh
cp .env.example .env
# edit WARPTWEET_INTEROP_SERVER_HOST and WARPTWEET_INTEROP_SSH_IDENTITY
# set WARPTWEET_INTEROP_SSH_KNOWN_HOSTS or WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT
# put server .deb and client .pkg in ./artifacts/
ssh-add --apple-use-keychain   # unlock key once
make interop
```

`make interop` loads `.env`, fills digests/commit/listen defaults, then runs the
orchestrator. Configure `WARPTWEET_INTEROP_SSH_KNOWN_HOSTS` or
`WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT` before running; admin SSH keeps
`StrictHostKeyChecking=yes` as required by `scripts/interop/config.example.env`.

## Run (explicit config)

```sh
ssh-add --apple-use-keychain   # or ssh-add /path/to/key
./scripts/interop/orchestrate.sh --config scripts/interop/config.env
```

On success Phase A prints work dir, invite path, and evidence path. Exit 0 even
when evidence is incomplete (`not_run` remaining); exit non-zero on hard failures
(install, invite, connect, missing config).

Optional lifecycle after connect:

```sh
export WARPTWEET_INTEROP_RUN_LIFECYCLE=1
./scripts/interop/orchestrate.sh --config scripts/interop/config.env
```

## Evidence

Output is a full-schema `warptweet.release-evidence` document. Phase A records
`pass`/`fail` for cases it runs and fills the rest with `not_run`.  
`releaseevidence.Complete` stays false until WP8 is finished. Do not enable the
website CTA from Phase A output alone.

## Upgrade path

| Later change | How |
| --- | --- |
| Remote client host | Add `run_on_client` transport; cases stay the same |
| Postgres fixture | Optional profile beside echo; default remains echo |
| Full WP8 cases | Add modules under `scripts/interop/cases/` and stop auto-`not_run` |
| Artifact install variants | Extend `lib/package.sh` only |

## Non-goals (Phase A)

- Building packages from this git tree on the hosts  
- Classical-only / flood / tamper negatives  
- Marking public release complete  

Enrollment is no longer a non-goal: Phase A uses the invite-pinned TLS 1.3
control plane. It still does not complete the full negative, rekey, packaging,
upgrade, and architecture matrix.
