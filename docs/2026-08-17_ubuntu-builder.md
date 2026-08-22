# Repeatable Ubuntu host-package builder

Keep one persistent Ubuntu 24.04 or 26.04 VM. Do not treat a throwaway
cloud instance as the signing computer. Bootstrap once. Build every RC
from this Mac with one command.

## One-time VM

Create the VM with SSH and passwordless sudo for `ubuntu`. Example cloud-init:

```yaml
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-ed25519 AAAA...your-key
packages:
  - git
  - rsync
```

Then from this Mac, put the host in `.env`:

```sh
WARPTWEET_INTEROP_SERVER_HOST=203.0.113.10
WARPTWEET_INTEROP_SERVER_USER=ubuntu
WARPTWEET_INTEROP_SSH_IDENTITY=$HOME/.ssh/id_ed25519
WARPTWEET_INTEROP_SSH_KNOWN_HOSTS=$HOME/.ssh/known_hosts
WARPTWEET_INTEROP_SSH_PORT=22
```

Obtain the VM host-key fingerprint from an independent trusted channel
(provider console, out-of-band note, or a prior verified install). Compare
that fingerprint with `ssh-keyscan` before appending anything to
`known_hosts`:

```sh
ssh-keyscan -H 203.0.113.10
# compare the printed SHA256 fingerprint with the trusted value
# only then:
ssh-keyscan -H 203.0.113.10 >> "$HOME/.ssh/known_hosts"
ssh -o StrictHostKeyChecking=yes -i "$HOME/.ssh/id_ed25519" ubuntu@203.0.113.10 'sudo -n true && echo ready'
```

## Every Linux RC

From the tagged WarpTweet tree on this Mac. `VERSION` must match
`command.Version` in `internal/command/command.go`. Host, SSH identity,
and `WARPTWEET_LINUX_GPG_KEY` come from `.env`.

```sh
make linux-rc VERSION=0.1.0-rc.7
```

That script:

1. rsyncs the tree to `/var/tmp/warptweet-rc` on the VM
2. runs `scripts/bootstrap-ubuntu-builder.sh` on every RC, which always
   performs `apt-get update` and package installation
3. fetches or reuses authenticated OpenSSH/OpenSSL sources
4. compiles the Linux OpenSSH stage as `warptweet-build`
5. assembles `warptweet_${VERSION}_${amd64|arm64}.deb`
6. copies it to `dist/`
7. signs locally with `gpg` and `ar`. Both tools are required. The RC
   build fails if either is missing unless
   `WARPTWEET_LINUX_REMOTE_SIGN=1` enables remote signing.

The first compile is long. Later RCs reuse `/var/lib/warptweet-build/warptweet-openssh-stage`.

## What `.env` is not

`.env` plus `make interop` is the later dual-host matrix. It can also build an
unsigned lab `.deb`. It is not a substitute for this signed RC path.
