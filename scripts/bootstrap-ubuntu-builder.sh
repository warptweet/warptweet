#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# One-time root bootstrap for a persistent Ubuntu package builder.
# After this, scripts/build-linux-rc-remote.sh can assemble host .debs over SSH.
# Do not copy the WarpTweet GPG signing key in this step.

if [ "$(id -u)" != "0" ]; then
    echo "bootstrap-ubuntu-builder: must run as root" >&2
    exit 77
fi
if [ "$(uname -s)" != Linux ]; then
    echo "bootstrap-ubuntu-builder: Linux only" >&2
    exit 69
fi

WT_GO_VERSION=${WARPTWEET_INTEROP_GO_VERSION:-1.26.5}
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq \
    build-essential autoconf automake libtool pkg-config \
    zlib1g-dev libpam0g-dev libselinux1-dev libedit-dev libkrb5-dev \
    libfido2-dev libcbor-dev \
    gpg gpg-agent libtext-template-perl passwd perl python3-minimal sudo \
    ca-certificates curl dpkg-dev fakeroot acl rsync binutils git

if ! id warptweet-sshd >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home \
        --home-dir /var/empty/warptweet-sshd --shell /usr/sbin/nologin warptweet-sshd || true
fi
install -d -o root -g root -m 0755 /var/empty/warptweet-sshd

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! getent passwd warptweet-build >/dev/null 2>&1; then
    if [ ! -x "$WT_SCRIPT_DIRECTORY/provision-openssh-build-account.sh" ]; then
        echo "bootstrap-ubuntu-builder: missing provision-openssh-build-account.sh" >&2
        exit 65
    fi
    WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 "$WT_SCRIPT_DIRECTORY/provision-openssh-build-account.sh"
fi

WT_GO_ROOT=/usr/local/go
WT_NEED_GO=1
if [ -x "$WT_GO_ROOT/bin/go" ]; then
    WT_HAVE=$("$WT_GO_ROOT/bin/go" env GOVERSION 2>/dev/null || true)
    case "$WT_HAVE" in
        go"$WT_GO_VERSION" | go"$WT_GO_VERSION".*) WT_NEED_GO=0 ;;
    esac
fi
if [ "$WT_NEED_GO" -eq 1 ]; then
    WT_ARCH=$(uname -m)
    case "$WT_ARCH" in
        x86_64 | amd64) WT_GO_ARCH=amd64 ;;
        aarch64 | arm64) WT_GO_ARCH=arm64 ;;
        *)
            echo "unsupported builder arch: $WT_ARCH" >&2
            exit 65
            ;;
    esac
    WT_TGZ="go${WT_GO_VERSION}.linux-${WT_GO_ARCH}.tar.gz"
    WT_TGZ_SHA256=''
    case "${WT_GO_VERSION}:${WT_GO_ARCH}" in
        1.26.5:amd64) WT_TGZ_SHA256='5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053' ;;
        1.26.5:arm64) WT_TGZ_SHA256='fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49' ;;
        *)
            echo "no reviewed SHA-256 for go${WT_GO_VERSION} linux/${WT_GO_ARCH}" >&2
            exit 65
            ;;
    esac
    WT_TMP=$(mktemp -d)
    chmod 0700 "$WT_TMP"
    trap 'rm -rf "$WT_TMP"' EXIT
    curl --proto '=https' --tlsv1.2 --fail --location "https://go.dev/dl/${WT_TGZ}" -o "$WT_TMP/${WT_TGZ}"
    WT_GOT_SHA256=$(sha256sum "$WT_TMP/${WT_TGZ}" | awk '{print $1}')
    if [ "$WT_GOT_SHA256" != "$WT_TGZ_SHA256" ]; then
        echo "Go archive checksum mismatch for ${WT_TGZ}" >&2
        exit 65
    fi
    rm -rf "$WT_GO_ROOT"
    tar -C /usr/local -xzf "$WT_TMP/${WT_TGZ}"
fi

install -d -o root -g root -m 0755 /var/tmp/warptweet-rc
echo "bootstrap-ubuntu-builder: ready (go=$("$WT_GO_ROOT/bin/go" version))"
