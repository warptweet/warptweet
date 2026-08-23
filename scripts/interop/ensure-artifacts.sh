#!/bin/sh
# shellcheck shell=sh
# Build local-dev interop packages into WARPTWEET_INTEROP_ARTIFACTS when missing.
# Client .pkg: native macOS OpenSSH stage + controller + provisioner.
# Server .deb: Linux OpenSSH stage via Docker (linux/amd64) or remote SSH host.
#
# Env:
#   WARPTWEET_INTEROP_ARTIFACTS   output dir (created)
#   WARPTWEET_INTEROP_BUILD_CACHE  stage/source cache (default: <repo>/.cache/interop-build)
#   WARPTWEET_INTEROP_BUILD_SERVER  docker | remote | auto (default: auto)
#   WARPTWEET_RELEASE_VERSION     package version (default: 0.1.0-dev)
#   WT_REPO_ROOT                  repository root (required if not cwd-detectable)
set -eu
LC_ALL=C
export LC_ALL

ensure_log() { echo "make interop: $*" >&2; }
ensure_die() { echo "make interop: $*" >&2; exit 1; }

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPO_ROOT=${WT_REPO_ROOT:-$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/../.." && pwd)}
cd "$WT_REPO_ROOT"

: "${WARPTWEET_INTEROP_ARTIFACTS:=$WT_REPO_ROOT/artifacts}"
case "$WARPTWEET_INTEROP_ARTIFACTS" in
    /*) ;;
    *) WARPTWEET_INTEROP_ARTIFACTS=$WT_REPO_ROOT/$WARPTWEET_INTEROP_ARTIFACTS ;;
esac
: "${WARPTWEET_INTEROP_BUILD_CACHE:=$WT_REPO_ROOT/.cache/interop-build}"
case "$WARPTWEET_INTEROP_BUILD_CACHE" in
    /*) ;;
    *) WARPTWEET_INTEROP_BUILD_CACHE=$WT_REPO_ROOT/$WARPTWEET_INTEROP_BUILD_CACHE ;;
esac
: "${WARPTWEET_INTEROP_BUILD_SERVER:=auto}"
: "${WARPTWEET_RELEASE_VERSION:=0.1.0-dev}"
export WARPTWEET_VERSION=$WARPTWEET_RELEASE_VERSION

mkdir -p "$WARPTWEET_INTEROP_ARTIFACTS" "$WARPTWEET_INTEROP_BUILD_CACHE"

. "$WT_REPO_ROOT/third_party/openssh/source.env"
. "$WT_REPO_ROOT/third_party/openssl/source.env"

_have_server=
_have_client=
if ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.deb >/dev/null 2>&1 || ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.rpm >/dev/null 2>&1; then
    _have_server=1
fi
if ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.pkg >/dev/null 2>&1; then
    _have_client=1
fi
if [ -n "$_have_server" ] && [ -n "$_have_client" ]; then
    ensure_log "artifacts already present under $WARPTWEET_INTEROP_ARTIFACTS"
    exit 0
fi

_arch=$(uname -m)
case "$_arch" in
    arm64 | aarch64) _darwin_token=arm64 ;;
    x86_64 | amd64) _darwin_token=amd64 ;;
    *) ensure_die "unsupported local arch: $_arch" ;;
esac

# --- shared: authenticated sources (cached) ---
ensure_sources() {
    command -v gpg >/dev/null 2>&1 || ensure_die "gpg required (brew install gnupg)"
    command -v curl >/dev/null 2>&1 || ensure_die "curl required"
    # Keep fetch HOME short: macOS AF_UNIX socket paths break gpg-agent when deep.
    _src_home=${WARPTWEET_INTEROP_SOURCE_HOME:-/tmp/wtib-src}
    mkdir -p "$_src_home/tmp" "$WARPTWEET_INTEROP_BUILD_CACHE/sources"
    chmod 0700 "$_src_home" "$_src_home/tmp" 2>/dev/null || true
    if [ ! -f "$_src_home/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
        if [ -f "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
            ensure_log "restoring cached OpenSSH source"
            rm -rf "$_src_home/warptweet-openssh-source"
            mkdir -p "$_src_home"
            cp -a "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source" "$_src_home/"
        else
            ensure_log "fetching OpenSSH source (authenticated)"
            rm -rf "$_src_home/warptweet-openssh-source"
            HOME="$_src_home" TMPDIR="$_src_home/tmp" \
                "$WT_REPO_ROOT/scripts/fetch-openssh.sh" "$_src_home/warptweet-openssh-source"
            rm -rf "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source"
            cp -a "$_src_home/warptweet-openssh-source" "$WARPTWEET_INTEROP_BUILD_CACHE/sources/"
        fi
    fi
    if [ ! -f "$_src_home/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
        if [ -f "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
            ensure_log "restoring cached OpenSSL source"
            rm -rf "$_src_home/warptweet-openssl-source"
            cp -a "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source" "$_src_home/"
        else
            ensure_log "fetching OpenSSL source (authenticated)"
            rm -rf "$_src_home/warptweet-openssl-source"
            HOME="$_src_home" TMPDIR="$_src_home/tmp" \
                "$WT_REPO_ROOT/scripts/fetch-openssl.sh" "$_src_home/warptweet-openssl-source"
            rm -rf "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source"
            cp -a "$_src_home/warptweet-openssl-source" "$WARPTWEET_INTEROP_BUILD_CACHE/sources/"
        fi
    fi
    WT_OPENSSH_ARCHIVE=$_src_home/warptweet-openssh-source/$OPENSSH_ARCHIVE
    WT_OPENSSL_ARCHIVE=$_src_home/warptweet-openssl-source/$OPENSSL_ARCHIVE
    export WT_OPENSSH_ARCHIVE WT_OPENSSL_ARCHIVE
}

# --- macOS client .pkg ---
ensure_client_pkg() {
    if [ -n "$_have_client" ]; then
        return 0
    fi
    [ "$(uname -s)" = Darwin ] || ensure_die "client .pkg build requires macOS"
    ensure_sources

    # Short paths: long stage parents break OpenSSH scp3 regress on APFS.
    _stage_cache=$WARPTWEET_INTEROP_BUILD_CACHE/openssh-darwin-stage
    _stage=${WARPTWEET_INTEROP_DARWIN_STAGE:-/tmp/wtib/openssh-darwin-stage}
    mkdir -p "$(dirname "$_stage")"
    _marker=$_stage/Library/Application\ Support/WarpTweet/share/openssh-bundle.sha256
    _marker_cache=$_stage_cache/Library/Application\ Support/WarpTweet/share/openssh-bundle.sha256
    if [ ! -f "$_marker" ] && [ -f "$_marker_cache" ]; then
        ensure_log "restoring cached macOS OpenSSH stage to short path"
        rm -rf "$_stage"
        mkdir -p "$(dirname "$_stage")"
        cp -a "$_stage_cache" "$_stage"
    fi
    if [ ! -f "$_marker" ]; then
        ensure_log "building macOS OpenSSH client stage (long; cached after first run)"
        rm -rf "$_stage"
        # Upstream regress needs a live agent; background/nohup runs often lack one.
        _agent_sock=${SSH_AUTH_SOCK:-}
        _started_agent=0
        if [ -z "$_agent_sock" ] || [ ! -S "$_agent_sock" ]; then
            ensure_log "starting private ssh-agent for OpenSSH regress"
            eval "$(ssh-agent -s)" >/dev/null
            _started_agent=1
        fi
        # shellcheck disable=SC2030,SC2031
        # scp3 regress is broken on some macOS/APFS hosts; client stage does not ship scp.
        # Do not override HOME: OpenSSH percent-expansion tests compare ~ to the
        # real passwd home, not $HOME.
        : "${SKIP_LTESTS:=scp3}"
        mkdir -p /tmp/wtib-src/tmp
        if ! TMPDIR=/tmp/wtib-src/tmp \
            SSH_AUTH_SOCK=$SSH_AUTH_SOCK \
            SSH_AGENT_PID=${SSH_AGENT_PID:-} \
            SKIP_LTESTS=$SKIP_LTESTS \
            "$WT_REPO_ROOT/scripts/build-openssh-darwin.sh" \
            "$WT_OPENSSH_ARCHIVE" \
            "$WT_OPENSSL_ARCHIVE" \
            "$_stage"; then
            if [ "$_started_agent" -eq 1 ] && [ -n "${SSH_AGENT_PID:-}" ]; then
                kill "$SSH_AGENT_PID" >/dev/null 2>&1 || true
            fi
            ensure_die "macOS OpenSSH stage build failed"
        fi
        if [ "$_started_agent" -eq 1 ] && [ -n "${SSH_AGENT_PID:-}" ]; then
            kill "$SSH_AGENT_PID" >/dev/null 2>&1 || true
        fi
        rm -rf "$_stage_cache"
        cp -a "$_stage" "$_stage_cache"
    else
        ensure_log "reusing macOS OpenSSH stage at $_stage"
    fi

    ensure_log "building controller + provisioner"
    mkdir -p "$WT_REPO_ROOT/bin"
    GOCACHE=${GOCACHE:-/private/tmp/warptweet-go-build}
    export GOCACHE
    mkdir -p "$GOCACHE"
    MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0}
    export MACOSX_DEPLOYMENT_TARGET
    CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
    CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
    export CGO_CFLAGS CGO_LDFLAGS
    CGO_ENABLED=1 go build -trimpath -o "$WT_REPO_ROOT/bin/warptweet" "$WT_REPO_ROOT/cmd/warptweet"
    CGO_ENABLED=1 go build -trimpath -o "$WT_REPO_ROOT/bin/warptweet-provisioner" "$WT_REPO_ROOT/cmd/warptweet-provisioner"

    # Sign with Developer ID when available (matches productionCodeSigningTeamID).
    _sign_id=${WARPTWEET_CODESIGN_IDENTITY:-"Developer ID Application: Baldwinson Corporation (CP4268Q8UF)"}
    if command -v codesign >/dev/null 2>&1 && security find-identity -v -p codesigning 2>/dev/null | grep -Fq "$_sign_id"; then
        ensure_log "codesigning client payload with $_sign_id"
        for _bin in \
            "$WT_REPO_ROOT/bin/warptweet" \
            "$WT_REPO_ROOT/bin/warptweet-provisioner" \
            "$_stage/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh" \
            "$_stage/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen"; do
            [ -f "$_bin" ] || continue
            codesign --force --options runtime --timestamp --sign "$_sign_id" "$_bin"
        done
    else
        ensure_log "warning: codesign identity not available; package will fail production Team ID checks"
    fi

    _pkg=$WARPTWEET_INTEROP_ARTIFACTS/warptweet-client_${WARPTWEET_RELEASE_VERSION}_${_darwin_token}.pkg
    if [ -e "$_pkg" ]; then
        rm -f "$_pkg"
    fi
    ensure_log "assembling client package $_pkg"
    "$WT_REPO_ROOT/scripts/build-macos-pkg.sh" \
        "$_stage" \
        "$WT_REPO_ROOT/bin/warptweet" \
        "$WT_REPO_ROOT/bin/warptweet-provisioner" \
        "$_pkg"
    _have_client=1
    ensure_log "client package ready: $_pkg"
}

# --- Linux server .deb via Docker ---
ensure_server_deb_docker() {
    command -v docker >/dev/null 2>&1 || ensure_die "docker required to build server .deb on this Mac"
    ensure_sources

    _out_deb=warptweet_${WARPTWEET_RELEASE_VERSION}_amd64.deb
    _go_image=${WARPTWEET_INTEROP_GO_IMAGE:-}
    case "$_go_image" in
        *@sha256:*) ;;
        *)
            ensure_die "WARPTWEET_INTEROP_GO_IMAGE must be a digest-pinned image (name@sha256:...)"
            ;;
    esac
    ensure_log "building Linux server package in Docker ($_go_image, linux/amd64); first run is long"

    # Mount repo + cache; write .deb into artifacts.
    docker run --rm -i --platform linux/amd64 \
        -v "$WT_REPO_ROOT:/src:ro" \
        -v "$WARPTWEET_INTEROP_BUILD_CACHE:/cache" \
        -v "$WARPTWEET_INTEROP_ARTIFACTS:/out" \
        -e WARPTWEET_VERSION="$WARPTWEET_RELEASE_VERSION" \
        -e OPENSSH_ARCHIVE="$OPENSSH_ARCHIVE" \
        -e OPENSSL_ARCHIVE="$OPENSSL_ARCHIVE" \
        -e OUT_DEB="$_out_deb" \
        "$_go_image" \
        bash -euo pipefail <<'DOCKER'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential autoconf automake libtool pkg-config \
  zlib1g-dev libpam0g-dev libselinux1-dev libedit-dev libkrb5-dev \
  libfido2-dev libcbor-dev \
  gpg gpg-agent libtext-template-perl passwd perl python3-minimal sudo \
  rsync dpkg-dev fakeroot acl

# Build account (CI parity).
if ! id warptweet-build >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home \
    --home-dir /var/empty/warptweet-sshd --shell /usr/sbin/nologin warptweet-sshd || true
  install -d -o root -g root -m 0755 /var/empty/warptweet-sshd
  cp -a /src /work
  cd /work
  WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 ./scripts/provision-openssh-build-account.sh
else
  cp -a /src /work
  cd /work
fi

WT_BUILD_HOME=/var/lib/warptweet-build
# Reuse cached authenticated archives when present.
mkdir -p "$WT_BUILD_HOME/tmp"
if [ -f "/cache/sources/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
  mkdir -p "$WT_BUILD_HOME/warptweet-openssh-source"
  cp -a "/cache/sources/warptweet-openssh-source/." "$WT_BUILD_HOME/warptweet-openssh-source/"
  chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-source"
else
  sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" \
    ./scripts/fetch-openssh.sh "$WT_BUILD_HOME/warptweet-openssh-source"
fi
if [ -f "/cache/sources/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
  mkdir -p "$WT_BUILD_HOME/warptweet-openssl-source"
  cp -a "/cache/sources/warptweet-openssl-source/." "$WT_BUILD_HOME/warptweet-openssl-source/"
  chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssl-source"
else
  sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" \
    ./scripts/fetch-openssl.sh "$WT_BUILD_HOME/warptweet-openssl-source"
fi

if [ ! -d "$WT_BUILD_HOME/warptweet-openssh-stage/opt/warptweet/libexec/openssh" ]; then
  rm -rf "$WT_BUILD_HOME/warptweet-openssh-stage"
  # Prefer cached stage from prior docker run.
  if [ -d /cache/openssh-linux-stage/opt/warptweet/libexec/openssh ]; then
    cp -a /cache/openssh-linux-stage "$WT_BUILD_HOME/warptweet-openssh-stage"
    chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-stage"
  else
    sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" SUDO=sudo \
      ./scripts/build-openssh.sh \
      "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
      "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
      "$WT_BUILD_HOME/warptweet-openssh-stage"
    rm -rf /cache/openssh-linux-stage
    cp -a "$WT_BUILD_HOME/warptweet-openssh-stage" /cache/openssh-linux-stage
  fi
fi

# Controller and provisioner for linux/amd64 inside the container.
go build -trimpath -o /tmp/warptweet ./cmd/warptweet
go build -trimpath -o /tmp/warptweet-provisioner ./cmd/warptweet-provisioner

rm -rf /tmp/wt-pkg-out
./scripts/build-linux-packages.sh \
  "$WT_BUILD_HOME/warptweet-openssh-stage" \
  /tmp/warptweet \
  /tmp/wt-pkg-out

# Prefer the produced .deb
DEB=$(ls -1 /tmp/wt-pkg-out/*.deb 2>/dev/null | head -1)
test -n "$DEB"
cp -a "$DEB" "/out/$OUT_DEB"
echo "wrote /out/$OUT_DEB"
DOCKER

    _have_server=1
    ensure_log "server package ready: $WARPTWEET_INTEROP_ARTIFACTS/$_out_deb"
}

# --- Linux server .deb built on the remote interop host ---
ensure_server_deb_remote() {
    [ -n "${WARPTWEET_INTEROP_SERVER_HOST:-}" ] || ensure_die "WARPTWEET_INTEROP_SERVER_HOST required for remote server package build"
    ensure_sources
    ensure_log "building Linux server package on $WARPTWEET_INTEROP_SERVER_HOST (long)"

    # Minimal SSH helpers (dev-run has not loaded lib/ssh.sh yet).
    # ssh uses -p for port; scp uses -P (-p means preserve times).
    _ssh_opts="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes"
    _ssh_opts="$_ssh_opts -o PreferredAuthentications=publickey"
    if [ -n "${WARPTWEET_INTEROP_SSH_IDENTITY:-}" ]; then
        _id=$WARPTWEET_INTEROP_SSH_IDENTITY
        case "$_id" in
            ~/*) _id=$HOME/${_id#~/} ;;
        esac
        _id=$(printf '%s' "$_id" | sed "s#\$HOME#$HOME#g; s#\${HOME}#$HOME#g")
        _ssh_opts="$_ssh_opts -i $_id"
    fi
    _port=${WARPTWEET_INTEROP_SSH_PORT:-22}
    _ssh_base="$_ssh_opts -p $_port"
    _scp_base="$_ssh_opts -P $_port"
    if [ -n "${WARPTWEET_INTEROP_SERVER_USER:-}" ]; then
        _target="${WARPTWEET_INTEROP_SERVER_USER}@$WARPTWEET_INTEROP_SERVER_HOST"
    else
        _target=$WARPTWEET_INTEROP_SERVER_HOST
    fi
    # shellcheck disable=SC2086
    ssh $_ssh_base "$_target" 'echo remote_ok' >/dev/null 2>&1 || \
        ensure_die "ssh to $_target failed; fix key auth or set WARPTWEET_INTEROP_BUILD_SERVER=docker"

    _remote_root=/var/tmp/warptweet-interop-build
    # shellcheck disable=SC2086
    ssh $_ssh_base "$_target" "sudo rm -rf '$_remote_root' && mkdir -p '$_remote_root' && sudo chown \"\$USER:\" '$_remote_root'"

    ensure_log "syncing tree to remote (no .git)"
    # shellcheck disable=SC2086
    rsync -az --delete \
        -e "ssh $_ssh_base" \
        --exclude '.git' --exclude 'artifacts' --exclude '.cache' --exclude 'scripts/interop/work' \
        --exclude 'node_modules' --exclude 'site/node_modules' --exclude 'dist' \
        "$WT_REPO_ROOT/" "$_target:$_remote_root/src/"

    # shellcheck disable=SC2086
    rsync -az -e "ssh $_ssh_base" \
        "$WARPTWEET_INTEROP_BUILD_CACHE/sources/" "$_target:$_remote_root/sources/" 2>/dev/null || true

    # Official Go toolchain (distro golang-go is far below go.mod 1.26).
    _go_ver=${WARPTWEET_INTEROP_GO_VERSION:-1.26.5}
    # Write the remote script to a file first. OpenSSH regress tests inherit
    # stdin and would otherwise consume the remainder of a stdin-fed script.
    # shellcheck disable=SC2086
    ssh $_ssh_base "$_target" "export WARPTWEET_VERSION='$WARPTWEET_RELEASE_VERSION' OPENSSH_ARCHIVE='$OPENSSH_ARCHIVE' OPENSSL_ARCHIVE='$OPENSSL_ARCHIVE' REMOTE_ROOT='$_remote_root' WT_GO_VERSION='$_go_ver'; cat > \"\$REMOTE_ROOT/remote-build.sh\" && bash -euo pipefail \"\$REMOTE_ROOT/remote-build.sh\"" <<'REMOTE' || ensure_die "remote server package build failed"
cd "$REMOTE_ROOT/src"
echo "remote nproc=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential autoconf automake libtool pkg-config \
  zlib1g-dev libpam0g-dev libselinux1-dev libedit-dev libkrb5-dev \
  gpg gpg-agent libtext-template-perl passwd perl python3-minimal sudo \
  ca-certificates curl dpkg-dev fakeroot acl rsync binutils

# Pin Go to match local Docker interop image / go.mod.
_go_root=/usr/local/go
_need_go=1
if [ -x "$_go_root/bin/go" ]; then
  _have=$("$_go_root/bin/go" env GOVERSION 2>/dev/null || true)
  case "$_have" in
    go"$WT_GO_VERSION"|go"$WT_GO_VERSION".*) _need_go=0 ;;
  esac
fi
if [ "$_need_go" -eq 1 ]; then
  _arch=$(uname -m)
  case "$_arch" in
    x86_64|amd64) _go_arch=amd64 ;;
    aarch64|arm64) _go_arch=arm64 ;;
    *) echo "unsupported remote arch: $_arch" >&2; exit 1 ;;
  esac
  _go_tgz="go${WT_GO_VERSION}.linux-${_go_arch}.tar.gz"
  _go_sha=''
  case "${WT_GO_VERSION}:${_go_arch}" in
    1.26.5:amd64) _go_sha='5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053' ;;
    1.26.5:arm64) _go_sha='fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49' ;;
    *) echo "no reviewed SHA-256 for go${WT_GO_VERSION} linux/${_go_arch}" >&2; exit 1 ;;
  esac
  _go_tmp=$(mktemp -d)
  chmod 0700 "$_go_tmp"
  trap 'rm -rf "$_go_tmp"' EXIT
  curl --proto '=https' --tlsv1.2 --fail --location "https://go.dev/dl/${_go_tgz}" -o "$_go_tmp/${_go_tgz}"
  _got=$(sha256sum "$_go_tmp/${_go_tgz}" | awk '{print $1}')
  if [ "$_got" != "$_go_sha" ]; then
    echo "Go archive checksum mismatch for ${_go_tgz}" >&2
    exit 1
  fi
  sudo rm -rf "$_go_root"
  sudo tar -C /usr/local -xzf "$_go_tmp/${_go_tgz}"
  rm -rf "$_go_tmp"
  trap - EXIT
fi
export PATH="/usr/local/go/bin:$PATH"
go version

if ! id warptweet-build >/dev/null 2>&1; then
  sudo useradd --system --user-group --no-create-home \
    --home-dir /var/empty/warptweet-sshd --shell /usr/sbin/nologin warptweet-sshd || true
  sudo install -d -o root -g root -m 0755 /var/empty/warptweet-sshd
  sudo env WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 ./scripts/provision-openssh-build-account.sh
fi

WT_BUILD_HOME=/var/lib/warptweet-build
if [ -d "$REMOTE_ROOT/sources/warptweet-openssh-source" ]; then
  sudo rm -rf "$WT_BUILD_HOME/warptweet-openssh-source"
  sudo mkdir -p "$WT_BUILD_HOME/warptweet-openssh-source"
  sudo cp -a "$REMOTE_ROOT/sources/warptweet-openssh-source/." "$WT_BUILD_HOME/warptweet-openssh-source/"
  sudo chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-source"
else
  sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" \
    ./scripts/fetch-openssh.sh "$WT_BUILD_HOME/warptweet-openssh-source"
fi
if [ -d "$REMOTE_ROOT/sources/warptweet-openssl-source" ]; then
  sudo rm -rf "$WT_BUILD_HOME/warptweet-openssl-source"
  sudo mkdir -p "$WT_BUILD_HOME/warptweet-openssl-source"
  sudo cp -a "$REMOTE_ROOT/sources/warptweet-openssl-source/." "$WT_BUILD_HOME/warptweet-openssl-source/"
  sudo chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssl-source"
else
  sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" \
    ./scripts/fetch-openssl.sh "$WT_BUILD_HOME/warptweet-openssl-source"
fi

if [ -d "$WT_BUILD_HOME/warptweet-openssh-stage/opt/warptweet/libexec/openssh" ]; then
  echo "reusing remote OpenSSH stage at $WT_BUILD_HOME/warptweet-openssh-stage"
else
  sudo rm -rf "$WT_BUILD_HOME/warptweet-openssh-stage"
  sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" SUDO=sudo \
    ./scripts/build-openssh.sh \
    "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
    "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
    "$WT_BUILD_HOME/warptweet-openssh-stage"
fi

# Controller + provisioner + package assembly must run as non-root (build-linux-packages refuses root).
go build -trimpath -o "$REMOTE_ROOT/warptweet" ./cmd/warptweet
go build -trimpath -o "$REMOTE_ROOT/warptweet-provisioner" ./cmd/warptweet-provisioner
chown warptweet-build:warptweet-build "$REMOTE_ROOT/warptweet" "$REMOTE_ROOT/warptweet-provisioner"
chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-stage"
install -d -o warptweet-build -g warptweet-build -m 0755 "$REMOTE_ROOT/out"
rm -rf "$REMOTE_ROOT/out/pkg"
sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" WARPTWEET_VERSION="${WARPTWEET_VERSION:-0.1.0-dev}" \
  ./scripts/build-linux-packages.sh \
  "$WT_BUILD_HOME/warptweet-openssh-stage" \
  "$REMOTE_ROOT/warptweet" \
  "$REMOTE_ROOT/out/pkg"
DEB=$(ls -1 "$REMOTE_ROOT/out/pkg"/*.deb | head -1)
cp -a "$DEB" "$REMOTE_ROOT/server.deb"
REMOTE

    _out_deb=warptweet_${WARPTWEET_RELEASE_VERSION}_amd64.deb
    # shellcheck disable=SC2086
    scp $_scp_base "$_target:$_remote_root/server.deb" "$WARPTWEET_INTEROP_ARTIFACTS/$_out_deb"
    _have_server=1
    ensure_log "server package ready: $WARPTWEET_INTEROP_ARTIFACTS/$_out_deb"
}

ensure_server_deb() {
    if [ -n "$_have_server" ]; then
        return 0
    fi
    case "$WARPTWEET_INTEROP_BUILD_SERVER" in
        docker)
            ensure_server_deb_docker
            ;;
        remote)
            ensure_server_deb_remote
            ;;
        auto)
            # Prefer docker on the Mac so package build does not depend on lab SSH.
            if command -v docker >/dev/null 2>&1; then
                ensure_server_deb_docker
            else
                ensure_server_deb_remote
            fi
            ;;
        *)
            ensure_die "WARPTWEET_INTEROP_BUILD_SERVER must be docker, remote, or auto"
            ;;
    esac
}

ensure_log "ensuring interop packages under $WARPTWEET_INTEROP_ARTIFACTS"
ensure_client_pkg
ensure_server_deb
ensure_log "artifacts ready"
exit 0
