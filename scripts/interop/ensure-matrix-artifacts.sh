#!/bin/sh
# shellcheck shell=sh
# Optional extra package builds:
#   warptweet-client_${VERSION}_amd64.pkg   (darwin-amd64 via Rosetta)
#   warptweet_${VERSION}_arm64.deb          (linux-arm64 via Docker)
#
# First-edition CTA does not require darwin-amd64. linux-arm64 host packages
# are still used by the required darwin-arm64 × linux-arm64 matrix cell.
set -eu
LC_ALL=C
export LC_ALL

ensure_log() { echo "make interop-matrix: $*" >&2; }
ensure_die() { echo "make interop-matrix: $*" >&2; exit 1; }

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPO_ROOT=${WT_REPO_ROOT:-$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/../.." && pwd)}
cd "$WT_REPO_ROOT"

if [ -f "$WT_REPO_ROOT/.env" ]; then
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            '' | \#*) continue ;;
            *=*)
                _key=${_line%%=*}
                _val=${_line#*=}
                case "$_val" in
                    \"*\") _val=${_val#\"}; _val=${_val%\"} ;;
                    \'*\') _val=${_val#\'}; _val=${_val%\'} ;;
                esac
                _val=$(printf '%s' "$_val" | sed "s#\$HOME#$HOME#g; s#\${HOME}#$HOME#g; s#\$PWD#$WT_REPO_ROOT#g; s#\${PWD}#$WT_REPO_ROOT#g")
                eval "_have=\${$_key+x}"
                if [ -z "${_have:-}" ]; then
                    export "$_key=$_val"
                fi
                ;;
        esac
    done <"$WT_REPO_ROOT/.env"
fi

: "${WARPTWEET_INTEROP_ARTIFACTS:=$WT_REPO_ROOT/artifacts}"
: "${WARPTWEET_INTEROP_BUILD_CACHE:=$WT_REPO_ROOT/.cache/interop-build}"
: "${WARPTWEET_RELEASE_VERSION:=0.1.0-dev}"
export WARPTWEET_VERSION=$WARPTWEET_RELEASE_VERSION
mkdir -p "$WARPTWEET_INTEROP_ARTIFACTS" "$WARPTWEET_INTEROP_BUILD_CACHE"

. "$WT_REPO_ROOT/third_party/openssh/source.env"
. "$WT_REPO_ROOT/third_party/openssl/source.env"

_src_home=${WARPTWEET_INTEROP_SOURCE_HOME:-/tmp/wtib-src}
mkdir -p "$_src_home/tmp" "$WARPTWEET_INTEROP_BUILD_CACHE/sources"
chmod 0700 "$_src_home" "$_src_home/tmp" 2>/dev/null || true
if [ ! -f "$_src_home/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
    if [ -f "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
        rm -rf "$_src_home/warptweet-openssh-source"
        cp -a "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source" "$_src_home/"
    else
        HOME="$_src_home" TMPDIR="$_src_home/tmp" \
            "$WT_REPO_ROOT/scripts/fetch-openssh.sh" "$_src_home/warptweet-openssh-source"
        rm -rf "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssh-source"
        cp -a "$_src_home/warptweet-openssh-source" "$WARPTWEET_INTEROP_BUILD_CACHE/sources/"
    fi
fi
if [ ! -f "$_src_home/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
    if [ -f "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
        rm -rf "$_src_home/warptweet-openssl-source"
        cp -a "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source" "$_src_home/"
    else
        HOME="$_src_home" TMPDIR="$_src_home/tmp" \
            "$WT_REPO_ROOT/scripts/fetch-openssl.sh" "$_src_home/warptweet-openssl-source"
        rm -rf "$WARPTWEET_INTEROP_BUILD_CACHE/sources/warptweet-openssl-source"
        cp -a "$_src_home/warptweet-openssl-source" "$WARPTWEET_INTEROP_BUILD_CACHE/sources/"
    fi
fi
WT_OPENSSH_ARCHIVE=$_src_home/warptweet-openssh-source/$OPENSSH_ARCHIVE
WT_OPENSSL_ARCHIVE=$_src_home/warptweet-openssl-source/$OPENSSL_ARCHIVE

ensure_darwin_amd64_pkg() {
    _pkg=$WARPTWEET_INTEROP_ARTIFACTS/warptweet-client_${WARPTWEET_RELEASE_VERSION}_amd64.pkg
    if [ -f "$_pkg" ]; then
        ensure_log "darwin-amd64 package already present: $_pkg"
        return 0
    fi
    [ "$(uname -s)" = Darwin ] || ensure_die "darwin-amd64 .pkg requires macOS"
    arch -x86_64 uname -m >/dev/null 2>&1 || ensure_die "Rosetta is required to compile darwin-amd64"
    _stage=${WARPTWEET_INTEROP_DARWIN_AMD64_STAGE:-/tmp/wtib-amd64/openssh-darwin-stage}
    _stage_cache=$WARPTWEET_INTEROP_BUILD_CACHE/openssh-darwin-amd64-stage
    _marker=$_stage/Library/Application\ Support/WarpTweet/share/openssh-bundle.sha256
    mkdir -p "$(dirname "$_stage")"
    if [ ! -f "$_marker" ] && [ -f "$_stage_cache/Library/Application Support/WarpTweet/share/openssh-bundle.sha256" ]; then
        ensure_log "restoring cached darwin-amd64 OpenSSH stage"
        rm -rf "$_stage"
        cp -a "$_stage_cache" "$_stage"
    fi
    if [ ! -f "$_marker" ]; then
        ensure_log "building darwin-amd64 OpenSSH stage under Rosetta"
        rm -rf "$_stage"
        : "${SKIP_LTESTS:=scp3}"
        arch -x86_64 env \
            TMPDIR=/tmp/wtib-src/tmp \
            SKIP_LTESTS=$SKIP_LTESTS \
            MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0} \
            "$WT_REPO_ROOT/scripts/build-openssh-darwin.sh" \
            "$WT_OPENSSH_ARCHIVE" \
            "$WT_OPENSSL_ARCHIVE" \
            "$_stage"
        rm -rf "$_stage_cache"
        cp -a "$_stage" "$_stage_cache"
    fi
    ensure_log "building darwin-amd64 controller + provisioner"
    mkdir -p "$WT_REPO_ROOT/bin"
    GOCACHE=${GOCACHE:-/private/tmp/warptweet-go-build-amd64}
    mkdir -p "$GOCACHE"
    arch -x86_64 env \
        GOARCH=amd64 CGO_ENABLED=1 GOCACHE=$GOCACHE \
        MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0} \
        CGO_CFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-13.0}" \
        CGO_LDFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-13.0}" \
        go build -trimpath -o "$WT_REPO_ROOT/bin/warptweet-amd64" "$WT_REPO_ROOT/cmd/warptweet"
    arch -x86_64 env \
        GOARCH=amd64 CGO_ENABLED=1 GOCACHE=$GOCACHE \
        MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0} \
        CGO_CFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-13.0}" \
        CGO_LDFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-13.0}" \
        go build -trimpath -o "$WT_REPO_ROOT/bin/warptweet-provisioner-amd64" "$WT_REPO_ROOT/cmd/warptweet-provisioner"
    _sign_id=${WARPTWEET_CODESIGN_IDENTITY:-"Developer ID Application: Baldwinson Corporation (CP4268Q8UF)"}
    if command -v codesign >/dev/null 2>&1 && security find-identity -v -p codesigning 2>/dev/null | grep -Fq "$_sign_id"; then
        for _bin in \
            "$WT_REPO_ROOT/bin/warptweet-amd64" \
            "$WT_REPO_ROOT/bin/warptweet-provisioner-amd64" \
            "$_stage/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh" \
            "$_stage/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen"; do
            [ -f "$_bin" ] || continue
            codesign --force --options runtime --timestamp --sign "$_sign_id" "$_bin"
        done
    fi
    if [ -z "${WARPTWEET_INSTALLER_IDENTITY:-}" ] &&
        security find-identity -v -p basic 2>/dev/null | grep -Fq "Developer ID Installer: Baldwinson Corporation (CP4268Q8UF)"; then
        WARPTWEET_INSTALLER_IDENTITY="Developer ID Installer: Baldwinson Corporation (CP4268Q8UF)"
        export WARPTWEET_INSTALLER_IDENTITY
    fi
    if [ -z "${WARPTWEET_NOTARY_PROFILE:-}" ] && [ -n "${WARPTWEET_INSTALLER_IDENTITY:-}" ]; then
        WARPTWEET_NOTARY_PROFILE=warptweet-notary
        export WARPTWEET_NOTARY_PROFILE
    fi
    rm -f "$_pkg" "$_pkg.sha256"
    "$WT_REPO_ROOT/scripts/build-macos-pkg.sh" \
        "$_stage" \
        "$WT_REPO_ROOT/bin/warptweet-amd64" \
        "$WT_REPO_ROOT/bin/warptweet-provisioner-amd64" \
        "$_pkg"
    ensure_log "darwin-amd64 package ready: $_pkg"
}

ensure_linux_arm64_deb() {
    _deb=$WARPTWEET_INTEROP_ARTIFACTS/warptweet_${WARPTWEET_RELEASE_VERSION}_arm64.deb
    if [ -f "$_deb" ]; then
        ensure_log "linux-arm64 package already present: $_deb"
        return 0
    fi
    command -v docker >/dev/null 2>&1 || ensure_die "docker is required to build linux-arm64"
    _go_ver=${WARPTWEET_INTEROP_GO_VERSION:-1.26.5}
    ensure_log "building linux-arm64 server package in Docker (linux/arm64)"
    docker run --rm -i --platform linux/arm64 \
        -v "$WT_REPO_ROOT:/src:ro" \
        -v "$WARPTWEET_INTEROP_BUILD_CACHE:/cache" \
        -v "$WARPTWEET_INTEROP_ARTIFACTS:/out" \
        -e WARPTWEET_VERSION="$WARPTWEET_RELEASE_VERSION" \
        -e OPENSSH_ARCHIVE="$OPENSSH_ARCHIVE" \
        -e OPENSSL_ARCHIVE="$OPENSSL_ARCHIVE" \
        -e WT_GO_VERSION="$_go_ver" \
        -e OUT_DEB="warptweet_${WARPTWEET_RELEASE_VERSION}_arm64.deb" \
        ubuntu:24.04 \
        bash -euo pipefail <<'DOCKER'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential autoconf automake libtool pkg-config \
  zlib1g-dev libpam0g-dev libselinux1-dev libedit-dev libkrb5-dev \
  gpg gpg-agent libtext-template-perl passwd perl python3-minimal sudo \
  ca-certificates curl dpkg-dev fakeroot acl rsync binutils
cp -a /src /work
cd /work
_go_root=/usr/local/go
_go_tgz="go${WT_GO_VERSION}.linux-arm64.tar.gz"
_go_sha='fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49'
if [ "$WT_GO_VERSION" != "1.26.5" ]; then
    echo "no reviewed SHA-256 for go${WT_GO_VERSION} linux/arm64" >&2
    exit 1
fi
_go_tmp=$(mktemp -d)
curl --proto '=https' --tlsv1.2 --fail --location "https://go.dev/dl/${_go_tgz}" -o "$_go_tmp/${_go_tgz}"
_got=$(sha256sum "$_go_tmp/${_go_tgz}" | awk '{print $1}')
[ "$_got" = "$_go_sha" ]
rm -rf "$_go_root"
tar -C /usr/local -xzf "$_go_tmp/${_go_tgz}"
rm -rf "$_go_tmp"
export PATH="/usr/local/go/bin:$PATH"
if ! id warptweet-build >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home \
        --home-dir /var/empty/warptweet-sshd --shell /usr/sbin/nologin warptweet-sshd || true
    install -d -o root -g root -m 0755 /var/empty/warptweet-sshd
    WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 ./scripts/provision-openssh-build-account.sh
fi
WT_BUILD_HOME=/var/lib/warptweet-build
mkdir -p "$WT_BUILD_HOME/tmp"
if [ -f "/cache/sources/warptweet-openssh-source/$OPENSSH_ARCHIVE" ]; then
    mkdir -p "$WT_BUILD_HOME/warptweet-openssh-source"
    cp -a "/cache/sources/warptweet-openssh-source/." "$WT_BUILD_HOME/warptweet-openssh-source/"
    chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-source"
fi
if [ -f "/cache/sources/warptweet-openssl-source/$OPENSSL_ARCHIVE" ]; then
    mkdir -p "$WT_BUILD_HOME/warptweet-openssl-source"
    cp -a "/cache/sources/warptweet-openssl-source/." "$WT_BUILD_HOME/warptweet-openssl-source/"
    chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssl-source"
fi
if [ ! -d "$WT_BUILD_HOME/warptweet-openssh-stage/opt/warptweet/libexec/openssh" ]; then
    if [ -d /cache/openssh-linux-arm64-stage/opt/warptweet/libexec/openssh ]; then
        cp -a /cache/openssh-linux-arm64-stage "$WT_BUILD_HOME/warptweet-openssh-stage"
        chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-stage"
    else
        sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" SUDO=sudo \
            ./scripts/build-openssh.sh \
            "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
            "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
            "$WT_BUILD_HOME/warptweet-openssh-stage"
        rm -rf /cache/openssh-linux-arm64-stage
        cp -a "$WT_BUILD_HOME/warptweet-openssh-stage" /cache/openssh-linux-arm64-stage
    fi
fi
go build -trimpath -o /tmp/warptweet ./cmd/warptweet
go build -trimpath -o /tmp/warptweet-provisioner ./cmd/warptweet-provisioner
chown warptweet-build:warptweet-build /tmp/warptweet /tmp/warptweet-provisioner
chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-stage"
# build-linux-packages creates the output directory and refuses a pre-existing one.
rm -rf /tmp/wt-pkg-out
sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" WARPTWEET_VERSION="${WARPTWEET_VERSION:-0.1.0-dev}" \
    ./scripts/build-linux-packages.sh \
    "$WT_BUILD_HOME/warptweet-openssh-stage" \
    /tmp/warptweet \
    /tmp/wt-pkg-out
DEB=$(ls -1 /tmp/wt-pkg-out/*.deb | head -1)
test -f "$DEB"
cp -a "$DEB" "/out/$OUT_DEB"
test -f "/out/$OUT_DEB"
DOCKER
    [ -f "$_deb" ] || ensure_die "linux-arm64 docker build did not publish $_deb"
    if [ -n "${WARPTWEET_LINUX_GPG_KEY:-}" ] && [ -x "$WT_REPO_ROOT/scripts/sign-linux-deb.sh" ]; then
        ensure_log "signing linux-arm64 package with $WARPTWEET_LINUX_GPG_KEY"
        "$WT_REPO_ROOT/scripts/sign-linux-deb.sh" "$_deb" ||
            ensure_log "warning: linux-arm64 GPG signing failed"
    fi
    ensure_log "linux-arm64 package ready: $_deb"
}

ensure_log "building remaining matrix packages under $WARPTWEET_INTEROP_ARTIFACTS"
# Linux/arm64 is Docker and does not need the Developer ID keychain. Do it
# first so a productsign prompt cannot stall the whole matrix.
ensure_linux_arm64_deb
ensure_darwin_amd64_pkg
ensure_log "matrix artifacts ready"
exit 0
