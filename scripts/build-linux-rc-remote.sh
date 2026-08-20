#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Build a signed Linux host RC on a persistent Ubuntu builder over SSH.
# Run from the Mac. The GPG secret key stays on this machine unless you
# explicitly import it on the builder for remote signing.

fail() {
    echo "build-linux-rc-remote: $*" >&2
    exit 1
}

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
cd "$WT_REPOSITORY_ROOT"

if [ -f "$WT_REPOSITORY_ROOT/.env" ]; then
    # shellcheck disable=SC1091
    set -a
    # Load KEY=VALUE lines only.
    while IFS= read -r WT_LINE || [ -n "$WT_LINE" ]; do
        case "$WT_LINE" in
            '' | \#*) continue ;;
            *=*)
                WT_KEY=${WT_LINE%%=*}
                WT_VAL=${WT_LINE#*=}
                case "$WT_KEY" in
                    '' | [0-9]* | *[!A-Za-z0-9_]*)
                        fail "invalid .env key: $WT_KEY"
                        ;;
                esac
                case "$WT_VAL" in
                    \"*\") WT_VAL=${WT_VAL#\"}; WT_VAL=${WT_VAL%\"} ;;
                    \'*\') WT_VAL=${WT_VAL#\'}; WT_VAL=${WT_VAL%\'} ;;
                esac
                WT_VAL=$(printf '%s' "$WT_VAL" | sed "s#\$HOME#$HOME#g; s#\${HOME}#$HOME#g; s#\$PWD#$WT_REPOSITORY_ROOT#g; s#\${PWD}#$WT_REPOSITORY_ROOT#g")
                if printenv "$WT_KEY" >/dev/null 2>&1; then
                    continue
                fi
                export "$WT_KEY=$WT_VAL"
                ;;
        esac
    done <"$WT_REPOSITORY_ROOT/.env"
    set +a
fi

. "$WT_REPOSITORY_ROOT/third_party/openssh/source.env"
. "$WT_REPOSITORY_ROOT/third_party/openssl/source.env"

wt_valid_dotted_ints() {
    WT_REST=$1
    WT_WANT=$2
    WT_COUNT=0
    while [ -n "$WT_REST" ]; do
        case "$WT_REST" in
            *.*)
                WT_PART=${WT_REST%%.*}
                WT_REST=${WT_REST#*.}
                if [ -z "$WT_REST" ]; then
                    return 1
                fi
                ;;
            *)
                WT_PART=$WT_REST
                WT_REST=
                ;;
        esac
        case "$WT_PART" in
            '' | *[!0-9]*) return 1 ;;
        esac
        WT_COUNT=$((WT_COUNT + 1))
    done
    [ "$WT_COUNT" -eq "$WT_WANT" ]
}

wt_valid_release_version() {
    case "$1" in
        *-*)
            WT_CORE=${1%%-*}
            WT_SUFFIX=${1#*-}
            wt_valid_dotted_ints "$WT_CORE" 3 || return 1
            case "$WT_SUFFIX" in
                rc.[0-9]*)
                    WT_RC=${WT_SUFFIX#rc.}
                    case "$WT_RC" in
                        '' | *[!0-9]*) return 1 ;;
                    esac
                    ;;
                *)
                    return 1
                    ;;
            esac
            ;;
        *)
            wt_valid_dotted_ints "$1" 3 || return 1
            ;;
    esac
}

require_chars() {
    WT_REQUIRE_NAME=$1
    WT_REQUIRE_VALUE=$2
    WT_REQUIRE_CLASS=$3
    case "$WT_REQUIRE_VALUE" in
        '') fail "$WT_REQUIRE_NAME is required" ;;
    esac
    case "$WT_REQUIRE_CLASS" in
        version)
            case "$WT_REQUIRE_VALUE" in
                *-dev* | latest) fail "$WT_REQUIRE_NAME=$WT_REQUIRE_VALUE is not a release-candidate version" ;;
            esac
            if ! wt_valid_release_version "$WT_REQUIRE_VALUE"; then
                fail "$WT_REQUIRE_NAME must look like 0.1.0 or 0.1.0-rc.1"
            fi
            ;;
        goversion)
            if ! wt_valid_dotted_ints "$WT_REQUIRE_VALUE" 3; then
                fail "$WT_REQUIRE_NAME must look like 1.26.5"
            fi
            ;;
        gpgkey)
            case "$WT_REQUIRE_VALUE" in
                *[!0-9A-Fa-f]*) fail "$WT_REQUIRE_NAME must be hexadecimal" ;;
            esac
            if [ "${#WT_REQUIRE_VALUE}" -lt 8 ] || [ "${#WT_REQUIRE_VALUE}" -gt 40 ]; then
                fail "$WT_REQUIRE_NAME must be 8-40 hex characters"
            fi
            ;;
        host)
            case "$WT_REQUIRE_VALUE" in
                *[!A-Za-z0-9._-]*) fail "$WT_REQUIRE_NAME contains forbidden characters" ;;
            esac
            ;;
        user)
            case "$WT_REQUIRE_VALUE" in
                *[!A-Za-z0-9_-]* | [0-9]* | '' | -*) fail "$WT_REQUIRE_NAME is not a safe username" ;;
            esac
            ;;
        port)
            case "$WT_REQUIRE_VALUE" in
                *[!0-9]* | 0 | 0*) fail "$WT_REQUIRE_NAME must be a TCP port 1-65535" ;;
            esac
            if [ "$WT_REQUIRE_VALUE" -gt 65535 ]; then
                fail "$WT_REQUIRE_NAME must be a TCP port 1-65535"
            fi
            ;;
        abspath)
            case "$WT_REQUIRE_VALUE" in
                /*) ;;
                *) fail "$WT_REQUIRE_NAME must be an absolute path" ;;
            esac
            case "$WT_REQUIRE_VALUE" in
                *[!A-Za-z0-9._/+-]*) fail "$WT_REQUIRE_NAME contains forbidden path characters" ;;
            esac
            ;;
        archive)
            case "$WT_REQUIRE_VALUE" in
                *[!A-Za-z0-9._-]*) fail "$WT_REQUIRE_NAME contains forbidden characters" ;;
            esac
            ;;
        *)
            fail "unknown validation class $WT_REQUIRE_CLASS"
            ;;
    esac
}

WT_VERSION=${WARPTWEET_VERSION:-}
WT_GO_VERSION=${WARPTWEET_INTEROP_GO_VERSION:-1.26.5}
WT_USER=${WARPTWEET_INTEROP_SERVER_USER:-ubuntu}
WT_HOST=${WARPTWEET_INTEROP_SERVER_HOST:-}
WT_PORT=${WARPTWEET_INTEROP_SSH_PORT:-22}
require_chars WARPTWEET_VERSION "$WT_VERSION" version
WT_TREE_VERSION=$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$WT_REPOSITORY_ROOT/internal/command/command.go")
WT_TREE_COUNT=$(printf '%s\n' "$WT_TREE_VERSION" | grep -c .)
if [ "$WT_TREE_COUNT" -ne 1 ]; then
    fail "expected exactly one command.Version in internal/command/command.go"
fi
if [ "$WT_VERSION" != "$WT_TREE_VERSION" ]; then
    fail "WARPTWEET_VERSION=$WT_VERSION does not match command.Version=$WT_TREE_VERSION"
fi
require_chars WARPTWEET_INTEROP_GO_VERSION "$WT_GO_VERSION" goversion
require_chars WARPTWEET_LINUX_GPG_KEY "${WARPTWEET_LINUX_GPG_KEY:-}" gpgkey
require_chars WARPTWEET_INTEROP_SERVER_HOST "$WT_HOST" host
require_chars WARPTWEET_INTEROP_SERVER_USER "$WT_USER" user
require_chars WARPTWEET_INTEROP_SSH_PORT "$WT_PORT" port
require_chars OPENSSH_ARCHIVE "$OPENSSH_ARCHIVE" archive
require_chars OPENSSL_ARCHIVE "$OPENSSL_ARCHIVE" archive
case "${WARPTWEET_LINUX_REMOTE_SIGN:-}" in
    '' | 0 | 1) ;;
    *) fail "WARPTWEET_LINUX_REMOTE_SIGN must be empty, 0, or 1" ;;
esac
WT_TARGET="$WT_USER@$WT_HOST"
WT_REMOTE_ROOT=/var/tmp/warptweet-rc
WT_OUT_DIR=${WARPTWEET_RC_OUTPUT:-$WT_REPOSITORY_ROOT/dist}
mkdir -p "$WT_OUT_DIR"

WT_KNOWN_HOSTS=${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}
case "$WT_KNOWN_HOSTS" in
    ~/*) WT_KNOWN_HOSTS=$HOME/${WT_KNOWN_HOSTS#~/} ;;
esac
require_chars WARPTWEET_INTEROP_SSH_KNOWN_HOSTS "$WT_KNOWN_HOSTS" abspath
if [ ! -f "$WT_KNOWN_HOSTS" ]; then
    fail "pre-populated known_hosts required: $WT_KNOWN_HOSTS"
fi
WT_SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$WT_KNOWN_HOSTS -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ServerAliveInterval=30 -o ServerAliveCountMax=120"
if [ -n "${WARPTWEET_INTEROP_SSH_IDENTITY:-}" ]; then
    WT_ID=$WARPTWEET_INTEROP_SSH_IDENTITY
    case "$WT_ID" in
        ~/*) WT_ID=$HOME/${WT_ID#~/} ;;
    esac
    require_chars WARPTWEET_INTEROP_SSH_IDENTITY "$WT_ID" abspath
    WT_SSH_OPTS="$WT_SSH_OPTS -i $WT_ID"
fi

# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" 'echo remote_ok' >/dev/null \
    || fail "ssh to $WT_TARGET failed; add your pubkey and passwordless sudo first"

echo "build-linux-rc-remote: syncing $WT_TARGET:$WT_REMOTE_ROOT"
# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" \
    "sudo mkdir -p '$WT_REMOTE_ROOT' && sudo chown \"\$USER:\" '$WT_REMOTE_ROOT'"
# shellcheck disable=SC2086
rsync -az --delete \
    -e "ssh $WT_SSH_OPTS -p $WT_PORT" \
    --exclude '.git' --exclude 'artifacts' --exclude '.cache' \
    --exclude 'scripts/interop/work' --exclude 'node_modules' --exclude 'dist' --exclude 'local' \
    "$WT_REPOSITORY_ROOT/" "$WT_TARGET:$WT_REMOTE_ROOT/src/"

if [ -d "$WT_REPOSITORY_ROOT/.cache/interop-build/sources" ]; then
    # shellcheck disable=SC2086
    rsync -az -e "ssh $WT_SSH_OPTS -p $WT_PORT" \
        "$WT_REPOSITORY_ROOT/.cache/interop-build/sources/" "$WT_TARGET:$WT_REMOTE_ROOT/sources/" || true
fi

echo "build-linux-rc-remote: bootstrapping builder if needed"
# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" \
    "sudo env WARPTWEET_INTEROP_GO_VERSION='$WT_GO_VERSION' \
        '$WT_REMOTE_ROOT/src/scripts/bootstrap-ubuntu-builder.sh'"

echo "build-linux-rc-remote: compiling OpenSSH stage (long)"
# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" \
    "export WARPTWEET_VERSION='$WT_VERSION' OPENSSH_ARCHIVE='$OPENSSH_ARCHIVE' OPENSSL_ARCHIVE='$OPENSSL_ARCHIVE' REMOTE_ROOT='$WT_REMOTE_ROOT' PATH=/usr/local/go/bin:\$PATH; bash -euo pipefail" <<'REMOTE' || fail "OpenSSH stage SSH session failed"
cd "$REMOTE_ROOT/src"
go version
WT_BUILD_HOME=/var/lib/warptweet-build
sudo install -d -o warptweet-build -g warptweet-build -m 0700 "$WT_BUILD_HOME/tmp"

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

WT_STAGE_MANIFEST=$WT_BUILD_HOME/warptweet-openssh-stage.manifest
wt_stage_inputs() {
    sha256sum \
        "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
        "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
        ./scripts/build-openssh.sh \
        ./scripts/apply-openssh-grant-hook.sh \
        ./scripts/apply-openssh-forward-only.sh \
        ./third_party/openssh/warptweet-grant.c \
        ./third_party/openssh/warptweet-grant.h \
        ./third_party/openssh/patches/0001-warptweet-grant-register.patch
}
WT_STAGE_OK=0
if [ -d "$WT_BUILD_HOME/warptweet-openssh-stage/opt/warptweet/libexec/openssh" ] &&
    [ -f "$WT_STAGE_MANIFEST" ] &&
    [ "$(wt_stage_inputs)" = "$(cat "$WT_STAGE_MANIFEST")" ]; then
    WT_STAGE_OK=1
    echo "build-linux-rc-remote: reusing OpenSSH stage (manifest match)"
fi
if [ "$WT_STAGE_OK" -ne 1 ]; then
    sudo rm -rf "$WT_BUILD_HOME/warptweet-openssh-stage" "$WT_STAGE_MANIFEST"
    sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" TMPDIR="$WT_BUILD_HOME/tmp" SUDO=sudo \
        ./scripts/build-openssh.sh \
        "$WT_BUILD_HOME/warptweet-openssh-source/$OPENSSH_ARCHIVE" \
        "$WT_BUILD_HOME/warptweet-openssl-source/$OPENSSL_ARCHIVE" \
        "$WT_BUILD_HOME/warptweet-openssh-stage"
    wt_stage_inputs >"$WT_STAGE_MANIFEST"
fi
uname -m >"$REMOTE_ROOT/arch"
echo "build-linux-rc-remote: OpenSSH stage ready"
REMOTE

echo "build-linux-rc-remote: building controller and .deb"
# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" \
    "export WARPTWEET_VERSION='$WT_VERSION' REMOTE_ROOT='$WT_REMOTE_ROOT' PATH=/usr/local/go/bin:\$PATH; bash -euo pipefail" <<'PACKAGE' || fail "package SSH session failed"
cd "$REMOTE_ROOT/src"
WT_BUILD_HOME=/var/lib/warptweet-build
test -d "$WT_BUILD_HOME/warptweet-openssh-stage/opt/warptweet/libexec/openssh"
echo "build-linux-rc-remote: building controller and provisioner"
go build -trimpath -o "$REMOTE_ROOT/warptweet" ./cmd/warptweet
go build -trimpath -o "$REMOTE_ROOT/warptweet-provisioner" ./cmd/warptweet-provisioner
sudo chown warptweet-build:warptweet-build "$REMOTE_ROOT/warptweet" "$REMOTE_ROOT/warptweet-provisioner"
sudo chown -R warptweet-build:warptweet-build "$WT_BUILD_HOME/warptweet-openssh-stage"
sudo rm -rf "$WT_BUILD_HOME/pkg-out"
echo "build-linux-rc-remote: assembling .deb"
sudo -u warptweet-build -H env HOME="$WT_BUILD_HOME" WARPTWEET_VERSION="$WARPTWEET_VERSION" \
    ./scripts/build-linux-packages.sh \
    "$WT_BUILD_HOME/warptweet-openssh-stage" \
    "$REMOTE_ROOT/warptweet" \
    "$WT_BUILD_HOME/pkg-out"
cp -a "$WT_BUILD_HOME/pkg-out"/*.deb "$REMOTE_ROOT/server.deb"
test -f "$REMOTE_ROOT/server.deb"
echo "build-linux-rc-remote: wrote $REMOTE_ROOT/server.deb"
PACKAGE

if ! WT_REMOTE_ARCH=$(ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" "cat '$WT_REMOTE_ROOT/arch'"); then
    fail "remote build did not write $WT_REMOTE_ROOT/arch; the compile SSH session likely dropped"
fi
case "$WT_REMOTE_ARCH" in
    x86_64 | amd64) WT_DEB_ARCH=amd64 ;;
    aarch64 | arm64) WT_DEB_ARCH=arm64 ;;
    *) fail "unsupported remote arch $WT_REMOTE_ARCH" ;;
esac
WT_DEB="$WT_OUT_DIR/warptweet_${WT_VERSION}_${WT_DEB_ARCH}.deb"
if [ -e "$WT_DEB" ]; then
    fail "refusing to overwrite $WT_DEB"
fi
# shellcheck disable=SC2086
ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" "test -f '$WT_REMOTE_ROOT/server.deb'" \
    || fail "remote package step did not produce $WT_REMOTE_ROOT/server.deb"
# shellcheck disable=SC2086
scp $WT_SSH_OPTS -P "$WT_PORT" "$WT_TARGET:$WT_REMOTE_ROOT/server.deb" "$WT_DEB"
echo "build-linux-rc-remote: fetched $WT_DEB"

if command -v gpg >/dev/null 2>&1 && command -v ar >/dev/null 2>&1; then
    "$WT_REPOSITORY_ROOT/scripts/sign-linux-deb.sh" "$WT_DEB"
elif [ "${WARPTWEET_LINUX_REMOTE_SIGN:-}" = "1" ]; then
    echo "build-linux-rc-remote: signing on the builder (WARPTWEET_LINUX_REMOTE_SIGN=1)"
    # shellcheck disable=SC2086
    scp $WT_SSH_OPTS -P "$WT_PORT" "$WT_DEB" "$WT_TARGET:$WT_REMOTE_ROOT/to-sign.deb"
    gpg --export-secret-keys --armor "$WARPTWEET_LINUX_GPG_KEY" \
        | ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" "umask 077 && cat >'$WT_REMOTE_ROOT/sign.key'"
    # shellcheck disable=SC2086
    ssh $WT_SSH_OPTS -p "$WT_PORT" "$WT_TARGET" \
        "export GNUPGHOME='$WT_REMOTE_ROOT/gnupg' REMOTE_ROOT='$WT_REMOTE_ROOT' WARPTWEET_LINUX_GPG_KEY='$WARPTWEET_LINUX_GPG_KEY'; bash -euo pipefail" <<'SIGN'
umask 077
cleanup_sign() {
    rm -rf "$GNUPGHOME" "$REMOTE_ROOT/sign.key"
}
trap cleanup_sign EXIT HUP INT TERM
mkdir -m 0700 -p "$GNUPGHOME"
gpg --batch --import "$REMOTE_ROOT/sign.key"
"$REMOTE_ROOT/src/scripts/sign-linux-deb.sh" "$REMOTE_ROOT/to-sign.deb"
SIGN
    # shellcheck disable=SC2086
    scp $WT_SSH_OPTS -P "$WT_PORT" "$WT_TARGET:$WT_REMOTE_ROOT/to-sign.deb" "$WT_DEB"
    echo "build-linux-rc-remote: signed on builder and replaced $WT_DEB"
else
    fail "local gpg+ar unavailable; set WARPTWEET_LINUX_REMOTE_SIGN=1 to sign on the builder"
fi

echo "build-linux-rc-remote: ready $WT_DEB"
shasum -a 256 "$WT_DEB"
