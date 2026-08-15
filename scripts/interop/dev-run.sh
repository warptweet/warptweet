#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Zero-arg local-dev entry for dual-host interop.
# Loads repo .env (and optional scripts/interop/config.env), fills happy-path
# defaults, then runs orchestrate.sh. Not a substitute for full WP8 evidence.

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPO_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/../.." && pwd)
cd "$WT_REPO_ROOT"

interop_dev_die() {
    echo "make interop: $*" >&2
    exit 1
}

interop_dev_log() {
    echo "make interop: $*" >&2
}

# Load env files without overriding variables already set in the shell.
load_env_file() {
    _file=$1
    [ -f "$_file" ] || return 0
    interop_dev_log "loading $_file"
    # Export assignments; ignore comments and blank lines.
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            '' | \#*) continue ;;
        esac
        case "$_line" in
            *=*)
                _key=${_line%%=*}
                _val=${_line#*=}
                # Strip optional surrounding quotes.
                case "$_val" in
                    \"*\") _val=${_val#\"}; _val=${_val%\"} ;;
                    \'*\') _val=${_val#\'}; _val=${_val%\'} ;;
                esac
                # Expand $HOME and $PWD only.
                _val=$(printf '%s' "$_val" | sed "s#\$HOME#$HOME#g; s#\$PWD#$WT_REPO_ROOT#g; s#\${HOME}#$HOME#g; s#\${PWD}#$WT_REPO_ROOT#g")
                eval "_cur=\${$_key+x}"
                if [ -z "${_cur:-}" ]; then
                    export "$_key=$_val"
                fi
                ;;
        esac
    done <"$_file"
}

load_env_file "$WT_REPO_ROOT/.env"
load_env_file "$WT_SCRIPT_DIRECTORY/config.env"

# Local-dev mode: relax pre-declared engine pins; record them post-install.
export WARPTWEET_INTEROP_LOCAL_DEV=1

# --- Required: server host ---
if [ -z "${WARPTWEET_INTEROP_SERVER_HOST:-}" ]; then
    interop_dev_die "set WARPTWEET_INTEROP_SERVER_HOST in .env (see .env.example)"
fi

# --- SSH identity ---
if [ -n "${WARPTWEET_INTEROP_SSH_IDENTITY:-}" ]; then
    case "$WARPTWEET_INTEROP_SSH_IDENTITY" in
        ~/*) WARPTWEET_INTEROP_SSH_IDENTITY=$HOME/${WARPTWEET_INTEROP_SSH_IDENTITY#~/} ;;
    esac
    if [ ! -f "$WARPTWEET_INTEROP_SSH_IDENTITY" ]; then
        interop_dev_die "SSH identity not found: $WARPTWEET_INTEROP_SSH_IDENTITY"
    fi
    export WARPTWEET_INTEROP_SSH_IDENTITY
    # Ensure agent can use it (may prompt once for passphrase).
    if command -v ssh-add >/dev/null 2>&1; then
        if ! ssh-add -l >/dev/null 2>&1; then
            interop_dev_log "ssh-agent has no keys; running ssh-add on identity"
            ssh-add "$WARPTWEET_INTEROP_SSH_IDENTITY" || interop_dev_die "ssh-add failed"
        fi
    fi
fi

: "${WARPTWEET_INTEROP_SERVER_USER:=ubuntu}"
: "${WARPTWEET_INTEROP_SSH_PORT:=22}"
export WARPTWEET_INTEROP_SERVER_USER WARPTWEET_INTEROP_SSH_PORT

# Listen default: host:2222 when host is an IP or hostname.
if [ -z "${WARPTWEET_INTEROP_SERVER_LISTEN:-}" ]; then
    WARPTWEET_INTEROP_SERVER_LISTEN="${WARPTWEET_INTEROP_SERVER_HOST}:2222"
fi
export WARPTWEET_INTEROP_SERVER_LISTEN

# Host key: local-dev may TOFU via keyscan when neither pin is set.
if [ -z "${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS:-}" ] && [ -z "${WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT:-}" ]; then
    export WARPTWEET_INTEROP_SSH_TRUST_ONCE=1
    interop_dev_log "warning: no SSH host pin; local-dev will TOFU keyscan for this run only"
fi

# --- Artifacts (auto-build when missing) ---
: "${WARPTWEET_INTEROP_ARTIFACTS:=$WT_REPO_ROOT/artifacts}"
case "$WARPTWEET_INTEROP_ARTIFACTS" in
    /*) ;;
    *) WARPTWEET_INTEROP_ARTIFACTS=$WT_REPO_ROOT/$WARPTWEET_INTEROP_ARTIFACTS ;;
esac
export WARPTWEET_INTEROP_ARTIFACTS
: "${WARPTWEET_RELEASE_VERSION:=0.1.0-dev}"
export WARPTWEET_RELEASE_VERSION
export WT_REPO_ROOT
export WARPTWEET_INTEROP_BUILD_SERVER="${WARPTWEET_INTEROP_BUILD_SERVER:-auto}"
export WARPTWEET_INTEROP_BUILD_CACHE="${WARPTWEET_INTEROP_BUILD_CACHE:-$WT_REPO_ROOT/.cache/interop-build}"

_need_build=0
if [ ! -d "$WARPTWEET_INTEROP_ARTIFACTS" ]; then
    _need_build=1
elif ! ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.deb >/dev/null 2>&1 && ! ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.rpm >/dev/null 2>&1; then
    _need_build=1
elif ! ls "$WARPTWEET_INTEROP_ARTIFACTS"/*.pkg >/dev/null 2>&1; then
    _need_build=1
fi
if [ "$_need_build" -eq 1 ]; then
    interop_dev_log "packages missing; building via scripts/interop/ensure-artifacts.sh"
    "$WT_SCRIPT_DIRECTORY/ensure-artifacts.sh" || interop_dev_die "ensure-artifacts failed"
fi
[ -d "$WARPTWEET_INTEROP_ARTIFACTS" ] || interop_dev_die "artifacts dir missing: $WARPTWEET_INTEROP_ARTIFACTS"

if [ -z "${WARPTWEET_INTEROP_SERVER_PACKAGE_FILE:-}" ]; then
    WARPTWEET_INTEROP_SERVER_PACKAGE_FILE=$(
        cd "$WARPTWEET_INTEROP_ARTIFACTS" && ls -1 *.deb 2>/dev/null | head -1
    )
    if [ -z "$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE" ]; then
        WARPTWEET_INTEROP_SERVER_PACKAGE_FILE=$(
            cd "$WARPTWEET_INTEROP_ARTIFACTS" && ls -1 *.rpm 2>/dev/null | head -1
        )
    fi
fi
if [ -z "${WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE:-}" ]; then
    WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE=$(
        cd "$WARPTWEET_INTEROP_ARTIFACTS" && ls -1 *.pkg 2>/dev/null | head -1
    )
fi
[ -n "$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE" ] || interop_dev_die "no server .deb/.rpm in $WARPTWEET_INTEROP_ARTIFACTS"
[ -n "$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE" ] || interop_dev_die "no client .pkg in $WARPTWEET_INTEROP_ARTIFACTS"
export WARPTWEET_INTEROP_SERVER_PACKAGE_FILE WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE

_server_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE
_client_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE
[ -f "$_server_pkg" ] || interop_dev_die "missing $_server_pkg"
[ -f "$_client_pkg" ] || interop_dev_die "missing $_client_pkg"

digest_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

if [ -z "${WARPTWEET_SERVER_PACKAGE_SHA256:-}" ]; then
    WARPTWEET_SERVER_PACKAGE_SHA256=$(digest_file "$_server_pkg")
fi
if [ -z "${WARPTWEET_CLIENT_PACKAGE_SHA256:-}" ]; then
    WARPTWEET_CLIENT_PACKAGE_SHA256=$(digest_file "$_client_pkg")
fi
export WARPTWEET_SERVER_PACKAGE_SHA256 WARPTWEET_CLIENT_PACKAGE_SHA256

# Engine digests filled post-install in local-dev when unset.
: "${WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256:=pending}"
: "${WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256:=pending}"
export WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256 WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256

if [ -z "${WARPTWEET_SOURCE_COMMIT:-}" ]; then
    WARPTWEET_SOURCE_COMMIT=$(git -C "$WT_REPO_ROOT" rev-parse HEAD 2>/dev/null || true)
fi
[ -n "${WARPTWEET_SOURCE_COMMIT:-}" ] || interop_dev_die "set WARPTWEET_SOURCE_COMMIT or run inside a git checkout"
export WARPTWEET_SOURCE_COMMIT

_arch=$(uname -m)
case "$_arch" in
    arm64 | aarch64) _client_profile=darwin-arm64 ;;
    x86_64 | amd64) _client_profile=darwin-amd64 ;;
    *) _client_profile=darwin-arm64 ;;
esac
: "${WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID:=$_client_profile}"
: "${WARPTWEET_SERVER_ARTIFACT_PROFILE_ID:=linux-amd64}"
export WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID WARPTWEET_SERVER_ARTIFACT_PROFILE_ID

: "${WARPTWEET_INTEROP_SERVER_CTRL:=/opt/warptweet/bin/warptweet}"
# macOS client package installs under Application Support, not /opt.
: "${WARPTWEET_INTEROP_CLIENT_CTRL:=/Library/Application Support/WarpTweet/bin/warptweet}"
: "${WARPTWEET_INTEROP_ECHO_PORT:=18432}"
: "${WARPTWEET_INTEROP_CLIENT_NAME:=interop-mac}"
: "${WARPTWEET_INTEROP_RUN_LIFECYCLE:=0}"
export WARPTWEET_INTEROP_SERVER_CTRL WARPTWEET_INTEROP_CLIENT_CTRL
export WARPTWEET_INTEROP_ECHO_PORT WARPTWEET_INTEROP_CLIENT_NAME WARPTWEET_INTEROP_RUN_LIFECYCLE

: "${WARPTWEET_INTEROP_WORK:=$WT_REPO_ROOT/scripts/interop/work}"
mkdir -p "$WARPTWEET_INTEROP_WORK"
# Fresh evidence path each run under work/
WARPTWEET_INTEROP_EVIDENCE_OUTPUT=$WARPTWEET_INTEROP_WORK/evidence-$(date -u +%Y%m%dT%H%M%SZ).json
export WARPTWEET_INTEROP_WORK WARPTWEET_INTEROP_EVIDENCE_OUTPUT

interop_dev_log "server=$WARPTWEET_INTEROP_SERVER_HOST listen=$WARPTWEET_INTEROP_SERVER_LISTEN"
interop_dev_log "artifacts=$WARPTWEET_INTEROP_ARTIFACTS"
interop_dev_log "server_pkg=$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE"
interop_dev_log "client_pkg=$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE"
interop_dev_log "work=$WARPTWEET_INTEROP_WORK"

exec "$WT_SCRIPT_DIRECTORY/orchestrate.sh"
