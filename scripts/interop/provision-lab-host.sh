#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Bootstrap a freshly spun Ubuntu interop host over the same SSH config as
# make interop: Docker Engine, Compose plugin, python3, iproute2, and loopback
# Postgres bound to 127.0.0.1:5432. Safe to re-run. Loads repo-root .env.
# Invoked as `make lab-host`. orchestrate.sh calls the same helpers, so a
# first `make interop` against a new VPS also installs Docker.

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPO_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/../.." && pwd)
cd "$WT_REPO_ROOT"
WARPTWEET_INTEROP_ROOT=$WT_SCRIPT_DIRECTORY
export WARPTWEET_INTEROP_ROOT WT_REPO_ROOT

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

: "${WARPTWEET_INTEROP_SERVER_HOST:?set WARPTWEET_INTEROP_SERVER_HOST}"
: "${WARPTWEET_INTEROP_SERVER_USER:=root}"
: "${WARPTWEET_INTEROP_SSH_PORT:=22}"
: "${WARPTWEET_INTEROP_WORK:=$WT_REPO_ROOT/scripts/interop/work}"
mkdir -p "$WARPTWEET_INTEROP_WORK"
export WARPTWEET_INTEROP_SERVER_HOST WARPTWEET_INTEROP_SERVER_USER WARPTWEET_INTEROP_SSH_PORT WARPTWEET_INTEROP_WORK
if [ -z "${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS:-}" ] && [ -z "${WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT:-}" ]; then
    export WARPTWEET_INTEROP_SSH_TRUST_ONCE=1
    export WARPTWEET_INTEROP_LOCAL_DEV=1
fi

# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/common.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/ssh.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/postgres.sh"

interop_ssh_check
interop_ensure_loopback_postgres 5432
echo "lab host docker+postgres ready on $WARPTWEET_INTEROP_SERVER_HOST 127.0.0.1:5432"
interop_ssh "sudo sh -s" <<'REMOTE' || true
set -eu
echo "docker=$(command -v docker || echo missing)"
docker version --format 'engine={{.Server.Version}}' 2>/dev/null || true
docker compose version 2>/dev/null || true
ss -lnt | grep -E '127.0.0.1:5432|:5432' || netstat -lnt 2>/dev/null | grep 5432 || true
docker inspect -f 'postgres={{.State.Status}}' warptweet-interop-postgres 2>/dev/null || true
REMOTE
