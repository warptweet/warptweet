# shellcheck shell=sh
# Shared helpers for dual-host interop Phase A.

interop_die() {
    echo "interop: $*" >&2
    exit 1
}

interop_log() {
    echo "interop: $*" >&2
}

interop_require_cmd() {
    command -v "$1" >/dev/null 2>&1 || interop_die "required command not found: $1"
}

interop_is_hex64() {
    case "$1" in
        *[!0-9a-f]* | "") return 1 ;;
        *)
            [ "${#1}" -eq 64 ]
            ;;
    esac
}

interop_is_hex40() {
    case "$1" in
        *[!0-9a-f]* | "") return 1 ;;
        *)
            [ "${#1}" -eq 40 ]
            ;;
    esac
}

interop_digest_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

interop_json_escape() {
    # Full JSON string escaping (control chars, quotes, backslash).
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])'
}

# Refuse source-tree controllers.
interop_assert_package_ctrl() {
    _path=$1
    _label=$2
    case "$_path" in
        /opt/warptweet/* | /usr/local/* | /opt/homebrew/* | /Library/*) ;;
        *)
            interop_die "$_label controller path must be package-owned (got: $_path)"
            ;;
    esac
    [ -x "$_path" ] || interop_die "$_label controller not executable: $_path"
}

# Run the installed client controller as the logged-in operator. The signed
# package's root provisioner owns privileged state mutation; the public CLI
# never needs sudo or an AppleScript authorization prompt after installation.
interop_client_cmd() {
    _out=${INTEROP_CLIENT_OUT:-/tmp/wt-interop-client.out}
    _err=${INTEROP_CLIENT_ERR:-/tmp/wt-interop-client.err}
    : >"$_out"
    : >"$_err"
    if ! "$WARPTWEET_INTEROP_CLIENT_CTRL" "$@" >"$_out" 2>"$_err"; then
        cat "$_out"
        cat "$_err" >&2
        return 1
    fi
    cat "$_out"
}

# Run a short POSIX script as root. Prefer passwordless sudo; otherwise the
# same administrator-privileges prompt the .pkg installer uses.
interop_admin_sh() {
    _script=$1
    [ -n "$_script" ] || return 1
    if sudo -n sh -c "$_script" >/dev/null 2>&1; then
        return 0
    fi
    command -v osascript >/dev/null 2>&1 || return 1
    _quoted=$(printf '%s' "$_script" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))')
    osascript -e "do shell script $_quoted with administrator privileges" >/dev/null
}

interop_record_result() {
    # id class status detail
    _id=$1
    _class=$2
    _status=$3
    _detail=$(interop_json_escape "${4:-}")
    if [ -n "${WARPTWEET_INTEROP_RESULTS_FILE:-}" ] && [ -s "$WARPTWEET_INTEROP_RESULTS_FILE" ] &&
        grep -F "\"id\":\"$_id\"" "$WARPTWEET_INTEROP_RESULTS_FILE" >/dev/null 2>&1; then
        interop_die "duplicate result id $_id"
    fi
    printf '{"id":"%s","class":"%s","status":"%s","detail":"%s"}\n' \
        "$_id" "$_class" "$_status" "$_detail" >>"$WARPTWEET_INTEROP_RESULTS_FILE"
    interop_log "result $_id=$_status ${_detail}"
}

# LISTEN is the guest bind. Pass --advertise only when ADVERTISE is explicitly
# set. Never default ADVERTISE=LISTEN: omitting --advertise publishes listen.
interop_host_publication_args() {
    printf '%s' "--listen '${WARPTWEET_INTEROP_SERVER_LISTEN}'"
    if [ -n "${WARPTWEET_INTEROP_SERVER_ADVERTISE:-}" ]; then
        printf '%s' " --advertise '${WARPTWEET_INTEROP_SERVER_ADVERTISE}'"
    fi
    if [ -n "${WARPTWEET_INTEROP_ENROLL_LISTEN:-}" ]; then
        printf '%s' " --enroll-listen '${WARPTWEET_INTEROP_ENROLL_LISTEN}'"
    fi
    if [ -n "${WARPTWEET_INTEROP_ENROLL_ADVERTISE:-}" ]; then
        printf '%s' " --enroll-advertise '${WARPTWEET_INTEROP_ENROLL_ADVERTISE}'"
    fi
}

interop_hostport_host() {
    python3 -c 'import sys
v=sys.argv[1]
if v.startswith("["):
    print(v[1:v.index("]")])
else:
    print(v.rsplit(":",1)[0])
' "$1"
}

interop_hostport_port() {
    python3 -c 'import sys
v=sys.argv[1]
print(v.rsplit(":",1)[-1])
' "$1"
}

# Mac TCP uses published dials. When advertise is unset the product publishes
# listen as the dial; that is not defaulting ADVERTISE=LISTEN.
interop_published_data_dial() {
    if [ -n "${WARPTWEET_INTEROP_SERVER_ADVERTISE:-}" ]; then
        printf '%s' "$WARPTWEET_INTEROP_SERVER_ADVERTISE"
    else
        printf '%s' "$WARPTWEET_INTEROP_SERVER_LISTEN"
    fi
}

interop_published_enroll_dial() {
    if [ -n "${WARPTWEET_INTEROP_ENROLL_ADVERTISE:-}" ]; then
        printf '%s' "$WARPTWEET_INTEROP_ENROLL_ADVERTISE"
        return 0
    fi
    if [ -n "${WARPTWEET_INTEROP_ENROLL_LISTEN:-}" ]; then
        printf '%s' "$WARPTWEET_INTEROP_ENROLL_LISTEN"
        return 0
    fi
    _data=$(interop_published_data_dial)
    _host=$(interop_hostport_host "$_data")
    case "$_host" in
        *:*) printf '[%s]:29722' "$_host" ;;
        *) printf '%s:29722' "$_host" ;;
    esac
}

interop_load_config() {
    PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
    export PATH
    if [ -n "${WARPTWEET_INTEROP_CONFIG:-}" ] && [ -f "$WARPTWEET_INTEROP_CONFIG" ]; then
        # shellcheck disable=SC1090
        . "$WARPTWEET_INTEROP_CONFIG"
    fi

    : "${WARPTWEET_INTEROP_SERVER_HOST:?WARPTWEET_INTEROP_SERVER_HOST is required}"
    : "${WARPTWEET_INTEROP_SERVER_USER:=}"
    : "${WARPTWEET_INTEROP_SSH_IDENTITY:=}"
    : "${WARPTWEET_INTEROP_SSH_PORT:=22}"
    : "${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS:=}"
    : "${WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT:=}"
    : "${WARPTWEET_INTEROP_SSH_TRUST_ONCE:=0}"
    : "${WARPTWEET_INTEROP_LOCAL_DEV:=0}"
    if [ -z "$WARPTWEET_INTEROP_SSH_KNOWN_HOSTS" ] && [ -z "$WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT" ]; then
        if [ "$WARPTWEET_INTEROP_SSH_TRUST_ONCE" != "1" ] && [ "$WARPTWEET_INTEROP_LOCAL_DEV" != "1" ]; then
            interop_die "set WARPTWEET_INTEROP_SSH_KNOWN_HOSTS or WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT"
        fi
    fi
    if [ -n "$WARPTWEET_INTEROP_SSH_KNOWN_HOSTS" ] && [ ! -f "$WARPTWEET_INTEROP_SSH_KNOWN_HOSTS" ]; then
        interop_die "WARPTWEET_INTEROP_SSH_KNOWN_HOSTS not a file: $WARPTWEET_INTEROP_SSH_KNOWN_HOSTS"
    fi
    : "${WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE:=true}"
    : "${WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION:=false}"
    : "${WARPTWEET_RELEASE_VERSION:?WARPTWEET_RELEASE_VERSION is required}"
    : "${WARPTWEET_SOURCE_COMMIT:?WARPTWEET_SOURCE_COMMIT is required}"
    : "${WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID:?required}"
    : "${WARPTWEET_SERVER_ARTIFACT_PROFILE_ID:?required}"
    : "${WARPTWEET_CLIENT_PACKAGE_SHA256:?required}"
    : "${WARPTWEET_SERVER_PACKAGE_SHA256:?required}"
    : "${WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256:=}"
    : "${WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256:=}"
    : "${WARPTWEET_INTEROP_ARTIFACTS:?WARPTWEET_INTEROP_ARTIFACTS is required}"
    : "${WARPTWEET_INTEROP_SERVER_PACKAGE_FILE:?required}"
    : "${WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE:?required}"
    : "${WARPTWEET_INTEROP_SERVER_CTRL:=/opt/warptweet/bin/warptweet}"
    if [ -z "${WARPTWEET_INTEROP_CLIENT_CTRL:-}" ]; then
        if [ "$(uname -s)" = Darwin ]; then
            WARPTWEET_INTEROP_CLIENT_CTRL="/Library/Application Support/WarpTweet/bin/warptweet"
        else
            WARPTWEET_INTEROP_CLIENT_CTRL=/opt/warptweet/bin/warptweet
        fi
    fi
    : "${WARPTWEET_INTEROP_SERVER_LISTEN:?WARPTWEET_INTEROP_SERVER_LISTEN is required (bind ip:port)}"
    : "${WARPTWEET_INTEROP_SERVER_ADVERTISE:=}"
    : "${WARPTWEET_INTEROP_ENROLL_LISTEN:=}"
    : "${WARPTWEET_INTEROP_ENROLL_ADVERTISE:=}"
    export WARPTWEET_INTEROP_SERVER_LISTEN WARPTWEET_INTEROP_SERVER_ADVERTISE
    export WARPTWEET_INTEROP_ENROLL_LISTEN WARPTWEET_INTEROP_ENROLL_ADVERTISE
    : "${WARPTWEET_INTEROP_ECHO_PORT:=18432}"
    if [ -z "${WARPTWEET_INTEROP_CLIENT_NAME:-}" ]; then
        WARPTWEET_INTEROP_CLIENT_NAME=interop-mac-$(date -u +%Y%m%dT%H%M%SZ | tr 'A-Z' 'a-z')
    fi
    if [ -z "${WARPTWEET_INTEROP_CLIENT_LISTEN_PORT:-}" ]; then
        WARPTWEET_INTEROP_CLIENT_LISTEN_PORT=$((18433 + $(date -u +%s) % 1400))
    fi
    : "${WARPTWEET_INTEROP_RUN_LIFECYCLE:=0}"
    export WARPTWEET_INTEROP_CLIENT_NAME WARPTWEET_INTEROP_CLIENT_LISTEN_PORT WARPTWEET_INTEROP_RUN_LIFECYCLE

    interop_is_hex40 "$WARPTWEET_SOURCE_COMMIT" || interop_die "WARPTWEET_SOURCE_COMMIT must be 40 lowercase hex"
    interop_is_hex64 "$WARPTWEET_CLIENT_PACKAGE_SHA256" || interop_die "bad client package sha256"
    interop_is_hex64 "$WARPTWEET_SERVER_PACKAGE_SHA256" || interop_die "bad server package sha256"
    if [ "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" != "pending" ] && [ -n "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" ]; then
        interop_is_hex64 "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" || interop_die "bad client engine manifest sha256"
    fi
    if [ "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" != "pending" ] && [ -n "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" ]; then
        interop_is_hex64 "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" || interop_die "bad server engine manifest sha256"
    fi
    if [ "$WARPTWEET_INTEROP_LOCAL_DEV" != "1" ]; then
        if [ -z "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" ] || [ "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            interop_die "WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256 is required outside local-dev"
        fi
        if [ -z "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" ] || [ "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            interop_die "WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256 is required outside local-dev"
        fi
    fi

    if [ -z "${WARPTWEET_INTEROP_WORK:-}" ]; then
        WARPTWEET_INTEROP_WORK=$(mktemp -d "${TMPDIR:-/tmp}/warptweet-interop.XXXXXX")
    else
        mkdir -p "$WARPTWEET_INTEROP_WORK"
    fi
    if [ -z "${WARPTWEET_INTEROP_EVIDENCE_OUTPUT:-}" ]; then
        WARPTWEET_INTEROP_EVIDENCE_OUTPUT="$WARPTWEET_INTEROP_WORK/evidence.json"
    fi
    WARPTWEET_INTEROP_RESULTS_FILE="$WARPTWEET_INTEROP_WORK/results.ndjson"
    WARPTWEET_INTEROP_INVITE="$WARPTWEET_INTEROP_WORK/${WARPTWEET_INTEROP_CLIENT_NAME}.wtinvite"
    if [ "${WARPTWEET_INTEROP_REBOOT_RESUME:-0}" = "1" ]; then
        [ -s "$WARPTWEET_INTEROP_RESULTS_FILE" ] || interop_die "reboot resume is missing results.ndjson"
        : "${WARPTWEET_INTEROP_STARTED_AT:=$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
    else
        if [ -e "$WARPTWEET_INTEROP_EVIDENCE_OUTPUT" ] || [ -L "$WARPTWEET_INTEROP_EVIDENCE_OUTPUT" ]; then
            interop_die "evidence output must not already exist: $WARPTWEET_INTEROP_EVIDENCE_OUTPUT"
        fi
        : >"$WARPTWEET_INTEROP_RESULTS_FILE"
        WARPTWEET_INTEROP_STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    fi

    export WARPTWEET_INTEROP_WORK WARPTWEET_INTEROP_RESULTS_FILE WARPTWEET_INTEROP_INVITE
    export WARPTWEET_INTEROP_EVIDENCE_OUTPUT WARPTWEET_INTEROP_STARTED_AT
}
