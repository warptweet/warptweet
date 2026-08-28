#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

fail() {
    echo "live tunnel gate: $*" >&2
    exit 1
}

pass() {
    printf 'live tunnel gate: PASS %s\n' "$*"
}

if [ "${WARPTWEET_CI_LIVE_TUNNEL:-}" != "1" ]; then
    fail "WARPTWEET_CI_LIVE_TUNNEL=1 is required; this gate is only for an ephemeral CI runner"
fi
if [ "$(uname -s)" != Linux ]; then
    fail "Linux is required"
fi
if [ "$(id -u)" != "0" ]; then
    fail "root UID is required"
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 64
fi

for WT_TOOL in awk chmod chown cmp curl date dd env getent grep groupadd id install kill mknod python3 realpath sed sha256sum sleep stat sudo timeout uname useradd; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        fail "required tool is unavailable: $WT_TOOL"
    fi
done

umask 077

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WT_PIDFD_SIGNAL_HELPER="$WT_SCRIPT_DIRECTORY/pidfd-signal.py"
WT_PYTHON=$(realpath -e -- "$(command -v python3)")
if [ ! -f "$WT_PIDFD_SIGNAL_HELPER" ] || [ -L "$WT_PIDFD_SIGNAL_HELPER" ]; then
    fail "pidfd signal helper is missing or unsafe"
fi
if [ "$(realpath -e -- "$WT_PIDFD_SIGNAL_HELPER")" != "$WT_PIDFD_SIGNAL_HELPER" ]; then
    fail "pidfd signal helper path is not physically resolved"
fi
WT_PIDFD_SIGNAL_HELPER_MODE=$(stat -c '%a' "$WT_PIDFD_SIGNAL_HELPER")
if [ $((0$WT_PIDFD_SIGNAL_HELPER_MODE & 022)) -ne 0 ]; then
    fail "pidfd signal helper must not be group or world writable"
fi
env -i LANG=C LC_ALL=C "$WT_PYTHON" -c \
    'import os, signal; assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")' ||
    fail "Python Linux pidfd APIs are unavailable"

WT_CONTROLLER=/opt/warptweet/bin/warptweet
WT_SSH=/opt/warptweet/libexec/openssh/bin/ssh
WT_KEYGEN=/opt/warptweet/libexec/openssh/bin/ssh-keygen
WT_SSHD=/opt/warptweet/libexec/openssh/sbin/sshd
WT_SERVER_MANIFEST=/etc/warptweet/server.wt
WT_SERVER_CONFIG=/etc/warptweet/sshd_config
WT_HOST_KEY=/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key
WT_HOST_PUBLIC_KEY="$WT_HOST_KEY.pub"
WT_AUTHORIZED_KEYS=/var/lib/warptweet/authorized_keys/warptweet
WT_BUNDLE_MANIFEST=/opt/warptweet/share/openssh-bundle.sha256
WT_TEST_CONFIG_DIRECTORY=/opt/warptweet/etc/live-gate
WT_STATE_DIRECTORY=/run/warptweet/live-gate
WT_SERVER_RUNTIME_DIRECTORY=/run/warptweet/server
WT_CLIENT_RUNTIME_ROOT=/run/warptweet/tunnels
WT_CONTROLLER_RUNTIME_DIRECTORY="$WT_CLIENT_RUNTIME_ROOT/live"

WT_CLIENT_USER=warptweet-client
WT_CLIENT_GROUP=warptweet-client
WT_SECONDARY_UNPRIVILEGED_USER=nobody
WT_CLIENT_MANIFEST=/etc/warptweet/client.wt
WT_CLIENT_IDENTITY_DIRECTORY=/etc/warptweet/identity
WT_CLIENT_KEY="$WT_CLIENT_IDENTITY_DIRECTORY/client"
WT_CLIENT_TRUST_DIRECTORY=/etc/warptweet/trust
WT_KNOWN_HOSTS="$WT_CLIENT_TRUST_DIRECTORY/known_hosts"
WT_GLOBAL_KNOWN_HOSTS="$WT_CLIENT_TRUST_DIRECTORY/known_hosts.empty"

WT_PROFILE=warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519-chacha20
WT_KEX=mlkem768x25519-sha256
WT_COMPOSITE_KEY=ssh-mldsa44-ed25519@openssh.com
WT_CLASSICAL_KEY_TYPE=ssh-ed25519
WT_APPROVED_CIPHER_ONE=chacha20-poly1305@openssh.com
WT_APPROVED_CIPHER_TWO=aes256-gcm@openssh.com
WT_SERVER_PORT=2222
WT_TARGET_PORT=5432
WT_FORBIDDEN_TARGET_PORT=5433
WT_FORWARD_PORT=15432
WT_SOCKS_PORT=15435
WT_TUNNEL_ID=live
WT_HOST_ALIAS=warptweet-peer

WT_CLIENT_KEY_CANDIDATE="$WT_TEST_CONFIG_DIRECTORY/client_mldsa44_ed25519_key"
WT_CLIENT_PUBLIC_KEY="$WT_CLIENT_KEY_CANDIDATE.pub"
WT_WRONG_HOST_KEY="$WT_TEST_CONFIG_DIRECTORY/wrong_host_mldsa44_ed25519_key"
WT_CLASSICAL_KEY="$WT_TEST_CONFIG_DIRECTORY/classical_ed25519_key"
WT_WRONG_KNOWN_HOSTS="$WT_TEST_CONFIG_DIRECTORY/known_hosts.wrong"
WT_CLIENT_MANIFEST_CANDIDATE="$WT_TEST_CONFIG_DIRECTORY/client.candidate.wt"
WT_RENDERED_CLIENT_CONFIG="$WT_TEST_CONFIG_DIRECTORY/client.conf"
WT_RAW_CLIENT_CONFIG="$WT_TEST_CONFIG_DIRECTORY/client-raw.conf"
WT_CLASSICAL_CLIENT_CONFIG="$WT_TEST_CONFIG_DIRECTORY/client-classical.conf"
WT_WRONG_HOST_CLIENT_CONFIG="$WT_TEST_CONFIG_DIRECTORY/client-wrong-host.conf"

WT_SERVER_LOG="$WT_STATE_DIRECTORY/sshd-debug.log"
WT_POSITIVE_SERVER_LOG="$WT_STATE_DIRECTORY/sshd-controller-positive.log"
WT_SERVER_STDERR="$WT_STATE_DIRECTORY/sshd.stderr.log"
WT_TARGET_LOG="$WT_STATE_DIRECTORY/target.log"
WT_FORBIDDEN_TARGET_LOG="$WT_STATE_DIRECTORY/forbidden-target.log"
WT_CONTROLLER_LOG="$WT_STATE_DIRECTORY/controller.log"
WT_CONTROLLER_STDOUT="$WT_STATE_DIRECTORY/controller.stdout"
WT_GRANT_LOG="$WT_STATE_DIRECTORY/grant-listen.log"
WT_GRANT_SOCKET=/run/warptweet/server/grant-session.sock
WT_PAYLOAD_DIRECTORY="$WT_STATE_DIRECTORY/http"
WT_FORBIDDEN_PAYLOAD_DIRECTORY="$WT_STATE_DIRECTORY/http-forbidden"
WT_PAYLOAD="$WT_PAYLOAD_DIRECTORY/rekey.bin"
WT_RECEIVED_PAYLOAD="$WT_STATE_DIRECTORY/rekey.received"

WT_TARGET_PID=''
WT_TARGET_ID=''
WT_FORBIDDEN_TARGET_PID=''
WT_FORBIDDEN_TARGET_ID=''
WT_SSHD_PID=''
WT_SSHD_ID=''
WT_CONTROLLER_PID=''
WT_CONTROLLER_ID=''
WT_CLIENT_PID=''
WT_CLIENT_ID=''
WT_SOCKS_PID=''
WT_SOCKS_ID=''
WT_GRANT_PID=''
WT_GRANT_ID=''

process_identity() {
    WT_IDENTITY_PID=$1
    WT_IDENTITY_DIRECTORY=$(stat -Lc '%d:%i' "/proc/$WT_IDENTITY_PID" 2>/dev/null) || return 1
    WT_IDENTITY_START=$(awk '{ value = $0; sub(/^.*\) /, "", value); split(value, fields); print fields[20] }' \
        "/proc/$WT_IDENTITY_PID/stat" 2>/dev/null) || return 1
    [ -n "$WT_IDENTITY_START" ] || return 1
    printf '%s:%s\n' "$WT_IDENTITY_DIRECTORY" "$WT_IDENTITY_START"
}

process_executable() {
    realpath -e -- "/proc/$1/exe" 2>/dev/null
}

process_effective_uid() {
    awk '/^Uid:/ { print $3; exit }' "/proc/$1/status" 2>/dev/null
}

process_state() {
    awk '{ value = $0; sub(/^.*\) /, "", value); split(value, fields); print fields[1] }' \
        "/proc/$1/stat" 2>/dev/null
}

# Linux records children per thread. Go os/exec forks from a runtime thread, so
# the packaged SSH child is under task/<tid>/children, not necessarily the main
# thread (tid == pid).
process_children() {
    WT_CHILDREN_PARENT=$1
    for WT_TASK_CHILDREN in "/proc/$WT_CHILDREN_PARENT/task/"*/children; do
        [ -f "$WT_TASK_CHILDREN" ] || continue
        awk '{ for (i = 1; i <= NF; i++) print $i }' "$WT_TASK_CHILDREN" 2>/dev/null || true
    done | awk 'NF && !seen[$0]++'
}

dump_process_children() {
    WT_DUMP_PARENT=$1
    WT_DUMP_LABEL=$2
    WT_DUMP_MAIN=$(awk '{ print }' "/proc/$WT_DUMP_PARENT/task/$WT_DUMP_PARENT/children" 2>/dev/null || true)
    echo "live tunnel gate: $WT_DUMP_LABEL pid=$WT_DUMP_PARENT main-thread children=$WT_DUMP_MAIN" >&2
    WT_DUMP_CHILDREN=$(process_children "$WT_DUMP_PARENT")
    if [ -z "$WT_DUMP_CHILDREN" ]; then
        echo "live tunnel gate: $WT_DUMP_LABEL has no thread children" >&2
        return 0
    fi
    for WT_DUMP_CHILD in $WT_DUMP_CHILDREN; do
        echo "live tunnel gate: $WT_DUMP_LABEL child pid=$WT_DUMP_CHILD exe=$(process_executable "$WT_DUMP_CHILD" || true) state=$(process_state "$WT_DUMP_CHILD" || true) uid=$(process_effective_uid "$WT_DUMP_CHILD" || true)" >&2
    done
}

wait_for_owned_process() {
    WT_WAIT_PID=$1
    WT_WAIT_EXECUTABLE=$2
    WT_WAIT_LABEL=$3
    WT_WAIT_ATTEMPT=0
    while [ "$WT_WAIT_ATTEMPT" -lt 100 ]; do
        if kill -0 "$WT_WAIT_PID" 2>/dev/null; then
            WT_WAIT_STATE=$(process_state "$WT_WAIT_PID" || true)
            if [ "$WT_WAIT_STATE" = Z ]; then
                fail "$WT_WAIT_LABEL process exited before ownership was established"
            fi
            WT_WAIT_CURRENT_EXECUTABLE=$(process_executable "$WT_WAIT_PID" || true)
            if [ "$WT_WAIT_CURRENT_EXECUTABLE" = "$WT_WAIT_EXECUTABLE" ]; then
                process_identity "$WT_WAIT_PID" || fail "cannot identify $WT_WAIT_LABEL process"
                return 0
            fi
        else
            fail "$WT_WAIT_LABEL process exited before ownership was established"
        fi
        WT_WAIT_ATTEMPT=$((WT_WAIT_ATTEMPT + 1))
        sleep 0.1
    done
    echo "live tunnel gate: $WT_WAIT_LABEL pid=$WT_WAIT_PID want=$WT_WAIT_EXECUTABLE got=$(process_executable "$WT_WAIT_PID" || true) state=$(process_state "$WT_WAIT_PID" || true) uid=$(process_effective_uid "$WT_WAIT_PID" || true)" >&2
    if [ -f "$WT_CONTROLLER_LOG" ]; then
        echo "live tunnel gate: controller log:" >&2
        cat "$WT_CONTROLLER_LOG" >&2 || true
    fi
    fail "$WT_WAIT_LABEL process did not become the expected executable"
}

stop_owned_process() {
    WT_STOP_PID=$1
    WT_STOP_ID=$2
    WT_STOP_EXECUTABLE=$3
    WT_STOP_LABEL=$4
    if [ -z "$WT_STOP_PID" ]; then
        return 0
    fi
    if [ ! -e "/proc/$WT_STOP_PID" ]; then
        wait "$WT_STOP_PID" 2>/dev/null || true
        return 0
    fi
    WT_STOP_SIGNAL_STATUS=0
    env -i LANG=C LC_ALL=C \
        "$WT_PYTHON" "$WT_PIDFD_SIGNAL_HELPER" \
        "$WT_STOP_PID" "$WT_STOP_ID" "$WT_STOP_EXECUTABLE" TERM || WT_STOP_SIGNAL_STATUS=$?
    case "$WT_STOP_SIGNAL_STATUS" in
        0) ;;
        75)
            wait "$WT_STOP_PID" 2>/dev/null || true
            return 0
            ;;
        76)
            echo "live tunnel gate: refusing to signal substituted $WT_STOP_LABEL PID $WT_STOP_PID" >&2
            return 1
            ;;
        *)
            echo "live tunnel gate: pidfd TERM failed for owned $WT_STOP_LABEL PID $WT_STOP_PID" >&2
            return 1
            ;;
    esac
    WT_STOP_ATTEMPT=0
    while [ "$WT_STOP_ATTEMPT" -lt 50 ]; do
        if [ ! -e "/proc/$WT_STOP_PID" ]; then
            wait "$WT_STOP_PID" 2>/dev/null || true
            return 0
        fi
        WT_STOP_CURRENT_ID=$(process_identity "$WT_STOP_PID" || true)
        if [ "$WT_STOP_CURRENT_ID" != "$WT_STOP_ID" ]; then
            echo "live tunnel gate: $WT_STOP_LABEL PID was reused during cleanup" >&2
            return 1
        fi
        WT_STOP_STATE=$(awk '{ value = $0; sub(/^.*\) /, "", value); split(value, fields); print fields[1] }' \
            "/proc/$WT_STOP_PID/stat" 2>/dev/null || true)
        if [ "$WT_STOP_STATE" = Z ]; then
            wait "$WT_STOP_PID" 2>/dev/null || true
            return 0
        fi
        WT_STOP_ATTEMPT=$((WT_STOP_ATTEMPT + 1))
        sleep 0.1
    done
    WT_STOP_SIGNAL_STATUS=0
    env -i LANG=C LC_ALL=C \
        "$WT_PYTHON" "$WT_PIDFD_SIGNAL_HELPER" \
        "$WT_STOP_PID" "$WT_STOP_ID" "$WT_STOP_EXECUTABLE" KILL || WT_STOP_SIGNAL_STATUS=$?
    case "$WT_STOP_SIGNAL_STATUS" in
        0) ;;
        75)
            wait "$WT_STOP_PID" 2>/dev/null || true
            return 0
            ;;
        76)
            echo "live tunnel gate: refusing to kill substituted $WT_STOP_LABEL PID $WT_STOP_PID" >&2
            return 1
            ;;
        *)
            echo "live tunnel gate: pidfd KILL failed for owned $WT_STOP_LABEL PID $WT_STOP_PID" >&2
            return 1
            ;;
    esac
    wait "$WT_STOP_PID" 2>/dev/null || true
    return 0
}

cleanup() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
    WT_CLEANUP_FAILED=0
    stop_owned_process "$WT_SOCKS_PID" "$WT_SOCKS_ID" "$WT_SSH" "SOCKS client" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_CLIENT_PID" "$WT_CLIENT_ID" "$WT_SSH" "controller SSH child" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_CONTROLLER_PID" "$WT_CONTROLLER_ID" "$WT_CONTROLLER" "controller" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_SSHD_PID" "$WT_SSHD_ID" "$WT_SSHD" "sshd" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_GRANT_PID" "$WT_GRANT_ID" "$WT_CONTROLLER" "grant session authority" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_FORBIDDEN_TARGET_PID" "$WT_FORBIDDEN_TARGET_ID" "$WT_PYTHON" "forbidden target" || WT_CLEANUP_FAILED=1
    stop_owned_process "$WT_TARGET_PID" "$WT_TARGET_ID" "$WT_PYTHON" "application target" || WT_CLEANUP_FAILED=1
    if [ "$WT_CLEANUP_STATUS" -eq 0 ] && [ "$WT_CLEANUP_FAILED" -ne 0 ]; then
        WT_CLEANUP_STATUS=1
    fi
    exit "$WT_CLEANUP_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_directory() {
    WT_REQUIRED_DIRECTORY=$1
    WT_REQUIRED_MODE=$2
    if [ ! -d "$WT_REQUIRED_DIRECTORY" ] || [ -L "$WT_REQUIRED_DIRECTORY" ]; then
        fail "required directory is missing or unsafe: $WT_REQUIRED_DIRECTORY"
    fi
    if [ "$(realpath -e -- "$WT_REQUIRED_DIRECTORY")" != "$WT_REQUIRED_DIRECTORY" ]; then
        fail "required directory is not physically resolved: $WT_REQUIRED_DIRECTORY"
    fi
    if [ "$(stat -c '%u:%g:%a' "$WT_REQUIRED_DIRECTORY")" != "0:0:$WT_REQUIRED_MODE" ]; then
        fail "required directory has unexpected ownership or mode: $WT_REQUIRED_DIRECTORY"
    fi
}

require_file() {
    WT_REQUIRED_FILE=$1
    WT_REQUIRED_MODE=$2
    WT_REQUIRED_EXECUTABLE=$3
    if [ ! -f "$WT_REQUIRED_FILE" ] || [ -L "$WT_REQUIRED_FILE" ]; then
        fail "required file is missing or unsafe: $WT_REQUIRED_FILE"
    fi
    if [ "$(realpath -e -- "$WT_REQUIRED_FILE")" != "$WT_REQUIRED_FILE" ]; then
        fail "required file is not physically resolved: $WT_REQUIRED_FILE"
    fi
    if [ "$(stat -c '%u:%g:%a' "$WT_REQUIRED_FILE")" != "0:0:$WT_REQUIRED_MODE" ]; then
        fail "required file has unexpected ownership or mode: $WT_REQUIRED_FILE"
    fi
    if [ "$WT_REQUIRED_EXECUTABLE" = yes ] && [ ! -x "$WT_REQUIRED_FILE" ]; then
        fail "required executable is not executable: $WT_REQUIRED_FILE"
    fi
}

require_account() {
    WT_ACCOUNT_USER=$1
    WT_ACCOUNT_HOME=$2
    WT_ACCOUNT_SHELL=$3
    WT_ACCOUNT_ENTRY=$(getent passwd "$WT_ACCOUNT_USER") || fail "required account is missing: $WT_ACCOUNT_USER"
    IFS=: read -r WT_ACCOUNT_NAME _ WT_ACCOUNT_UID WT_ACCOUNT_GID _ WT_ACCOUNT_ACTUAL_HOME WT_ACCOUNT_ACTUAL_SHELL <<EOF
$WT_ACCOUNT_ENTRY
EOF
    if [ "$WT_ACCOUNT_NAME" != "$WT_ACCOUNT_USER" ] || [ "$WT_ACCOUNT_UID" = 0 ] ||
        [ "$WT_ACCOUNT_ACTUAL_HOME" != "$WT_ACCOUNT_HOME" ] ||
        [ "$WT_ACCOUNT_ACTUAL_SHELL" != "$WT_ACCOUNT_SHELL" ]; then
        fail "account does not match fixed live-gate contract: $WT_ACCOUNT_USER"
    fi
    WT_GROUP_ENTRY=$(getent group "$WT_ACCOUNT_USER") || fail "required account group is missing: $WT_ACCOUNT_USER"
    IFS=: read -r WT_GROUP_NAME _ WT_GROUP_GID _ <<EOF
$WT_GROUP_ENTRY
EOF
    if [ "$WT_GROUP_NAME" != "$WT_ACCOUNT_USER" ] || [ "$WT_GROUP_GID" != "$WT_ACCOUNT_GID" ]; then
        fail "account group does not match fixed live-gate contract: $WT_ACCOUNT_USER"
    fi
}

require_public_key_only_account() {
    WT_PUBLIC_KEY_ACCOUNT=$1
    WT_SHADOW_ENTRY=$(getent shadow "$WT_PUBLIC_KEY_ACCOUNT") ||
        fail "required shadow account is missing: $WT_PUBLIC_KEY_ACCOUNT"
    IFS=: read -r WT_SHADOW_NAME WT_SHADOW_PASSWORD _ _ _ _ _ _ _ <<EOF
$WT_SHADOW_ENTRY
EOF
    if [ "$WT_SHADOW_NAME" != "$WT_PUBLIC_KEY_ACCOUNT" ] ||
        [ "$WT_SHADOW_PASSWORD" != '*NP*' ]; then
        fail "dedicated account must use the Linux public-key-only *NP* password sentinel"
    fi
}

provision_dedicated_client_account() {
    if getent passwd "$WT_CLIENT_USER" >/dev/null 2>&1 ||
        getent group "$WT_CLIENT_GROUP" >/dev/null 2>&1; then
        fail "dedicated client account or group already exists; refusing to reuse host identity"
    fi
    # warptweet run only authorizes the packaged client UID/GID 920.
    groupadd --system --gid 920 "$WT_CLIENT_GROUP"
    useradd \
        --system \
        --uid 920 \
        --gid 920 \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        "$WT_CLIENT_USER"

    WT_CLIENT_ACCOUNT_ENTRY=$(getent passwd "$WT_CLIENT_USER") ||
        fail "provisioned client account is missing"
    IFS=: read -r WT_CLIENT_ACCOUNT_NAME WT_CLIENT_ACCOUNT_PASSWORD WT_CLIENT_UID WT_CLIENT_GID _ WT_CLIENT_HOME WT_CLIENT_SHELL <<EOF
$WT_CLIENT_ACCOUNT_ENTRY
EOF
    WT_CLIENT_GROUP_ENTRY=$(getent group "$WT_CLIENT_GROUP") ||
        fail "provisioned client group is missing"
    IFS=: read -r WT_CLIENT_GROUP_NAME WT_CLIENT_GROUP_PASSWORD WT_CLIENT_GROUP_GID WT_CLIENT_GROUP_MEMBERS <<EOF
$WT_CLIENT_GROUP_ENTRY
EOF
    if [ "$WT_CLIENT_ACCOUNT_NAME" != "$WT_CLIENT_USER" ] ||
        [ "$WT_CLIENT_ACCOUNT_PASSWORD" != x ] ||
        [ "$WT_CLIENT_UID" != 920 ] ||
        [ "$WT_CLIENT_GID" != 920 ] ||
        [ "$WT_CLIENT_HOME" != /nonexistent ] ||
        [ "$WT_CLIENT_SHELL" != /usr/sbin/nologin ] ||
        [ "$WT_CLIENT_GROUP_NAME" != "$WT_CLIENT_GROUP" ] ||
        [ "$WT_CLIENT_GROUP_PASSWORD" != x ] ||
        [ "$WT_CLIENT_GROUP_GID" != "$WT_CLIENT_GID" ] ||
        [ -n "$WT_CLIENT_GROUP_MEMBERS" ]; then
        fail "provisioned client account does not match the fixed dedicated identity contract"
    fi
    if [ "$(awk -F: -v name="$WT_CLIENT_USER" '$1 == name { count++ } END { print count + 0 }' /etc/passwd)" != 1 ] ||
        [ "$(awk -F: -v uid="$WT_CLIENT_UID" '$3 == uid { count++ } END { print count + 0 }' /etc/passwd)" != 1 ] ||
        [ "$(awk -F: -v gid="$WT_CLIENT_GID" '$4 == gid { count++ } END { print count + 0 }' /etc/passwd)" != 1 ] ||
        [ "$(awk -F: -v name="$WT_CLIENT_GROUP" '$1 == name { count++ } END { print count + 0 }' /etc/group)" != 1 ] ||
        [ "$(awk -F: -v gid="$WT_CLIENT_GID" '$3 == gid { count++ } END { print count + 0 }' /etc/group)" != 1 ]; then
        fail "client UID, primary GID, account name, or group name is not unique"
    fi
    WT_CLIENT_SUPPLEMENTARY_STATUS=0
    awk -F: -v user="$WT_CLIENT_USER" '
        $4 != "" {
            count = split($4, members, ",")
            for (member_index = 1; member_index <= count; member_index++) {
                if (members[member_index] == user) {
                    found = 1
                }
            }
        }
        END { exit(found ? 0 : 42) }
    ' /etc/group || WT_CLIENT_SUPPLEMENTARY_STATUS=$?
    case "$WT_CLIENT_SUPPLEMENTARY_STATUS" in
        0)
            fail "client account is listed as a supplementary group member"
            ;;
        42)
            ;;
        *)
            fail "cannot determine client supplementary group membership"
            ;;
    esac
    if [ "$(id -G "$WT_CLIENT_USER")" != "$WT_CLIENT_GID" ]; then
        fail "client account has supplementary group authority"
    fi

    WT_SECONDARY_UNPRIVILEGED_UID=$(id -u "$WT_SECONDARY_UNPRIVILEGED_USER") ||
        fail "second unprivileged regression account is missing"
    if [ "$WT_SECONDARY_UNPRIVILEGED_UID" = 0 ] ||
        [ "$WT_SECONDARY_UNPRIVILEGED_UID" = "$WT_CLIENT_UID" ]; then
        fail "second regression account must use a distinct non-root UID"
    fi
    case " $(id -G "$WT_SECONDARY_UNPRIVILEGED_USER") " in
        *" $WT_CLIENT_GID "*)
            fail "second regression account unexpectedly belongs to the client group"
            ;;
    esac
    pass "dedicated client UID and single-member primary group provisioned without reuse"
}

require_client_state_layout() {
    if [ "$(stat -c '%u:%g:%a' "$WT_CLIENT_MANIFEST")" != "0:$WT_CLIENT_GID:440" ] ||
        [ "$(stat -c '%u:%g:%a' "$WT_CLIENT_IDENTITY_DIRECTORY")" != "0:$WT_CLIENT_GID:750" ] ||
        [ "$(stat -c '%u:%g:%a' "$WT_CLIENT_KEY")" != "$WT_CLIENT_UID:$WT_CLIENT_GID:600" ] ||
        [ "$(stat -c '%u:%g:%a' "$WT_CLIENT_TRUST_DIRECTORY")" != "0:$WT_CLIENT_GID:750" ] ||
        [ "$(stat -c '%u:%g:%a' "$WT_KNOWN_HOSTS")" != "0:$WT_CLIENT_GID:440" ] ||
        [ "$(stat -c '%u:%g:%a' "$WT_GLOBAL_KNOWN_HOSTS")" != "0:$WT_CLIENT_GID:440" ]; then
        fail "fixed client state has unexpected ownership or mode"
    fi
    for WT_CLIENT_STATE_PATH in \
        "$WT_CLIENT_MANIFEST" \
        "$WT_CLIENT_IDENTITY_DIRECTORY" \
        "$WT_CLIENT_KEY" \
        "$WT_CLIENT_TRUST_DIRECTORY" \
        "$WT_KNOWN_HOSTS" \
        "$WT_GLOBAL_KNOWN_HOSTS"; do
        if [ -L "$WT_CLIENT_STATE_PATH" ] ||
            [ "$(realpath -e -- "$WT_CLIENT_STATE_PATH")" != "$WT_CLIENT_STATE_PATH" ]; then
            fail "fixed client state contains a symlink or unresolved path: $WT_CLIENT_STATE_PATH"
        fi
    done
    if [ -s "$WT_GLOBAL_KNOWN_HOSTS" ]; then
        fail "fixed global known-hosts file must be exactly empty"
    fi
}

managed_client_state_evidence() {
    for WT_EVIDENCE_PATH in \
        /etc/warptweet \
        "$WT_CLIENT_MANIFEST" \
        "$WT_CLIENT_IDENTITY_DIRECTORY" \
        "$WT_CLIENT_KEY" \
        "$WT_CLIENT_TRUST_DIRECTORY" \
        "$WT_KNOWN_HOSTS" \
        "$WT_GLOBAL_KNOWN_HOSTS"; do
        stat -c '%n:%d:%i:%u:%g:%f:%s:%Y' "$WT_EVIDENCE_PATH"
        if [ -f "$WT_EVIDENCE_PATH" ]; then
            sha256sum "$WT_EVIDENCE_PATH"
        fi
    done
}

prove_managed_client_state_immutable() {
    WT_MUTATION_USER=$1
    WT_MUTATION_LABEL=$2
    WT_MUTATION_BEFORE=$(managed_client_state_evidence)
    (
        cd /
        sudo -n -u "$WT_MUTATION_USER" -- \
            env -i LANG=C LC_ALL=C \
            "$WT_PYTHON" - "$WT_MUTATION_LABEL" \
            "$WT_CLIENT_MANIFEST" \
            "$WT_CLIENT_KEY" \
            "$WT_KNOWN_HOSTS" \
            "$WT_GLOBAL_KNOWN_HOSTS" \
            -- \
            /etc/warptweet \
            "$WT_CLIENT_IDENTITY_DIRECTORY" \
            "$WT_CLIENT_TRUST_DIRECTORY" <<'PY'
import errno
import os
import sys
import tempfile

label = sys.argv[1]
separator = sys.argv.index("--")
managed_files = sys.argv[2:separator]
managed_directories = sys.argv[separator + 1:]


def expect_permission_denied(description, operation):
    try:
        operation()
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            return
        raise SystemExit(f"{description} failed for the wrong reason: {error}") from error
    raise SystemExit(f"{description} unexpectedly succeeded")


for index, path in enumerate(managed_files):
    def append_file(path=path):
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            os.write(descriptor, b"mutation")
        finally:
            os.close(descriptor)

    # OpenSSH requires the private identity to be 0600 and service-owned.
    # That UID may rewrite the file; it still cannot replace it in the
    # root-owned identity directory.
    try:
        metadata = os.lstat(path)
        owner_writable = (
            metadata.st_uid == os.getuid() and (metadata.st_mode & 0o777) == 0o600
        )
    except OSError:
        owner_writable = False
    if not owner_writable:
        expect_permission_denied(f"{label} append {path}", append_file)
        expect_permission_denied(f"{label} chmod {path}", lambda path=path: os.chmod(path, 0o600))
    expect_permission_denied(
        f"{label} rename {path}",
        lambda path=path: os.rename(path, path + ".warptweet-mutation"),
    )
    descriptor, replacement = tempfile.mkstemp(
        prefix=f"warptweet-{label}-{index}-",
        dir="/tmp",
    )
    try:
        os.write(descriptor, b"replacement")
    finally:
        os.close(descriptor)
    try:
        expect_permission_denied(
            f"{label} replace {path}",
            lambda path=path, replacement=replacement: os.replace(replacement, path),
        )
    finally:
        if os.path.exists(replacement):
            os.unlink(replacement)

for path in managed_directories:
    probe = os.path.join(path, ".warptweet-mutation")

    def create_in_directory(probe=probe):
        descriptor = os.open(
            probe,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        os.close(descriptor)

    expect_permission_denied(f"{label} write within {path}", create_in_directory)
    expect_permission_denied(f"{label} chmod {path}", lambda path=path: os.chmod(path, 0o700))
    expect_permission_denied(
        f"{label} rename {path}",
        lambda path=path: os.rename(path, path + ".warptweet-mutation"),
    )
PY
    ) || fail "$WT_MUTATION_LABEL principal did not fail closed against managed client state"
    WT_MUTATION_AFTER=$(managed_client_state_evidence)
    if [ "$WT_MUTATION_BEFORE" != "$WT_MUTATION_AFTER" ]; then
        fail "$WT_MUTATION_LABEL principal changed managed client state or an ancestor"
    fi
    pass "$WT_MUTATION_LABEL UID cannot write, chmod, rename, or replace fixed client state"
}

run_as_dedicated_client() {
    env -i LANG=C LC_ALL=C \
        "$WT_PYTHON" -c '
import os
import sys

uid = int(sys.argv[1])
gid = int(sys.argv[2])
executable = sys.argv[3]
arguments = sys.argv[3:]
os.setgroups([])
os.setgid(gid)
os.setuid(uid)
os.chdir("/")
os.execve(executable, arguments, {"LANG": "C", "LC_ALL": "C"})
' "$WT_CLIENT_UID" "$WT_CLIENT_GID" "$@"
}

require_empty_client_runtime_directory() {
    if [ "$(stat -c '%u:%g:%a' "$WT_CONTROLLER_RUNTIME_DIRECTORY")" != "$WT_CLIENT_UID:$WT_CLIENT_GID:700" ]; then
        fail "fixed client readiness directory is not service-owned mode 0700"
    fi
    for WT_RUNTIME_ENTRY in \
        "$WT_CONTROLLER_RUNTIME_DIRECTORY"/* \
        "$WT_CONTROLLER_RUNTIME_DIRECTORY"/.[!.]* \
        "$WT_CONTROLLER_RUNTIME_DIRECTORY"/..?*; do
        if [ -e "$WT_RUNTIME_ENTRY" ] || [ -L "$WT_RUNTIME_ENTRY" ]; then
            fail "fixed client readiness directory contains an unexpected persistent entry: $WT_RUNTIME_ENTRY"
        fi
    done
}

provision_and_probe_tun() {
    require_directory /dev 755
    if [ -e /dev/net ] || [ -L /dev/net ]; then
        require_directory /dev/net 755
    else
        install -d -o root -g root -m 0755 /dev/net
    fi
    if [ -e /dev/net/tun ] || [ -L /dev/net/tun ]; then
        if [ ! -c /dev/net/tun ] || [ -L /dev/net/tun ]; then
            fail "/dev/net/tun exists but is not a non-symlink character device"
        fi
    else
        mknod -m 0600 /dev/net/tun c 10 200
    fi
    if [ "$(realpath -e -- /dev/net/tun)" != /dev/net/tun ]; then
        fail "/dev/net/tun is not physically resolved"
    fi
    chown root:root /dev/net/tun
    chmod 0600 /dev/net/tun
    if [ "$(stat -c '%u:%g:%a' /dev/net/tun)" != "0:0:600" ]; then
        fail "/dev/net/tun has unexpected ownership or mode"
    fi
    if ! env -i LANG=C LC_ALL=C "$WT_PYTHON" -c '
import fcntl
import os
import stat
import struct
import sys

device = sys.argv[1]
device_stat = os.stat(device, follow_symlinks=False)
if not stat.S_ISCHR(device_stat.st_mode):
    raise SystemExit("TUN path is not a character device")
if os.major(device_stat.st_rdev) != 10 or os.minor(device_stat.st_rdev) != 200:
    raise SystemExit("TUN character device is not Linux 10:200")
descriptor = os.open(device, os.O_RDWR | os.O_CLOEXEC)
try:
    fcntl.ioctl(
        descriptor,
        0x400454CA,
        struct.pack("16sH22x", b"wtgate%d", 0x0001 | 0x1000),
    )
finally:
    os.close(descriptor)
' /dev/net/tun; then
        fail "TUNSETIFF capability probe failed; Docker must expose /dev/net/tun and CAP_NET_ADMIN"
    fi
    pass "Linux TUN device and CAP_NET_ADMIN are available for the required rejection probe"
}

assert_port_free() {
    python3 -c 'import socket,sys; s=socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.close()' "$1" ||
        fail "required loopback port is already in use: $1"
}

dump_live_gate_file() {
    WT_DUMP_PATH=$1
    WT_DUMP_LABEL=$2
    echo "live tunnel gate: $WT_DUMP_LABEL ($WT_DUMP_PATH):" >&2
    if [ -f "$WT_DUMP_PATH" ]; then
        cat "$WT_DUMP_PATH" >&2 || true
    else
        echo "live tunnel gate: $WT_DUMP_PATH is absent" >&2
    fi
}

wait_for_log() {
    WT_WAIT_LOG=$1
    WT_WAIT_TEXT=$2
    WT_WAIT_LABEL=$3
    WT_WAIT_PID=${4:-}
    WT_WAIT_ATTEMPT=0
    while [ "$WT_WAIT_ATTEMPT" -lt 200 ]; do
        if grep -F "$WT_WAIT_TEXT" "$WT_WAIT_LOG" >/dev/null 2>&1; then
            return 0
        fi
        if [ -n "$WT_WAIT_PID" ] && ! kill -0 "$WT_WAIT_PID" 2>/dev/null; then
            dump_live_gate_file "$WT_WAIT_LOG" "$WT_WAIT_LABEL log after process exit"
            if [ -n "$WT_CONTROLLER_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_CONTROLLER_LOG" ]; then
                dump_live_gate_file "$WT_CONTROLLER_LOG" "controller log"
            fi
            if [ -n "$WT_SERVER_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_SERVER_LOG" ]; then
                dump_live_gate_file "$WT_SERVER_LOG" "sshd log"
            fi
            if [ -n "$WT_GRANT_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_GRANT_LOG" ]; then
                dump_live_gate_file "$WT_GRANT_LOG" "grant session authority log"
            fi
            fail "$WT_WAIT_LABEL process $WT_WAIT_PID exited before evidence appeared in $WT_WAIT_LOG"
        fi
        WT_WAIT_ATTEMPT=$((WT_WAIT_ATTEMPT + 1))
        sleep 0.1
    done
    dump_live_gate_file "$WT_WAIT_LOG" "$WT_WAIT_LABEL log after timeout"
    if [ -n "$WT_CONTROLLER_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_CONTROLLER_LOG" ]; then
        dump_live_gate_file "$WT_CONTROLLER_LOG" "controller log"
    fi
    if [ -n "$WT_SERVER_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_SERVER_LOG" ]; then
        dump_live_gate_file "$WT_SERVER_LOG" "sshd log"
    fi
    if [ -n "$WT_GRANT_LOG" ] && [ "$WT_WAIT_LOG" != "$WT_GRANT_LOG" ]; then
        dump_live_gate_file "$WT_GRANT_LOG" "grant session authority log"
    fi
    fail "$WT_WAIT_LABEL evidence did not appear in $WT_WAIT_LOG"
}

server_log_line_count() {
    if [ ! -f "$WT_SERVER_LOG" ]; then
        printf '%s\n' 0
        return 0
    fi
    awk 'END { print NR + 0 }' "$WT_SERVER_LOG"
}

capture_server_evidence() {
    WT_CAPTURE_START_LINE=$1
    WT_CAPTURE_NAME=$2
    WT_CAPTURE_OUTPUT="$WT_STATE_DIRECTORY/negative-$WT_CAPTURE_NAME.server.log"
    awk -v start="$WT_CAPTURE_START_LINE" 'NR > start' "$WT_SERVER_LOG" >"$WT_CAPTURE_OUTPUT"
    if [ ! -s "$WT_CAPTURE_OUTPUT" ]; then
        fail "$WT_CAPTURE_NAME produced no isolated server transcript"
    fi
}

expect_ssh_failure() {
    WT_NEGATIVE_NAME=$1
    WT_NEGATIVE_PATTERN=$2
    shift 2
    WT_NEGATIVE_LOG="$WT_STATE_DIRECTORY/negative-$WT_NEGATIVE_NAME.log"
    WT_NEGATIVE_STDOUT="$WT_STATE_DIRECTORY/negative-$WT_NEGATIVE_NAME.stdout"
    WT_NEGATIVE_STATUS=0
    timeout --signal=TERM --kill-after=5 20 \
        env -i LANG=C LC_ALL=C \
        "$WT_SSH" -vvv "$@" >"$WT_NEGATIVE_STDOUT" 2>"$WT_NEGATIVE_LOG" || WT_NEGATIVE_STATUS=$?
    if [ "$WT_NEGATIVE_STATUS" -eq 0 ]; then
        fail "$WT_NEGATIVE_NAME request unexpectedly succeeded"
    fi
    case "$WT_NEGATIVE_STATUS" in
        124|137) fail "$WT_NEGATIVE_NAME request timed out instead of failing closed" ;;
    esac
    if ! grep -E "$WT_NEGATIVE_PATTERN" "$WT_NEGATIVE_LOG" >/dev/null 2>&1; then
        fail "$WT_NEGATIVE_NAME failed without the expected fail-closed evidence"
    fi
    pass "$WT_NEGATIVE_NAME rejected"
}

expect_session_channel_failure() {
    WT_SESSION_NAME=$1
    shift
    WT_SESSION_START_LINE=$(server_log_line_count)
    expect_ssh_failure "$WT_SESSION_NAME" \
        'administratively prohibited|request failed|open failed' \
        "$@"
    capture_server_evidence "$WT_SESSION_START_LINE" "$WT_SESSION_NAME"
    WT_SESSION_SERVER_LOG="$WT_STATE_DIRECTORY/negative-$WT_SESSION_NAME.server.log"
    if ! awk '
        /server_input_channel_open: ctype session/ { channel_open++ }
        /input_session_request/ { session_request++ }
        /session_open: channel [0-9]+/ { session_open++ }
        /no more sessions/ { exhausted++ }
        /session open failed/ { rejected++ }
        /server_input_channel_open: failure session/ { open_failure++ }
        /Starting session:/ || /subsystem request for/ { executed = 1 }
        END {
            exit(channel_open == 1 && session_request == 1 &&
                session_open == 1 && exhausted == 1 && rejected == 1 &&
                open_failure == 1 && !executed ? 0 : 1)
        }
    ' "$WT_SESSION_SERVER_LOG"; then
        fail "$WT_SESSION_NAME lacks isolated MaxSessions=0 rejection evidence"
    fi
    pass "$WT_SESSION_NAME reached sshd and was rejected at the session-channel boundary"
}

verify_complete_kex_epochs() {
    WT_KEX_TRANSCRIPT=$1
    awk \
        -v expected_kex="$WT_KEX" \
        -v expected_host_key="$WT_COMPOSITE_KEY" \
        -v cipher_one="$WT_APPROVED_CIPHER_ONE" \
        -v cipher_two="$WT_APPROVED_CIPHER_TWO" '
        function complete_epoch() {
            return phase == 4 && newkeys_sent == 1 && newkeys_received == 1
        }
        function field_after(marker, value) {
            sub("^.*" marker, "", value)
            sub("[[:space:]]+\\[(preauth|postauth)\\]$", "", value)
            sub("[[:space:]]+$", "", value)
            return value
        }
        function cipher_allowed(marker, value, suffix) {
            value = field_after(marker, $0)
            suffix = " MAC: <implicit> compression: none"
            return value == cipher_one suffix || value == cipher_two suffix
        }
        function finish_epoch() {
            if (!epoch_open) {
                return
            }
            if (!complete_epoch()) {
                bad = 1
            }
            epoch_count++
            epoch_open = 0
        }
        index($0, "Connection from ") == 1 {
            connection_count++
            connection_address = $3
            connection_port = $5
            next
        }
        /kex: algorithm:/ {
            if (connection_count != 1) {
                bad = 1
            }
            finish_epoch()
            epoch_open = 1
            phase = 1
            newkeys_sent = 0
            newkeys_received = 0
            if (field_after("kex: algorithm: ", $0) != expected_kex) {
                bad = 1
            }
            next
        }
        /kex: host key algorithm:/ {
            if (!epoch_open || phase != 1 ||
                field_after("kex: host key algorithm: ", $0) != expected_host_key) {
                bad = 1
            } else {
                phase = 2
            }
            next
        }
        /kex: client->server cipher:/ {
            if (!epoch_open || phase != 2 ||
                !cipher_allowed("kex: client->server cipher: ")) {
                bad = 1
            } else {
                phase = 3
            }
            next
        }
        /kex: server->client cipher:/ {
            if (!epoch_open || phase != 3 ||
                !cipher_allowed("kex: server->client cipher: ")) {
                bad = 1
            } else {
                phase = 4
            }
            next
        }
        /SSH2_MSG_NEWKEYS sent/ {
            if (!epoch_open || phase != 4 || ++newkeys_sent != 1) {
                bad = 1
            }
            next
        }
        /SSH2_MSG_NEWKEYS received/ {
            if (!epoch_open || phase != 4 || ++newkeys_received != 1) {
                bad = 1
            }
            next
        }
        index($0, "Accepted publickey for warptweet from ") == 1 {
            accepted_count++
            if ($6 != connection_address || $8 != connection_port ||
                index($0, " ssh2: " expected_host_key " ") == 0 ||
                !epoch_open || !complete_epoch()) {
                bad = 1
            }
            next
        }
        END {
            finish_epoch()
            exit(connection_count == 1 && accepted_count == 1 &&
                epoch_count >= 2 && !bad ? 0 : 1)
        }
    ' "$WT_KEX_TRANSCRIPT"
}

for WT_DIRECTORY in \
    /opt \
    /opt/warptweet \
    /opt/warptweet/bin \
    /opt/warptweet/etc \
    /var/lib/warptweet/ssh \
    /var/lib/warptweet/authorized_keys \
    /opt/warptweet/libexec \
    /opt/warptweet/libexec/openssh \
    /opt/warptweet/libexec/openssh/bin \
    /opt/warptweet/libexec/openssh/libexec \
    /opt/warptweet/libexec/openssh/sbin \
    /opt/warptweet/share \
    /opt/warptweet/share/licenses \
    /opt/warptweet/share/licenses/openssh \
    /opt/warptweet/share/licenses/openssl \
    /etc \
    /etc/warptweet \
    /var \
    /var/empty \
    /var/empty/warptweet-sshd; do
    require_directory "$WT_DIRECTORY" 755
done

for WT_EXECUTABLE in "$WT_CONTROLLER" "$WT_SSH" "$WT_KEYGEN" "$WT_SSHD"; do
    require_file "$WT_EXECUTABLE" 755 yes
done
require_file "$WT_SERVER_MANIFEST" 644 no
require_file "$WT_SERVER_CONFIG" 644 no
require_file "$WT_HOST_KEY" 600 no
require_file "$WT_HOST_PUBLIC_KEY" 644 no
require_file "$WT_AUTHORIZED_KEYS" 644 no
require_file "$WT_BUNDLE_MANIFEST" 644 no
require_file /opt/warptweet/share/openssh-source.txt 644 no
require_file /opt/warptweet/share/openssl-source.txt 644 no
require_file /opt/warptweet/share/licenses/openssh/LICENCE 644 no
require_file /opt/warptweet/share/licenses/openssl/LICENSE.txt 644 no

require_account warptweet /nonexistent /usr/sbin/nologin
require_account warptweet-sshd /var/empty/warptweet-sshd /usr/sbin/nologin
require_public_key_only_account warptweet
for WT_CLIENT_STATE_PATH in \
    "$WT_CLIENT_MANIFEST" \
    "$WT_CLIENT_IDENTITY_DIRECTORY" \
    "$WT_CLIENT_TRUST_DIRECTORY"; do
    if [ -e "$WT_CLIENT_STATE_PATH" ] || [ -L "$WT_CLIENT_STATE_PATH" ]; then
        fail "fixed client state already exists; refusing to reuse host state: $WT_CLIENT_STATE_PATH"
    fi
done
provision_dedicated_client_account
require_file /etc/passwd 644 no
require_file /etc/group 644 no
provision_and_probe_tun

(
    cd /
    sha256sum --check --strict opt/warptweet/share/openssh-bundle.sha256 >/dev/null
) || fail "installed nine-file OpenSSH bundle failed authentication"

if [ -e "$WT_TEST_CONFIG_DIRECTORY" ] || [ -L "$WT_TEST_CONFIG_DIRECTORY" ]; then
    fail "test client directory already exists; refusing to reuse host state"
fi
if [ -e "$WT_STATE_DIRECTORY" ] || [ -L "$WT_STATE_DIRECTORY" ]; then
    fail "test runtime directory already exists; refusing to reuse host state"
fi
if [ -e "$WT_CLIENT_RUNTIME_ROOT" ] || [ -L "$WT_CLIENT_RUNTIME_ROOT" ]; then
    fail "client runtime root already exists; refusing to reuse host state"
fi
install -d -o root -g root -m 0700 "$WT_TEST_CONFIG_DIRECTORY"
require_directory /run 755
if [ -e /run/warptweet ] || [ -L /run/warptweet ]; then
    require_directory /run/warptweet 755
else
    install -d -o root -g root -m 0755 /run/warptweet
fi
if [ -e "$WT_SERVER_RUNTIME_DIRECTORY" ] || [ -L "$WT_SERVER_RUNTIME_DIRECTORY" ]; then
    fail "server runtime directory already exists; refusing to reuse host state"
fi
install -d -o root -g root -m 0750 "$WT_SERVER_RUNTIME_DIRECTORY"
install -d -o root -g root -m 0755 "$WT_CLIENT_RUNTIME_ROOT"
install -d -o "$WT_CLIENT_USER" -g "$WT_CLIENT_GROUP" -m 0700 \
    "$WT_CONTROLLER_RUNTIME_DIRECTORY"
install -d -o root -g "$WT_CLIENT_GROUP" -m 0750 \
    "$WT_CLIENT_IDENTITY_DIRECTORY" \
    "$WT_CLIENT_TRUST_DIRECTORY"
install -d -o root -g root -m 0700 \
    "$WT_STATE_DIRECTORY" \
    "$WT_PAYLOAD_DIRECTORY" \
    "$WT_FORBIDDEN_PAYLOAD_DIRECTORY"
require_empty_client_runtime_directory

WT_INITIAL_SERVER_REPORT="$WT_STATE_DIRECTORY/server-doctor-initial.json"
"$WT_CONTROLLER" doctor-server --config "$WT_SERVER_MANIFEST" >"$WT_INITIAL_SERVER_REPORT"
grep -F '"status":"preflight_ready"' "$WT_INITIAL_SERVER_REPORT" >/dev/null ||
    fail "initial fixed-layout server doctor did not pass"

WT_RENDERED_SERVER_TEST="$WT_STATE_DIRECTORY/sshd_config.rendered"
"$WT_CONTROLLER" render-server --config "$WT_SERVER_MANIFEST" >"$WT_RENDERED_SERVER_TEST"
cmp -s "$WT_RENDERED_SERVER_TEST" "$WT_SERVER_CONFIG" ||
    fail "installed server configuration differs from the deterministic renderer"

WT_RENDERED_EFFECTIVE="$WT_STATE_DIRECTORY/sshd-effective-rendered.txt"
env -i LANG=C LC_ALL=C \
    "$WT_SSHD" -T -f "$WT_SERVER_CONFIG" >"$WT_RENDERED_EFFECTIVE"
WT_RENDERED_REKEY=$(awk '$1 == "rekeylimit" { print $2 " " $3 }' "$WT_RENDERED_EFFECTIVE")
[ "$WT_RENDERED_REKEY" = "536870912 3600" ] ||
    fail "rendered server RekeyLimit is $WT_RENDERED_REKEY, want 536870912 3600"
grep -Fx 'LogLevel VERBOSE' "$WT_RENDERED_EFFECTIVE" >/dev/null ||
    fail "rendered server LogLevel is not VERBOSE"
pass "rendered server policy remains 512M/1h and VERBOSE"

WT_OVERRIDE_EFFECTIVE="$WT_STATE_DIRECTORY/sshd-effective-live-override.txt"
env -i LANG=C LC_ALL=C \
	"$WT_SSHD" -T -f "$WT_SERVER_CONFIG" \
	-o LogLevel=DEBUG3 \
	-o 'RekeyLimit=1K 0' >"$WT_OVERRIDE_EFFECTIVE"
WT_OVERRIDE_REKEY=$(awk '$1 == "rekeylimit" { print $2 " " $3 }' "$WT_OVERRIDE_EFFECTIVE")
[ "$WT_OVERRIDE_REKEY" = "1024 0" ] ||
    fail "test server RekeyLimit override is $WT_OVERRIDE_REKEY, want 1024 0"
grep -Fx 'LogLevel DEBUG3' "$WT_OVERRIDE_EFFECTIVE" >/dev/null ||
    fail "test server LogLevel override is not DEBUG3"
pass "test-only server override is effective"

assert_port_free "$WT_SERVER_PORT"
assert_port_free "$WT_TARGET_PORT"
assert_port_free "$WT_FORBIDDEN_TARGET_PORT"
assert_port_free "$WT_FORWARD_PORT"
assert_port_free "$WT_SOCKS_PORT"

env -i LANG=C LC_ALL=C \
    "$WT_KEYGEN" -q -t mldsa44-ed25519 -N '' -C warptweet-live-client -f "$WT_CLIENT_KEY_CANDIDATE"
env -i LANG=C LC_ALL=C \
    "$WT_KEYGEN" -q -t mldsa44-ed25519 -N '' -C warptweet-live-wrong-host -f "$WT_WRONG_HOST_KEY"
env -i LANG=C LC_ALL=C \
    "$WT_KEYGEN" -q -t ed25519 -N '' -C warptweet-live-classical-negative -f "$WT_CLASSICAL_KEY"
chmod 0600 "$WT_CLIENT_KEY_CANDIDATE" "$WT_WRONG_HOST_KEY" "$WT_CLASSICAL_KEY"
chmod 0644 "$WT_CLIENT_PUBLIC_KEY" "$WT_WRONG_HOST_KEY.pub" "$WT_CLASSICAL_KEY.pub"

WT_SSH_SHA256=$(sha256sum "$WT_SSH" | awk '{print $1}')
{
    printf '%s\n' '{'
    printf '%s\n' '  "kind": "warptweet.client-tunnels",'
    printf '%s\n' '  "schema_version": 2,'
    printf '  "profile_id": "%s",\n' "$WT_PROFILE"
    printf '  "ssh_binary_sha256": "%s",\n' "$WT_SSH_SHA256"
    printf '%s\n' '  "server": {'
    printf '    "host": "127.0.0.1", "port": %s, "user": "warptweet"\n' "$WT_SERVER_PORT"
    printf '%s\n' '  },'
    printf '%s\n' '  "tunnels": ['
    printf '%s\n' '    {'
    printf '      "id": "%s",\n' "$WT_TUNNEL_ID"
    printf '      "listen": {"address": "127.0.0.1", "port": %s},\n' "$WT_FORWARD_PORT"
    printf '      "target": {"address": "127.0.0.1", "port": %s}\n' "$WT_TARGET_PORT"
    printf '%s\n' '    }'
    printf '%s\n' '  ],'
    printf '%s\n' '  "supervision": {"initial_backoff": "250ms", "max_backoff": "1s"}'
    printf '%s\n' '}'
} >"$WT_CLIENT_MANIFEST_CANDIDATE"
chmod 0600 "$WT_CLIENT_MANIFEST_CANDIDATE"

"$WT_CONTROLLER" validate --config "$WT_CLIENT_MANIFEST_CANDIDATE" >"$WT_STATE_DIRECTORY/client-validate.json"
"$WT_CONTROLLER" render-known-host \
    --config "$WT_CLIENT_MANIFEST_CANDIDATE" \
    --tunnel "$WT_TUNNEL_ID" \
    --public-key "$WT_HOST_PUBLIC_KEY" >"$WT_STATE_DIRECTORY/known_hosts.new"
"$WT_CONTROLLER" render-known-host \
    --config "$WT_CLIENT_MANIFEST_CANDIDATE" \
    --tunnel "$WT_TUNNEL_ID" \
    --public-key "$WT_WRONG_HOST_KEY.pub" >"$WT_STATE_DIRECTORY/known_hosts.wrong.new"
install -o root -g root -m 0600 "$WT_STATE_DIRECTORY/known_hosts.wrong.new" "$WT_WRONG_KNOWN_HOSTS"

install -o root -g "$WT_CLIENT_GROUP" -m 0440 \
    "$WT_CLIENT_MANIFEST_CANDIDATE" "$WT_CLIENT_MANIFEST"
install -o "$WT_CLIENT_USER" -g "$WT_CLIENT_GROUP" -m 0600 \
    "$WT_CLIENT_KEY_CANDIDATE" "$WT_CLIENT_KEY"
install -o root -g "$WT_CLIENT_GROUP" -m 0440 \
    "$WT_STATE_DIRECTORY/known_hosts.new" "$WT_KNOWN_HOSTS"
install -o root -g "$WT_CLIENT_GROUP" -m 0440 /dev/null "$WT_GLOBAL_KNOWN_HOSTS"
require_client_state_layout
prove_managed_client_state_immutable "$WT_CLIENT_USER" service
prove_managed_client_state_immutable "$WT_SECONDARY_UNPRIVILEGED_USER" secondary

WT_NOT_AFTER=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ) ||
    fail "cannot compute authorization expiry"
"$WT_CONTROLLER" render-authorized-key \
    --config "$WT_SERVER_MANIFEST" \
    --public-key "$WT_CLIENT_PUBLIC_KEY" \
    --not-after "$WT_NOT_AFTER" >"$WT_STATE_DIRECTORY/authorized_keys.new"
install -o root -g root -m 0644 "$WT_STATE_DIRECTORY/authorized_keys.new" "$WT_AUTHORIZED_KEYS"

WT_FINAL_SERVER_REPORT="$WT_STATE_DIRECTORY/server-doctor-live.json"
"$WT_CONTROLLER" doctor-server --config "$WT_SERVER_MANIFEST" >"$WT_FINAL_SERVER_REPORT"
grep -F '"status":"preflight_ready"' "$WT_FINAL_SERVER_REPORT" >/dev/null ||
    fail "server doctor rejected the live composite authorization"
grep -F '"authorized_key_count":1' "$WT_FINAL_SERVER_REPORT" >/dev/null ||
    fail "server doctor did not validate exactly one live composite authorization"

WT_CLIENT_REPORT="$WT_STATE_DIRECTORY/client-doctor.json"
run_as_dedicated_client "$WT_CONTROLLER" doctor \
    --config "$WT_CLIENT_MANIFEST" \
    --tunnel "$WT_TUNNEL_ID" >"$WT_CLIENT_REPORT"
grep -F '"status":"preflight_ready"' "$WT_CLIENT_REPORT" >/dev/null ||
    fail "client doctor did not pass the fixed-layout client policy"
pass "client doctor passed as the dedicated non-root client UID"

"$WT_CONTROLLER" render-client \
    --config "$WT_CLIENT_MANIFEST" \
    --tunnel "$WT_TUNNEL_ID" >"$WT_RENDERED_CLIENT_CONFIG"
chmod 0600 "$WT_RENDERED_CLIENT_CONFIG"
grep -Fx '    RekeyLimit "512M" "1h"' "$WT_RENDERED_CLIENT_CONFIG" >/dev/null ||
    fail "rendered client RekeyLimit changed"
grep -Fx '    LogLevel "VERBOSE"' "$WT_RENDERED_CLIENT_CONFIG" >/dev/null ||
    fail "rendered client LogLevel changed"
grep -Fx "    LocalForward \"[127.0.0.1]:$WT_FORWARD_PORT\" \"[127.0.0.1]:$WT_TARGET_PORT\"" \
    "$WT_RENDERED_CLIENT_CONFIG" >/dev/null ||
    fail "rendered client omits the one exact local forward"
grep -Fx '    Tunnel "no"' "$WT_RENDERED_CLIENT_CONFIG" >/dev/null ||
    fail "rendered client does not disable tunnel-device forwarding"
if grep -E '^[[:space:]]*(RemoteForward|DynamicForward)[[:space:]]' \
    "$WT_RENDERED_CLIENT_CONFIG" >/dev/null; then
    fail "rendered client contains a forbidden forwarding mode"
fi

sed "s#IdentityFile \"$WT_CLIENT_KEY\"#IdentityFile \"$WT_CLIENT_KEY_CANDIDATE\"#" \
    "$WT_RENDERED_CLIENT_CONFIG" >"$WT_RAW_CLIENT_CONFIG"
chmod 0600 "$WT_RAW_CLIENT_CONFIG"
grep -Fx "    IdentityFile \"$WT_CLIENT_KEY\"" "$WT_RAW_CLIENT_CONFIG" >/dev/null &&
    fail "raw negative-test config retained the installed group-readable identity path"
grep -Fx "    IdentityFile \"$WT_CLIENT_KEY_CANDIDATE\"" "$WT_RAW_CLIENT_CONFIG" >/dev/null ||
    fail "raw negative-test config does not use the root-only staging identity"

sed "s#UserKnownHostsFile \"$WT_KNOWN_HOSTS\"#UserKnownHostsFile \"$WT_WRONG_KNOWN_HOSTS\"#" \
    "$WT_RAW_CLIENT_CONFIG" >"$WT_WRONG_HOST_CLIENT_CONFIG"
chmod 0600 "$WT_WRONG_HOST_CLIENT_CONFIG"
grep -Fx "    UserKnownHostsFile \"$WT_KNOWN_HOSTS\"" "$WT_WRONG_HOST_CLIENT_CONFIG" >/dev/null &&
    fail "wrong-host negative config retained the trusted pin path"
grep -Fx "    UserKnownHostsFile \"$WT_WRONG_KNOWN_HOSTS\"" "$WT_WRONG_HOST_CLIENT_CONFIG" >/dev/null ||
    fail "wrong-host negative config was not rewritten exactly once"

sed \
    -e "s#IdentityFile \"$WT_CLIENT_KEY_CANDIDATE\"#IdentityFile \"$WT_CLASSICAL_KEY\"#" \
    -e "s#PubkeyAcceptedAlgorithms \"$WT_COMPOSITE_KEY\"#PubkeyAcceptedAlgorithms \"$WT_CLASSICAL_KEY_TYPE\"#" \
    "$WT_RAW_CLIENT_CONFIG" >"$WT_CLASSICAL_CLIENT_CONFIG"
chmod 0600 "$WT_CLASSICAL_CLIENT_CONFIG"
grep -Fx "    IdentityFile \"$WT_CLIENT_KEY_CANDIDATE\"" "$WT_CLASSICAL_CLIENT_CONFIG" >/dev/null &&
    fail "classical-key negative config retained the composite identity path"
grep -Fx "    IdentityFile \"$WT_CLASSICAL_KEY\"" "$WT_CLASSICAL_CLIENT_CONFIG" >/dev/null ||
    fail "classical-key negative config was not rewritten exactly once"
grep -Fx "    PubkeyAcceptedAlgorithms \"$WT_COMPOSITE_KEY\"" "$WT_CLASSICAL_CLIENT_CONFIG" >/dev/null &&
    fail "classical-key negative config retained the composite user-auth algorithm"
grep -Fx "    PubkeyAcceptedAlgorithms \"$WT_CLASSICAL_KEY_TYPE\"" "$WT_CLASSICAL_CLIENT_CONFIG" >/dev/null ||
    fail "classical-key negative config does not offer only Ed25519 user authentication"

WT_DYNAMIC_CLI_LOG="$WT_STATE_DIRECTORY/negative-controller-dynamic.log"
if run_as_dedicated_client "$WT_CONTROLLER" run \
    --config "$WT_CLIENT_MANIFEST" \
    --tunnel "$WT_TUNNEL_ID" \
    --once \
    --dynamic-forward "127.0.0.1:$WT_SOCKS_PORT" >"$WT_STATE_DIRECTORY/negative-controller-dynamic.stdout" 2>"$WT_DYNAMIC_CLI_LOG"; then
    fail "controller accepted a DynamicForward request"
fi
grep -E 'flag provided but not defined|unexpected positional arguments' "$WT_DYNAMIC_CLI_LOG" >/dev/null ||
    fail "controller rejected DynamicForward without a closed-CLI error"
pass "controller DynamicForward rejected"

dd if=/dev/zero of="$WT_PAYLOAD" bs=1024 count=64 status=none
printf '%s\n' 'warptweet-forbidden-target-canary' >"$WT_FORBIDDEN_PAYLOAD_DIRECTORY/canary.txt"

python3 -m http.server "$WT_TARGET_PORT" \
    --bind 127.0.0.1 \
    --directory "$WT_PAYLOAD_DIRECTORY" >"$WT_TARGET_LOG" 2>&1 &
WT_TARGET_PID=$!
WT_TARGET_ID=$(wait_for_owned_process "$WT_TARGET_PID" "$WT_PYTHON" "application target")

python3 -m http.server "$WT_FORBIDDEN_TARGET_PORT" \
    --bind 127.0.0.1 \
    --directory "$WT_FORBIDDEN_PAYLOAD_DIRECTORY" >"$WT_FORBIDDEN_TARGET_LOG" 2>&1 &
WT_FORBIDDEN_TARGET_PID=$!
WT_FORBIDDEN_TARGET_ID=$(wait_for_owned_process "$WT_FORBIDDEN_TARGET_PID" "$WT_PYTHON" "forbidden target")

WT_TARGET_READY=0
WT_TARGET_ATTEMPT=0
while [ "$WT_TARGET_ATTEMPT" -lt 100 ]; do
    if curl --fail --silent --show-error --connect-timeout 1 --max-time 3 \
        --noproxy '*' \
        --output "$WT_STATE_DIRECTORY/target-direct" \
        "http://127.0.0.1:$WT_TARGET_PORT/rekey.bin" &&
        cmp -s "$WT_PAYLOAD" "$WT_STATE_DIRECTORY/target-direct"; then
        WT_TARGET_READY=1
        break
    fi
    WT_TARGET_ATTEMPT=$((WT_TARGET_ATTEMPT + 1))
    sleep 0.1
done
[ "$WT_TARGET_READY" -eq 1 ] || fail "application target did not become ready"
curl --fail --silent --show-error --connect-timeout 1 --max-time 3 \
    --noproxy '*' \
    --output "$WT_STATE_DIRECTORY/forbidden-target-direct" \
    "http://127.0.0.1:$WT_FORBIDDEN_TARGET_PORT/canary.txt" ||
    fail "forbidden-target canary did not become ready"

install -d -o root -g warptweet-sshd -m 0770 /var/lib/warptweet/sessions
install -d -o root -g warptweet-sshd -m 2750 /var/lib/warptweet/clients
WT_LIVE_CLIENT_ID=cafef00ddeadbeef
env -i LANG=C LC_ALL=C \
    "$WT_PYTHON" -c '
import hashlib, json, sys
public_key = open(sys.argv[1], encoding="utf-8").read().strip()
digest = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
record = {
    "client_id": sys.argv[2],
    "grant_id": "baddcafebeefdead",
    "tunnel_id": "live",
    "route_id": "live",
    "invite_id": "0d15ea5ecafebabe",
    "public_key": public_key,
    "public_key_sha256": digest,
    "management_token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "principal": "warptweet",
    "profile_id": sys.argv[3],
    "published_endpoint_generation": 1,
    "data": {"host": "127.0.0.1", "port": 2222},
    "enrollment": {"host": "127.0.0.1", "port": 29722},
    "target_address": "127.0.0.1",
    "target_port": int(sys.argv[4]),
    "status": "active",
    "accepted_at": "2026-08-28T00:00:00Z",
    "authorization_not_after": sys.argv[5],
    "authorization_duration_seconds": 2592000,
    "generation": "20260828T000000Z",
}
with open(sys.argv[6], "w", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2)
    handle.write("\n")
' "$WT_CLIENT_PUBLIC_KEY" "$WT_LIVE_CLIENT_ID" "$WT_PROFILE" "$WT_TARGET_PORT" "$WT_NOT_AFTER" "$WT_STATE_DIRECTORY/live-client.json" ||
    fail "cannot render the live-gate grant client record"
install -o root -g warptweet-sshd -m 0640 \
    "$WT_STATE_DIRECTORY/live-client.json" "/var/lib/warptweet/clients/${WT_LIVE_CLIENT_ID}.json"
install -o root -g root -m 0600 /dev/null "$WT_GRANT_LOG"
env -i LANG=C LC_ALL=C \
    "$WT_CONTROLLER" server grant-listen >"$WT_GRANT_LOG" 2>&1 &
WT_GRANT_PID=$!
WT_GRANT_ID=$(wait_for_owned_process "$WT_GRANT_PID" "$WT_CONTROLLER" "grant session authority")
WT_GRANT_READY=0
WT_GRANT_ATTEMPT=0
while [ "$WT_GRANT_ATTEMPT" -lt 100 ]; do
    if [ -S "$WT_GRANT_SOCKET" ]; then
        WT_GRANT_READY=1
        break
    fi
    if ! kill -0 "$WT_GRANT_PID" 2>/dev/null; then
        dump_live_gate_file "$WT_GRANT_LOG" "grant session authority log after process exit"
        fail "grant session authority process $WT_GRANT_PID exited before the grant socket appeared"
    fi
    WT_GRANT_ATTEMPT=$((WT_GRANT_ATTEMPT + 1))
    sleep 0.1
done
[ "$WT_GRANT_READY" -eq 1 ] || fail "grant session socket did not appear"
[ "$(stat -c '%u:%g:%a' "$WT_GRANT_SOCKET")" = "0:0:600" ] ||
    fail "grant session socket has unexpected ownership or mode"
pass "grant session authority is listening"

install -o root -g root -m 0600 /dev/null "$WT_SERVER_LOG"
install -o root -g root -m 0600 /dev/null "$WT_SERVER_STDERR"
env -i LANG=C LC_ALL=C \
	"$WT_SSHD" -D \
	-E "$WT_SERVER_LOG" \
	-f "$WT_SERVER_CONFIG" \
	-o LogLevel=DEBUG3 \
	-o 'RekeyLimit=1K 0' >"$WT_STATE_DIRECTORY/sshd.stdout" 2>"$WT_SERVER_STDERR" &
WT_SSHD_PID=$!
WT_SSHD_ID=$(wait_for_owned_process "$WT_SSHD_PID" "$WT_SSHD" "sshd")
wait_for_log "$WT_SERVER_LOG" "Server listening on 127.0.0.1 port $WT_SERVER_PORT" "sshd listener"
WT_CONTROLLER_SERVER_START_LINE=$(server_log_line_count)

env -i LANG=C LC_ALL=C \
    "$WT_PYTHON" -c '
import os
import sys

uid = int(sys.argv[1])
gid = int(sys.argv[2])
executable = sys.argv[3]
arguments = sys.argv[3:]
os.setgroups([])
os.setgid(gid)
os.setuid(uid)
os.chdir("/")
os.execve(executable, arguments, {"LANG": "C", "LC_ALL": "C"})
' "$WT_CLIENT_UID" "$WT_CLIENT_GID" "$WT_CONTROLLER" run \
    --config "$WT_CLIENT_MANIFEST" \
    --tunnel "$WT_TUNNEL_ID" \
    --once >"$WT_CONTROLLER_STDOUT" 2>"$WT_CONTROLLER_LOG" &
WT_CONTROLLER_PID=$!
WT_CONTROLLER_ID=$(wait_for_owned_process "$WT_CONTROLLER_PID" "$WT_CONTROLLER" "controller")
if [ "$(process_effective_uid "$WT_CONTROLLER_PID")" != "$WT_CLIENT_UID" ]; then
    fail "controller is not running as the dedicated client UID"
fi

wait_for_log \
    "$WT_CONTROLLER_LOG" \
    '"msg":"WarpTweet tunnel authenticated forward ready"' \
    "controller authenticated-forward readiness" \
    "$WT_CONTROLLER_PID"
if [ -e "$WT_CONTROLLER_RUNTIME_DIRECTORY/c" ] || [ -L "$WT_CONTROLLER_RUNTIME_DIRECTORY/c" ]; then
    fail "one-shot readiness control socket still exists after authenticated readiness"
fi
require_empty_client_runtime_directory
pass "authenticated SSH readiness was logged before tunneled payload transit"

WT_FORWARD_READY=0
WT_FORWARD_ATTEMPT=0
while [ "$WT_FORWARD_ATTEMPT" -lt 150 ]; do
    if curl --fail --silent --show-error --connect-timeout 1 --max-time 5 \
        --noproxy '*' \
        --output "$WT_RECEIVED_PAYLOAD" \
        "http://127.0.0.1:$WT_FORWARD_PORT/rekey.bin" &&
        cmp -s "$WT_PAYLOAD" "$WT_RECEIVED_PAYLOAD"; then
        WT_FORWARD_READY=1
        break
    fi
    if ! kill -0 "$WT_CONTROLLER_PID" 2>/dev/null; then
        fail "controller exited before authenticated payload transit"
    fi
    WT_FORWARD_ATTEMPT=$((WT_FORWARD_ATTEMPT + 1))
    sleep 0.2
done
[ "$WT_FORWARD_READY" -eq 1 ] || fail "controller tunnel did not carry the deterministic HTTP payload"
pass "controller carried deterministic HTTP payload"

WT_CHILD_ATTEMPT=0
while [ "$WT_CHILD_ATTEMPT" -lt 100 ]; do
    WT_CHILDREN=$(process_children "$WT_CONTROLLER_PID")
    WT_MATCHED_CHILD=''
    WT_MATCHED_COUNT=0
    for WT_CHILD in $WT_CHILDREN; do
        if [ "$(process_executable "$WT_CHILD" || true)" = "$WT_SSH" ]; then
            WT_MATCHED_CHILD=$WT_CHILD
            WT_MATCHED_COUNT=$((WT_MATCHED_COUNT + 1))
        fi
    done
    if [ "$WT_MATCHED_COUNT" -eq 1 ]; then
        WT_CLIENT_PID=$WT_MATCHED_CHILD
        WT_CLIENT_ID=$(process_identity "$WT_CLIENT_PID") || fail "cannot identify controller SSH child"
        if [ "$(process_effective_uid "$WT_CLIENT_PID")" != "$WT_CLIENT_UID" ]; then
            fail "controller SSH child is not running as the dedicated client UID"
        fi
        break
    fi
    if [ "$WT_MATCHED_COUNT" -ne 0 ]; then
        dump_process_children "$WT_CONTROLLER_PID" "controller"
        fail "controller owns more than one packaged SSH child"
    fi
    WT_CHILD_ATTEMPT=$((WT_CHILD_ATTEMPT + 1))
    sleep 0.1
done
if [ -z "$WT_CLIENT_PID" ]; then
    dump_process_children "$WT_CONTROLLER_PID" "controller"
    fail "controller packaged SSH child was not observed"
fi

WT_REKEY_ATTEMPT=0
WT_KEX_EPOCHS_COMPLETE=0
WT_CURRENT_CONTROLLER_SERVER_LOG="$WT_STATE_DIRECTORY/sshd-controller-current.log"
while [ "$WT_REKEY_ATTEMPT" -lt 200 ]; do
    awk -v start="$WT_CONTROLLER_SERVER_START_LINE" \
        'NR > start' "$WT_SERVER_LOG" >"$WT_CURRENT_CONTROLLER_SERVER_LOG"
    if verify_complete_kex_epochs "$WT_CURRENT_CONTROLLER_SERVER_LOG"; then
        WT_KEX_EPOCHS_COMPLETE=1
        break
    fi
    WT_REKEY_ATTEMPT=$((WT_REKEY_ATTEMPT + 1))
    sleep 0.1
done
[ "$WT_KEX_EPOCHS_COMPLETE" -eq 1 ] ||
    fail "server DEBUG transcript did not contain two complete controller KEX epochs"
install -o root -g root -m 0600 \
    "$WT_CURRENT_CONTROLLER_SERVER_LOG" "$WT_POSITIVE_SERVER_LOG"

stop_owned_process "$WT_CLIENT_PID" "$WT_CLIENT_ID" "$WT_SSH" "controller SSH child" ||
    fail "could not stop the owned controller SSH child"
WT_CLIENT_PID=''
WT_CLIENT_ID=''
stop_owned_process "$WT_CONTROLLER_PID" "$WT_CONTROLLER_ID" "$WT_CONTROLLER" "controller" ||
    fail "could not stop the owned controller"
WT_CONTROLLER_PID=''
WT_CONTROLLER_ID=''

grep -F '"msg":"WarpTweet tunnel preflight passed"' "$WT_CONTROLLER_LOG" >/dev/null ||
    fail "controller log omits successful launch attestation"
verify_complete_kex_epochs "$WT_POSITIVE_SERVER_LOG" ||
    fail "controller transcript does not bind every complete KEX epoch to the exact profile"
pass "controller transcript contains two complete exact-profile KEX epochs and one composite user authentication"

expect_ssh_failure classical-kex \
    'no matching key exchange method found' \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -o KexAlgorithms=curve25519-sha256 \
    -N -T "$WT_HOST_ALIAS"

expect_ssh_failure wrong-host-pin \
    'Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED' \
    -F "$WT_WRONG_HOST_CLIENT_CONFIG" \
    -N -T "$WT_HOST_ALIAS"

WT_CLASSICAL_SERVER_START_LINE=$(server_log_line_count)
expect_ssh_failure classical-user-key \
    'Permission denied \(publickey\)' \
    -F "$WT_CLASSICAL_CLIENT_CONFIG" \
    -N -T "$WT_HOST_ALIAS"
capture_server_evidence "$WT_CLASSICAL_SERVER_START_LINE" classical-user-key
if ! grep -F "signature algorithm $WT_CLASSICAL_KEY_TYPE not in PubkeyAcceptedAlgorithms" \
    "$WT_STATE_DIRECTORY/negative-classical-user-key.server.log" >/dev/null; then
    fail "server transcript does not prove rejection of an offered Ed25519 user key"
fi
if grep -F "Accepted publickey for warptweet" \
    "$WT_STATE_DIRECTORY/negative-classical-user-key.server.log" >/dev/null; then
    fail "server transcript accepted a key during the classical-user negative"
fi
pass "server rejected an actually offered Ed25519 user key"

expect_ssh_failure unapproved-target \
    'administratively prohibited|stdio forwarding failed|open failed' \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -W "127.0.0.1:$WT_FORBIDDEN_TARGET_PORT" \
    "$WT_HOST_ALIAS"

expect_session_channel_failure shell-without-command \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -o SessionType=default \
    -T "$WT_HOST_ALIAS"

expect_session_channel_failure exec-command \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -o SessionType=default \
    -T "$WT_HOST_ALIAS" /bin/true

expect_session_channel_failure sftp-subsystem \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -o SessionType=subsystem \
    -T -s "$WT_HOST_ALIAS" sftp

expect_session_channel_failure scp-style-exec \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -o SessionType=default \
    -T "$WT_HOST_ALIAS" "scp -t /tmp/warptweet-live-gate"

expect_ssh_failure reverse-forward \
    'Server has disabled port forwarding' \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -N -T \
    -R "127.0.0.1:25432:127.0.0.1:$WT_TARGET_PORT" \
    "$WT_HOST_ALIAS"

expect_ssh_failure tun-forward \
    'Server has rejected tunnel device forwarding' \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -N -T -w any:any "$WT_HOST_ALIAS"

WT_SOCKS_LOG="$WT_STATE_DIRECTORY/negative-socks.log"
env -i LANG=C LC_ALL=C \
    "$WT_SSH" -vvv \
    -F "$WT_RAW_CLIENT_CONFIG" \
    -N -T \
    -D "127.0.0.1:$WT_SOCKS_PORT" \
    "$WT_HOST_ALIAS" >"$WT_STATE_DIRECTORY/negative-socks.stdout" 2>"$WT_SOCKS_LOG" &
WT_SOCKS_PID=$!
WT_SOCKS_ID=$(wait_for_owned_process "$WT_SOCKS_PID" "$WT_SSH" "SOCKS client")
wait_for_log "$WT_SOCKS_LOG" "Local forwarding listening on 127.0.0.1 port $WT_SOCKS_PORT" "SOCKS listener"
if curl --fail --silent --show-error --connect-timeout 2 --max-time 10 \
    --noproxy '' \
    --socks5-hostname "127.0.0.1:$WT_SOCKS_PORT" \
    --output "$WT_STATE_DIRECTORY/negative-socks.received" \
    "http://127.0.0.1:$WT_FORBIDDEN_TARGET_PORT/canary.txt"; then
    fail "raw SOCKS forwarding reached the live unapproved target"
fi
wait_for_log "$WT_SOCKS_LOG" "administratively prohibited" "SOCKS PermitOpen rejection"
stop_owned_process "$WT_SOCKS_PID" "$WT_SOCKS_ID" "$WT_SSH" "SOCKS client" ||
    fail "could not stop the owned SOCKS client"
WT_SOCKS_PID=''
WT_SOCKS_ID=''
pass "raw SOCKS transit to unapproved target rejected"

for WT_OUTPUT in "$WT_STATE_DIRECTORY"/*; do
    if [ -f "$WT_OUTPUT" ] &&
        grep -E 'BEGIN OPENSSH PRIVATE KEY|b3BlbnNzaC1rZXktdjE' "$WT_OUTPUT" >/dev/null 2>&1; then
        fail "private key bytes appeared in captured live-gate output"
    fi
done

stop_owned_process "$WT_SSHD_PID" "$WT_SSHD_ID" "$WT_SSHD" "sshd" || fail "could not stop the owned sshd"
WT_SSHD_PID=''
WT_SSHD_ID=''
stop_owned_process "$WT_GRANT_PID" "$WT_GRANT_ID" "$WT_CONTROLLER" "grant session authority" ||
    fail "could not stop the owned grant session authority"
WT_GRANT_PID=''
WT_GRANT_ID=''
stop_owned_process "$WT_FORBIDDEN_TARGET_PID" "$WT_FORBIDDEN_TARGET_ID" "$WT_PYTHON" "forbidden target" ||
    fail "could not stop the owned forbidden target"
WT_FORBIDDEN_TARGET_PID=''
WT_FORBIDDEN_TARGET_ID=''
stop_owned_process "$WT_TARGET_PID" "$WT_TARGET_ID" "$WT_PYTHON" "application target" ||
    fail "could not stop the owned application target"
WT_TARGET_PID=''
WT_TARGET_ID=''

pass "implemented live tunnel checks completed; independent agent and X11 request evidence remains unproven"
