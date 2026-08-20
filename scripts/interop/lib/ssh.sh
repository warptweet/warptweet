# shellcheck shell=sh
# Admin SSH via agent. Optional IdentityFile still unlocks through ssh-agent.
# Host identity must be pre-pinned (known_hosts file or host-key fingerprint).

interop_ssh_prepare_known_hosts() {
    if [ -n "${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS:-}" ]; then
        WARPTWEET_INTEROP_SSH_KNOWN_HOSTS_EFFECTIVE=$WARPTWEET_INTEROP_SSH_KNOWN_HOSTS
        return 0
    fi
    interop_require_cmd ssh-keyscan
    interop_require_cmd ssh-keygen
    _kh=${WARPTWEET_INTEROP_WORK:-${TMPDIR:-/tmp}}/interop-known_hosts
    : >"$_kh"
    _port=${WARPTWEET_INTEROP_SSH_PORT:-22}
    if ! ssh-keyscan -p "$_port" -T 5 "$WARPTWEET_INTEROP_SERVER_HOST" >"$_kh" 2>/dev/null; then
        interop_die "ssh-keyscan failed for $WARPTWEET_INTEROP_SERVER_HOST"
    fi
    if [ -n "${WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT:-}" ]; then
        _want=$(printf '%s' "$WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        _matched=0
        while IFS= read -r _line; do
            [ -n "$_line" ] || continue
            case "$_line" in
                \#*) continue ;;
            esac
            _fp=$(printf '%s\n' "$_line" | ssh-keygen -lf - 2>/dev/null | awk '{print tolower($2)}' | tr -d ' ')
            _fp_hash=${_fp#sha256:}
            _want_hash=${_want#sha256:}
            if [ "$_fp" = "$_want" ] || [ "$_fp_hash" = "$_want_hash" ]; then
                _matched=1
                break
            fi
        done <"$_kh"
        if [ "$_matched" -ne 1 ]; then
            interop_die "host key fingerprint mismatch for $WARPTWEET_INTEROP_SERVER_HOST (want $WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT)"
        fi
    else
        # Local-dev TOFU for this run only (StrictHostKeyChecking=yes against scanned file).
        if [ "${WARPTWEET_INTEROP_SSH_TRUST_ONCE:-0}" != "1" ] && [ "${WARPTWEET_INTEROP_LOCAL_DEV:-0}" != "1" ]; then
            interop_die "set WARPTWEET_INTEROP_SSH_KNOWN_HOSTS or WARPTWEET_INTEROP_SSH_HOST_KEY_FINGERPRINT"
        fi
        interop_log "warning: TOFU host key for $WARPTWEET_INTEROP_SERVER_HOST into $_kh (local-dev only)"
    fi
    WARPTWEET_INTEROP_SSH_KNOWN_HOSTS_EFFECTIVE=$_kh
    export WARPTWEET_INTEROP_SSH_KNOWN_HOSTS_EFFECTIVE
}

# Shared -o flags for ssh and scp (no port flag: ssh uses -p, scp uses -P).
interop_ssh_opts() {
    if [ -z "${WARPTWEET_INTEROP_SSH_KNOWN_HOSTS_EFFECTIVE:-}" ]; then
        interop_ssh_prepare_known_hosts
    fi
    _args="-o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$WARPTWEET_INTEROP_SSH_KNOWN_HOSTS_EFFECTIVE -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes"
    if [ -n "${WARPTWEET_INTEROP_SSH_IDENTITY:-}" ]; then
        _args="$_args -i $WARPTWEET_INTEROP_SSH_IDENTITY"
    fi
    # Prefer agent; do not pass passwords on the CLI.
    _args="$_args -o PreferredAuthentications=publickey"
    printf '%s' "$_args"
}

interop_ssh_base() {
    # ssh(1) port flag is -p
    printf '%s -p %s' "$(interop_ssh_opts)" "${WARPTWEET_INTEROP_SSH_PORT:-22}"
}

interop_scp_base() {
    # scp(1) port flag is -P ( -p means preserve times )
    printf '%s -P %s' "$(interop_ssh_opts)" "${WARPTWEET_INTEROP_SSH_PORT:-22}"
}

interop_ssh_target() {
    if [ -n "${WARPTWEET_INTEROP_SERVER_USER:-}" ]; then
        printf '%s@%s' "$WARPTWEET_INTEROP_SERVER_USER" "$WARPTWEET_INTEROP_SERVER_HOST"
    else
        printf '%s' "$WARPTWEET_INTEROP_SERVER_HOST"
    fi
}

interop_ssh() {
    # shellcheck disable=SC2046,SC2086
    ssh $(interop_ssh_base) "$(interop_ssh_target)" "$@"
}

interop_scp_from() {
    _remote_path=$1
    _local_path=$2
    # shellcheck disable=SC2046,SC2086
    scp $(interop_scp_base) "$(interop_ssh_target):$_remote_path" "$_local_path"
}

interop_scp_to() {
    _local_path=$1
    _remote_path=$2
    # shellcheck disable=SC2046,SC2086
    scp $(interop_scp_base) "$_local_path" "$(interop_ssh_target):$_remote_path"
}

interop_ssh_check() {
    interop_require_cmd ssh
    interop_require_cmd scp
    interop_ssh_prepare_known_hosts
    if ! interop_ssh "printf ok" >/dev/null 2>&1; then
        interop_die "ssh to $(interop_ssh_target) failed (unlock key into ssh-agent and retry)"
    fi
    interop_log "ssh ok -> $(interop_ssh_target)"
}
