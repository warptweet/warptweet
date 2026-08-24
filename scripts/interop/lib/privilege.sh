# shellcheck shell=sh
# Live package UID/capability/host-sign isolation evidence (WT-SR-007).

interop_collect_privilege_evidence() {
    _out=${WARPTWEET_INTEROP_WORK:-/tmp}/privilege-evidence.txt
    _err=${WARPTWEET_INTEROP_WORK:-/tmp}/privilege-evidence.err
    _probe=${WARPTWEET_INTEROP_ROOT:-.}/lib/privilege-probe.sh
    [ -f "$_probe" ] || interop_die "missing privilege probe $_probe"
    : >"$_out"
    : >"$_err"

    interop_scp_to "$_probe" /tmp/warptweet-privilege-probe.sh
    # Probe inspects root-owned host keys and another uid's /proc/fd.
    # Must run as root: a sudoers lab user (not root@VPS) cannot even stat the key.
    if interop_ssh "sudo sh /tmp/warptweet-privilege-probe.sh" >"$_out" 2>"$_err" &&
        grep -q '^privilege PASS$' "$_out"; then
        cat "$_out"
        interop_log "privilege evidence written to $_out"
        return 0
    fi
    cat "$_out" "$_err" >&2 || true
    interop_log "privilege evidence failed; see $_out and $_err"
    return 1
}
