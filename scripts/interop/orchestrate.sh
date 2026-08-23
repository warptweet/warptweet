#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Phase A dual-host interop orchestrator.
# - Local Mac client (this machine)
# - Remote Linux server over ssh-agent
# - Install pinned packages from artifacts (Option B)
# - Deterministic echo fixture on server loopback
# - host → invite → connect → payload
#
# This produces a release-evidence JSON. Phase A almost always leaves some
# checklist ids as not_run; that is intentional until the full WP8 matrix lands.

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WARPTWEET_INTEROP_ROOT=$WT_SCRIPT_DIRECTORY
WT_REPO_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/../.." && pwd)

# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/common.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/ssh.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/package.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/fixture.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/evidence.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/privilege.sh"
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/cases.sh"

usage() {
    cat <<'EOF'
usage: orchestrate.sh [--config path.env]

Environment: see scripts/interop/config.example.env

Prerequisites:
  - ssh-agent has the remote key unlocked
  - artifact files present under WARPTWEET_INTEROP_ARTIFACTS
  - sudo on remote for package install + fixture
  - sudo on local Mac for .pkg install
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)
            export WARPTWEET_INTEROP_CONFIG=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 64
            ;;
    esac
done

export WARPTWEET_INTEROP_ROOT WT_REPO_ROOT
interop_load_config
interop_require_cmd ssh
interop_require_cmd scp
interop_require_cmd python3
interop_require_cmd sudo

interop_log "work dir $WARPTWEET_INTEROP_WORK"
interop_ssh_check
interop_cleanup_stale_client_routes

# --- Install pinned packages ---
if interop_phase_install_packages; then
    :
else
    interop_emit_evidence || true
    interop_die "package install phase failed"
fi

# --- Server preflight (best-effort doctor-server) ---
if interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' doctor-server --config /etc/warptweet/server.wt" >/tmp/wt-interop-doctor-server.out 2>/tmp/wt-interop-doctor-server.err; then
    interop_record_result engine-identity-trust-preflight positive pass "doctor-server preflight_ready (or accepted)"
else
    # host may create server.wt; try after host if this fails.
    interop_log "doctor-server before host failed (may be ok pre-init); will retry after host"
    _NEED_DOCTOR_RETRY=1
fi

# --- Echo fixture ---
interop_ensure_echo_fixture "$WARPTWEET_INTEROP_ECHO_PORT"

# --- Host + invite on remote ---
_remote_invite="/tmp/${WARPTWEET_INTEROP_CLIENT_NAME}.wtinvite"
interop_ssh "sudo rm -f '$_remote_invite'"

# `host` is the sole public bootstrap path. It must establish both listeners
# before reporting the invite.
if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${WARPTWEET_INTEROP_ECHO_PORT} --listen '${WARPTWEET_INTEROP_SERVER_LISTEN}' --name '${WARPTWEET_INTEROP_CLIENT_NAME}' --out '$_remote_invite'" >/tmp/wt-interop-host.out 2>/tmp/wt-interop-host.err; then
    interop_record_result invite-enroll-single-use positive fail "warptweet host failed: $(tr '\n' ' ' </tmp/wt-interop-host.err | cut -c1-200)"
    interop_emit_evidence || true
    interop_die "host failed"
fi
interop_log "host ready"

# Always pull the invite minted this run (do not reuse a leftover local file).
if ! interop_ssh "sudo cat '$_remote_invite'" >"$WARPTWEET_INTEROP_INVITE"; then
    interop_record_result invite-enroll-single-use positive fail "invite retrieval failed"
    interop_emit_evidence || true
    interop_die "invite retrieval failed"
fi
if [ ! -s "$WARPTWEET_INTEROP_INVITE" ]; then
    interop_record_result invite-enroll-single-use positive fail "invite file not retrieved"
    interop_emit_evidence || true
    interop_die "invite missing locally"
fi
chmod 0600 "$WARPTWEET_INTEROP_INVITE"
interop_log "invite at $WARPTWEET_INTEROP_INVITE"

# Re-read the two readiness boundaries that `host` has established.
_listen_port=${WARPTWEET_INTEROP_SERVER_LISTEN##*:}
if ! interop_ssh "ss -lntp 2>/dev/null | grep -q ':$_listen_port' || netstat -lntp 2>/dev/null | grep -q ':$_listen_port'"; then
    interop_record_result engine-identity-trust-preflight positive fail "host reported ready without SSH listener"
    interop_emit_evidence || true
    interop_die "SSH listener missing after host"
fi
if ! interop_ssh "ss -lntp 2>/dev/null | grep -q ':29722' || netstat -lntp 2>/dev/null | grep -q ':29722'"; then
    interop_record_result invite-enroll-single-use positive fail "host reported ready without enrollment listener"
    interop_emit_evidence || true
    interop_die "enrollment listener missing after host"
fi
if interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' doctor-server --config /etc/warptweet/server.wt" >/tmp/wt-interop-doctor-server2.out 2>/tmp/wt-interop-doctor-server2.err; then
    interop_record_result engine-identity-trust-preflight positive pass "doctor-server after host"
else
    interop_record_result engine-identity-trust-preflight positive fail "doctor-server failed after host"
    interop_emit_evidence || true
    interop_die "doctor-server failed after host"
fi

if interop_collect_privilege_evidence; then
    interop_log "live UID/capability/host-sign isolation matched the unit contract"
else
    interop_emit_evidence || true
    interop_die "live UID/capability/host-sign isolation failed"
fi

# --- Connect on local Mac ---
interop_assert_package_ctrl "$WARPTWEET_INTEROP_CLIENT_CTRL" "client"
# Flags before positionals: Go flag.Parse stops at the first positional.
if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-connect.out INTEROP_CLIENT_ERR=/tmp/wt-interop-connect.err \
    interop_client_cmd connect --yes --listen-port "${WARPTWEET_INTEROP_CLIENT_LISTEN_PORT:-18433}" "$WARPTWEET_INTEROP_INVITE" >/dev/null; then
    interop_record_result invite-enroll-single-use positive fail "connect failed: $(tr '\n' ' ' </tmp/wt-interop-connect.err | cut -c1-200)"
    interop_emit_evidence || true
    interop_die "connect failed"
fi
# Single-use: second enroll/connect with same invite must fail.
if INTEROP_CLIENT_OUT=/tmp/wt-interop-reuse.out INTEROP_CLIENT_ERR=/tmp/wt-interop-reuse.err \
    interop_client_cmd enroll --yes "$WARPTWEET_INTEROP_INVITE" >/dev/null; then
    interop_record_result invite-enroll-single-use positive fail "invite reuse succeeded"
else
    interop_record_result invite-enroll-single-use positive pass "connect ok; invite reuse rejected"
fi

# Parse local open endpoint from connect output.
_open=$(sed -n 's/^open[[:space:]]*//p' /tmp/wt-interop-connect.out | head -1 | tr -d '\r')
if [ -z "$_open" ]; then
    INTEROP_CLIENT_OUT=/tmp/wt-interop-status.json INTEROP_CLIENT_ERR=/tmp/wt-interop-status.err \
        interop_client_cmd status --json "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || true
    _open=$(python3 -c "import sys,json; d=json.load(open('/tmp/wt-interop-status.json')); print(d.get('listen_endpoint') or d.get('ListenEndpoint') or '')" 2>/dev/null || true)
fi
if [ -z "$_open" ]; then
    interop_record_result deterministic-target-payload positive fail "could not determine local listen endpoint"
    interop_emit_evidence || true
    interop_die "no local open endpoint"
fi
interop_log "local open $_open"
WARPTWEET_INTEROP_OPEN_ENDPOINT=$_open
export WARPTWEET_INTEROP_OPEN_ENDPOINT

# Best-effort readiness signal: status phase Ready or payload success.
if INTEROP_CLIENT_OUT=/tmp/wt-interop-status.json INTEROP_CLIENT_ERR=/tmp/wt-interop-status.err \
    interop_client_cmd status --json "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null; then
    if grep -q 'Ready' /tmp/wt-interop-status.json 2>/dev/null; then
        interop_record_result pid-bound-readiness positive pass "status reports Ready"
    else
        interop_record_result pid-bound-readiness positive not_run "status did not clearly report Ready; payload may still prove transit"
    fi
else
    interop_record_result pid-bound-readiness positive not_run "status failed"
fi

# --- Deterministic payload ---
if interop_payload_through_local "$_open" "warptweet-interop-payload-v1"; then
    interop_record_result deterministic-target-payload positive pass "echo payload matched through loopback"
else
    interop_record_result deterministic-target-payload positive fail "echo payload mismatch or connection failed"
fi

interop_phase_algorithms
interop_phase_agent_skill
interop_phase_invite_fail_closed
interop_phase_second_route
interop_phase_forwarding

# --- Optional lifecycle ---
if [ "${WARPTWEET_INTEROP_RUN_LIFECYCLE}" = "1" ]; then
    _life_ok=1
    _life_detail=""
    # Rotate and revoke use the live grant path. Do not down first.
    if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-rotate.out INTEROP_CLIENT_ERR=/tmp/wt-interop-rotate.err \
        interop_client_cmd rotate "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null; then
        _life_ok=0
        _life_detail="rotate: $(tr '\n' ' ' </tmp/wt-interop-rotate.err | cut -c1-160)"
    fi
    if [ "$_life_ok" -eq 1 ] && [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        if ! interop_payload_through_local "$WARPTWEET_INTEROP_OPEN_ENDPOINT" "warptweet-interop-payload-v1"; then
            _life_ok=0
            _life_detail="payload after rotate failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        INTEROP_CLIENT_OUT=/tmp/wt-interop-down.out INTEROP_CLIENT_ERR=/tmp/wt-interop-down.err \
            interop_client_cmd down "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || _life_ok=0
        if [ "$_life_ok" -ne 1 ]; then
            _life_detail="down failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        INTEROP_CLIENT_OUT=/tmp/wt-interop-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-up.err \
            interop_client_cmd up --once "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || _life_ok=0
        if [ "$_life_ok" -ne 1 ]; then
            _life_detail="up failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ] && [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        if ! interop_payload_through_local "$WARPTWEET_INTEROP_OPEN_ENDPOINT" "warptweet-interop-payload-v1"; then
            _life_ok=0
            _life_detail="payload after up failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-revoke.out INTEROP_CLIENT_ERR=/tmp/wt-interop-revoke.err \
            interop_client_cmd revoke "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null; then
            _life_ok=0
            _life_detail="revoke: $(tr '\n' ' ' </tmp/wt-interop-revoke.err | cut -c1-160)"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        interop_record_result stop-restart-rotate-revoke-upgrade positive pass "rotate, payload, down, up, payload, revoke (upgrade not in this pass)"
    else
        interop_record_result stop-restart-rotate-revoke-upgrade positive fail "${_life_detail:-lifecycle command failed}"
    fi
fi

# interop_emit_evidence: 0=all pass, 1=pass+not_run only, 2=fail present
_ev=0
interop_emit_evidence || _ev=$?
if [ "$_ev" -eq 0 ]; then
    interop_log "Phase A complete: full checklist pass (unexpected for Phase A)"
    exit 0
fi
if [ "$_ev" -eq 2 ]; then
    interop_log "Phase A complete with failures: evidence=$WARPTWEET_INTEROP_EVIDENCE_OUTPUT"
    interop_log "invite=$WARPTWEET_INTEROP_INVITE work=$WARPTWEET_INTEROP_WORK"
    exit 1
fi
if [ "${WARPTWEET_INTEROP_LOCAL_DEV:-0}" = "1" ]; then
    interop_log "Phase A happy path passed; remaining WP8 cases are not_run (CTA stays dark)"
    interop_log "invite=$WARPTWEET_INTEROP_INVITE evidence=$WARPTWEET_INTEROP_EVIDENCE_OUTPUT work=$WARPTWEET_INTEROP_WORK"
    exit 0
fi
interop_log "Phase A incomplete: partial evidence is fail"
interop_log "invite=$WARPTWEET_INTEROP_INVITE evidence=$WARPTWEET_INTEROP_EVIDENCE_OUTPUT work=$WARPTWEET_INTEROP_WORK"
exit 1
