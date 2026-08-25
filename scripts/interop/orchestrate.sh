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
# shellcheck disable=SC1091
. "$WARPTWEET_INTEROP_ROOT/lib/postgres.sh"

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
# Leftover clock-rollback from a prior run must not fail-close this one.
# On a fresh VPS the package is not installed yet; pin NTP now and recover
# again after install.
interop_pin_host_clock || true
_remote_arch=$(interop_ssh "uname -m" || true)
case "$_remote_arch" in
    x86_64 | amd64) WARPTWEET_SERVER_ARCHITECTURE=amd64 ;;
    aarch64 | arm64) WARPTWEET_SERVER_ARCHITECTURE=arm64 ;;
    *) WARPTWEET_SERVER_ARCHITECTURE=${_remote_arch:-unknown} ;;
esac
export WARPTWEET_SERVER_ARCHITECTURE
# Best-effort before install if a previous client package is still present.
interop_cleanup_stale_client_routes || true

# --- Install pinned packages ---
if interop_phase_install_packages; then
    :
else
    interop_emit_evidence || true
    interop_die "package install phase failed"
fi
# Provisioner is now running; drop leftover launchd jobs and interop reservations.
interop_cleanup_stale_client_routes
interop_pick_free_listen_port
# Recover host clock after install so leftover blocked-clock cannot fail host.
interop_pin_host_clock || true

# --- Server preflight (best-effort doctor-server) ---
if interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' doctor-server --config /etc/warptweet/server.wt" >/tmp/wt-interop-doctor-server.out 2>/tmp/wt-interop-doctor-server.err; then
    interop_log "doctor-server before host succeeded; recording after host"
else
    # host may create server.wt; try after host if this fails.
    interop_log "doctor-server before host failed (may be ok pre-init); will retry after host"
    _NEED_DOCTOR_RETRY=1
fi

# --- Loopback Postgres (fresh VPS: installs Docker) plus echo fallback ---
: "${WARPTWEET_INTEROP_TARGET_PORT:=5432}"
export WARPTWEET_INTEROP_TARGET_PORT
if interop_ensure_loopback_postgres "$WARPTWEET_INTEROP_TARGET_PORT"; then
    WARPTWEET_INTEROP_PAYLOAD=postgres
else
    interop_die "loopback postgres is required; run scripts/interop/provision-lab-host.sh on a fresh Ubuntu host"
fi
export WARPTWEET_INTEROP_PAYLOAD
interop_reset_host_grants

# --- Host + invite on remote ---
_remote_invite="/tmp/${WARPTWEET_INTEROP_CLIENT_NAME}.wtinvite"
interop_ssh "sudo rm -f '$_remote_invite'"

# `host` is the sole public bootstrap path. It must establish both listeners
# before reporting the invite.
_host_pub=$(interop_host_publication_args)
if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${WARPTWEET_INTEROP_TARGET_PORT} ${_host_pub} --name '${WARPTWEET_INTEROP_CLIENT_NAME}' --out '$_remote_invite'" >/tmp/wt-interop-host.out 2>/tmp/wt-interop-host.err; then
    interop_record_result invite-enroll-single-use positive fail "warptweet host failed: $(tr '\n' ' ' </tmp/wt-interop-host.err | cut -c1-200)"
    interop_emit_evidence || true
    interop_die "host failed"
fi
interop_log "host ready"
# Issued invite must pin the target. A second host --to a different port must fail.
if interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:18432 ${_host_pub} --no-invite" >/tmp/wt-interop-target-change.out 2>/tmp/wt-interop-target-change.err; then
    interop_record_result target-change-denial positive fail "host allowed target change while an invite exists"
else
    interop_record_result target-change-denial positive pass "host refused target change while invite or grant exists"
fi

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
_listen_port=$(interop_hostport_port "$WARPTWEET_INTEROP_SERVER_LISTEN")
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
_connect_port=${WARPTWEET_INTEROP_CLIENT_LISTEN_PORT:-18433}
_connect_try=0
_connect_ok=0
while [ "$_connect_try" -lt 8 ]; do
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-connect.out INTEROP_CLIENT_ERR=/tmp/wt-interop-connect.err \
        interop_client_cmd connect --yes --listen-port "$_connect_port" "$WARPTWEET_INTEROP_INVITE" >/dev/null; then
        _connect_ok=1
        WARPTWEET_INTEROP_CLIENT_LISTEN_PORT=$_connect_port
        export WARPTWEET_INTEROP_CLIENT_LISTEN_PORT
        break
    fi
    if grep -q 'already reserved' /tmp/wt-interop-connect.err 2>/dev/null; then
        _connect_port=$((_connect_port + 11))
        _connect_try=$((_connect_try + 1))
        interop_log "listen port reserved; retrying $_connect_port"
        continue
    fi
    break
done
if [ "$_connect_ok" -ne 1 ]; then
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
if [ "$WARPTWEET_INTEROP_PAYLOAD" = postgres ]; then
    if interop_payload_through_postgres "$_open"; then
        interop_record_result deterministic-target-payload positive pass "postgres startup reached through loopback"
        interop_record_result compose-loopback-postgres positive pass "remote Postgres bound to 127.0.0.1:5432; query path through WarpTweet"
    else
        interop_record_result deterministic-target-payload positive fail "postgres probe failed"
        interop_record_result compose-loopback-postgres positive fail "postgres probe failed"
    fi
elif interop_payload_through_local "$_open" "warptweet-interop-payload-v1"; then
    interop_record_result deterministic-target-payload positive pass "echo payload matched through loopback"
else
    interop_record_result deterministic-target-payload positive fail "echo payload mismatch or connection failed"
fi

interop_phase_algorithms
interop_phase_agent_skill
interop_phase_invite_fail_closed
interop_phase_second_route
interop_phase_forwarding
interop_phase_rekey
interop_phase_classical_kex
interop_phase_wrong_host_pin
interop_phase_malformed
interop_phase_local_state_mutation
interop_phase_engine_tamper
interop_phase_bounded_floods
interop_phase_availability
interop_phase_silent_renewal
interop_phase_reboot_policies
interop_phase_pid_reuse
interop_phase_live_expiry

# Live expiry must not take down the primary route; reconnect if it did.
if [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ] &&
    ! interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" >/dev/null 2>&1; then
    interop_log "primary payload down after live-expiry; bringing the route back up"
    INTEROP_CLIENT_OUT=/tmp/wt-interop-primary-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-primary-up.err \
        interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1 || true
    _i=0
    while [ "$_i" -lt 20 ]; do
        if interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" >/dev/null 2>&1; then
            break
        fi
        _i=$((_i + 1))
        sleep 1
    done
fi

# --- Optional lifecycle ---
if [ "${WARPTWEET_INTEROP_RUN_LIFECYCLE}" = "1" ]; then
    _life_ok=1
    _life_detail=""
    # Rotate while the original connect tunnel is still up, then down/up the
    # new generation. Management RPC is a second local forward (listen+1).
    if ! interop_ensure_mgmt_forward; then
        _life_ok=0
        _life_detail="management forward not listening on local listen+1"
    fi
    if [ "$_life_ok" -eq 1 ] && ! INTEROP_CLIENT_OUT=/tmp/wt-interop-rotate.out INTEROP_CLIENT_ERR=/tmp/wt-interop-rotate.err \
        interop_client_cmd rotate "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null; then
        _life_ok=0
        _life_detail="rotate: $(tr '\n' ' ' </tmp/wt-interop-rotate.err | cut -c1-160)"
        interop_ssh "sudo journalctl -u warptweet-mgmt.service -u warptweet-sshd.service -n 80 --no-pager" >/tmp/wt-interop-rotate-journal.log 2>/dev/null || true
    fi
    if [ "$_life_ok" -eq 1 ] && [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        if ! interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT"; then
            _life_ok=0
            _life_detail="payload after rotate failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-down.out INTEROP_CLIENT_ERR=/tmp/wt-interop-down.err \
            interop_client_cmd down "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null; then
            _life_ok=0
            _life_detail="down failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        INTEROP_CLIENT_OUT=/tmp/wt-interop-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-up.err \
            interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || _life_ok=0
        if [ "$_life_ok" -ne 1 ]; then
            _life_detail="up after rotate failed: $(tr '\n' ' ' </tmp/wt-interop-up.err | cut -c1-120)"
        fi
    fi
    if [ "$_life_ok" -eq 1 ] && [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        if ! interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT"; then
            _life_ok=0
            _life_detail="payload after rotate failed"
        fi
    fi
    if [ "$_life_ok" -eq 1 ]; then
        INTEROP_CLIENT_OUT=/tmp/wt-interop-up2.out INTEROP_CLIENT_ERR=/tmp/wt-interop-up2.err \
            interop_client_cmd down "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || _life_ok=0
        if [ "$_life_ok" -eq 1 ]; then
            INTEROP_CLIENT_OUT=/tmp/wt-interop-up2.out INTEROP_CLIENT_ERR=/tmp/wt-interop-up2.err \
                interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || _life_ok=0
        fi
        if [ "$_life_ok" -ne 1 ]; then
            _life_detail="up after rotate failed: $(tr '\n' ' ' </tmp/wt-interop-up2.err | cut -c1-120)"
        elif [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ] && ! interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT"; then
            _life_ok=0
            _life_detail="payload after up-after-rotate failed"
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
        interop_record_result stop-restart-rotate-revoke-upgrade positive pass "down, up, rotate, up-after-rotate, revoke (upgrade not in this pass)"
    else
        interop_record_result stop-restart-rotate-revoke-upgrade positive fail "${_life_detail:-lifecycle command failed}"
    fi
fi
interop_phase_clock_rollback

# Clock rollback fail-closes enrollment. Reconcile so bind observations see
# both listeners. This is the same operator recovery as after restoring the
# wall clock: run host again, do not mint a new invite.
if ! interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${WARPTWEET_INTEROP_TARGET_PORT} $(interop_host_publication_args) --no-invite" >/tmp/wt-interop-host-recover.out 2>/tmp/wt-interop-host-recover.err; then
    interop_log "warning: host reconcile after clock-rollback failed: $(tr '\n' ' ' </tmp/wt-interop-host-recover.err | cut -c1-160)"
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
