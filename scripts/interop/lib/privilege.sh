# shellcheck shell=sh
# Live package UID/capability/host-sign isolation evidence (WT-SR-007).

interop_collect_privilege_evidence() {
    _out=${WARPTWEET_INTEROP_WORK:-/tmp}/privilege-evidence.txt
    _err=${WARPTWEET_INTEROP_WORK:-/tmp}/privilege-evidence.err
    : >"$_out"
    : >"$_err"

    # Copy the probe to a remote file. ssh stdin is not a safe script channel:
    # an empty `sh -s` exits 0 and looks like a pass.
    if ! interop_ssh "cat > /tmp/warptweet-privilege-probe.sh && sh /tmp/warptweet-privilege-probe.sh" >"$_out" 2>"$_err" <<'REMOTE'
set -eu
LC_ALL=C
export LC_ALL

fail() { echo "privilege FAIL: $*" >&2; exit 1; }
ok() { echo "privilege ok: $*"; }

SSHD_UNIT=warptweet-sshd.service
SIGN_UNIT=warptweet-hostsign.service
HOST_KEY=/var/lib/warptweet/ssh/ssh_host_mldsa44_ed25519_key
SIGN_SOCK=/run/warptweet/hostsign/sign.sock
WANT_UID=901
WANT_GID=901
# CAP_NET_BIND_SERVICE is bit 10 = 0x400.
WANT_CAP=0000000000000400

systemctl is-active --quiet "$SSHD_UNIT" || fail "$SSHD_UNIT is not active"
systemctl is-active --quiet "$SIGN_UNIT" || fail "$SIGN_UNIT is not active"

sshd_user=$(systemctl show -p User --value "$SSHD_UNIT")
sshd_group=$(systemctl show -p Group --value "$SSHD_UNIT")
sshd_capb=$(systemctl show -p CapabilityBoundingSet --value "$SSHD_UNIT" | tr '[:upper:]' '[:lower:]')
sshd_capa=$(systemctl show -p AmbientCapabilities --value "$SSHD_UNIT" | tr '[:upper:]' '[:lower:]')
sshd_exec=$(systemctl show -p ExecStart --value "$SSHD_UNIT")
[ "$sshd_user" = "warptweet-sshd" ] || fail "sshd User=$sshd_user want warptweet-sshd"
[ "$sshd_group" = "warptweet-sshd" ] || fail "sshd Group=$sshd_group want warptweet-sshd"
[ "$sshd_capb" = "cap_net_bind_service" ] || fail "sshd CapabilityBoundingSet=$sshd_capb"
[ "$sshd_capa" = "cap_net_bind_service" ] || fail "sshd AmbientCapabilities=$sshd_capa"
case "$sshd_exec" in
    *"warptweet server data-plane"*) ;;
    *) fail "sshd ExecStart=$sshd_exec" ;;
esac
ok "sshd unit User=$sshd_user Group=$sshd_group caps=$sshd_capb"

sign_user=$(systemctl show -p User --value "$SIGN_UNIT")
sign_group=$(systemctl show -p Group --value "$SIGN_UNIT")
sign_capb=$(systemctl show -p CapabilityBoundingSet --value "$SIGN_UNIT")
sign_exec=$(systemctl show -p ExecStart --value "$SIGN_UNIT")
[ "$sign_user" = "root" ] || fail "hostsign User=$sign_user want root"
[ "$sign_group" = "warptweet-sshd" ] || fail "hostsign Group=$sign_group want warptweet-sshd"
case "$sign_capb" in
    '' | '~') ;;
    *) fail "hostsign CapabilityBoundingSet=$sign_capb want empty" ;;
esac
case "$sign_exec" in
    *"warptweet server host-sign"*) ;;
    *) fail "hostsign ExecStart=$sign_exec" ;;
esac
ok "hostsign unit User=$sign_user Group=$sign_group empty bounding set"

sshd_pid=$(systemctl show -p MainPID --value "$SSHD_UNIT")
sign_pid=$(systemctl show -p MainPID --value "$SIGN_UNIT")
[ "$sshd_pid" -gt 1 ] || fail "sshd MainPID=$sshd_pid"
[ "$sign_pid" -gt 1 ] || fail "hostsign MainPID=$sign_pid"

sshd_uid=$(awk '/^Uid:/{print $3}' "/proc/$sshd_pid/status")
sshd_gid=$(awk '/^Gid:/{print $3}' "/proc/$sshd_pid/status")
sshd_eff=$(awk '/^CapEff:/{print tolower($2)}' "/proc/$sshd_pid/status")
sshd_bnd=$(awk '/^CapBnd:/{print tolower($2)}' "/proc/$sshd_pid/status")
sshd_amb=$(awk '/^CapAmb:/{print tolower($2)}' "/proc/$sshd_pid/status")
[ "$sshd_uid" = "$WANT_UID" ] || fail "sshd euid=$sshd_uid want $WANT_UID"
[ "$sshd_gid" = "$WANT_GID" ] || fail "sshd egid=$sshd_gid want $WANT_GID"
[ "$sshd_eff" = "$WANT_CAP" ] || fail "sshd CapEff=$sshd_eff want $WANT_CAP"
[ "$sshd_bnd" = "$WANT_CAP" ] || fail "sshd CapBnd=$sshd_bnd want $WANT_CAP"
[ "$sshd_amb" = "$WANT_CAP" ] || fail "sshd CapAmb=$sshd_amb want $WANT_CAP"
ok "sshd pid=$sshd_pid euid=$sshd_uid egid=$sshd_gid CapEff=$sshd_eff"

sign_uid=$(awk '/^Uid:/{print $3}' "/proc/$sign_pid/status")
sign_gid=$(awk '/^Gid:/{print $3}' "/proc/$sign_pid/status")
[ "$sign_uid" = "0" ] || fail "hostsign euid=$sign_uid want 0"
[ "$sign_gid" = "$WANT_GID" ] || fail "hostsign egid=$sign_gid want $WANT_GID"
ok "hostsign pid=$sign_pid euid=$sign_uid egid=$sign_gid"

[ -f "$HOST_KEY" ] || fail "missing host key $HOST_KEY"
host_stat=$(stat -c '%u:%g:%a' "$HOST_KEY")
[ "$host_stat" = "0:0:600" ] || fail "host key ownership/mode $host_stat want 0:0:600"
if sudo -u warptweet-sshd test -r "$HOST_KEY"; then
    fail "warptweet-sshd can read host private key"
fi
ok "host key $host_stat not readable by warptweet-sshd"

sshd_has_key=0
for fd in /proc/"$sshd_pid"/fd/*; do
    [ -e "$fd" ] || continue
    dest=$(readlink "$fd" 2>/dev/null || true)
    case "$dest" in
        "$HOST_KEY" | "$HOST_KEY"*) sshd_has_key=1 ;;
    esac
done
[ "$sshd_has_key" -eq 0 ] || fail "data-plane process has host private key open"
ok "data-plane fds do not include host private key"

[ -S "$SIGN_SOCK" ] || fail "missing host-sign socket $SIGN_SOCK"
sock_stat=$(stat -c '%u:%g:%a' "$SIGN_SOCK")
[ "$sock_stat" = "0:901:660" ] || fail "host-sign socket $sock_stat want 0:901:660"
ok "host-sign socket $sock_stat"

sshd_cwd=$(readlink "/proc/$sshd_pid/cwd" 2>/dev/null || true)
echo "sshd cwd=$sshd_cwd cmdline=$(tr '\0' ' ' <"/proc/$sshd_pid/cmdline")"
echo "sign cmdline=$(tr '\0' ' ' <"/proc/$sign_pid/cmdline")"
echo "privilege PASS"
REMOTE
    then
        cat "$_out"
        interop_log "privilege evidence written to $_out"
        return 0
    fi
    cat "$_out" "$_err" >&2 || true
    interop_log "privilege evidence failed; see $_out and $_err"
    return 1
}
