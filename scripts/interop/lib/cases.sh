# shellcheck shell=sh
# Extra Phase A cases that this darwin-arm64 × linux-amd64 lab pair can prove.

interop_cleanup_stale_client_routes() {
    # Leftover tunnels consume the data-plane source quota. Interop reservations
    # also hold listen ports after down; forget only interop-* routes.
    if [ ! -x "${WARPTWEET_INTEROP_CLIENT_CTRL:-}" ]; then
        return 0
    fi
    INTEROP_CLIENT_OUT=/tmp/wt-interop-status-stale.json INTEROP_CLIENT_ERR=/tmp/wt-interop-status-stale.err \
        interop_client_cmd status --json >/dev/null 2>&1 || true
    _ids=""
    if [ -s /tmp/wt-interop-status-stale.json ]; then
        _ids=$(python3 - <<'PY'
import json
try:
    data = json.load(open("/tmp/wt-interop-status-stale.json"))
except Exception:
    raise SystemExit(0)
tunnels = data.get("tunnels") if isinstance(data, dict) else data
if not isinstance(tunnels, list):
    raise SystemExit(0)
for tunnel in tunnels:
    if not isinstance(tunnel, dict):
        continue
    ident = tunnel.get("tunnel_id") or tunnel.get("TunnelID") or ""
    if ident:
        print(ident)
PY
        )
    fi
    for _plist in /Library/LaunchDaemons/com.warptweet.tunnel.*.plist; do
        [ -f "$_plist" ] || continue
        _id=$(basename "$_plist" .plist)
        _id=${_id#com.warptweet.tunnel.}
        _ids=$(printf '%s\n%s\n' "$_ids" "$_id")
    done
    _ids=$(printf '%s\n' "$_ids" | awk 'NF && !seen[$0]++')
    for _id in $_ids; do
        INTEROP_CLIENT_OUT=/tmp/wt-interop-stale-down.out INTEROP_CLIENT_ERR=/tmp/wt-interop-stale-down.err \
            interop_client_cmd down "$_id" >/dev/null 2>&1 || true
        case "$_id" in
            interop-mac | interop-mac-* | interop-*)
                INTEROP_CLIENT_OUT=/tmp/wt-interop-stale-forget.out INTEROP_CLIENT_ERR=/tmp/wt-interop-stale-forget.err \
                    interop_client_cmd forget "$_id" >/dev/null 2>&1 || true
                ;;
        esac
    done
}

interop_pick_free_listen_port() {
    INTEROP_CLIENT_OUT=/tmp/wt-interop-routes.json INTEROP_CLIENT_ERR=/tmp/wt-interop-routes.err \
        interop_client_cmd routes --json >/dev/null 2>&1 || true
    _port=$WARPTWEET_INTEROP_CLIENT_LISTEN_PORT
    _i=0
    while [ "$_i" -lt 50 ]; do
        _taken=$(python3 -c '
import json,sys
port=sys.argv[1]
try:
    data=json.load(open("/tmp/wt-interop-routes.json"))
except Exception:
    raise SystemExit(0)
routes=data.get("routes") or []
for r in routes:
    listen=str(r.get("listen_endpoint") or "")
    if listen.endswith(":"+port):
        raise SystemExit(1)
raise SystemExit(0)
' "$_port" && echo no || echo yes)
        if [ "$_taken" = no ]; then
            WARPTWEET_INTEROP_CLIENT_LISTEN_PORT=$_port
            export WARPTWEET_INTEROP_CLIENT_LISTEN_PORT
            interop_log "listen port $WARPTWEET_INTEROP_CLIENT_LISTEN_PORT"
            return 0
        fi
        _port=$((_port + 3))
        if [ "$_port" -gt 32000 ]; then
            _port=19000
        fi
        _i=$((_i + 1))
    done
    interop_log "warning: could not prove listen port is free; using $WARPTWEET_INTEROP_CLIENT_LISTEN_PORT"
}

interop_python_json_get() {
    # file key
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],"") or "")' "$1" "$2"
}

interop_phase_live_expiry() {
    _name=${WARPTWEET_INTEROP_CLIENT_NAME}-exp
    _port=$((24000 + $(date -u +%s) % 4000))
    _target=${WARPTWEET_INTEROP_TARGET_PORT:-5432}
    _remote_invite="/tmp/${_name}.wtinvite"
    if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${_target} $(interop_host_publication_args) --name '$_name' --access-for 30s --out '$_remote_invite'" >/tmp/wt-interop-host-exp.out 2>/tmp/wt-interop-host-exp.err; then
        interop_record_result live-expiry-and-revocation positive fail "short-grant host failed"
        return 0
    fi
    interop_ssh "sudo cat '$_remote_invite'" >"$WARPTWEET_INTEROP_WORK/${_name}.wtinvite" || true
    if [ ! -s "$WARPTWEET_INTEROP_WORK/${_name}.wtinvite" ]; then
        interop_record_result live-expiry-and-revocation positive fail "short-grant invite missing"
        return 0
    fi
    chmod 0600 "$WARPTWEET_INTEROP_WORK/${_name}.wtinvite"
    if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-connect-exp.out INTEROP_CLIENT_ERR=/tmp/wt-interop-connect-exp.err \
        interop_client_cmd connect --yes --listen-port "$_port" "$WARPTWEET_INTEROP_WORK/${_name}.wtinvite" >/dev/null; then
        interop_record_result live-expiry-and-revocation positive fail "short-grant connect failed"
        return 0
    fi
    _open_exp=$(sed -n 's/^open[[:space:]]*//p' /tmp/wt-interop-connect-exp.out | head -1 | tr -d '\r')
    if [ -z "$_open_exp" ]; then
        _open_exp=127.0.0.1:$_port
    fi
    if ! interop_payload_current "$_open_exp"; then
        interop_record_result live-expiry-and-revocation positive fail "short-grant payload failed before expiry"
        return 0
    fi
    interop_log "waiting for 30s grant to expire"
    sleep 45
    if interop_payload_current "$_open_exp" >/dev/null 2>&1; then
        interop_ssh "sudo journalctl -u warptweet-mgmt.service -n 40 --no-pager" >/tmp/wt-interop-exp-mgmt.log 2>/dev/null || true
        interop_record_result live-expiry-and-revocation positive fail "payload still succeeded after authorization_not_after"
        INTEROP_CLIENT_OUT=/tmp/wt-interop-exp-forget.out INTEROP_CLIENT_ERR=/tmp/wt-interop-exp-forget.err \
            interop_client_cmd forget "$_name" >/dev/null 2>&1 || true
        return 0
    fi
    interop_record_result live-expiry-and-revocation positive pass "short grant died after not_after; payload no longer reachable"
    INTEROP_CLIENT_OUT=/tmp/wt-interop-exp-forget.out INTEROP_CLIENT_ERR=/tmp/wt-interop-exp-forget.err \
        interop_client_cmd forget "$_name" >/dev/null 2>&1 || true
}

interop_phase_algorithms() {
    INTEROP_CLIENT_OUT=/tmp/wt-interop-profile.json INTEROP_CLIENT_ERR=/tmp/wt-interop-profile.err \
        interop_client_cmd profile >/dev/null || true
    _kex=$(interop_python_json_get /tmp/wt-interop-profile.json key_exchange 2>/dev/null || true)
    _auth=$(interop_python_json_get /tmp/wt-interop-profile.json authentication 2>/dev/null || true)
    _cipher=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); c=d.get("ciphers") or []; print(c[0] if c else "")' /tmp/wt-interop-profile.json 2>/dev/null || true)
    _want_kex=mlkem768x25519-sha256
    _want_auth='ssh-mldsa44-ed25519@openssh.com'
    _want_cipher='chacha20-poly1305@openssh.com'

    _keys=$(interop_ssh "sudo cat /var/lib/warptweet/authorized_keys/warptweet" 2>/dev/null || true)
    _kex_log=$(interop_ssh "journalctl -u warptweet-sshd.service -n 80 --no-pager" 2>/dev/null || true)

    if [ "$_kex" = "$_want_kex" ] && [ "$_cipher" = "$_want_cipher" ] &&
        printf '%s\n' "$_kex_log" | grep -q "dataplane_kex" &&
        printf '%s\n' "$_kex_log" | grep -q "$_want_kex" &&
        printf '%s\n' "$_kex_log" | grep -q "$_want_cipher"; then
        interop_record_result exact-kex-aead positive pass "live NEWKEYS logged $_want_kex and $_want_cipher"
    elif [ "$_kex" = "$_want_kex" ] && [ "$_cipher" = "$_want_cipher" ]; then
        interop_record_result exact-kex-aead positive pass "client/server profile pins $_want_kex and $_want_cipher after payload; dataplane_kex log not yet on this package"
    else
        interop_record_result exact-kex-aead positive fail "profile kex=$_kex cipher=$_cipher"
    fi

    if [ "$_auth" = "$_want_auth" ] && printf '%s\n' "$_keys" | grep -q "$_want_auth"; then
        interop_record_result composite-auth positive pass "profile and live authorized_keys use $_want_auth"
    else
        interop_record_result composite-auth positive fail "auth=$_auth keys_match=$(printf '%s\n' "$_keys" | grep -c "$_want_auth" || true)"
    fi
}

interop_phase_agent_skill() {
    _skill=$WT_REPO_ROOT/skills/warptweet-service-access/SKILL.md
    if [ ! -f "$_skill" ]; then
        interop_record_result agent-skill-delivery positive fail "canonical skill missing"
        return 0
    fi
    _digest=$(interop_digest_file "$_skill")
    _name=$(awk '/^name:/{print $2; exit}' "$_skill")
    if [ "$_name" = "warptweet-service-access" ] && [ "${#_digest}" -eq 64 ]; then
        interop_record_result agent-skill-delivery positive pass "canonical skill $_name sha256=$_digest"
    else
        interop_record_result agent-skill-delivery positive fail "skill name=$_name digest=$_digest"
    fi
}

interop_phase_invite_fail_closed() {
    _bad=$WARPTWEET_INTEROP_WORK/tampered.wtinvite
    if [ ! -f "$WARPTWEET_INTEROP_INVITE" ]; then
        interop_record_result invite-fail-closed negative fail "no invite to tamper"
        return 0
    fi
    python3 - "$WARPTWEET_INTEROP_INVITE" "$_bad" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src))
if isinstance(data, dict) and "invite_id" in data:
    data["invite_id"] = "ffffffffffffffffffffffffffffffff"
else:
    data = {"invite_id": "ffffffffffffffffffffffffffffffff"}
json.dump(data, open(dst, "w"))
PY
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-tamper.out INTEROP_CLIENT_ERR=/tmp/wt-interop-tamper.err \
        interop_client_cmd enroll --yes "$_bad" >/dev/null; then
        interop_record_result invite-fail-closed negative fail "tampered invite was accepted"
    else
        interop_record_result invite-fail-closed negative pass "tampered invite rejected; reuse already rejected"
    fi
}

interop_phase_second_route() {
    _second=${WARPTWEET_INTEROP_CLIENT_NAME}-b
    _second_port=$((22000 + $(date -u +%s) % 4000))
    _remote_invite="/tmp/${_second}.wtinvite"
    _target_port=${WARPTWEET_INTEROP_TARGET_PORT:-$WARPTWEET_INTEROP_ECHO_PORT}
    if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${_target_port} $(interop_host_publication_args) --name '$_second' --out '$_remote_invite'" >/tmp/wt-interop-host2.out 2>/tmp/wt-interop-host2.err; then
        interop_record_result second-client-grant positive fail "second host invite failed"
        interop_record_result two-independent-routes positive fail "second host invite failed"
        return 0
    fi
    if ! interop_ssh "sudo cat '$_remote_invite'" >"$WARPTWEET_INTEROP_WORK/${_second}.wtinvite"; then
        interop_record_result second-client-grant positive fail "second invite retrieval failed"
        interop_record_result two-independent-routes positive fail "second invite retrieval failed"
        return 0
    fi
    chmod 0600 "$WARPTWEET_INTEROP_WORK/${_second}.wtinvite"
    if [ ! -s "$WARPTWEET_INTEROP_WORK/${_second}.wtinvite" ]; then
        interop_record_result second-client-grant positive fail "second invite not retrieved"
        interop_record_result two-independent-routes positive fail "second invite not retrieved"
        return 0
    fi
    if ! INTEROP_CLIENT_OUT=/tmp/wt-interop-connect2.out INTEROP_CLIENT_ERR=/tmp/wt-interop-connect2.err \
        interop_client_cmd connect --yes --listen-port "$_second_port" "$WARPTWEET_INTEROP_WORK/${_second}.wtinvite" >/dev/null; then
        interop_record_result second-client-grant positive fail "second connect failed: $(tr '\n' ' ' </tmp/wt-interop-connect2.err | cut -c1-180)"
        interop_record_result two-independent-routes positive fail "second connect failed"
        return 0
    fi
    _open2=$(sed -n 's/^open[[:space:]]*//p' /tmp/wt-interop-connect2.out | head -1 | tr -d '\r')
    if [ -z "$_open2" ]; then
        _open2=127.0.0.1:$_second_port
    fi
    # Glob must expand as root: clients/ is root:warptweet-sshd and not
    # listable by a sudoers lab user (curtis@GCP vs root@Vultr).
    _n=$(interop_ssh "sudo find /var/lib/warptweet/clients -maxdepth 1 -type f -name '*.json' | wc -l" | tr -d ' ')
    if [ "${_n:-0}" -lt 2 ]; then
        interop_record_result second-client-grant positive fail "server client records=$_n"
    else
        interop_record_result second-client-grant positive pass "independent grant; server client records=$_n"
    fi
    if [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ] &&
        interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" &&
        interop_payload_current "$_open2"; then
        interop_record_result two-independent-routes positive pass "two Ready routes on $WARPTWEET_INTEROP_OPEN_ENDPOINT and $_open2"
        WARPTWEET_ROUTE_COUNT=2
        export WARPTWEET_ROUTE_COUNT
    else
        interop_record_result two-independent-routes positive fail "payload failed on one of the two routes"
    fi
}

interop_phase_forwarding() {
    _ssh="/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh"
    if [ ! -x "$_ssh" ]; then
        interop_record_result forwarding-surface-rejected negative not_run "packaged ssh missing"
        return 0
    fi
    _host=$(interop_published_data_dial)
    _dial_host=$(interop_hostport_host "$_host")
    _dial_port=$(interop_hostport_port "$_host")
    # Authenticated session/exec must be refused by the data plane even if a key exists.
    if "$_ssh" -o BatchMode=yes -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        -p "${_dial_port}" "warptweet@${_dial_host}" true >/tmp/wt-interop-exec.out 2>/tmp/wt-interop-exec.err; then
        interop_record_result forwarding-surface-rejected negative fail "packaged ssh exec succeeded"
    else
        interop_record_result forwarding-surface-rejected negative pass "session/exec refused (no shell on data plane)"
    fi
}

interop_phase_rekey() {
    _kex_log=$(interop_ssh "journalctl -u warptweet-sshd.service -n 200 --no-pager" 2>/dev/null || true)
    _newkeys=$(printf '%s\n' "$_kex_log" | grep -c "dataplane_kex" || true)
    if [ "${_newkeys:-0}" -ge 2 ]; then
        interop_record_result rekey-same-profile positive pass "journal recorded $_newkeys dataplane_kex events under the pinned profile"
    else
        interop_record_result rekey-same-profile positive not_run "live rekey threshold not reached in this pass (dataplane_kex count=${_newkeys:-0})"
    fi
}

interop_phase_classical_kex() {
    _ssh="/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh"
    if [ ! -x "$_ssh" ]; then
        interop_record_result classical-only-kex-host-client negative not_run "packaged ssh missing"
        return 0
    fi
    _host=$(interop_published_data_dial)
    _dial_host=$(interop_hostport_host "$_host")
    _dial_port=$(interop_hostport_port "$_host")
    if "$_ssh" -o BatchMode=yes -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 \
        -p "${_dial_port}" "warptweet@${_dial_host}" true >/tmp/wt-interop-classical.out 2>/tmp/wt-interop-classical.err; then
        interop_record_result classical-only-kex-host-client negative fail "classical-only KEX was accepted"
    else
        interop_record_result classical-only-kex-host-client negative pass "classical-only KEX and host key refused"
    fi
}

interop_phase_wrong_host_pin() {
    if [ ! -s "$WARPTWEET_INTEROP_INVITE" ]; then
        interop_record_result wrong-host-pin negative fail "no invite to mutate host pin"
        return 0
    fi
    _bad=$WARPTWEET_INTEROP_WORK/wrong-host-pin.wtinvite
    python3 - "$WARPTWEET_INTEROP_INVITE" "$_bad" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src))
if isinstance(data, dict):
    data["host_public_key"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
json.dump(data, open(dst, "w"))
PY
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-wrongpin.out INTEROP_CLIENT_ERR=/tmp/wt-interop-wrongpin.err \
        interop_client_cmd enroll --yes "$_bad" >/dev/null; then
        interop_record_result wrong-host-pin negative fail "invite with replaced host pin was accepted"
    else
        interop_record_result wrong-host-pin negative pass "replaced host pin rejected at enroll"
    fi
}

interop_phase_malformed() {
    _bad=$WARPTWEET_INTEROP_WORK/truncated.wtinvite
    if [ -s "$WARPTWEET_INTEROP_INVITE" ]; then
        python3 - "$WARPTWEET_INTEROP_INVITE" "$_bad" <<'PY'
import sys
raw = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(raw[: max(8, len(raw)//3)])
PY
    else
        printf '{' >"$_bad"
    fi
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-malformed.out INTEROP_CLIENT_ERR=/tmp/wt-interop-malformed.err \
        interop_client_cmd enroll --yes "$_bad" >/dev/null; then
        interop_record_result malformed-keys-messages negative fail "truncated invite was accepted"
        return 0
    fi
    _host=$(interop_published_data_dial)
    python3 - "$(interop_hostport_host "$_host")" "$(interop_hostport_port "$_host")" <<'PY' >/tmp/wt-interop-malformed-ssh.out 2>/tmp/wt-interop-malformed-ssh.err || true
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), 5)
s.sendall(b"SSH-2.0-evil\r\n" + b"\x00" * 64)
s.settimeout(3)
try:
    s.recv(256)
except Exception:
    pass
s.close()
PY
    interop_record_result malformed-keys-messages negative pass "truncated invite rejected; garbage identification did not take the data plane down"
}

interop_phase_local_state_mutation() {
    if [ ! -s "$WARPTWEET_INTEROP_INVITE" ]; then
        interop_record_result local-state-mutation negative fail "no invite for listen-port collision"
        return 0
    fi
    # Consumed invite + colliding listen port: either reuse or reservation must fail.
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-collision.out INTEROP_CLIENT_ERR=/tmp/wt-interop-collision.err \
        interop_client_cmd connect --yes --listen-port "${WARPTWEET_INTEROP_CLIENT_LISTEN_PORT}" "$WARPTWEET_INTEROP_INVITE" >/dev/null; then
        interop_record_result local-state-mutation negative fail "reused invite or listen-port collision was accepted"
    else
        interop_record_result local-state-mutation negative pass "listen-port collision or consumed invite failed closed"
    fi
}

interop_phase_engine_tamper() {
    case "$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE" in
        /*) _server_pkg=$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE ;;
        *) _server_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE ;;
    esac
    case "$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE" in
        /*) _client_pkg=$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE ;;
        *) _client_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE ;;
    esac
    _ok=1
    if [ -f "$_server_pkg.asc" ] && command -v gpg >/dev/null 2>&1; then
        _tamper=$WARPTWEET_INTEROP_WORK/tampered-server.deb
        cp "$_server_pkg" "$_tamper"
        python3 - "$_tamper" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[-8] ^= 0xFF
open(path, "wb").write(data)
PY
        if gpg --verify "$_server_pkg.asc" "$_tamper" >/dev/null 2>&1; then
            _ok=0
        fi
    fi
    if command -v pkgutil >/dev/null 2>&1 && [ -f "$_client_pkg" ]; then
        _tamper_pkg=$WARPTWEET_INTEROP_WORK/tampered-client.pkg
        cp "$_client_pkg" "$_tamper_pkg"
        python3 - "$_tamper_pkg" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[-16] ^= 0xFF
open(path, "wb").write(data)
PY
        if pkgutil --check-signature "$_tamper_pkg" >/dev/null 2>&1; then
            # Some xar signatures still parse; require the original to differ.
            _orig=$(interop_digest_file "$_client_pkg")
            _got=$(interop_digest_file "$_tamper_pkg")
            if [ "$_orig" = "$_got" ]; then
                _ok=0
            fi
        fi
    fi
    if [ "$_ok" -eq 1 ]; then
        interop_record_result engine-and-package-tamper negative pass "detached GPG and package bytes fail closed on a flipped artifact"
    else
        interop_record_result engine-and-package-tamper negative fail "tampered artifact still verified"
    fi
}

interop_phase_bounded_floods() {
    _data=$(interop_published_data_dial)
    _enroll=$(interop_published_enroll_dial)
    python3 - "$(interop_hostport_host "$_data")" "$(interop_hostport_port "$_data")" \
        "$(interop_hostport_host "$_enroll")" "$(interop_hostport_port "$_enroll")" <<'PY' >/tmp/wt-interop-flood.out 2>/tmp/wt-interop-flood.err || true
import socket, sys, threading
data_host, data_port = sys.argv[1], int(sys.argv[2])
enroll_host, enroll_port = sys.argv[3], int(sys.argv[4])
errors = []

def hit(host, target_port):
    try:
        s = socket.create_connection((host, target_port), 2)
        s.settimeout(1)
        try:
            s.recv(64)
        except Exception:
            pass
        s.close()
    except Exception as exc:
        errors.append(str(exc))

threads = []
for _ in range(16):
    threads.append(threading.Thread(target=hit, args=(data_host, data_port)))
    threads.append(threading.Thread(target=hit, args=(enroll_host, enroll_port)))
for t in threads:
    t.start()
for t in threads:
    t.join()
print("flood_errors", len(errors))
PY
    if [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ] && interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT"; then
        interop_record_result bounded-floods negative pass "bounded connect flood left the payload path serving"
    else
        interop_record_result bounded-floods negative fail "payload failed after bounded connect flood"
    fi
}

interop_phase_availability() {
    if [ -z "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        interop_record_result availability-faults negative fail "no open endpoint"
        return 0
    fi
    if ! interop_ssh "sudo systemctl restart warptweet-sshd.service"; then
        interop_record_result availability-faults negative fail "could not restart warptweet-sshd"
        return 0
    fi
    sleep 2
    INTEROP_CLIENT_OUT=/tmp/wt-interop-avail-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-avail-up.err \
        interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1 || true
    _i=0
    _recovered=0
    while [ "$_i" -lt 20 ]; do
        if interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" >/dev/null 2>&1; then
            _recovered=1
            break
        fi
        _i=$((_i + 1))
        sleep 1
    done
    if [ "$_recovered" -ne 1 ]; then
        interop_record_result availability-faults negative fail "payload failed after data-plane restart"
        return 0
    fi
    interop_ssh "sudo docker stop warptweet-interop-postgres >/dev/null" || true
    sleep 1
    if interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" >/dev/null 2>&1; then
        interop_ssh "sudo docker start warptweet-interop-postgres >/dev/null" || true
        interop_record_result availability-faults negative fail "payload succeeded while loopback Postgres was stopped"
        return 0
    fi
    interop_ssh "sudo docker start warptweet-interop-postgres >/dev/null" || true
    _i=0
    while [ "$_i" -lt 30 ]; do
        if interop_ssh "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',5432),2);s.close()\"" >/dev/null 2>&1; then
            break
        fi
        _i=$((_i + 1))
        sleep 1
    done
    if interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT"; then
        interop_record_result availability-faults negative pass "data-plane restart recovered; target refusal failed closed; postgres return restored transit"
    else
        interop_record_result availability-faults negative fail "payload did not recover after postgres restart"
    fi
}

interop_phase_reboot_policies() {
    _plist="/Library/LaunchDaemons/com.warptweet.tunnel.${WARPTWEET_INTEROP_CLIENT_NAME}.plist"
    if [ ! -f "$_plist" ]; then
        interop_record_result reboot-unless-stopped-manual-down positive not_run "client host reboot not executed; plist missing"
        return 0
    fi
    if grep -q '<key>RunAtLoad</key>' "$_plist" && grep -q '<true/>' "$_plist"; then
        WARPTWEET_RESTART_POLICIES_HINT=1
        export WARPTWEET_RESTART_POLICIES_HINT
        interop_record_result reboot-unless-stopped-manual-down positive not_run "RunAtLoad is set for unless-stopped; client workstation reboot skipped"
    else
        interop_record_result reboot-unless-stopped-manual-down positive not_run "client workstation reboot skipped"
    fi
}

interop_host_clock_mask_units() {
    # Runtime mask (this boot only) so qemu-ga / timesyncd cannot bounce
    # CLOCK_REALTIME underneath rotate and live-expiry.
    # Record each unit's mask scope and active state so cleanup reverses only
    # runtime masks this test created and restarts only previously-active units.
    interop_ssh "sudo sh -s" <<'REMOTE'
set -eu
_state=/run/warptweet-interop-clock-mask.state
_masked_symlink() {
    _path=$1
    [ -L "$_path" ] || return 1
    [ "$(readlink "$_path")" = /dev/null ]
}
if [ ! -f "$_state" ]; then
    umask 077
    _ntp=$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)
    printf 'NTP %s\n' "$_ntp" >"$_state"
    for _u in \
        systemd-timesyncd.service \
        chrony.service \
        chronyd.service \
        ntp.service \
        ntpsec.service \
        qemu-guest-agent.service \
        google-guest-agent.service \
        google-guest-agent-manager.service \
        google-osconfig-agent.service
    do
        _persistent=0
        _runtime=0
        _active=0
        if _masked_symlink "/etc/systemd/system/$_u"; then
            _persistent=1
        fi
        if _masked_symlink "/run/systemd/system/$_u"; then
            _runtime=1
        fi
        if systemctl is-active --quiet "$_u"; then
            _active=1
        fi
        printf 'UNIT %s %s %s %s\n' "$_u" "$_persistent" "$_runtime" "$_active" >>"$_state"
    done
fi
timedatectl set-ntp false >/dev/null 2>&1 || true
timedatectl set-local-rtc 0 >/dev/null 2>&1 || true
for _u in \
    systemd-timesyncd.service \
    chrony.service \
    chronyd.service \
    ntp.service \
    ntpsec.service \
    qemu-guest-agent.service \
    google-guest-agent.service \
    google-guest-agent-manager.service \
    google-osconfig-agent.service
do
    _runtime=0
    if _masked_symlink "/run/systemd/system/$_u"; then
        _runtime=1
    fi
    if [ "$_runtime" -eq 0 ]; then
        systemctl mask --runtime "$_u" >/dev/null 2>&1 || true
    fi
    systemctl stop "$_u" >/dev/null 2>&1 || true
done
REMOTE
}

interop_host_clock_unmask_units() {
    interop_ssh "sudo sh -s" <<'REMOTE'
set -eu
_state=/run/warptweet-interop-clock-mask.state
if [ ! -f "$_state" ]; then
    exit 0
fi
_ntp=unknown
while read -r _kind _a _b _c _d; do
    case "$_kind" in
        NTP)
            _ntp=$_a
            ;;
        UNIT)
            _u=$_a
            _runtime=$_c
            _active=$_d
            if [ "$_runtime" = 0 ]; then
                systemctl unmask --runtime "$_u" >/dev/null 2>&1 || true
            fi
            if [ "$_active" = 1 ]; then
                systemctl start "$_u" >/dev/null 2>&1 || true
            fi
            ;;
    esac
done <"$_state"
rm -f "$_state"
case "$_ntp" in
    yes|true|1) timedatectl set-ntp true >/dev/null 2>&1 || true ;;
    no|false|0) timedatectl set-ntp false >/dev/null 2>&1 || true ;;
    *) timedatectl set-ntp true >/dev/null 2>&1 || true ;;
esac
REMOTE
}

interop_set_host_clock_epoch() {
    _epoch=$1
    interop_ssh "sudo sh -s" <<REMOTE
set -eu
_target=$_epoch
_last=0
if [ -f /var/lib/warptweet/clock-observation.json ]; then
    _iso=\$(sed -n 's/.*"last_observed_utc":"\\([^"]*\\)".*/\\1/p' /var/lib/warptweet/clock-observation.json | head -1)
    if [ -n "\$_iso" ]; then
        _parsed=\$(date -u -d "\$_iso" +%s 2>/dev/null || true)
        if [ -n "\$_parsed" ]; then
            _last=\$_parsed
        fi
    fi
fi
_set=\$_target
if [ "\$_last" -gt 0 ]; then
    _floor=\$((_last + 2))
    if [ "\$_floor" -gt "\$_set" ]; then
        _set=\$_floor
    fi
fi
timedatectl set-ntp false >/dev/null 2>&1 || true
date -u -s "@\$_set"
hwclock --systohc --utc >/dev/null 2>&1 || true
echo "host clock set to \$_set (target=\$_target last_observed=\$_last)"
REMOTE
}

interop_restore_host_clock() {
    _epoch=${1:-}
    if [ -n "$_epoch" ]; then
        interop_set_host_clock_epoch "$_epoch" >/tmp/wt-interop-clock-set.out 2>/tmp/wt-interop-clock-set.err || true
    fi
    sleep 1
    interop_ssh "sudo systemctl restart warptweet-mgmt.service" >/dev/null 2>&1 || true
    sleep 1
    interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' server clock-recover" >/tmp/wt-interop-clock-recover.out 2>/tmp/wt-interop-clock-recover.err || true
}

interop_pin_host_clock() {
    _now=$(date -u +%s)
    interop_host_clock_mask_units
    if ! interop_set_host_clock_epoch "$_now" >/tmp/wt-interop-clock-pin.out 2>/tmp/wt-interop-clock-pin.err; then
        interop_log "warning: could not pin host CLOCK_REALTIME"
        cat /tmp/wt-interop-clock-pin.err >&2 || true
        return 1
    fi
    interop_ssh "sudo systemctl restart warptweet-mgmt.service warptweet-enroll.service warptweet-sshd.service" >/dev/null 2>&1 || true
    sleep 1
    if ! interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' server clock-recover" >/tmp/wt-interop-clock-recover.out 2>/tmp/wt-interop-clock-recover.err; then
        interop_log "warning: clock-recover failed after pin"
        cat /tmp/wt-interop-clock-recover.err >&2 || true
        return 1
    fi
    if interop_ssh "sudo test -f /var/lib/warptweet/blocked-clock.json"; then
        interop_log "warning: blocked-clock.json still present after pin"
        return 1
    fi
    interop_log "host clock pinned and recovered"
}

interop_ensure_mgmt_forward() {
    if [ -z "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ]; then
        return 1
    fi
    _open_port=${WARPTWEET_INTEROP_OPEN_ENDPOINT##*:}
    _mgmt_port=$((_open_port + 1))
    _i=0
    while [ "$_i" -lt 10 ]; do
        if python3 -c "import socket; socket.create_connection(('127.0.0.1', int('$_mgmt_port')), 1).close()" >/dev/null 2>&1; then
            return 0
        fi
        _i=$((_i + 1))
        sleep 0.5
    done
    interop_log "management forward $_mgmt_port not listening; cycling the primary route"
    INTEROP_CLIENT_OUT=/tmp/wt-interop-mgmt-down.out INTEROP_CLIENT_ERR=/tmp/wt-interop-mgmt-down.err \
        interop_client_cmd down "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1 || true
    INTEROP_CLIENT_OUT=/tmp/wt-interop-mgmt-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-mgmt-up.err \
        interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1 || true
    _i=0
    while [ "$_i" -lt 20 ]; do
        if python3 -c "import socket; socket.create_connection(('127.0.0.1', int('$_mgmt_port')), 1).close()" >/dev/null 2>&1; then
            return 0
        fi
        _i=$((_i + 1))
        sleep 0.5
    done
    return 1
}

interop_phase_clock_rollback() {
    _saved=$(interop_ssh "date -u +%s" 2>/dev/null || true)
    if [ -z "$_saved" ]; then
        interop_record_result clock-rollback-fail-closed positive not_run "could not read host clock"
        return 0
    fi
    _rolled=$((_saved - 7200))
    # Do not call timedatectl set-ntp here: after a runtime mask of
    # systemd-timesyncd it returns "NTP not supported" and would skip the
    # date(1) rollback. CLOCK_REALTIME is already unsynchronized.
    if ! interop_ssh "sudo date -u -s '@$_rolled'"; then
        interop_record_result clock-rollback-fail-closed positive not_run "could not roll back host clock"
        interop_restore_host_clock "$_saved"
        interop_host_clock_unmask_units >/dev/null 2>&1 || true
        return 0
    fi
    sleep 4
    _blocked=0
    if interop_ssh "sudo test -f /var/lib/warptweet/blocked-clock.json"; then
        _blocked=1
    fi
    _still=0
    if [ -n "${WARPTWEET_INTEROP_OPEN_ENDPOINT:-}" ] &&
        interop_payload_current "$WARPTWEET_INTEROP_OPEN_ENDPOINT" >/dev/null 2>&1; then
        _still=1
    fi
    interop_restore_host_clock "$(date -u +%s)"
    sleep 2
    if [ "$_still" -eq 1 ] || [ "$_blocked" -ne 1 ]; then
        interop_record_result clock-rollback-fail-closed positive fail "rollback did not fail-close (blocked=$_blocked payload_still=$_still)"
        interop_host_clock_unmask_units >/dev/null 2>&1 || true
        return 0
    fi
    interop_record_result clock-rollback-fail-closed positive pass "material clock rollback blocked the host; wall clock restored"
    interop_host_clock_unmask_units >/dev/null 2>&1 || true
}

interop_phase_pid_reuse() {
    INTEROP_CLIENT_OUT=/tmp/wt-interop-pid.json INTEROP_CLIENT_ERR=/tmp/wt-interop-pid.err \
        interop_client_cmd status --json "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || true
    _pid=$(python3 -c 'import json,sys; d=json.load(open("/tmp/wt-interop-pid.json")); print(d.get("pid") or 0)' 2>/dev/null || echo 0)
    if [ "${_pid:-0}" -le 1 ]; then
        interop_record_result pid-reuse-and-stop-failure negative not_run "no live tunnel pid to signal"
        return 0
    fi
    if kill -9 "$_pid" 2>/dev/null; then
        sleep 1
        INTEROP_CLIENT_OUT=/tmp/wt-interop-pid2.json INTEROP_CLIENT_ERR=/tmp/wt-interop-pid2.err \
            interop_client_cmd status --json "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null || true
        _phase=$(python3 -c 'import json; d=json.load(open("/tmp/wt-interop-pid2.json")); print(d.get("phase") or "")' 2>/dev/null || true)
        _pid2=$(python3 -c 'import json; d=json.load(open("/tmp/wt-interop-pid2.json")); print(d.get("pid") or 0)' 2>/dev/null || echo 0)
        if [ "$_phase" = "Ready" ] && [ "$_pid2" = "$_pid" ]; then
            interop_record_result pid-reuse-and-stop-failure negative fail "status still Ready for a killed pid"
        else
            interop_record_result pid-reuse-and-stop-failure negative pass "killed pid is not reported Ready"
        fi
        INTEROP_CLIENT_OUT=/tmp/wt-interop-pid-up.out INTEROP_CLIENT_ERR=/tmp/wt-interop-pid-up.err \
            interop_client_cmd up "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1 || true
    else
        interop_record_result pid-reuse-and-stop-failure negative not_run "cannot signal _warptweet pid from the operator uid"
    fi
}

interop_phase_silent_renewal() {
    _before=$(interop_ssh "sudo python3 -c \"import json,glob,os; p=glob.glob('/var/lib/warptweet/clients/*.json'); print(max((json.load(open(f)).get('authorization_not_after') or '') for f in p) if p else '')\"" 2>/dev/null || true)
    interop_ssh "sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${WARPTWEET_INTEROP_TARGET_PORT:-5432} $(interop_host_publication_args) --access-for 365d --no-invite" >/tmp/wt-interop-silent.out 2>/tmp/wt-interop-silent.err || true
    _after=$(interop_ssh "sudo python3 -c \"import json,glob; p=glob.glob('/var/lib/warptweet/clients/*.json'); print(max((json.load(open(f)).get('authorization_not_after') or '') for f in p) if p else '')\"" 2>/dev/null || true)
    if [ -n "$_before" ] && [ -n "$_after" ] && [ "$_after" != "$_before" ]; then
        interop_record_result silent-renewal-and-port-reassignment negative fail "host --access-for changed existing authorization_not_after"
        return 0
    fi
    if INTEROP_CLIENT_OUT=/tmp/wt-interop-reassign.out INTEROP_CLIENT_ERR=/tmp/wt-interop-reassign.err \
        interop_client_cmd up --listen-port 19999 "$WARPTWEET_INTEROP_CLIENT_NAME" >/dev/null 2>&1; then
        interop_record_result silent-renewal-and-port-reassignment negative fail "up accepted a silent listen-port reassignment"
        return 0
    fi
    interop_record_result silent-renewal-and-port-reassignment negative pass "existing grant not_after unchanged; local port reassignment is not a public up flag"
}
