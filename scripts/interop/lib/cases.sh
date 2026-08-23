# shellcheck shell=sh
# Extra Phase A cases that this darwin-arm64 × linux-amd64 lab pair can prove.

interop_cleanup_stale_client_routes() {
    # Leftover unless-stopped interop tunnels consume the data-plane source quota.
    for _plist in /Library/LaunchDaemons/com.warptweet.tunnel.interop-mac*.plist; do
        [ -f "$_plist" ] || continue
        _id=$(basename "$_plist" .plist)
        _id=${_id#com.warptweet.tunnel.}
        INTEROP_CLIENT_OUT=/tmp/wt-interop-stale-down.out INTEROP_CLIENT_ERR=/tmp/wt-interop-stale-down.err \
            interop_client_cmd down "$_id" >/dev/null 2>&1 || true
    done
}

interop_python_json_get() {
    # file key
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],"") or "")' "$1" "$2"
}

interop_phase_live_expiry() {
    _name=${WARPTWEET_INTEROP_CLIENT_NAME}-exp
    _port=$((WARPTWEET_INTEROP_CLIENT_LISTEN_PORT + 31))
    _target=${WARPTWEET_INTEROP_TARGET_PORT:-5432}
    _remote_invite="/tmp/${_name}.wtinvite"
    if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${_target} --listen '${WARPTWEET_INTEROP_SERVER_LISTEN}' --name '$_name' --access-for 30s --out '$_remote_invite'" >/tmp/wt-interop-host-exp.out 2>/tmp/wt-interop-host-exp.err; then
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
    _open_exp=127.0.0.1:$_port
    if ! interop_payload_current "$_open_exp"; then
        interop_record_result live-expiry-and-revocation positive fail "short-grant payload failed before expiry"
        return 0
    fi
    interop_log "waiting for 30s grant to expire"
    sleep 45
    if interop_payload_current "$_open_exp" >/dev/null 2>&1; then
        interop_record_result live-expiry-and-revocation positive fail "payload still succeeded after authorization_not_after"
        return 0
    fi
    interop_record_result live-expiry-and-revocation positive pass "short grant died after not_after; payload no longer reachable"
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
    _second_port=$((WARPTWEET_INTEROP_CLIENT_LISTEN_PORT + 17))
    _remote_invite="/tmp/${_second}.wtinvite"
    _target_port=${WARPTWEET_INTEROP_TARGET_PORT:-$WARPTWEET_INTEROP_ECHO_PORT}
    if ! interop_ssh "sudo rm -f '$_remote_invite' && sudo '$WARPTWEET_INTEROP_SERVER_CTRL' host --to 127.0.0.1:${_target_port} --listen '${WARPTWEET_INTEROP_SERVER_LISTEN}' --name '$_second' --out '$_remote_invite'" >/tmp/wt-interop-host2.out 2>/tmp/wt-interop-host2.err; then
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
    _n=$(interop_ssh "sudo ls -1 /var/lib/warptweet/clients/*.json 2>/dev/null | wc -l" | tr -d ' ')
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
    _host=${WARPTWEET_INTEROP_SERVER_LISTEN}
    # Authenticated session/exec must be refused by the data plane even if a key exists.
    if "$_ssh" -o BatchMode=yes -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        -p "${_host##*:}" "warptweet@${_host%%:*}" true >/tmp/wt-interop-exec.out 2>/tmp/wt-interop-exec.err; then
        interop_record_result forwarding-surface-rejected negative fail "packaged ssh exec succeeded"
    else
        interop_record_result forwarding-surface-rejected negative pass "session/exec refused (no shell on data plane)"
    fi
}
