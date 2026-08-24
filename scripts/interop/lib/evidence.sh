# shellcheck shell=sh
# Emit warptweet.release-evidence v3 JSON. Validate before write.

# Exit codes:
#   0 — every result is pass (full checklist complete)
#   1 — incomplete only (pass + expected not_run; no fail)
#   2 — at least one executed case has status fail, or Validate failed
interop_emit_evidence() {
    _finished=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    _schema=${WARPTWEET_EVIDENCE_SCHEMA_VERSION:-3}
    case "$_schema" in
        3) ;;
        *)
            interop_log "unsupported WARPTWEET_EVIDENCE_SCHEMA_VERSION=$_schema (v3 only)"
            return 2
            ;;
    esac
    _checklist_ids="pkg-signature-and-manifest engine-identity-trust-preflight invite-enroll-single-use composite-auth exact-kex-aead rekey-same-profile pid-bound-readiness deterministic-target-payload stop-restart-rotate-revoke-upgrade classical-only-kex-host-client wrong-host-pin malformed-keys-messages invite-fail-closed forwarding-surface-rejected local-state-mutation engine-and-package-tamper bounded-floods availability-faults second-client-grant two-independent-routes reboot-unless-stopped-manual-down live-expiry-and-revocation clock-rollback-fail-closed target-change-denial compose-loopback-postgres agent-skill-delivery pid-reuse-and-stop-failure silent-renewal-and-port-reassignment"

    _have="$WARPTWEET_INTEROP_WORK/have_ids.txt"
    : >"$_have"
    if [ -s "$WARPTWEET_INTEROP_RESULTS_FILE" ]; then
        sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$WARPTWEET_INTEROP_RESULTS_FILE" >"$_have"
    fi
    _dup=$(sort "$_have" | uniq -d)
    if [ -n "$_dup" ]; then
        interop_log "duplicate result ids before write: $_dup"
        return 2
    fi

    _extra="$WARPTWEET_INTEROP_WORK/extra.ndjson"
    : >"$_extra"
    for _id in $_checklist_ids; do
        if ! grep -qx "$_id" "$_have" 2>/dev/null; then
            _class=positive
            case "$_id" in
                classical-* | wrong-* | malformed-* | invite-fail-* | forwarding-* | local-state-* | engine-and-* | bounded-* | availability-* | pid-reuse-* | silent-renewal-*)
                    _class=negative
                    ;;
            esac
            printf '{"id":"%s","class":"%s","status":"not_run","detail":"Phase A orchestrator did not execute this case"}\n' \
                "$_id" "$_class" >>"$_extra"
        fi
    done
    if [ -s "$_extra" ]; then
        cat "$_extra" >>"$WARPTWEET_INTEROP_RESULTS_FILE"
    fi

    _pkg_to_pkg=${WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE:-false}
    _src_sub=${WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION:-false}
    case "$_pkg_to_pkg" in true|false) ;; *) _pkg_to_pkg=false ;; esac
    case "$_src_sub" in true|false) ;; *) _src_sub=false ;; esac

    _server_arch=${WARPTWEET_SERVER_ARCHITECTURE:-unknown}
    _route_count=${WARPTWEET_ROUTE_COUNT:-0}
    case "$_route_count" in
        ''|*[!0-9]*) _route_count=0 ;;
    esac
    _restart_policies='[]'
    if [ -s "$WARPTWEET_INTEROP_RESULTS_FILE" ] &&
        grep -q '"id":"reboot-unless-stopped-manual-down"' "$WARPTWEET_INTEROP_RESULTS_FILE" &&
        ! grep '"id":"reboot-unless-stopped-manual-down"' "$WARPTWEET_INTEROP_RESULTS_FILE" | grep -q '"status":"not_run"'; then
        _restart_policies='["unless-stopped", "manual"]'
    fi

    _repo=${WT_REPO_ROOT:-}
    if [ -z "$_repo" ] && [ -n "${WARPTWEET_INTEROP_ROOT:-}" ]; then
        _repo=$(CDPATH= cd -- "$WARPTWEET_INTEROP_ROOT/../.." && pwd)
    fi
    if [ -z "$_repo" ] || [ ! -f "$_repo/packaging/evidence/checklist-v3.json" ]; then
        interop_log "cannot locate repository root for checklist-v3.json"
        return 2
    fi

    if ! interop_fill_networking_defaults; then
        interop_log "networking observations failed closed; evidence not written"
        return 2
    fi

    _draft="$WARPTWEET_INTEROP_WORK/evidence-draft.json"
    rm -f "$_draft"
    WARPTWEET_INTEROP_FINISHED_AT=$_finished \
        WARPTWEET_SERVER_ARCHITECTURE=$_server_arch \
        WARPTWEET_ROUTE_COUNT=$_route_count \
        WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE=$_pkg_to_pkg \
        WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION=$_src_sub \
        python3 - "$WARPTWEET_INTEROP_RESULTS_FILE" "$_draft" "$_restart_policies" <<'PY'
import json, os, sys

results_path, draft_path, restart_raw = sys.argv[1], sys.argv[2], sys.argv[3]
results = []
with open(results_path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if line:
            results.append(json.loads(line))
restart_policies = json.loads(restart_raw)

def env(name, default=""):
    return os.environ.get(name, default)

def as_bool(name, default="false"):
    return env(name, default).lower() == "true"

def require_bool(name):
    value = env(name).lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise SystemExit("missing required observation %s" % name)

def hostport(value, default_port):
    value = value.strip()
    if not value:
        return "", default_port
    if value.startswith("["):
        host = value[1:value.index("]")]
        port = int(value.rsplit(":", 1)[-1])
        return host, port
    host, port_s = value.rsplit(":", 1)
    return host, int(port_s)

listen = env("WARPTWEET_INTEROP_SERVER_LISTEN")
advertise = env("WARPTWEET_INTEROP_SERVER_ADVERTISE")
enroll_listen = env("WARPTWEET_INTEROP_ENROLL_LISTEN")
enroll_advertise = env("WARPTWEET_INTEROP_ENROLL_ADVERTISE")
bind_host, bind_port = hostport(listen, 2222)
data_dial = advertise or listen
data_host, data_port = hostport(data_dial, bind_port)
if enroll_listen:
    enroll_bind_host, enroll_bind_port = hostport(enroll_listen, 29722)
else:
    enroll_bind_host, enroll_bind_port = bind_host, 29722
if enroll_advertise:
    enroll_dial_host, enroll_dial_port = hostport(enroll_advertise, 29722)
else:
    enroll_dial_host, enroll_dial_port = data_host, 29722

cell_classes = [item for item in env("WARPTWEET_INTEROP_CELL_CLASSES", "matrix").split(",") if item]
model = env("WARPTWEET_INTEROP_PUBLICATION_MODEL")
if not model:
    model = "one_to_one_nat" if advertise and advertise != listen else "direct"
generation = int(env("WARPTWEET_INTEROP_PUBLISHED_ENDPOINT_GENERATION", "1") or "1")
observed_data = env("WARPTWEET_INTEROP_OBSERVED_DATA_LISTENER")
observed_enroll = env("WARPTWEET_INTEROP_OBSERVED_ENROLL_LISTENER")
if not observed_data or not observed_enroll:
    raise SystemExit("observed listeners were not captured from the guest")
match_binds = require_bool("WARPTWEET_INTEROP_LISTENERS_MATCH_BINDS")
test_dnat_absent = require_bool("WARPTWEET_INTEROP_TEST_DNAT_ABSENT")
loopback_alias_absent = require_bool("WARPTWEET_INTEROP_LOOPBACK_ALIAS_ABSENT")
invite_match = require_bool("WARPTWEET_INTEROP_INVITE_DIALS_MATCH")
invite_data_host = env("WARPTWEET_INTEROP_INVITE_DATA_HOST")
invite_enroll_host = env("WARPTWEET_INTEROP_INVITE_ENROLL_HOST")
try:
    invite_data_port = int(env("WARPTWEET_INTEROP_INVITE_DATA_PORT"))
    invite_enroll_port = int(env("WARPTWEET_INTEROP_INVITE_ENROLL_PORT"))
except ValueError:
    raise SystemExit("invite dials were not captured") from None
if not invite_data_host or not invite_enroll_host:
    raise SystemExit("invite dials were not captured")
clean_proof = env("WARPTWEET_CLEAN_TREE_PROOF", "not_recorded")
clean_tree = clean_proof in ("clean", "git-status-empty")
package_only = as_bool("WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE", "false")
client_platform = env("WARPTWEET_CLIENT_PLATFORM") or os.uname().sysname
client_arch = env("WARPTWEET_CLIENT_ARCHITECTURE") or os.uname().machine
data_resolved = env("WARPTWEET_INTEROP_DATA_RESOLVED_ADDR") or data_host
enroll_resolved = env("WARPTWEET_INTEROP_ENROLL_RESOLVED_ADDR") or enroll_dial_host
dial_status = env("WARPTWEET_INTEROP_CLIENT_DIAL_STATUS", "not_run")
spki_status = env("WARPTWEET_INTEROP_SPKI_STATUS", "not_run")
host_key_status = env("WARPTWEET_INTEROP_HOST_KEY_STATUS", "not_run")

document = {
    "kind": "warptweet.release-evidence",
    "schema_version": 3,
    "contract_id": "warptweet.adoption-release.v1",
    "contract_checklist_sha256": "",
    "release_version": env("WARPTWEET_RELEASE_VERSION"),
    "source_commit": env("WARPTWEET_SOURCE_COMMIT"),
    "clean_tree_proof": clean_proof,
    "client_package_sha256": env("WARPTWEET_CLIENT_PACKAGE_SHA256"),
    "server_package_sha256": env("WARPTWEET_SERVER_PACKAGE_SHA256"),
    "client_artifact_profile_id": env("WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID"),
    "server_artifact_profile_id": env("WARPTWEET_SERVER_ARTIFACT_PROFILE_ID"),
    "client_engine_manifest_sha256": env("WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256"),
    "server_engine_manifest_sha256": env("WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256"),
    "client_platform": client_platform,
    "server_platform": "linux",
    "client_architecture": client_arch,
    "server_architecture": env("WARPTWEET_SERVER_ARCHITECTURE", "unknown"),
    "host_target": env("WARPTWEET_HOST_TARGET", "127.0.0.1:5432"),
    "authorization_policy": env("WARPTWEET_AUTHORIZATION_POLICY", "30d-default-365d-max"),
    "route_count": int(env("WARPTWEET_ROUTE_COUNT", "0") or "0"),
    "restart_policies": restart_policies,
    "test_identity": "interop-phase-a-mac-client",
    "commands": ["./scripts/interop/orchestrate.sh"],
    "started_at": env("WARPTWEET_INTEROP_STARTED_AT"),
    "finished_at": env("WARPTWEET_INTEROP_FINISHED_AT"),
    "package_to_package": package_only,
    "source_tree_substitution": as_bool("WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION", "false"),
    "cell_classes": cell_classes,
    "results": results,
    "networking": {
        "cell_id": env("WARPTWEET_INTEROP_NETWORKING_CELL_ID"),
        "publication_model": model,
        "published_endpoint_generation": generation,
        "invite_schema_version": 3,
        "invite_dials_match_published": invite_match,
        "invite_dials": {
            "data": {"host": invite_data_host, "port": invite_data_port},
            "enrollment": {"host": invite_enroll_host, "port": invite_enroll_port},
        },
        "binds": {
            "data": {"address": bind_host, "port": bind_port},
            "enrollment": {"address": enroll_bind_host, "port": enroll_bind_port},
        },
        "dials": {
            "data": {"host": data_host, "port": data_port},
            "enrollment": {"host": enroll_dial_host, "port": enroll_dial_port},
        },
        "observed_listeners": {
            "data": observed_data,
            "enrollment": observed_enroll,
            "match_binds": match_binds,
        },
        "test_dnat_absent": test_dnat_absent,
        "loopback_alias_absent": loopback_alias_absent,
        "client_dials": [
            {"leg": "data", "host": data_host, "port": data_port, "status": dial_status},
            {"leg": "enrollment", "host": enroll_dial_host, "port": enroll_dial_port, "status": dial_status},
        ],
        "spki_result": {"status": spki_status},
        "host_key_result": {"status": host_key_status},
        "enrollment_resolved_addr": enroll_resolved,
        "data_resolved_addr": data_resolved,
        "operator_firewall_assumptions": env(
            "WARPTWEET_INTEROP_FIREWALL_ASSUMPTIONS",
            "operator-stated: inbound 2222/tcp and 29722/tcp; no guest DNAT helper",
        ),
        "operator_load_balancer_assumptions": env(
            "WARPTWEET_INTEROP_LB_ASSUMPTIONS",
            "none; not a proxy load balancer",
        ),
        "package_only": package_only,
        "clean_tree": clean_tree,
    },
}
redacted = env("WARPTWEET_REDACTED_LOG_PATH")
if redacted:
    document["redacted_log_path"] = redacted
with open(draft_path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
    handle.write("\n")
PY
    if [ ! -s "$_draft" ]; then
        interop_log "failed to assemble v3 evidence draft"
        return 2
    fi

    if ! (
        cd "$_repo" &&
            CGO_ENABLED=0 go run ./cmd/write-release-evidence \
                --root "$_repo" \
                --in "$_draft" \
                --out "$WARPTWEET_INTEROP_EVIDENCE_OUTPUT"
    ); then
        interop_log "Validate before write failed; evidence not written"
        return 2
    fi
    interop_log "wrote evidence $WARPTWEET_INTEROP_EVIDENCE_OUTPUT"

    if grep -E '"status": ?"fail"' "$WARPTWEET_INTEROP_EVIDENCE_OUTPUT" >/dev/null 2>&1; then
        interop_log "evidence contains fail; Phase A must exit non-zero"
        return 2
    fi
    if grep -E '"status": ?"not_run"' "$WARPTWEET_INTEROP_EVIDENCE_OUTPUT" >/dev/null 2>&1; then
        interop_log "evidence incomplete (not_run present); CTA must stay dark"
        return 1
    fi
    interop_log "evidence complete (all pass)"
    return 0
}

interop_classify_gce_cell() {
    _adv=${WARPTWEET_INTEROP_SERVER_ADVERTISE:-}
    _listen=${WARPTWEET_INTEROP_SERVER_LISTEN:-}
    _client=${WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID:-}
    _server=${WARPTWEET_SERVER_ARTIFACT_PROFILE_ID:-}
    if [ -z "$_adv" ] || [ "$_adv" = "$_listen" ]; then
        return 0
    fi
    if [ "$_client" != "darwin-arm64" ] || [ "$_server" != "linux-arm64" ]; then
        return 0
    fi
    if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$(interop_hostport_host "$_adv")" >/dev/null 2>&1; then
        return 0
    fi
    _classes=${WARPTWEET_INTEROP_CELL_CLASSES:-}
    if [ -z "$_classes" ]; then
        WARPTWEET_INTEROP_CELL_CLASSES=matrix,networking
    else
        case ",$_classes," in
            *,networking,*) ;;
            *) WARPTWEET_INTEROP_CELL_CLASSES="${_classes},networking" ;;
        esac
        case ",$WARPTWEET_INTEROP_CELL_CLASSES," in
            *,matrix,*) ;;
            *) WARPTWEET_INTEROP_CELL_CLASSES="matrix,$WARPTWEET_INTEROP_CELL_CLASSES" ;;
        esac
    fi
    if [ -z "${WARPTWEET_INTEROP_NETWORKING_CELL_ID:-}" ]; then
        WARPTWEET_INTEROP_NETWORKING_CELL_ID=gce-one-to-one-nat
    fi
    if [ -z "${WARPTWEET_INTEROP_PUBLICATION_MODEL:-}" ]; then
        WARPTWEET_INTEROP_PUBLICATION_MODEL=one_to_one_nat
    fi
    export WARPTWEET_INTEROP_CELL_CLASSES WARPTWEET_INTEROP_NETWORKING_CELL_ID WARPTWEET_INTEROP_PUBLICATION_MODEL
}

interop_fill_networking_defaults() {
    interop_classify_gce_cell
    if [ -z "${WARPTWEET_INTEROP_CLIENT_DIAL_STATUS:-}" ]; then
        if grep -q '"id":"invite-enroll-single-use".*"status":"pass"' "$WARPTWEET_INTEROP_RESULTS_FILE" 2>/dev/null; then
            WARPTWEET_INTEROP_CLIENT_DIAL_STATUS=pass
            WARPTWEET_INTEROP_SPKI_STATUS=pass
            WARPTWEET_INTEROP_HOST_KEY_STATUS=pass
        else
            WARPTWEET_INTEROP_CLIENT_DIAL_STATUS=not_run
            WARPTWEET_INTEROP_SPKI_STATUS=not_run
            WARPTWEET_INTEROP_HOST_KEY_STATUS=not_run
        fi
        export WARPTWEET_INTEROP_CLIENT_DIAL_STATUS WARPTWEET_INTEROP_SPKI_STATUS WARPTWEET_INTEROP_HOST_KEY_STATUS
    fi
    if [ -z "${WARPTWEET_INTEROP_SERVER_LISTEN:-}" ]; then
        interop_log "LISTEN bind is required for networking observations"
        return 1
    fi
    _data_port=$(interop_hostport_port "$WARPTWEET_INTEROP_SERVER_LISTEN")
    _enroll_port=29722
    if [ -n "${WARPTWEET_INTEROP_ENROLL_LISTEN:-}" ]; then
        _enroll_port=$(interop_hostport_port "$WARPTWEET_INTEROP_ENROLL_LISTEN")
    fi
    if [ -z "${WARPTWEET_INTEROP_PUBLISHED_ENDPOINT_GENERATION:-}" ]; then
        _gen=$(interop_ssh "sudo python3 -c \"import json; print(json.load(open('/etc/warptweet/server.wt')).get('network',{}).get('published_endpoint_generation',1))\"" ) || _gen=
        case "$_gen" in
            ''|*[!0-9]*) _gen=1 ;;
        esac
        WARPTWEET_INTEROP_PUBLISHED_ENDPOINT_GENERATION=$_gen
        export WARPTWEET_INTEROP_PUBLISHED_ENDPOINT_GENERATION
    fi
    if ! _probe=$(
        interop_ssh "sudo env WT_DATA_PORT=${_data_port} WT_ENROLL_PORT=${_enroll_port} python3 -" <<'REMOTE'
import os, re, shutil, subprocess

def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None

def iptables_status():
    if not shutil.which("iptables"):
        return "MISSING"
    out = run(["iptables", "-t", "nat", "-S"])
    if out is None:
        return "MISSING"
    if re.search(r"\b(DNAT|REDIRECT|NETMAP)\b", out):
        return "HAS_DNAT"
    return "NO_DNAT"

def nft_status():
    if not shutil.which("nft"):
        return "MISSING"
    out = run(["nft", "list", "ruleset"])
    if out is None:
        return "MISSING"
    if re.search(r"\b(dnat|redirect)\b", out, re.I):
        return "HAS_DNAT"
    return "NO_DNAT"

def lo_addrs():
    out = run(["ip", "-o", "addr", "show", "lo"]) or ""
    return re.findall(r"inet6? ([0-9a-fA-F:.]+)/", out)

def parse_local(local):
    local = local.strip()
    if local.startswith("["):
        host = local[1:local.index("]")]
        port = int(local.rsplit(":", 1)[-1])
        return host, port
    host, port_s = local.rsplit(":", 1)
    return host, int(port_s)

def unspecified(host):
    return host in ("0.0.0.0", "*", "::", "::0")

def format_listener(host, port):
    if ":" in host:
        return "[%s]:%s" % (host, port)
    return "%s:%s" % (host, port)

def listener_for(port):
    out = run(["ss", "-lntH"]) or run(["ss", "-lnt"]) or run(["netstat", "-lnt"]) or ""
    candidates = []
    for line in out.splitlines():
        for part in line.split():
            try:
                host, parsed_port = parse_local(part)
            except Exception:
                continue
            if parsed_port == port:
                candidates.append((host, parsed_port))
    if not candidates:
        return ""
    for host, parsed_port in candidates:
        if not unspecified(host):
            return format_listener(host, parsed_port)
    host, parsed_port = candidates[0]
    return format_listener(host, parsed_port)

print("IPTABLES=" + iptables_status())
print("NFT=" + nft_status())
print("LO=" + " ".join(lo_addrs()))
print("DATA_LISTENER=" + listener_for(int(os.environ["WT_DATA_PORT"])))
print("ENROLL_LISTENER=" + listener_for(int(os.environ["WT_ENROLL_PORT"])))
REMOTE
    ); then
        interop_log "guest networking probe failed"
        return 1
    fi
    _iptables=$(printf '%s\n' "$_probe" | sed -n 's/^IPTABLES=//p' | tail -n 1)
    _nft=$(printf '%s\n' "$_probe" | sed -n 's/^NFT=//p' | tail -n 1)
    _lo=$(printf '%s\n' "$_probe" | sed -n 's/^LO=//p' | tail -n 1)
    _obs_data=$(printf '%s\n' "$_probe" | sed -n 's/^DATA_LISTENER=//p' | tail -n 1)
    _obs_enroll=$(printf '%s\n' "$_probe" | sed -n 's/^ENROLL_LISTENER=//p' | tail -n 1)
    if [ -z "$_iptables" ] || [ -z "$_nft" ]; then
        interop_log "guest DNAT probe did not print iptables and nft results"
        return 1
    fi
    if [ "$_iptables" = "NO_DNAT" ] && [ "$_nft" = "NO_DNAT" ]; then
        WARPTWEET_INTEROP_TEST_DNAT_ABSENT=true
    else
        WARPTWEET_INTEROP_TEST_DNAT_ABSENT=false
    fi
    if ! printf '%s\n' "$_probe" | grep -q '^LO='; then
        interop_log "guest loopback addresses were not observed"
        return 1
    fi
    if [ -z "$_lo" ]; then
        interop_log "guest loopback address list was empty"
        return 1
    fi
    if [ -z "$_obs_data" ] || [ -z "$_obs_enroll" ]; then
        interop_log "guest listeners were not observed on bind ports"
        return 1
    fi
    WARPTWEET_INTEROP_OBSERVED_DATA_LISTENER=$_obs_data
    WARPTWEET_INTEROP_OBSERVED_ENROLL_LISTENER=$_obs_enroll
    _bind_host=$(interop_hostport_host "$WARPTWEET_INTEROP_SERVER_LISTEN")
    _bind_port=$(interop_hostport_port "$WARPTWEET_INTEROP_SERVER_LISTEN")
    if [ -n "${WARPTWEET_INTEROP_ENROLL_LISTEN:-}" ]; then
        _enroll_bind_host=$(interop_hostport_host "$WARPTWEET_INTEROP_ENROLL_LISTEN")
        _enroll_bind_port=$(interop_hostport_port "$WARPTWEET_INTEROP_ENROLL_LISTEN")
    else
        _enroll_bind_host=$_bind_host
        _enroll_bind_port=29722
    fi
    WARPTWEET_INTEROP_LISTENERS_MATCH_BINDS=$(
        python3 - "$_obs_data" "$_bind_host" "$_bind_port" "$_obs_enroll" "$_enroll_bind_host" "$_enroll_bind_port" <<'PY'
import ipaddress, sys

def canon(value, host, port):
    def parse(text):
        text = text.strip()
        if text.startswith("["):
            h = text[1:text.index("]")]
            p = int(text.rsplit(":", 1)[-1])
            return h, p
        h, p = text.rsplit(":", 1)
        return h, int(p)
    try:
        if value:
            host, port = parse(value)
        addr = ipaddress.ip_address(host)
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if addr.is_unspecified:
            return None
        return "%s/%s" % (addr.compressed, port)
    except Exception:
        return None

obs_data, bind_host, bind_port, obs_enroll, enroll_host, enroll_port = sys.argv[1:7]
ok = canon(obs_data, "", 0) == canon("", bind_host, int(bind_port)) and canon(obs_enroll, "", 0) == canon("", enroll_host, int(enroll_port))
print("true" if ok else "false")
PY
    )
    _alias_host=$(interop_hostport_host "$(interop_published_data_dial)")
    WARPTWEET_INTEROP_LOOPBACK_ALIAS_ABSENT=$(
        python3 - "$_lo" "$_alias_host" <<'PY'
import ipaddress, sys
raw, target = sys.argv[1], sys.argv[2]
try:
    want = ipaddress.ip_address(target)
    if getattr(want, "ipv4_mapped", None):
        want = want.ipv4_mapped
except Exception:
    print("false")
    raise SystemExit
if want.is_loopback:
    print("true")
    raise SystemExit
for item in raw.split():
    try:
        addr = ipaddress.ip_address(item)
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
    except Exception:
        continue
    if addr == want:
        print("false")
        raise SystemExit
print("true")
PY
    )
    if [ -z "${WARPTWEET_INTEROP_INVITE:-}" ] || [ ! -s "$WARPTWEET_INTEROP_INVITE" ]; then
        interop_log "invite file is required to compare published dials"
        return 1
    fi
    _invite_fields=$(
        python3 - "$WARPTWEET_INTEROP_INVITE" "$(interop_published_data_dial)" "$(interop_published_enroll_dial)" <<'PY'
import ipaddress, json, sys

def parse_hostport(value):
    value = value.strip()
    if value.startswith("["):
        return value[1:value.index("]")], int(value.rsplit(":", 1)[-1])
    host, port = value.rsplit(":", 1)
    return host, int(port)

def canon_host(host):
    try:
        addr = ipaddress.ip_address(host)
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        return addr.compressed
    except Exception:
        return host.strip().lower()

invite = json.load(open(sys.argv[1], encoding="utf-8"))
if invite.get("schema_version") != 3:
    raise SystemExit("invite schema is not 3")
data = invite["data"]
enroll = invite["enrollment"]
pub_data_host, pub_data_port = parse_hostport(sys.argv[2])
pub_enroll_host, pub_enroll_port = parse_hostport(sys.argv[3])
match = (
    canon_host(data["host"]) == canon_host(pub_data_host)
    and int(data["port"]) == pub_data_port
    and canon_host(enroll["host"]) == canon_host(pub_enroll_host)
    and int(enroll["port"]) == pub_enroll_port
)
print(data["host"])
print(int(data["port"]))
print(enroll["host"])
print(int(enroll["port"]))
print("true" if match else "false")
PY
    ) || {
        interop_log "invite schema-3 dials could not be read"
        return 1
    }
    WARPTWEET_INTEROP_INVITE_DATA_HOST=$(printf '%s\n' "$_invite_fields" | sed -n '1p')
    WARPTWEET_INTEROP_INVITE_DATA_PORT=$(printf '%s\n' "$_invite_fields" | sed -n '2p')
    WARPTWEET_INTEROP_INVITE_ENROLL_HOST=$(printf '%s\n' "$_invite_fields" | sed -n '3p')
    WARPTWEET_INTEROP_INVITE_ENROLL_PORT=$(printf '%s\n' "$_invite_fields" | sed -n '4p')
    WARPTWEET_INTEROP_INVITE_DIALS_MATCH=$(printf '%s\n' "$_invite_fields" | sed -n '5p')
    if [ -z "$WARPTWEET_INTEROP_INVITE_DATA_HOST" ] || [ -z "$WARPTWEET_INTEROP_INVITE_DIALS_MATCH" ]; then
        interop_log "invite dial comparison produced no observation"
        return 1
    fi
    export WARPTWEET_INTEROP_TEST_DNAT_ABSENT WARPTWEET_INTEROP_LOOPBACK_ALIAS_ABSENT
    export WARPTWEET_INTEROP_OBSERVED_DATA_LISTENER WARPTWEET_INTEROP_OBSERVED_ENROLL_LISTENER
    export WARPTWEET_INTEROP_LISTENERS_MATCH_BINDS
    export WARPTWEET_INTEROP_INVITE_DATA_HOST WARPTWEET_INTEROP_INVITE_DATA_PORT
    export WARPTWEET_INTEROP_INVITE_ENROLL_HOST WARPTWEET_INTEROP_INVITE_ENROLL_PORT
    export WARPTWEET_INTEROP_INVITE_DIALS_MATCH
}
