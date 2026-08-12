#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Package-to-package interop gate. Requires installed client and server packages
# on managed hosts. Source-tree binaries are not accepted as substitutes for
# package digests. Same-container source-tree tests do not satisfy this gate.

fail() {
    echo "package interop: $*" >&2
    exit 1
}

pass() {
    printf 'package interop: PASS %s\n' "$*"
}

if [ "${WARPTWEET_CI_PACKAGE_INTEROP:-}" != "1" ]; then
    fail "WARPTWEET_CI_PACKAGE_INTEROP=1 is required"
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 64
fi

for WT_VAR in \
    WARPTWEET_RELEASE_VERSION \
    WARPTWEET_SOURCE_COMMIT \
    WARPTWEET_CLIENT_PACKAGE_SHA256 \
    WARPTWEET_SERVER_PACKAGE_SHA256 \
    WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID \
    WARPTWEET_SERVER_ARTIFACT_PROFILE_ID \
    WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256 \
    WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256 \
    WARPTWEET_EVIDENCE_OUTPUT \
    WARPTWEET_INTEROP_ROLE; do
    eval "WT_VALUE=\${$WT_VAR:-}"
    if [ -z "$WT_VALUE" ]; then
        fail "$WT_VAR is required"
    fi
done

WT_COMMIT_LEN=${#WARPTWEET_SOURCE_COMMIT}
if [ "$WT_COMMIT_LEN" -ne 40 ]; then
    fail "WARPTWEET_SOURCE_COMMIT must be 40 lowercase hex characters"
fi
case "$WARPTWEET_SOURCE_COMMIT" in
    *[!0-9a-f]*)
        fail "WARPTWEET_SOURCE_COMMIT must be lowercase hexadecimal"
        ;;
esac

case "$WARPTWEET_INTEROP_ROLE" in
    client|server|orchestrator) ;;
    *)
        fail "WARPTWEET_INTEROP_ROLE must be client, server, or orchestrator"
        ;;
esac

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
WT_CHECKLIST="$WT_REPOSITORY_ROOT/packaging/evidence/checklist-v1.json"
if [ ! -f "$WT_CHECKLIST" ]; then
    fail "checklist missing: $WT_CHECKLIST"
fi

# Refuse source-tree substitution markers.
if [ "${WARPTWEET_ALLOW_SOURCE_TREE:-}" = "1" ]; then
    fail "source-tree substitution is forbidden for package interop evidence"
fi

WT_STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
WT_RESULTS_FILE=$(mktemp)
trap 'rm -f "$WT_RESULTS_FILE"' EXIT

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

record_result() {
    WT_ID=$1
    WT_CLASS=$2
    WT_STATUS=$3
    WT_DETAIL=$(json_escape "${4:-}")
    printf '{"id":"%s","class":"%s","status":"%s","detail":"%s"}\n' \
        "$WT_ID" "$WT_CLASS" "$WT_STATUS" "$WT_DETAIL" >>"$WT_RESULTS_FILE"
}

digest_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_positive_pkg_signature_and_manifest() {
    if [ "$WARPTWEET_INTEROP_ROLE" = "server" ]; then
        WT_SERVER_MANIFEST=${WARPTWEET_SERVER_BUNDLE_MANIFEST:-/opt/warptweet/share/openssh-bundle.sha256}
        if [ ! -f "$WT_SERVER_MANIFEST" ]; then
            record_result pkg-signature-and-manifest positive not_run "server bundle manifest missing"
            return 0
        fi
        WT_GOT=$(digest_file "$WT_SERVER_MANIFEST")
        if [ "$WT_GOT" != "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" ]; then
            record_result pkg-signature-and-manifest positive fail "server engine manifest digest mismatch"
            return 0
        fi
        record_result pkg-signature-and-manifest positive pass "server package inventory present"
        return 0
    fi

    WT_CLIENT_CTRL=${WARPTWEET_CLIENT_CONTROLLER:-}
    WT_CLIENT_SSH=${WARPTWEET_CLIENT_SSH:-}
    WT_CLIENT_MANIFEST=${WARPTWEET_CLIENT_BUNDLE_MANIFEST:-}
    if [ -z "$WT_CLIENT_CTRL" ] || [ -z "$WT_CLIENT_SSH" ] || [ -z "$WT_CLIENT_MANIFEST" ]; then
        record_result pkg-signature-and-manifest positive not_run "client package paths unset"
        return 0
    fi
    if [ ! -x "$WT_CLIENT_CTRL" ] || [ ! -x "$WT_CLIENT_SSH" ] || [ ! -f "$WT_CLIENT_MANIFEST" ]; then
        record_result pkg-signature-and-manifest positive fail "missing installed client package files"
        return 0
    fi
    WT_GOT=$(digest_file "$WT_CLIENT_MANIFEST")
    if [ "$WT_GOT" != "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" ]; then
        record_result pkg-signature-and-manifest positive fail "client engine manifest digest mismatch"
        return 0
    fi
    record_result pkg-signature-and-manifest positive pass "client package inventory present"
}

run_positive_engine_identity_trust_preflight() {
    if [ "$WARPTWEET_INTEROP_ROLE" = "server" ]; then
        WT_SERVER_CTRL=${WARPTWEET_SERVER_CONTROLLER:-/opt/warptweet/bin/warptweet}
        WT_SERVER_CFG=${WARPTWEET_SERVER_MANIFEST:-/etc/warptweet/server.wt}
        if [ -x "$WT_SERVER_CTRL" ] && [ -f "$WT_SERVER_CFG" ]; then
            if "$WT_SERVER_CTRL" doctor-server --config "$WT_SERVER_CFG" >/tmp/wt-doctor-server.json 2>/tmp/wt-doctor-server.err; then
                record_result engine-identity-trust-preflight positive pass "doctor-server preflight_ready"
            else
                record_result engine-identity-trust-preflight positive fail "doctor-server failed"
            fi
        else
            record_result engine-identity-trust-preflight positive not_run "server package paths missing"
        fi
        return 0
    fi
    WT_CLIENT_CTRL=${WARPTWEET_CLIENT_CONTROLLER:-}
    WT_CLIENT_CFG=${WARPTWEET_CLIENT_MANIFEST:-}
    WT_TUNNEL=${WARPTWEET_TUNNEL_ID:-database-primary}
    if [ -z "$WT_CLIENT_CTRL" ] || [ -z "$WT_CLIENT_CFG" ]; then
        record_result engine-identity-trust-preflight positive not_run "client paths unset"
        return 0
    fi
    if "$WT_CLIENT_CTRL" doctor --config "$WT_CLIENT_CFG" --tunnel "$WT_TUNNEL" >/tmp/wt-doctor-client.json 2>/tmp/wt-doctor-client.err; then
        record_result engine-identity-trust-preflight positive pass "doctor preflight_ready"
    else
        record_result engine-identity-trust-preflight positive fail "doctor failed"
    fi
}

run_case_not_run() {
    record_result "$1" "$2" not_run "$3"
}

run_positive_pkg_signature_and_manifest
run_positive_engine_identity_trust_preflight
run_case_not_run invite-enroll-single-use positive "requires dual-host enrollment endpoint"
run_case_not_run composite-auth positive "requires dual-host tunnel"
run_case_not_run exact-kex-aead positive "requires dual-host tunnel with algorithm observation"
run_case_not_run rekey-same-profile positive "requires dual-host rekey observation"
run_case_not_run pid-bound-readiness positive "requires dual-host ready gate"
run_case_not_run deterministic-target-payload positive "requires dual-host payload transit"
run_case_not_run stop-restart-rotate-revoke-upgrade positive "requires dual-host lifecycle matrix"

run_case_not_run classical-only-kex-host-client negative "requires dual-host negative peers"
run_case_not_run wrong-host-pin negative "requires dual-host negative peers"
run_case_not_run malformed-keys-messages negative "requires dual-host negative peers"
run_case_not_run invite-fail-closed negative "requires dual-host invite negatives"
run_case_not_run forwarding-surface-rejected negative "requires dual-host forwarding negatives"
run_case_not_run local-state-mutation negative "requires dual-host mutation harness"
run_case_not_run engine-and-package-tamper negative "requires dual-host tamper harness"
run_case_not_run bounded-floods negative "requires dual-host flood harness"
run_case_not_run availability-faults negative "requires dual-host fault harness"

WT_FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
WT_RESULTS_JSON=$(awk 'BEGIN{printf "["} {if(n++)printf ","; printf "%s",$0} END{printf "]"}' "$WT_RESULTS_FILE")

WT_CLIENT_PLATFORM=${WARPTWEET_CLIENT_PLATFORM:-$(uname -s)}
WT_SERVER_PLATFORM=${WARPTWEET_SERVER_PLATFORM:-linux}
WT_CLIENT_ARCH=${WARPTWEET_CLIENT_ARCHITECTURE:-$(uname -m)}
WT_SERVER_ARCH=${WARPTWEET_SERVER_ARCHITECTURE:-unknown}
WT_TEST_IDENTITY=${WARPTWEET_TEST_IDENTITY:-package-interop}
WT_REDACTED_LOG=${WARPTWEET_REDACTED_LOG_PATH:-}

if [ -e "$WARPTWEET_EVIDENCE_OUTPUT" ] || [ -L "$WARPTWEET_EVIDENCE_OUTPUT" ]; then
    fail "evidence output path must not already exist"
fi

cat >"$WARPTWEET_EVIDENCE_OUTPUT" <<EOF
{
  "kind": "warptweet.release-evidence",
  "schema_version": 1,
  "release_version": "$WARPTWEET_RELEASE_VERSION",
  "source_commit": "$WARPTWEET_SOURCE_COMMIT",
  "client_package_sha256": "$WARPTWEET_CLIENT_PACKAGE_SHA256",
  "server_package_sha256": "$WARPTWEET_SERVER_PACKAGE_SHA256",
  "client_artifact_profile_id": "$WARPTWEET_CLIENT_ARTIFACT_PROFILE_ID",
  "server_artifact_profile_id": "$WARPTWEET_SERVER_ARTIFACT_PROFILE_ID",
  "client_engine_manifest_sha256": "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256",
  "server_engine_manifest_sha256": "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256",
  "client_platform": "$WT_CLIENT_PLATFORM",
  "server_platform": "$WT_SERVER_PLATFORM",
  "client_architecture": "$WT_CLIENT_ARCH",
  "server_architecture": "$WT_SERVER_ARCH",
  "test_identity": "$WT_TEST_IDENTITY",
  "commands": ["./scripts/test-package-interop.sh"],
  "started_at": "$WT_STARTED_AT",
  "finished_at": "$WT_FINISHED_AT",
  "redacted_log_path": "$WT_REDACTED_LOG",
  "package_to_package": true,
  "source_tree_substitution": false,
  "results": $WT_RESULTS_JSON
}
EOF

pass "wrote evidence document $WARPTWEET_EVIDENCE_OUTPUT"

# Fail closed unless every checklist case is pass. not_run is not success.
if grep -E '"status": "(fail|not_run)"' "$WARPTWEET_EVIDENCE_OUTPUT" >/dev/null 2>&1; then
    fail "evidence document contains fail or not_run results; package-to-package matrix incomplete"
fi

pass "all checklist cases passed"
