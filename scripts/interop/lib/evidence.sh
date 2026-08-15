# shellcheck shell=sh
# Emit warptweet.release-evidence JSON from Phase A results (partial matrix OK).

# Exit codes:
#   0 — every result is pass (full checklist complete)
#   1 — incomplete only (pass + expected not_run; no fail)
#   2 — at least one executed case has status fail
interop_emit_evidence() {
    _finished=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    _results=$(awk 'BEGIN{printf "["} {if(n++)printf ","; printf "%s",$0} END{printf "]"}' "$WARPTWEET_INTEROP_RESULTS_FILE")

    # Fill remaining checklist ids as not_run so the document is schema-complete
    # but not Complete() for CTA until dual-host matrix is finished.
    _checklist_ids="pkg-signature-and-manifest engine-identity-trust-preflight invite-enroll-single-use composite-auth exact-kex-aead rekey-same-profile pid-bound-readiness deterministic-target-payload stop-restart-rotate-revoke-upgrade classical-only-kex-host-client wrong-host-pin malformed-keys-messages invite-fail-closed forwarding-surface-rejected local-state-mutation engine-and-package-tamper bounded-floods availability-faults"

    _have="$WARPTWEET_INTEROP_WORK/have_ids.txt"
    : >"$_have"
    if [ -s "$WARPTWEET_INTEROP_RESULTS_FILE" ]; then
        sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$WARPTWEET_INTEROP_RESULTS_FILE" >"$_have"
    fi

    _extra="$WARPTWEET_INTEROP_WORK/extra.ndjson"
    : >"$_extra"
    for _id in $_checklist_ids; do
        if ! grep -qx "$_id" "$_have" 2>/dev/null; then
            _class=positive
            case "$_id" in
                classical-* | wrong-* | malformed-* | invite-fail-* | forwarding-* | local-state-* | engine-and-* | bounded-* | availability-*)
                    _class=negative
                    ;;
            esac
            printf '{"id":"%s","class":"%s","status":"not_run","detail":"Phase A orchestrator did not execute this case"}\n' \
                "$_id" "$_class" >>"$_extra"
        fi
    done

    if [ -s "$_extra" ]; then
        cat "$_extra" >>"$WARPTWEET_INTEROP_RESULTS_FILE"
        _results=$(awk 'BEGIN{printf "["} {if(n++)printf ","; printf "%s",$0} END{printf "]"}' "$WARPTWEET_INTEROP_RESULTS_FILE")
    fi

    _pkg_to_pkg=${WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE:-false}
    _src_sub=${WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION:-false}
    case "$_pkg_to_pkg" in true|false) ;; *) _pkg_to_pkg=false ;; esac
    case "$_src_sub" in true|false) ;; *) _src_sub=false ;; esac

    cat >"$WARPTWEET_INTEROP_EVIDENCE_OUTPUT" <<EOF
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
  "client_platform": "$(uname -s)",
  "server_platform": "linux",
  "client_architecture": "$(uname -m)",
  "server_architecture": "unknown",
  "test_identity": "interop-phase-a-mac-client",
  "commands": ["./scripts/interop/orchestrate.sh"],
  "started_at": "$WARPTWEET_INTEROP_STARTED_AT",
  "finished_at": "$_finished",
  "redacted_log_path": "",
  "package_to_package": $_pkg_to_pkg,
  "source_tree_substitution": $_src_sub,
  "results": $_results
}
EOF
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
