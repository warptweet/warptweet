#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Local enrollment control-plane confidence gate.
# Runs pure Go loopback tests for invite mint, Accept, Submit enroll/rotate/revoke,
# and fail-closed invite cases. This is NOT package-to-package WP8 evidence and
# must not be used to light the public Homebrew CTA.

fail() {
    echo "enrollment control plane: $*" >&2
    exit 1
}

pass() {
    printf 'enrollment control plane: PASS %s\n' "$*"
}

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 64
fi

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
cd "$WT_REPOSITORY_ROOT"

if ! command -v go >/dev/null 2>&1; then
    fail "go is required"
fi

go test ./internal/enrollment/ ./internal/command/ -count=1
pass "enrollment and command package tests"

go test ./internal/server/ -run 'TestEnrollUnit|TestWarpTweetSSHDUnit|TestTunnelUnit' -count=1
pass "systemd unit contract tests"

pass "control-plane confidence complete (not WP8 package evidence)"
