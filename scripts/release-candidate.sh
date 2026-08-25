#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Assemble a signed WarpTweet release candidate. This script never publishes.
# It fail-closes on a dirty tree, a -dev version, or missing signing material.

fail() {
    echo "release-candidate: $*" >&2
    exit 1
}

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)

WT_VERSION=${WARPTWEET_VERSION:-}
if [ -z "$WT_VERSION" ]; then
    fail "WARPTWEET_VERSION is required and must not be a -dev version"
fi
case "$WT_VERSION" in
    *-dev*|latest|"")
        fail "WARPTWEET_VERSION=$WT_VERSION is not a release-candidate version"
        ;;
esac

if [ -n "$(git -C "$WT_REPOSITORY_ROOT" status --porcelain)" ]; then
    fail "working tree is dirty; commit or stash before assembling a candidate"
fi

WT_COMMIT=$(git -C "$WT_REPOSITORY_ROOT" rev-parse HEAD)
if [ "${#WT_COMMIT}" -ne 40 ]; then
    fail "source commit must be 40 lowercase hex characters"
fi
case "$WT_COMMIT" in
    *[!0-9a-f]*)
        fail "source commit must be lowercase hexadecimal"
        ;;
esac

if [ "${WARPTWEET_REQUIRE_SIGNED_PKG:-}" != "1" ] || [ "${WARPTWEET_REQUIRE_NOTARIZED_PKG:-}" != "1" ]; then
    fail "WARPTWEET_REQUIRE_SIGNED_PKG=1 and WARPTWEET_REQUIRE_NOTARIZED_PKG=1 are required"
fi
if [ -z "${WARPTWEET_INSTALLER_IDENTITY:-}" ]; then
    fail "WARPTWEET_INSTALLER_IDENTITY is required"
fi
case "$WARPTWEET_INSTALLER_IDENTITY" in
    *"(CP4268Q8UF)"*) ;;
    *)
        fail "WARPTWEET_INSTALLER_IDENTITY must include Team ID CP4268Q8UF"
        ;;
esac
if [ -z "${WARPTWEET_NOTARY_PROFILE:-}" ]; then
    fail "WARPTWEET_NOTARY_PROFILE is required"
fi
if [ -z "${WARPTWEET_LINUX_GPG_KEY:-}" ]; then
    fail "WARPTWEET_LINUX_GPG_KEY is required to sign host packages"
fi

echo "release-candidate: version=$WT_VERSION commit=$WT_COMMIT"
echo "release-candidate: signing gates are present; invoke the platform assemblers next"
echo "release-candidate: macOS: scripts/build-macos-pkg.sh with WARPTWEET_REQUIRE_SIGNED_PKG=1"
echo "release-candidate: Linux: scripts/build-linux-packages.sh then scripts/sign-linux-deb.sh"
echo "release-candidate: cask: go run ./cmd/warptweet-cask --version ... --sha256-arm64 ..."
echo "release-candidate: this script does not create tags, GitHub releases, or public communication"
