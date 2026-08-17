#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Sign one assembled WarpTweet .deb with the documented host-package key.

fail() {
    echo "sign-linux-deb: $*" >&2
    exit 1
}

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ABSOLUTE_DEB_PATH" >&2
    exit 64
fi

WT_DEB=$1
case "$WT_DEB" in
    /*) ;;
    *)
        fail "deb path must be absolute"
        ;;
esac
if [ ! -f "$WT_DEB" ] || [ -L "$WT_DEB" ]; then
    fail "deb is missing or a symlink"
fi
if [ -z "${WARPTWEET_LINUX_GPG_KEY:-}" ]; then
    fail "WARPTWEET_LINUX_GPG_KEY is required"
fi
if ! command -v dpkg-sig >/dev/null 2>&1; then
    fail "dpkg-sig is required"
fi

dpkg-sig --sign builder -k "$WARPTWEET_LINUX_GPG_KEY" "$WT_DEB"
if ! dpkg-sig --verify "$WT_DEB"; then
    fail "signature verification failed for $WT_DEB"
fi

echo "sign-linux-deb: signed $WT_DEB"
