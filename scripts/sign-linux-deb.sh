#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Sign one assembled WarpTweet .deb. Prefers dpkg-sig. Otherwise embeds a
# _gpgbuilder member with gpg+ar so Ubuntu hosts without the dpkg-sig package
# can still produce a verifiable signature.
#
# WarpTweet authenticity is the detached OpenPGP .asc of the whole archive
# (SHA-256 capable). dpkg-sig Version 4 still lists MD5 and SHA-1 on its
# Files: lines; those are wire fields for that format, not this project's
# integrity algorithm. The fallback clearsigned document also records SHA-256
# of each ar member.

fail() {
    echo "sign-linux-deb: $*" >&2
    exit 1
}

file_md5() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$1" | awk '{print $1}'
    else
        md5 -q "$1"
    fi
}

file_sha1() {
    if command -v sha1sum >/dev/null 2>&1; then
        sha1sum "$1" | awk '{print $1}'
    else
        shasum -a 1 "$1" | awk '{print $1}'
    fi
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
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
if ! command -v gpg >/dev/null 2>&1 || ! command -v ar >/dev/null 2>&1; then
    fail "gpg and ar are required"
fi

if command -v dpkg-sig >/dev/null 2>&1; then
    dpkg-sig --sign builder -k "$WARPTWEET_LINUX_GPG_KEY" "$WT_DEB"
    dpkg-sig --verify "$WT_DEB" || fail "dpkg-sig verification failed for $WT_DEB"
    echo "sign-linux-deb: signed $WT_DEB with dpkg-sig"
    exit 0
fi

WT_WORK=$(mktemp -d "${TMPDIR:-/tmp}/wt-debsign.XXXXXX")
cleanup() { rm -rf "$WT_WORK"; }
trap cleanup EXIT INT TERM
cd "$WT_WORK"

ar p "$WT_DEB" debian-binary >debian-binary
WT_CONTROL=$(ar t "$WT_DEB" | awk '/^control\.tar\./ {print; exit}')
WT_DATA=$(ar t "$WT_DEB" | awk '/^data\.tar\./ {print; exit}')
[ -n "$WT_CONTROL" ] && [ -n "$WT_DATA" ] || fail "deb is missing control or data members"
ar p "$WT_DEB" "$WT_CONTROL" >"$WT_CONTROL"
ar p "$WT_DEB" "$WT_DATA" >"$WT_DATA"

{
    echo "Version: 4"
    echo "Signer: WarpTweet Maintainers"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Role: builder"
    echo
    echo "Files:"
    for WT_MEMBER in debian-binary "$WT_CONTROL" "$WT_DATA"; do
        WT_SIZE=$(wc -c <"$WT_MEMBER" | tr -d ' ')
        echo " $(file_md5 "$WT_MEMBER") $(file_sha1 "$WT_MEMBER") $WT_SIZE $WT_MEMBER"
    done
    echo
    echo "SHA256:"
    for WT_MEMBER in debian-binary "$WT_CONTROL" "$WT_DATA"; do
        WT_SIZE=$(wc -c <"$WT_MEMBER" | tr -d ' ')
        echo " $(file_sha256 "$WT_MEMBER") $WT_SIZE $WT_MEMBER"
    done
} >signdata

gpg --batch --yes -u "$WARPTWEET_LINUX_GPG_KEY" --clearsign --output _gpgbuilder signdata
ar q "$WT_DEB" _gpgbuilder
gpg --verify _gpgbuilder >/dev/null
gpg --batch --yes -u "$WARPTWEET_LINUX_GPG_KEY" --armor --detach-sign --output "$WT_DEB.asc" "$WT_DEB"

echo "sign-linux-deb: signed $WT_DEB with gpg+ar (_gpgbuilder) and wrote $WT_DEB.asc"
