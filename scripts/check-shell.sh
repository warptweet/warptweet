#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Fetch the pinned ShellCheck binary and lint every POSIX script under
# scripts/ and packaging/. The pin table is the only allowed source identity.

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
. "$WT_REPOSITORY_ROOT/third_party/shellcheck/source.env"

list_scripts() {
    find "$WT_REPOSITORY_ROOT/scripts" "$WT_REPOSITORY_ROOT/packaging" \
        \( -name '*.sh' \
        -o -path "$WT_REPOSITORY_ROOT/packaging/macos/scripts/preinstall" \
        -o -path "$WT_REPOSITORY_ROOT/packaging/macos/scripts/postinstall" \) \
        -type f | LC_ALL=C sort
}

if [ "${1:-}" = "--list" ]; then
    if [ "$#" -ne 1 ]; then
        echo "usage: $0 [--list]" >&2
        exit 64
    fi
    list_scripts
    exit 0
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0 [--list]" >&2
    exit 64
fi

WT_KERNEL=$(uname -s)
WT_MACHINE=$(uname -m)
case "$WT_KERNEL:$WT_MACHINE" in
    Linux:x86_64 | Linux:amd64)
        WT_PLATFORM=linux.x86_64
        WT_ARCHIVE_SHA256=$SHELLCHECK_LINUX_X86_64_SHA256
        ;;
    Linux:aarch64 | Linux:arm64)
        WT_PLATFORM=linux.aarch64
        WT_ARCHIVE_SHA256=$SHELLCHECK_LINUX_AARCH64_SHA256
        ;;
    Darwin:x86_64)
        WT_PLATFORM=darwin.x86_64
        WT_ARCHIVE_SHA256=$SHELLCHECK_DARWIN_X86_64_SHA256
        ;;
    Darwin:arm64)
        WT_PLATFORM=darwin.aarch64
        WT_ARCHIVE_SHA256=$SHELLCHECK_DARWIN_AARCH64_SHA256
        ;;
    *)
        echo "no reviewed ShellCheck pin for $WT_KERNEL/$WT_MACHINE" >&2
        exit 65
        ;;
esac

WT_ARCHIVE="shellcheck-${SHELLCHECK_RELEASE_TAG}.${WT_PLATFORM}.tar.xz"
WT_URL="https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_RELEASE_TAG}/${WT_ARCHIVE}"
WT_CACHE="$WT_REPOSITORY_ROOT/.cache/shellcheck/${SHELLCHECK_RELEASE_TAG}/${WT_PLATFORM}"
WT_ARCHIVE_PATH="$WT_CACHE/$WT_ARCHIVE"

digest_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
        return 0
    fi
    shasum -a 256 "$1" | awk '{ print $1 }'
}

verify_archive() {
    WT_GOT=$(digest_file "$1")
    if [ "$WT_GOT" != "$WT_ARCHIVE_SHA256" ]; then
        echo "ShellCheck archive checksum mismatch for $WT_ARCHIVE" >&2
        exit 65
    fi
}

mkdir -p "$WT_CACHE"
if [ ! -f "$WT_ARCHIVE_PATH" ]; then
    WT_FETCH=$(mktemp -d)
    chmod 0700 "$WT_FETCH"
    trap 'rm -rf "$WT_FETCH"' EXIT
    curl --proto '=https' --tlsv1.2 --fail --location "$WT_URL" -o "$WT_FETCH/$WT_ARCHIVE"
    verify_archive "$WT_FETCH/$WT_ARCHIVE"
    mv "$WT_FETCH/$WT_ARCHIVE" "$WT_ARCHIVE_PATH"
    rm -rf "$WT_FETCH"
    trap - EXIT
fi
verify_archive "$WT_ARCHIVE_PATH"

WT_TMP=$(mktemp -d)
chmod 0700 "$WT_TMP"
trap 'rm -rf "$WT_TMP"' EXIT
tar -xJf "$WT_ARCHIVE_PATH" -C "$WT_TMP"
WT_BINARY="$WT_TMP/shellcheck-${SHELLCHECK_RELEASE_TAG}/shellcheck"
if [ ! -x "$WT_BINARY" ]; then
    echo "ShellCheck archive missing executable" >&2
    exit 65
fi

WT_REPORTED=$("$WT_BINARY" --version | awk '/^version:/ { print $2 }')
if [ "$WT_REPORTED" != "$SHELLCHECK_VERSION" ]; then
    echo "verified ShellCheck is $WT_REPORTED, want $SHELLCHECK_VERSION" >&2
    exit 65
fi

if ! list_scripts | grep -q .; then
    echo "check-shell: no scripts found" >&2
    exit 66
fi

list_scripts | tr '\n' '\0' | xargs -0 "$WT_BINARY" \
    -s sh \
    --norc \
    --severity=warning \
    --exclude=SC1007,SC1091
