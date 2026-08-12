#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ABSOLUTE_DESTINATION_DIRECTORY" >&2
    exit 64
fi

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
. "$WT_REPOSITORY_ROOT/third_party/openssh/source.env"

WT_DESTINATION_INPUT=$1
case "$WT_DESTINATION_INPUT" in
    /*) ;;
    *)
        echo "destination directory must be absolute" >&2
        exit 64
        ;;
esac
case "$WT_DESTINATION_INPUT" in
    /|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "destination directory must be a clean absolute path using safe ASCII characters" >&2
        exit 64
        ;;
esac
WT_DESTINATION_BASENAME=${WT_DESTINATION_INPUT##*/}
case "$WT_DESTINATION_BASENAME" in
    [A-Za-z0-9]*) ;;
    *)
        echo "destination directory must have an alphanumeric basename" >&2
        exit 64
        ;;
esac
case "$WT_DESTINATION_BASENAME" in
    *[!A-Za-z0-9._-]*)
        echo "destination directory basename contains an unsafe character" >&2
        exit 64
        ;;
esac
WT_DESTINATION_PARENT_INPUT=${WT_DESTINATION_INPUT%/*}
if [ -z "$WT_DESTINATION_PARENT_INPUT" ]; then
    WT_DESTINATION_PARENT_INPUT=/
fi
if [ ! -d "$WT_DESTINATION_PARENT_INPUT" ]; then
    echo "destination parent directory must already exist" >&2
    exit 66
fi
WT_DESTINATION_PARENT=$(CDPATH= cd -- "$WT_DESTINATION_PARENT_INPUT" 2>/dev/null && pwd -P) || {
    echo "cannot resolve destination parent directory" >&2
    exit 66
}
case "$WT_DESTINATION_PARENT" in
    /*) ;;
    *)
        echo "resolved destination parent must be absolute" >&2
        exit 66
        ;;
esac
case "$WT_DESTINATION_PARENT" in
    *//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "resolved destination parent path contains an unsafe character or component" >&2
        exit 66
        ;;
esac
if [ ! -d "$WT_DESTINATION_PARENT" ] || [ -L "$WT_DESTINATION_PARENT" ]; then
    echo "resolved destination parent must be a non-symlink directory" >&2
    exit 66
fi
WT_DESTINATION="$WT_DESTINATION_PARENT/$WT_DESTINATION_BASENAME"
if [ -e "$WT_DESTINATION" ] || [ -L "$WT_DESTINATION" ]; then
    echo "destination directory must not already exist" >&2
    exit 73
fi

for WT_TOOL in awk chmod curl gpg gpg-agent install mkdir mktemp mv rm stat; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        echo "required tool is unavailable: $WT_TOOL" >&2
        exit 69
    fi
done

if WT_DESTINATION_PARENT_ID=$(stat -c '%d:%i' "$WT_DESTINATION_PARENT" 2>/dev/null); then
    WT_STAT_STYLE=gnu
else
    WT_STAT_STYLE=bsd
    WT_DESTINATION_PARENT_ID=$(stat -f '%d:%i' "$WT_DESTINATION_PARENT" 2>/dev/null) || {
        echo "cannot identify destination parent directory" >&2
        exit 66
    }
fi

path_identity() {
    if [ "$WT_STAT_STYLE" = gnu ]; then
        stat -c '%d:%i' "$1" 2>/dev/null
    else
        stat -f '%d:%i' "$1" 2>/dev/null
    fi
}

assert_destination_parent_unchanged() {
    if [ ! -d "$WT_DESTINATION_PARENT" ] || [ -L "$WT_DESTINATION_PARENT" ]; then
        echo "destination parent directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_PARENT_ID=$(path_identity "$WT_DESTINATION_PARENT") || {
        echo "cannot re-identify destination parent directory" >&2
        return 1
    }
    if [ "$WT_CURRENT_PARENT_ID" != "$WT_DESTINATION_PARENT_ID" ]; then
        echo "destination parent directory identity changed" >&2
        return 1
    fi
}

WT_PRIVATE_ROOT=''
WT_PRIVATE_ROOT_ID=''
cleanup() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WT_PRIVATE_ROOT" ] && { [ -e "$WT_PRIVATE_ROOT" ] || [ -L "$WT_PRIVATE_ROOT" ]; }; then
        WT_CLEANUP_PARENT_ID=$(path_identity "$WT_DESTINATION_PARENT" 2>/dev/null || true)
        WT_CLEANUP_ROOT_ID=$(path_identity "$WT_PRIVATE_ROOT" 2>/dev/null || true)
        if [ -n "$WT_PRIVATE_ROOT_ID" ] &&
            [ -d "$WT_PRIVATE_ROOT" ] && [ ! -L "$WT_PRIVATE_ROOT" ] &&
            [ "$WT_CLEANUP_PARENT_ID" = "$WT_DESTINATION_PARENT_ID" ] &&
            [ "$WT_CLEANUP_ROOT_ID" = "$WT_PRIVATE_ROOT_ID" ]; then
            if ! rm -rf -- "$WT_PRIVATE_ROOT"; then
                echo "warning: could not remove private fetch directory $WT_PRIVATE_ROOT" >&2
                if [ "$WT_CLEANUP_STATUS" -eq 0 ]; then
                    WT_CLEANUP_STATUS=1
                fi
            fi
        else
            echo "warning: refusing cleanup because the private fetch path or parent was substituted" >&2
            if [ "$WT_CLEANUP_STATUS" -eq 0 ]; then
                WT_CLEANUP_STATUS=1
            fi
        fi
    fi
    exit "$WT_CLEANUP_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_private_root_unchanged() {
    assert_destination_parent_unchanged
    if [ ! -d "$WT_PRIVATE_ROOT" ] || [ -L "$WT_PRIVATE_ROOT" ]; then
        echo "private fetch directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_PRIVATE_ROOT_ID=$(path_identity "$WT_PRIVATE_ROOT") || {
        echo "cannot re-identify private fetch directory" >&2
        return 1
    }
    if [ "$WT_CURRENT_PRIVATE_ROOT_ID" != "$WT_PRIVATE_ROOT_ID" ]; then
        echo "private fetch directory identity changed" >&2
        return 1
    fi
}

WT_PRIVATE_ROOT=$(mktemp -d "$WT_DESTINATION_PARENT/.warptweet-openssh-fetch.XXXXXXXX")
case "$WT_PRIVATE_ROOT" in
    "$WT_DESTINATION_PARENT"/.warptweet-openssh-fetch.*) ;;
    *)
        echo "mktemp returned a path outside the destination parent" >&2
        WT_PRIVATE_ROOT=''
        exit 70
        ;;
esac
WT_PRIVATE_ROOT_ID=$(path_identity "$WT_PRIVATE_ROOT") || {
    echo "cannot identify private fetch directory" >&2
    exit 70
}
chmod 0700 "$WT_PRIVATE_ROOT"
assert_private_root_unchanged

WT_DOWNLOAD_DIRECTORY="$WT_PRIVATE_ROOT/download"
WT_PUBLICATION_DIRECTORY="$WT_PRIVATE_ROOT/publish"
WT_GNUPG_DIRECTORY="$WT_PRIVATE_ROOT/gnupg"
mkdir -m 0700 "$WT_DOWNLOAD_DIRECTORY" "$WT_GNUPG_DIRECTORY"
WT_ARCHIVE_PATH="$WT_DOWNLOAD_DIRECTORY/$OPENSSH_ARCHIVE"
WT_SIGNATURE_PATH="$WT_ARCHIVE_PATH.asc"
WT_RELEASE_KEY_PATH="$WT_DOWNLOAD_DIRECTORY/RELEASE_KEY.asc"
WT_SIGNATURE_STATUS_PATH="$WT_DOWNLOAD_DIRECTORY/signature.status"

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$WT_ARCHIVE_PATH" "$OPENSSH_SOURCE_URL"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$WT_SIGNATURE_PATH" "$OPENSSH_SIGNATURE_URL"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$WT_RELEASE_KEY_PATH" "$OPENSSH_RELEASE_KEY_URL"

if command -v sha256sum >/dev/null 2>&1; then
    WT_ACTUAL_SHA256=$(sha256sum "$WT_ARCHIVE_PATH" | awk '{print $1}')
else
    WT_ACTUAL_SHA256=$(shasum -a 256 "$WT_ARCHIVE_PATH" | awk '{print $1}')
fi
if [ "$WT_ACTUAL_SHA256" != "$OPENSSH_SOURCE_SHA256" ]; then
    echo "OpenSSH source SHA-256 mismatch" >&2
    exit 65
fi

if ! gpg --batch --show-keys --with-colons "$WT_RELEASE_KEY_PATH" 2>/dev/null | \
    awk -F: -v expected="$OPENSSH_RELEASE_KEY_FINGERPRINT" \
        '$1 == "fpr" && $10 == expected { found = 1 } END { exit(found ? 0 : 1) }'; then
    echo "OpenSSH release key fingerprint mismatch" >&2
    exit 65
fi
gpg --batch --quiet --homedir "$WT_GNUPG_DIRECTORY" --import "$WT_RELEASE_KEY_PATH"
if ! gpg --batch --homedir "$WT_GNUPG_DIRECTORY" --status-fd 1 \
    --verify "$WT_SIGNATURE_PATH" "$WT_ARCHIVE_PATH" >"$WT_SIGNATURE_STATUS_PATH"; then
    echo "OpenSSH release signature verification failed" >&2
    exit 65
fi
if ! awk -v expected="$OPENSSH_RELEASE_KEY_FINGERPRINT" \
    '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $3 == expected && $NF == expected { valid = 1 } END { exit(valid ? 0 : 1) }' \
    "$WT_SIGNATURE_STATUS_PATH"; then
    echo "OpenSSH release signature was not made by the pinned primary key" >&2
    exit 65
fi

assert_private_root_unchanged
mkdir -m 0755 "$WT_PUBLICATION_DIRECTORY"
install -m 0644 "$WT_ARCHIVE_PATH" "$WT_PUBLICATION_DIRECTORY/$OPENSSH_ARCHIVE"
install -m 0644 "$WT_SIGNATURE_PATH" "$WT_PUBLICATION_DIRECTORY/$OPENSSH_ARCHIVE.asc"
WT_PUBLICATION_ID=$(path_identity "$WT_PUBLICATION_DIRECTORY") || {
    echo "cannot identify private publication directory" >&2
    exit 70
}
assert_private_root_unchanged
WT_CURRENT_PUBLICATION_ID=$(path_identity "$WT_PUBLICATION_DIRECTORY") || {
    echo "cannot re-identify private publication directory" >&2
    exit 70
}
if [ ! -d "$WT_PUBLICATION_DIRECTORY" ] || [ -L "$WT_PUBLICATION_DIRECTORY" ] ||
    [ "$WT_CURRENT_PUBLICATION_ID" != "$WT_PUBLICATION_ID" ]; then
    echo "private publication directory identity changed" >&2
    exit 70
fi
if [ -e "$WT_DESTINATION" ] || [ -L "$WT_DESTINATION" ]; then
    echo "destination appeared before publication; refusing to overwrite it" >&2
    exit 73
fi
if [ "$WT_STAT_STYLE" = gnu ]; then
    mv -nT -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"
else
    mv -hn -- "$WT_PUBLICATION_DIRECTORY" "$WT_DESTINATION"
fi
assert_destination_parent_unchanged
if [ -e "$WT_PUBLICATION_DIRECTORY" ] || [ -L "$WT_PUBLICATION_DIRECTORY" ]; then
    echo "destination publication did not consume the private directory" >&2
    exit 73
fi
if [ ! -d "$WT_DESTINATION" ] || [ -L "$WT_DESTINATION" ]; then
    echo "published destination is missing or unsafe" >&2
    exit 73
fi
WT_PUBLISHED_ID=$(path_identity "$WT_DESTINATION") || {
    echo "cannot identify published destination" >&2
    exit 73
}
if [ "$WT_PUBLISHED_ID" != "$WT_PUBLICATION_ID" ]; then
    echo "published destination identity does not match the private directory" >&2
    exit 73
fi
echo "verified $OPENSSH_ARCHIVE ($OPENSSH_SOURCE_SHA256)"
