#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
umask 022

if [ "$#" -ne 3 ]; then
    echo "usage: $0 ABSOLUTE_OPENSSH_ARCHIVE ABSOLUTE_OPENSSL_ARCHIVE ABSOLUTE_NEW_STAGE_DIRECTORY" >&2
    exit 64
fi
if ! command -v id >/dev/null 2>&1; then
    echo "required tool is unavailable: id" >&2
    exit 69
fi
if [ "$(id -u)" = "0" ]; then
    echo "the OpenSSH regression build must run as its dedicated non-root account" >&2
    exit 77
fi

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
. "$WT_REPOSITORY_ROOT/third_party/openssh/source.env"
. "$WT_REPOSITORY_ROOT/third_party/openssl/source.env"

WT_OPENSSH_ARCHIVE_INPUT=$1
WT_OPENSSL_ARCHIVE_INPUT=$2
WT_FINAL_STAGE_INPUT=$3
for WT_INPUT_PATH in "$WT_OPENSSH_ARCHIVE_INPUT" "$WT_OPENSSL_ARCHIVE_INPUT" "$WT_FINAL_STAGE_INPUT"; do
    case "$WT_INPUT_PATH" in
        /*) ;;
        *)
            echo "source and stage paths must be absolute" >&2
            exit 64
            ;;
    esac
    case "$WT_INPUT_PATH" in
        /|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
            echo "source and stage paths must be clean absolute paths using safe ASCII characters" >&2
            exit 64
            ;;
    esac
    WT_INPUT_BASENAME=${WT_INPUT_PATH##*/}
    case "$WT_INPUT_BASENAME" in
        [A-Za-z0-9]*) ;;
        *)
            echo "source and stage paths must have alphanumeric basenames" >&2
            exit 64
            ;;
    esac
    case "$WT_INPUT_BASENAME" in
        *[!A-Za-z0-9._-]*)
            echo "source or stage basename contains an unsafe character" >&2
            exit 64
            ;;
    esac
done

WT_OPENSSH_ARCHIVE_BASENAME=${WT_OPENSSH_ARCHIVE_INPUT##*/}
WT_OPENSSH_PARENT_INPUT=${WT_OPENSSH_ARCHIVE_INPUT%/*}
if [ -z "$WT_OPENSSH_PARENT_INPUT" ]; then
    WT_OPENSSH_PARENT_INPUT=/
fi
if [ ! -d "$WT_OPENSSH_PARENT_INPUT" ]; then
    echo "OpenSSH archive parent directory must exist" >&2
    exit 66
fi
WT_OPENSSH_PARENT=$(CDPATH= cd -- "$WT_OPENSSH_PARENT_INPUT" 2>/dev/null && pwd -P) || {
    echo "cannot resolve OpenSSH archive parent directory" >&2
    exit 66
}
case "$WT_OPENSSH_PARENT" in
    /*) ;;
    *)
        echo "resolved OpenSSH archive parent must be absolute" >&2
        exit 66
        ;;
esac
case "$WT_OPENSSH_PARENT" in
    *//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "resolved OpenSSH archive parent path contains an unsafe character or component" >&2
        exit 66
        ;;
esac
if [ ! -d "$WT_OPENSSH_PARENT" ] || [ -L "$WT_OPENSSH_PARENT" ]; then
    echo "resolved OpenSSH archive parent must be a non-symlink directory" >&2
    exit 66
fi
WT_OPENSSH_ARCHIVE="$WT_OPENSSH_PARENT/$WT_OPENSSH_ARCHIVE_BASENAME"
if [ ! -f "$WT_OPENSSH_ARCHIVE" ] || [ -L "$WT_OPENSSH_ARCHIVE" ]; then
    echo "OpenSSH archive must be a regular non-symlink file" >&2
    exit 66
fi

WT_OPENSSL_ARCHIVE_BASENAME=${WT_OPENSSL_ARCHIVE_INPUT##*/}
WT_OPENSSL_PARENT_INPUT=${WT_OPENSSL_ARCHIVE_INPUT%/*}
if [ -z "$WT_OPENSSL_PARENT_INPUT" ]; then
    WT_OPENSSL_PARENT_INPUT=/
fi
if [ ! -d "$WT_OPENSSL_PARENT_INPUT" ]; then
    echo "OpenSSL archive parent directory must exist" >&2
    exit 66
fi
WT_OPENSSL_PARENT=$(CDPATH= cd -- "$WT_OPENSSL_PARENT_INPUT" 2>/dev/null && pwd -P) || {
    echo "cannot resolve OpenSSL archive parent directory" >&2
    exit 66
}
case "$WT_OPENSSL_PARENT" in
    /*) ;;
    *)
        echo "resolved OpenSSL archive parent must be absolute" >&2
        exit 66
        ;;
esac
case "$WT_OPENSSL_PARENT" in
    *//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "resolved OpenSSL archive parent path contains an unsafe character or component" >&2
        exit 66
        ;;
esac
if [ ! -d "$WT_OPENSSL_PARENT" ] || [ -L "$WT_OPENSSL_PARENT" ]; then
    echo "resolved OpenSSL archive parent must be a non-symlink directory" >&2
    exit 66
fi
WT_OPENSSL_ARCHIVE="$WT_OPENSSL_PARENT/$WT_OPENSSL_ARCHIVE_BASENAME"
if [ ! -f "$WT_OPENSSL_ARCHIVE" ] || [ -L "$WT_OPENSSL_ARCHIVE" ]; then
    echo "OpenSSL archive must be a regular non-symlink file" >&2
    exit 66
fi

WT_FINAL_STAGE_BASENAME=${WT_FINAL_STAGE_INPUT##*/}
WT_STAGE_PARENT_INPUT=${WT_FINAL_STAGE_INPUT%/*}
if [ -z "$WT_STAGE_PARENT_INPUT" ]; then
    WT_STAGE_PARENT_INPUT=/
fi
if [ ! -d "$WT_STAGE_PARENT_INPUT" ]; then
    echo "stage parent directory must already exist" >&2
    exit 66
fi
WT_STAGE_PARENT=$(CDPATH= cd -- "$WT_STAGE_PARENT_INPUT" 2>/dev/null && pwd -P) || {
    echo "cannot resolve stage parent directory" >&2
    exit 66
}
case "$WT_STAGE_PARENT" in
    /*) ;;
    *)
        echo "resolved stage parent must be absolute" >&2
        exit 66
        ;;
esac
case "$WT_STAGE_PARENT" in
    *//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "resolved stage parent path contains an unsafe character or component" >&2
        exit 66
        ;;
esac
if [ ! -d "$WT_STAGE_PARENT" ] || [ -L "$WT_STAGE_PARENT" ]; then
    echo "resolved stage parent must be a non-symlink directory" >&2
    exit 66
fi
WT_FINAL_STAGE_DIRECTORY="$WT_STAGE_PARENT/$WT_FINAL_STAGE_BASENAME"
if [ -e "$WT_FINAL_STAGE_DIRECTORY" ] || [ -L "$WT_FINAL_STAGE_DIRECTORY" ]; then
    echo "stage directory must not already exist" >&2
    exit 73
fi

for WT_TOOL in awk chmod getent getfacl id install make mkdir mktemp mv perl readelf rm setfacl sort stat sudo tar uname; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        echo "required tool is unavailable: $WT_TOOL" >&2
        exit 69
    fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "required SHA-256 tool is unavailable: sha256sum or shasum" >&2
    exit 69
fi

if [ "$(uname -s)" != Linux ]; then
    echo "the production OpenSSH/OpenSSL bundle build is supported only on Linux" >&2
    exit 69
fi
WT_BUILD_ARCHITECTURE=$(uname -m)
case "$WT_BUILD_ARCHITECTURE" in
    x86_64|aarch64) ;;
    *)
        echo "unsupported Linux production architecture: $WT_BUILD_ARCHITECTURE" >&2
        exit 65
        ;;
esac
WT_BUILD_ACCOUNT=warptweet-build
WT_BUILD_GROUP=warptweet-build
WT_BUILD_SHELL=/bin/sh
WT_UNPRIVILEGED_REGRESSION_ACCOUNT=nobody
if [ "${SUDO:-}" != "sudo" ]; then
    echo "SUDO must be exactly sudo for the pinned OpenSSH regression suite" >&2
    exit 77
fi
if [ -n "${TEST_SSH_UNSAFE_PERMISSIONS:-}" ]; then
    echo "TEST_SSH_UNSAFE_PERMISSIONS is forbidden for the private OpenSSH regression build" >&2
    exit 77
fi
WT_BUILD_UID=$(id -u)
WT_BUILD_GID=$(id -g)
case "$WT_BUILD_UID:$WT_BUILD_GID" in
    *[!0-9:]*|0:*|*:0)
        echo "the OpenSSH regression build account must have non-root numeric identifiers" >&2
        exit 77
        ;;
esac
if [ "$(id -un)" != "$WT_BUILD_ACCOUNT" ] ||
    [ "$(id -gn)" != "$WT_BUILD_GROUP" ] ||
    [ "$(id -Gn)" != "$WT_BUILD_GROUP" ]; then
    echo "the OpenSSH regression build must use only the dedicated account and group" >&2
    exit 77
fi
WT_BUILD_PASSWD_ENTRY=$(getent passwd "$WT_BUILD_ACCOUNT") || {
    echo "the dedicated OpenSSH regression passwd entry is unavailable" >&2
    exit 77
}
WT_PASSWD_UID=$(printf '%s\n' "$WT_BUILD_PASSWD_ENTRY" | awk -F: '{ print $3 }')
WT_PASSWD_GID=$(printf '%s\n' "$WT_BUILD_PASSWD_ENTRY" | awk -F: '{ print $4 }')
WT_BUILD_HOME=$(printf '%s\n' "$WT_BUILD_PASSWD_ENTRY" | awk -F: '{ print $6 }')
WT_PASSWD_SHELL=$(printf '%s\n' "$WT_BUILD_PASSWD_ENTRY" | awk -F: '{ print $7 }')
if ! printf '%s\n' "$WT_BUILD_PASSWD_ENTRY" | awk -F: \
    -v account="$WT_BUILD_ACCOUNT" \
    -v uid="$WT_BUILD_UID" \
    -v gid="$WT_BUILD_GID" \
    -v shell="$WT_BUILD_SHELL" '
        $1 == account && $3 == uid && $4 == gid && $7 == shell && NF == 7 { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "the dedicated OpenSSH regression passwd entry is invalid" >&2
    exit 77
fi
WT_BUILD_GROUP_ENTRY=$(getent group "$WT_BUILD_GROUP") || {
    echo "the dedicated OpenSSH regression group entry is unavailable" >&2
    exit 77
}
if ! printf '%s\n' "$WT_BUILD_GROUP_ENTRY" | awk -F: \
    -v group="$WT_BUILD_GROUP" \
    -v gid="$WT_BUILD_GID" '
        $1 == group && $3 == gid && $4 == "" && NF == 4 { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "the dedicated OpenSSH regression group entry is invalid" >&2
    exit 77
fi
if [ "$WT_PASSWD_UID" != "$WT_BUILD_UID" ] ||
    [ "$WT_PASSWD_GID" != "$WT_BUILD_GID" ] ||
    [ "$WT_PASSWD_SHELL" != "$WT_BUILD_SHELL" ] ||
    [ ! -x "$WT_BUILD_SHELL" ]; then
    echo "the dedicated OpenSSH regression identity does not match its pinned account contract" >&2
    exit 77
fi
case "$WT_BUILD_HOME" in
    /*) ;;
    *)
        echo "the dedicated OpenSSH regression home must be absolute" >&2
        exit 77
        ;;
esac
case "$WT_BUILD_HOME" in
    /|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
        echo "the dedicated OpenSSH regression home path is unsafe" >&2
        exit 77
        ;;
esac
if [ "${HOME:-}" != "$WT_BUILD_HOME" ] ||
    [ ! -d "$WT_BUILD_HOME" ] || [ -L "$WT_BUILD_HOME" ]; then
    echo "HOME must be the dedicated non-symlink OpenSSH regression home" >&2
    exit 77
fi
WT_BUILD_HOME_PHYSICAL=$(CDPATH= cd -- "$WT_BUILD_HOME" 2>/dev/null && pwd -P) || {
    echo "cannot resolve the dedicated OpenSSH regression home" >&2
    exit 77
}
if [ "$WT_BUILD_HOME_PHYSICAL" != "$WT_BUILD_HOME" ]; then
    echo "the dedicated OpenSSH regression home must not traverse symlinks" >&2
    exit 77
fi
if WT_BUILD_HOME_METADATA=$(stat -c '%u:%g:%a' "$WT_BUILD_HOME" 2>/dev/null); then
    :
else
    WT_BUILD_HOME_METADATA=$(stat -f '%u:%g:%Lp' "$WT_BUILD_HOME" 2>/dev/null) || {
        echo "cannot inspect the dedicated OpenSSH regression home" >&2
        exit 77
    }
fi
if [ "$WT_BUILD_HOME_METADATA" != "$WT_BUILD_UID:$WT_BUILD_GID:700" ]; then
    echo "the dedicated OpenSSH regression home must be account-owned mode 0700" >&2
    exit 77
fi
WT_PRIVATE_DIRECTORY_ACL='user::rwx
group::---
other::---'
if [ "$(getfacl -cp "$WT_BUILD_HOME" 2>/dev/null || true)" != "$WT_PRIVATE_DIRECTORY_ACL" ]; then
    echo "the dedicated OpenSSH regression home must not have an extended ACL" >&2
    exit 77
fi
WT_NOBODY_ENTRY=$(getent passwd "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT") || {
    echo "the upstream cross-UID regression account is unavailable" >&2
    exit 77
}
if ! printf '%s\n' "$WT_NOBODY_ENTRY" | awk -F: '
    $1 == "nobody" && $3 ~ /^[0-9]+$/ && $3 != 0 && NF == 7 { found = 1 }
    END { exit(found ? 0 : 1) }
'; then
    echo "the upstream cross-UID regression account is invalid" >&2
    exit 77
fi
if ! sudo -n sh -c '
    set -eu
    WT_SHADOW_ENTRY=$(getent shadow "$1")
    WT_SHADOW_REMAINDER=${WT_SHADOW_ENTRY#*:}
    [ "$WT_SHADOW_REMAINDER" != "$WT_SHADOW_ENTRY" ]
    WT_SHADOW_PASSWORD=${WT_SHADOW_REMAINDER%%:*}
    [ "$WT_SHADOW_PASSWORD" = "*NP*" ]
' sh "$WT_BUILD_ACCOUNT" >/dev/null 2>&1; then
    echo "the dedicated OpenSSH regression account lacks its required non-password sentinel" >&2
    exit 77
fi
if ! sudo -n true >/dev/null 2>&1 ||
    ! sudo -n -u "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT" true >/dev/null 2>&1; then
    echo "the dedicated OpenSSH regression account lacks its required non-interactive run-as policy" >&2
    exit 77
fi
for WT_PRIVATE_PARENT in "$WT_OPENSSH_PARENT" "$WT_OPENSSL_PARENT" "$WT_STAGE_PARENT"; do
    case "$WT_PRIVATE_PARENT" in
        "$WT_BUILD_HOME"|"$WT_BUILD_HOME"/*) ;;
        *)
            echo "source archives and stage must remain inside the private build home" >&2
            exit 77
            ;;
    esac
done
if [ "$OPENSSL_LOGICAL_PREFIX" != /opt/warptweet/libexec/openssl-static ] ||
    [ "$OPENSSL_LOGICAL_CONFIG_DIRECTORY" != /opt/warptweet/etc/openssl-static ]; then
    echo "OpenSSL logical install layout does not match the production contract" >&2
    exit 65
fi

if WT_STAGE_PARENT_ID=$(stat -c '%d:%i' "$WT_STAGE_PARENT" 2>/dev/null); then
    WT_STAT_STYLE=gnu
else
    WT_STAT_STYLE=bsd
    WT_STAGE_PARENT_ID=$(stat -f '%d:%i' "$WT_STAGE_PARENT" 2>/dev/null) || {
        echo "cannot identify stage parent directory" >&2
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

WT_BUILD_HOME_ID=$(path_identity "$WT_BUILD_HOME") || {
    echo "cannot identify the dedicated OpenSSH regression home" >&2
    exit 77
}

assert_stage_parent_unchanged() {
    if [ ! -d "$WT_STAGE_PARENT" ] || [ -L "$WT_STAGE_PARENT" ]; then
        echo "stage parent directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_STAGE_PARENT_ID=$(path_identity "$WT_STAGE_PARENT") || {
        echo "cannot re-identify stage parent directory" >&2
        return 1
    }
    if [ "$WT_CURRENT_STAGE_PARENT_ID" != "$WT_STAGE_PARENT_ID" ]; then
        echo "stage parent directory identity changed" >&2
        return 1
    fi
}

WT_OPENSSH_PARENT_ID=$(path_identity "$WT_OPENSSH_PARENT") || {
    echo "cannot identify OpenSSH archive parent directory" >&2
    exit 66
}
WT_OPENSSH_ARCHIVE_ID=$(path_identity "$WT_OPENSSH_ARCHIVE") || {
    echo "cannot identify OpenSSH archive" >&2
    exit 66
}
WT_OPENSSL_PARENT_ID=$(path_identity "$WT_OPENSSL_PARENT") || {
    echo "cannot identify OpenSSL archive parent directory" >&2
    exit 66
}
WT_OPENSSL_ARCHIVE_ID=$(path_identity "$WT_OPENSSL_ARCHIVE") || {
    echo "cannot identify OpenSSL archive" >&2
    exit 66
}
assert_sources_unchanged() {
    if [ ! -d "$WT_OPENSSH_PARENT" ] || [ -L "$WT_OPENSSH_PARENT" ]; then
        echo "OpenSSH archive parent directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_OPENSSH_PARENT_ID=$(path_identity "$WT_OPENSSH_PARENT") || {
        echo "cannot re-identify OpenSSH archive parent directory" >&2
        return 1
    }
    WT_CURRENT_OPENSSH_ID=$(path_identity "$WT_OPENSSH_ARCHIVE") || {
        echo "cannot re-identify OpenSSH archive" >&2
        return 1
    }
    if [ "$WT_CURRENT_OPENSSH_PARENT_ID" != "$WT_OPENSSH_PARENT_ID" ] ||
        [ "$WT_CURRENT_OPENSSH_ID" != "$WT_OPENSSH_ARCHIVE_ID" ] ||
        [ ! -f "$WT_OPENSSH_ARCHIVE" ] || [ -L "$WT_OPENSSH_ARCHIVE" ]; then
        echo "OpenSSH archive or its parent changed during the build" >&2
        return 1
    fi
    if [ ! -d "$WT_OPENSSL_PARENT" ] || [ -L "$WT_OPENSSL_PARENT" ]; then
        echo "OpenSSL archive parent directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_OPENSSL_PARENT_ID=$(path_identity "$WT_OPENSSL_PARENT") || {
        echo "cannot re-identify OpenSSL archive parent directory" >&2
        return 1
    }
    WT_CURRENT_OPENSSL_ID=$(path_identity "$WT_OPENSSL_ARCHIVE") || {
        echo "cannot re-identify OpenSSL archive" >&2
        return 1
    }
    if [ "$WT_CURRENT_OPENSSL_PARENT_ID" != "$WT_OPENSSL_PARENT_ID" ] ||
        [ "$WT_CURRENT_OPENSSL_ID" != "$WT_OPENSSL_ARCHIVE_ID" ] ||
        [ ! -f "$WT_OPENSSL_ARCHIVE" ] || [ -L "$WT_OPENSSL_ARCHIVE" ]; then
        echo "OpenSSL archive or its parent changed during the build" >&2
        return 1
    fi
}

WT_BUILD_ROOT=''
WT_BUILD_ROOT_ID=''
WT_OPENSSH_SOURCE_ROOT_ID=''
WT_REGRESSION_ACL_ACTIVE=0

restore_regression_acl() {
    if [ "$WT_REGRESSION_ACL_ACTIVE" -ne 1 ]; then
        return 0
    fi
    WT_CURRENT_HOME_ID=$(path_identity "$WT_BUILD_HOME" 2>/dev/null || true)
    WT_CURRENT_BUILD_ROOT_ID=$(path_identity "$WT_BUILD_ROOT" 2>/dev/null || true)
    WT_CURRENT_SOURCE_ROOT_ID=$(path_identity "$WT_OPENSSH_SOURCE_ROOT" 2>/dev/null || true)
    if [ ! -d "$WT_BUILD_HOME" ] || [ -L "$WT_BUILD_HOME" ] ||
        [ ! -d "$WT_BUILD_ROOT" ] || [ -L "$WT_BUILD_ROOT" ] ||
        [ ! -d "$WT_OPENSSH_SOURCE_ROOT" ] || [ -L "$WT_OPENSSH_SOURCE_ROOT" ] ||
        [ "$WT_CURRENT_HOME_ID" != "$WT_BUILD_HOME_ID" ] ||
        [ "$WT_CURRENT_BUILD_ROOT_ID" != "$WT_BUILD_ROOT_ID" ] ||
        [ "$WT_CURRENT_SOURCE_ROOT_ID" != "$WT_OPENSSH_SOURCE_ROOT_ID" ]; then
        echo "refusing to restore regression ACLs through a substituted path" >&2
        return 1
    fi

    WT_ACL_RESTORE_STATUS=0
    for WT_ACL_PATH in "$WT_BUILD_HOME" "$WT_BUILD_ROOT" "$WT_OPENSSH_SOURCE_ROOT"; do
        if ! setfacl -b "$WT_ACL_PATH"; then
            WT_ACL_RESTORE_STATUS=1
        fi
        if ! chmod 0700 "$WT_ACL_PATH"; then
            WT_ACL_RESTORE_STATUS=1
        fi
        if [ "$(getfacl -cp "$WT_ACL_PATH" 2>/dev/null || true)" != "$WT_PRIVATE_DIRECTORY_ACL" ]; then
            WT_ACL_RESTORE_STATUS=1
        fi
    done
    if [ "$WT_ACL_RESTORE_STATUS" -ne 0 ]; then
        echo "could not restore the private OpenSSH regression directory ACLs" >&2
        return 1
    fi
    WT_REGRESSION_ACL_ACTIVE=0
}

cleanup() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
    if ! restore_regression_acl; then
        if [ "$WT_CLEANUP_STATUS" -eq 0 ]; then
            WT_CLEANUP_STATUS=1
        fi
    fi
    if [ -n "$WT_BUILD_ROOT" ] && { [ -e "$WT_BUILD_ROOT" ] || [ -L "$WT_BUILD_ROOT" ]; }; then
        WT_CLEANUP_PARENT_ID=$(path_identity "$WT_STAGE_PARENT" 2>/dev/null || true)
        WT_CLEANUP_ROOT_ID=$(path_identity "$WT_BUILD_ROOT" 2>/dev/null || true)
        if [ -n "$WT_BUILD_ROOT_ID" ] &&
            [ -d "$WT_BUILD_ROOT" ] && [ ! -L "$WT_BUILD_ROOT" ] &&
            [ "$WT_CLEANUP_PARENT_ID" = "$WT_STAGE_PARENT_ID" ] &&
            [ "$WT_CLEANUP_ROOT_ID" = "$WT_BUILD_ROOT_ID" ]; then
            if ! rm -rf -- "$WT_BUILD_ROOT"; then
                echo "warning: could not remove private build directory $WT_BUILD_ROOT" >&2
                if [ "$WT_CLEANUP_STATUS" -eq 0 ]; then
                    WT_CLEANUP_STATUS=1
                fi
            fi
        else
            echo "warning: refusing cleanup because the private build path or parent was substituted" >&2
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

assert_private_build_root_unchanged() {
    assert_stage_parent_unchanged
    if [ ! -d "$WT_BUILD_ROOT" ] || [ -L "$WT_BUILD_ROOT" ]; then
        echo "private build directory was substituted" >&2
        return 1
    fi
    WT_CURRENT_BUILD_ROOT_ID=$(path_identity "$WT_BUILD_ROOT") || {
        echo "cannot re-identify private build directory" >&2
        return 1
    }
    if [ "$WT_CURRENT_BUILD_ROOT_ID" != "$WT_BUILD_ROOT_ID" ]; then
        echo "private build directory identity changed" >&2
        return 1
    fi
}

WT_BUILD_ROOT=$(mktemp -d "$WT_STAGE_PARENT/.wtb.XXXXXXXX")
case "$WT_BUILD_ROOT" in
    "$WT_STAGE_PARENT"/.wtb.*) ;;
    *)
        echo "mktemp returned a path outside the stage parent" >&2
        WT_BUILD_ROOT=''
        exit 70
        ;;
esac
WT_BUILD_ROOT_ID=$(path_identity "$WT_BUILD_ROOT") || {
    echo "cannot identify private build directory" >&2
    exit 70
}
chmod 0700 "$WT_BUILD_ROOT"
assert_private_build_root_unchanged
WT_PRIVATE_OPENSSH_ARCHIVE="$WT_BUILD_ROOT/openssh-source-archive.tar.gz"
WT_PRIVATE_OPENSSL_ARCHIVE="$WT_BUILD_ROOT/openssl-source-archive.tar.gz"
WT_OPENSSH_SOURCE_ROOT="$WT_BUILD_ROOT/s"
WT_OPENSSL_SOURCE_ROOT="$WT_BUILD_ROOT/l"
assert_sources_unchanged
install -m 0600 "$WT_OPENSSH_ARCHIVE" "$WT_PRIVATE_OPENSSH_ARCHIVE"
install -m 0600 "$WT_OPENSSL_ARCHIVE" "$WT_PRIVATE_OPENSSL_ARCHIVE"
assert_sources_unchanged

if command -v sha256sum >/dev/null 2>&1; then
    WT_OPENSSH_ACTUAL_SHA256=$(sha256sum "$WT_PRIVATE_OPENSSH_ARCHIVE" | awk '{print $1}')
    WT_OPENSSL_ACTUAL_SHA256=$(sha256sum "$WT_PRIVATE_OPENSSL_ARCHIVE" | awk '{print $1}')
else
    WT_OPENSSH_ACTUAL_SHA256=$(shasum -a 256 "$WT_PRIVATE_OPENSSH_ARCHIVE" | awk '{print $1}')
    WT_OPENSSL_ACTUAL_SHA256=$(shasum -a 256 "$WT_PRIVATE_OPENSSL_ARCHIVE" | awk '{print $1}')
fi
if [ "$WT_OPENSSH_ACTUAL_SHA256" != "$OPENSSH_SOURCE_SHA256" ]; then
    echo "OpenSSH source SHA-256 mismatch" >&2
    exit 65
fi
if [ "$WT_OPENSSL_ACTUAL_SHA256" != "$OPENSSL_SOURCE_SHA256" ]; then
    echo "OpenSSL source SHA-256 mismatch" >&2
    exit 65
fi

mkdir -m 0700 "$WT_OPENSSH_SOURCE_ROOT" "$WT_OPENSSL_SOURCE_ROOT"
WT_OPENSSH_SOURCE_ROOT_ID=$(path_identity "$WT_OPENSSH_SOURCE_ROOT") || {
    echo "cannot identify the private OpenSSH source root" >&2
    exit 70
}
tar -xzf "$WT_PRIVATE_OPENSSH_ARCHIVE" -C "$WT_OPENSSH_SOURCE_ROOT"
tar -xzf "$WT_PRIVATE_OPENSSL_ARCHIVE" -C "$WT_OPENSSL_SOURCE_ROOT"
WT_OPENSSH_SOURCE_DIRECTORY="$WT_OPENSSH_SOURCE_ROOT/openssh-$OPENSSH_VERSION"
WT_OPENSSL_SOURCE_DIRECTORY="$WT_OPENSSL_SOURCE_ROOT/openssl-$OPENSSL_VERSION"
WT_OPENSSH_REGRESSION_DIRECTORY="$WT_OPENSSH_SOURCE_DIRECTORY/regress"
# forward-control.sh creates $OBJ/ctl-sock through a temporary name containing
# a dot plus 16 random bytes. Linux sun_path permits 107 pathname bytes plus
# its terminating NUL, so $OBJ may contain at most 81 bytes.
if [ "${#WT_OPENSSH_REGRESSION_DIRECTORY}" -gt 81 ]; then
    echo "private OpenSSH regression path exceeds the Linux control-socket budget" >&2
    exit 65
fi
if [ ! -x "$WT_OPENSSH_SOURCE_DIRECTORY/configure" ] ||
    [ ! -x "$WT_OPENSSH_SOURCE_DIRECTORY/config.guess" ]; then
    echo "OpenSSH archive did not contain the expected source tree" >&2
    exit 65
fi
if [ ! -x "$WT_OPENSSL_SOURCE_DIRECTORY/Configure" ] ||
    [ ! -f "$WT_OPENSSL_SOURCE_DIRECTORY/LICENSE.txt" ] ||
    [ -L "$WT_OPENSSL_SOURCE_DIRECTORY/LICENSE.txt" ]; then
    echo "OpenSSL archive did not contain the expected source tree and license" >&2
    exit 65
fi

if command -v nproc >/dev/null 2>&1; then
    WT_BUILD_JOBS=$(nproc)
else
    WT_BUILD_JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

WT_PRIVATE_STAGE_DIRECTORY="$WT_BUILD_ROOT/publish"
mkdir -m 0755 "$WT_PRIVATE_STAGE_DIRECTORY"
WT_PRIVATE_STAGE_ID=$(path_identity "$WT_PRIVATE_STAGE_DIRECTORY") || {
    echo "cannot identify private stage directory" >&2
    exit 70
}
WT_STAGE_DIRECTORY="$WT_PRIVATE_STAGE_DIRECTORY"

WT_OPENSSL_DESTDIR="$WT_BUILD_ROOT/openssl-destdir"
mkdir -m 0700 "$WT_OPENSSL_DESTDIR"
cd "$WT_OPENSSL_SOURCE_DIRECTORY"
LC_ALL=C ./Configure \
    "--prefix=$OPENSSL_LOGICAL_PREFIX" \
    "--openssldir=$OPENSSL_LOGICAL_CONFIG_DIRECTORY" \
    --libdir=lib \
    no-shared \
    no-module \
    no-dso \
    no-pinshared
LC_ALL=C make -j "$WT_BUILD_JOBS"
LC_ALL=C make test
LC_ALL=C make install_sw "DESTDIR=$WT_OPENSSL_DESTDIR"

WT_OPENSSL_PREFIX_PHYSICAL="$WT_OPENSSL_DESTDIR$OPENSSL_LOGICAL_PREFIX"
WT_OPENSSL_STATIC_CRYPTO="$WT_OPENSSL_PREFIX_PHYSICAL/lib/libcrypto.a"
if [ ! -f "$WT_OPENSSL_STATIC_CRYPTO" ] || [ -L "$WT_OPENSSL_STATIC_CRYPTO" ]; then
    echo "private OpenSSL install did not produce a regular static libcrypto archive" >&2
    exit 65
fi
if command -v sha256sum >/dev/null 2>&1; then
    WT_OPENSSL_STATIC_CRYPTO_SHA256=$(sha256sum "$WT_OPENSSL_STATIC_CRYPTO" | awk '{print $1}')
else
    WT_OPENSSL_STATIC_CRYPTO_SHA256=$(shasum -a 256 "$WT_OPENSSL_STATIC_CRYPTO" | awk '{print $1}')
fi
for WT_DYNAMIC_CRYPTO in \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libcrypto.so* \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libssl.so*; do
    if [ -e "$WT_DYNAMIC_CRYPTO" ] || [ -L "$WT_DYNAMIC_CRYPTO" ]; then
        echo "private OpenSSL install unexpectedly produced a shared crypto library" >&2
        exit 65
    fi
done

WT_EMPTY_PKG_CONFIG="$WT_BUILD_ROOT/empty-pkg-config"
mkdir -m 0700 "$WT_EMPTY_PKG_CONFIG"
cd "$WT_OPENSSH_SOURCE_DIRECTORY"
WT_TARGET_TUPLE=$(LC_ALL=C ./config.guess)
case "$WT_TARGET_TUPLE" in
    ''|*[!A-Za-z0-9._-]*)
        echo "OpenSSH target tuple is empty or contains unsafe characters" >&2
        exit 65
        ;;
esac
case "$WT_BUILD_ARCHITECTURE:$WT_TARGET_TUPLE" in
    x86_64:x86_64-*|aarch64:aarch64-*) ;;
    *)
        echo "OpenSSH target tuple does not match the native production architecture" >&2
        exit 65
        ;;
esac
set -- \
    --prefix=/opt/warptweet/libexec/openssh \
    --sysconfdir=/opt/warptweet/etc/openssh \
    --with-privsep-user=warptweet-sshd \
    --with-privsep-path=/var/empty/warptweet-sshd \
    --with-hardening \
	--with-pie \
	--without-kerberos5 \
	--without-ldns \
	--without-libedit \
	--without-pam \
	--without-rpath \
	--without-selinux \
	--without-zlib \
    "--with-ssl-dir=$WT_OPENSSL_PREFIX_PHYSICAL"
CPPFLAGS="-I$WT_OPENSSL_PREFIX_PHYSICAL/include" \
LDFLAGS="-L$WT_OPENSSL_PREFIX_PHYSICAL/lib" \
LIBS='' \
PKG_CONFIG_PATH='' \
PKG_CONFIG_LIBDIR="$WT_EMPTY_PKG_CONFIG" \
LC_ALL=C ./configure "$@"
LC_ALL=C make -j "$WT_BUILD_JOBS"
for WT_ACL_PATH in "$WT_BUILD_ROOT" "$WT_OPENSSH_SOURCE_ROOT"; do
    if [ "$(getfacl -cp "$WT_ACL_PATH" 2>/dev/null || true)" != "$WT_PRIVATE_DIRECTORY_ACL" ]; then
        echo "a private OpenSSH regression directory has an unexpected ACL" >&2
        exit 77
    fi
done
WT_REGRESSION_ACL_ACTIVE=1
if ! setfacl -m "u:$WT_UNPRIVILEGED_REGRESSION_ACCOUNT:--x" \
    "$WT_BUILD_HOME" "$WT_BUILD_ROOT" "$WT_OPENSSH_SOURCE_ROOT"; then
    echo "could not grant temporary cross-UID regression traversal" >&2
    exit 77
fi
if ! sudo -n -u "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT" \
    test -x "$WT_OPENSSH_SOURCE_DIRECTORY/ssh-add" >/dev/null 2>&1; then
    echo "the upstream cross-UID regression account cannot execute the built ssh-add" >&2
    exit 77
fi
if LC_ALL=C make tests; then
    WT_OPENSSH_TEST_STATUS=0
else
    WT_OPENSSH_TEST_STATUS=$?
fi
if ! restore_regression_acl; then
    exit 77
fi
if [ "$WT_OPENSSH_TEST_STATUS" -ne 0 ]; then
    exit "$WT_OPENSSH_TEST_STATUS"
fi

# Apply the grant hook only after upstream tests. The hook fail-closes when
# the WarpTweet grant socket is absent, which is correct in production and
# would reject OpenSSH's own pubkey-connect tests.
"$WT_REPOSITORY_ROOT/scripts/apply-openssh-grant-hook.sh" "$WT_OPENSSH_SOURCE_DIRECTORY"
if [ -x "$WT_OPENSSH_SOURCE_DIRECTORY/config.status" ]; then
    (CDPATH= cd -- "$WT_OPENSSH_SOURCE_DIRECTORY" && LC_ALL=C ./config.status)
fi
LC_ALL=C make -j "$WT_BUILD_JOBS" sshd sshd-session

WT_INSTALL_PREFIX="$WT_STAGE_DIRECTORY/opt/warptweet/libexec/openssh"
mkdir -p \
	"$WT_INSTALL_PREFIX/bin" \
	"$WT_INSTALL_PREFIX/sbin" \
	"$WT_INSTALL_PREFIX/libexec" \
	"$WT_STAGE_DIRECTORY/var/empty/warptweet-sshd"
chmod 0755 "$WT_STAGE_DIRECTORY/var/empty/warptweet-sshd"
install -m 0755 ssh "$WT_INSTALL_PREFIX/bin/ssh"
install -m 0755 ssh-keygen "$WT_INSTALL_PREFIX/bin/ssh-keygen"
install -m 0755 sshd "$WT_INSTALL_PREFIX/sbin/sshd"
install -m 0755 sshd-auth "$WT_INSTALL_PREFIX/libexec/sshd-auth"
install -m 0755 sshd-session "$WT_INSTALL_PREFIX/libexec/sshd-session"

WT_READELF_DYNAMIC="$WT_BUILD_ROOT/readelf-dynamic.txt"
for WT_EXECUTABLE in \
    "$WT_INSTALL_PREFIX/bin/ssh" \
    "$WT_INSTALL_PREFIX/bin/ssh-keygen" \
    "$WT_INSTALL_PREFIX/sbin/sshd" \
    "$WT_INSTALL_PREFIX/libexec/sshd-auth" \
    "$WT_INSTALL_PREFIX/libexec/sshd-session"; do
    if ! readelf -h --wide "$WT_EXECUTABLE" >/dev/null 2>&1; then
        echo "staged OpenSSH executable is not a readable ELF file: $WT_EXECUTABLE" >&2
        exit 65
    fi
    if ! readelf -d --wide "$WT_EXECUTABLE" >"$WT_READELF_DYNAMIC"; then
        echo "cannot inspect staged OpenSSH executable dynamic metadata: $WT_EXECUTABLE" >&2
        exit 65
    fi
    if awk '
        /\(RPATH\)|\(RUNPATH\)/ { rejected = 1 }
        /\(NEEDED\)/ && ($0 ~ /libcrypto/ || $0 ~ /libssl/) { rejected = 1 }
        END { exit(rejected ? 0 : 1) }
    ' "$WT_READELF_DYNAMIC"; then
        echo "staged OpenSSH executable has a forbidden crypto dependency or loader path: $WT_EXECUTABLE" >&2
        exit 65
    fi
done

WT_OPENSSH_LICENSE_SOURCE="$WT_OPENSSH_SOURCE_DIRECTORY/LICENCE"
if [ ! -f "$WT_OPENSSH_LICENSE_SOURCE" ] || [ -L "$WT_OPENSSH_LICENSE_SOURCE" ]; then
    echo "OpenSSH archive did not contain a regular LICENCE file" >&2
    exit 65
fi
mkdir -p \
    "$WT_STAGE_DIRECTORY/opt/warptweet/share/licenses/openssh" \
    "$WT_STAGE_DIRECTORY/opt/warptweet/share/licenses/openssl"
install -m 0644 "$WT_OPENSSH_LICENSE_SOURCE" \
    "$WT_STAGE_DIRECTORY/opt/warptweet/share/licenses/openssh/LICENCE"
install -m 0644 "$WT_OPENSSL_SOURCE_DIRECTORY/LICENSE.txt" \
    "$WT_STAGE_DIRECTORY/opt/warptweet/share/licenses/openssl/LICENSE.txt"

WT_INSTALLED_SSHD="$WT_INSTALL_PREFIX/sbin/sshd"
if command -v sha256sum >/dev/null 2>&1; then
    WT_SSHD_SHA256=$(sha256sum "$WT_INSTALLED_SSHD" | awk '{print $1}')
else
    WT_SSHD_SHA256=$(shasum -a 256 "$WT_INSTALLED_SSHD" | awk '{print $1}')
fi

WT_RECEIPT="$WT_STAGE_DIRECTORY/opt/warptweet/share/openssh-source.txt"
{
	echo "receipt_version=1"
	echo "version=$OPENSSH_VERSION"
	echo "engine_version=OpenSSH_10.4p1"
	echo "source_url=$OPENSSH_SOURCE_URL"
	echo "source_sha256=$OPENSSH_SOURCE_SHA256"
	echo "release_key_fingerprint=$OPENSSH_RELEASE_KEY_FINGERPRINT"
	echo "configure_prefix=/opt/warptweet/libexec/openssh"
	echo "sysconfdir=/opt/warptweet/etc/openssh"
	echo "privsep_user=warptweet-sshd"
	echo "privsep_path=/var/empty/warptweet-sshd"
	echo "hardening=yes"
	echo "pie=yes"
	echo "kerberos5=no"
	echo "ldns=no"
	echo "libedit=no"
	echo "pam=no"
	echo "selinux=no"
	echo "zlib=no"
	echo "sshd_path=/opt/warptweet/libexec/openssh/sbin/sshd"
	echo "sshd_sha256=$WT_SSHD_SHA256"
	echo "target_tuple=$WT_TARGET_TUPLE"
	echo "openssl_prefix=$OPENSSL_LOGICAL_PREFIX"
	echo "openssl_source_receipt_path=/opt/warptweet/share/openssl-source.txt"
	echo "openssl_source_sha256=$OPENSSL_SOURCE_SHA256"
	echo "openssl_linkage=static"
	echo "elf_dynamic_policy=passed"
	echo "tests=passed"
} >"$WT_RECEIPT"
chmod 0644 "$WT_RECEIPT"

WT_OPENSSL_RECEIPT="$WT_STAGE_DIRECTORY/opt/warptweet/share/openssl-source.txt"
{
	echo "receipt_version=1"
	echo "version=$OPENSSL_VERSION"
	echo "source_url=$OPENSSL_SOURCE_URL"
	echo "source_sha256=$OPENSSL_SOURCE_SHA256"
	echo "release_key_fingerprint=$OPENSSL_RELEASE_KEY_FINGERPRINT"
	echo "platform=linux"
	echo "architecture=$WT_BUILD_ARCHITECTURE"
	echo "configure_prefix=$OPENSSL_LOGICAL_PREFIX"
	echo "openssl_config_directory=$OPENSSL_LOGICAL_CONFIG_DIRECTORY"
	echo "shared=no"
	echo "module=no"
	echo "dso=no"
	echo "pinshared=no"
	echo "tests=passed"
	echo "linkage=static"
	echo "static_libcrypto_sha256=$WT_OPENSSL_STATIC_CRYPTO_SHA256"
	echo "license_path=/opt/warptweet/share/licenses/openssl/LICENSE.txt"
} >"$WT_OPENSSL_RECEIPT"
chmod 0644 "$WT_OPENSSL_RECEIPT"

WT_HASHES="$WT_STAGE_DIRECTORY/opt/warptweet/share/openssh-bundle.sha256"
(
	cd "$WT_STAGE_DIRECTORY"
	printf '%s\n' \
		opt/warptweet/libexec/openssh/bin/ssh \
		opt/warptweet/libexec/openssh/bin/ssh-keygen \
		opt/warptweet/libexec/openssh/libexec/sshd-auth \
		opt/warptweet/libexec/openssh/libexec/sshd-session \
		opt/warptweet/libexec/openssh/sbin/sshd \
		opt/warptweet/share/licenses/openssh/LICENCE \
		opt/warptweet/share/licenses/openssl/LICENSE.txt \
		opt/warptweet/share/openssh-source.txt \
		opt/warptweet/share/openssl-source.txt | \
		LC_ALL=C sort | while IFS= read -r WT_FILE; do
            if command -v sha256sum >/dev/null 2>&1; then
                sha256sum "$WT_FILE"
            else
                shasum -a 256 "$WT_FILE"
            fi
        done
) >"$WT_HASHES"
chmod 0644 "$WT_HASHES"

assert_private_build_root_unchanged
WT_CURRENT_PRIVATE_STAGE_ID=$(path_identity "$WT_STAGE_DIRECTORY") || {
    echo "cannot re-identify private stage directory" >&2
    exit 70
}
if [ ! -d "$WT_STAGE_DIRECTORY" ] || [ -L "$WT_STAGE_DIRECTORY" ] ||
    [ "$WT_CURRENT_PRIVATE_STAGE_ID" != "$WT_PRIVATE_STAGE_ID" ]; then
    echo "private stage directory identity changed" >&2
    exit 70
fi
if [ -e "$WT_FINAL_STAGE_DIRECTORY" ] || [ -L "$WT_FINAL_STAGE_DIRECTORY" ]; then
    echo "stage destination appeared before publication; refusing to overwrite it" >&2
    exit 73
fi
if [ "$WT_STAT_STYLE" = gnu ]; then
    mv -nT -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"
else
    mv -hn -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"
fi
assert_stage_parent_unchanged
if [ -e "$WT_STAGE_DIRECTORY" ] || [ -L "$WT_STAGE_DIRECTORY" ]; then
    echo "stage publication did not consume the private directory" >&2
    exit 73
fi
if [ ! -d "$WT_FINAL_STAGE_DIRECTORY" ] || [ -L "$WT_FINAL_STAGE_DIRECTORY" ]; then
    echo "published stage is missing or unsafe" >&2
    exit 73
fi
WT_PUBLISHED_STAGE_ID=$(path_identity "$WT_FINAL_STAGE_DIRECTORY") || {
    echo "cannot identify published stage" >&2
    exit 73
}
if [ "$WT_PUBLISHED_STAGE_ID" != "$WT_PRIVATE_STAGE_ID" ]; then
    echo "published stage identity does not match the private stage" >&2
    exit 73
fi
echo "built and tested OpenSSH $OPENSSH_VERSION in $WT_FINAL_STAGE_DIRECTORY"
