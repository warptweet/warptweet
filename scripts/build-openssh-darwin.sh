#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
umask 022

# Builds authenticated OpenSSL 3.5.7 and OpenSSH 10.4p1 on native macOS and
# stages the client-only inventory under the package-owned Application Support
# layout. Release binaries are native-only. The script does not ship server
# helpers or install into the live system prefix during the build.

if [ "$#" -ne 3 ]; then
    echo "usage: $0 ABSOLUTE_OPENSSH_ARCHIVE ABSOLUTE_OPENSSL_ARCHIVE ABSOLUTE_NEW_STAGE_DIRECTORY" >&2
    exit 64
fi
if ! command -v id >/dev/null 2>&1; then
    echo "required tool is unavailable: id" >&2
    exit 69
fi
if [ "$(id -u)" = "0" ]; then
    echo "the macOS OpenSSH client build must run as a non-root account" >&2
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

for WT_TOOL in awk cc chmod file id install make mkdir mktemp mv otool rm sort stat tar uname; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        echo "required tool is unavailable: $WT_TOOL" >&2
        exit 69
    fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "required SHA-256 tool is unavailable: sha256sum or shasum" >&2
    exit 69
fi
if ! command -v perl >/dev/null 2>&1; then
    echo "required tool is unavailable: perl" >&2
    exit 69
fi

if [ "$(uname -s)" != Darwin ]; then
    echo "the macOS OpenSSH client bundle build is supported only on Darwin" >&2
    exit 69
fi
WT_BUILD_ARCHITECTURE=$(uname -m)
case "$WT_BUILD_ARCHITECTURE" in
    arm64|x86_64) ;;
    *)
        echo "unsupported macOS production architecture: $WT_BUILD_ARCHITECTURE" >&2
        exit 65
        ;;
esac
case "$WT_BUILD_ARCHITECTURE" in
    arm64) WT_OPENSSL_CONFIGURE_TARGET=darwin64-arm64-cc ;;
    x86_64) WT_OPENSSL_CONFIGURE_TARGET=darwin64-x86_64-cc ;;
esac
case "$WT_BUILD_ARCHITECTURE" in
    arm64) WT_ARTIFACT_PROFILE_ID=darwin-arm64 ;;
    x86_64) WT_ARTIFACT_PROFILE_ID=darwin-amd64 ;;
esac

# Keep the private OpenSSL logical prefix identical to Linux: it is a DESTDIR
# build input only and is never shipped as a runtime library tree.
if [ "$OPENSSL_LOGICAL_PREFIX" != /opt/warptweet/libexec/openssl-static ] ||
    [ "$OPENSSL_LOGICAL_CONFIG_DIRECTORY" != /opt/warptweet/etc/openssl-static ]; then
    echo "OpenSSL logical install layout does not match the production contract" >&2
    exit 65
fi

WT_MACOS_MIN_VERSION=${WARPTWEET_MACOS_DEPLOYMENT_TARGET:-13.0}
case "$WT_MACOS_MIN_VERSION" in
    ''|*[!0-9.]*|.*|*.|*\.\.*)
        echo "WARPTWEET_MACOS_DEPLOYMENT_TARGET must be a dotted numeric version" >&2
        exit 64
        ;;
esac
export MACOSX_DEPLOYMENT_TARGET="$WT_MACOS_MIN_VERSION"

WT_COMPILER_IDENTITY=$(LC_ALL=C cc -v 2>&1 | awk '/version|Target:|InstalledDir:|Apple clang version|clang version/ { print }' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
case "$WT_COMPILER_IDENTITY" in
    '')
        echo "cannot determine compiler identity" >&2
        exit 69
        ;;
esac

WT_STAGE_PARENT_ID=$(stat -f '%d:%i' "$WT_STAGE_PARENT" 2>/dev/null) || {
    echo "cannot identify stage parent directory" >&2
    exit 66
}

path_identity() {
    stat -f '%d:%i' "$1" 2>/dev/null
}

digest_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
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

cleanup() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
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

WT_OPENSSH_ACTUAL_SHA256=$(digest_file "$WT_PRIVATE_OPENSSH_ARCHIVE")
WT_OPENSSL_ACTUAL_SHA256=$(digest_file "$WT_PRIVATE_OPENSSL_ARCHIVE")
if [ "$WT_OPENSSH_ACTUAL_SHA256" != "$OPENSSH_SOURCE_SHA256" ]; then
    echo "OpenSSH source SHA-256 mismatch" >&2
    exit 65
fi
if [ "$WT_OPENSSL_ACTUAL_SHA256" != "$OPENSSL_SOURCE_SHA256" ]; then
    echo "OpenSSL source SHA-256 mismatch" >&2
    exit 65
fi

mkdir -m 0700 "$WT_OPENSSH_SOURCE_ROOT" "$WT_OPENSSL_SOURCE_ROOT"
tar -xzf "$WT_PRIVATE_OPENSSH_ARCHIVE" -C "$WT_OPENSSH_SOURCE_ROOT"
tar -xzf "$WT_PRIVATE_OPENSSL_ARCHIVE" -C "$WT_OPENSSL_SOURCE_ROOT"
WT_OPENSSH_SOURCE_DIRECTORY="$WT_OPENSSH_SOURCE_ROOT/openssh-$OPENSSH_VERSION"
WT_OPENSSL_SOURCE_DIRECTORY="$WT_OPENSSL_SOURCE_ROOT/openssl-$OPENSSL_VERSION"
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

if command -v sysctl >/dev/null 2>&1; then
    WT_BUILD_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
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
    "$WT_OPENSSL_CONFIGURE_TARGET" \
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
WT_OPENSSL_STATIC_CRYPTO_SHA256=$(digest_file "$WT_OPENSSL_STATIC_CRYPTO")
for WT_DYNAMIC_CRYPTO in \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libcrypto.dylib \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libcrypto*.dylib \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libssl.dylib \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/libssl*.dylib \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/ossl-modules/* \
    "$WT_OPENSSL_PREFIX_PHYSICAL"/lib/engines-3/*; do
    if [ -e "$WT_DYNAMIC_CRYPTO" ] || [ -L "$WT_DYNAMIC_CRYPTO" ]; then
        echo "private OpenSSL install unexpectedly produced a shared crypto library or module" >&2
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
    arm64:aarch64-*|x86_64:x86_64-*) ;;
    *)
        echo "OpenSSH target tuple does not match the native production architecture" >&2
        exit 65
        ;;
esac

# Configure uses a space-free private prefix. Staged paths below map into the
# package-owned Application Support layout without embedding spaces in configure.
WT_OPENSSH_CONFIGURE_PREFIX=/opt/warptweet/libexec/openssh
set -- \
    "--prefix=$WT_OPENSSH_CONFIGURE_PREFIX" \
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
LC_ALL=C make tests

WT_PACKAGE_ROOT="$WT_STAGE_DIRECTORY/Library/Application Support/WarpTweet"
WT_INSTALL_PREFIX="$WT_PACKAGE_ROOT/libexec/openssh"
mkdir -p \
    "$WT_INSTALL_PREFIX/bin" \
    "$WT_PACKAGE_ROOT/share/licenses/openssh" \
    "$WT_PACKAGE_ROOT/share/licenses/openssl"
install -m 0755 ssh "$WT_INSTALL_PREFIX/bin/ssh"
install -m 0755 ssh-keygen "$WT_INSTALL_PREFIX/bin/ssh-keygen"

# Refuse to stage server helpers in the macOS client package.
for WT_FORBIDDEN in sshd sshd-auth sshd-session ssh-agent ssh-add sftp sftp-server ssh-keysign scp; do
    if [ -e "$WT_INSTALL_PREFIX/bin/$WT_FORBIDDEN" ] ||
        [ -e "$WT_INSTALL_PREFIX/sbin/$WT_FORBIDDEN" ] ||
        [ -e "$WT_INSTALL_PREFIX/libexec/$WT_FORBIDDEN" ]; then
        echo "macOS client stage unexpectedly contains server or unused helper $WT_FORBIDDEN" >&2
        exit 65
    fi
done

WT_OTOOL_LIBS="$WT_BUILD_ROOT/otool-libs.txt"
WT_OTOOL_LOAD="$WT_BUILD_ROOT/otool-load.txt"
WT_FILE_INFO="$WT_BUILD_ROOT/file-info.txt"
for WT_EXECUTABLE in \
    "$WT_INSTALL_PREFIX/bin/ssh" \
    "$WT_INSTALL_PREFIX/bin/ssh-keygen"; do
    if [ ! -f "$WT_EXECUTABLE" ] || [ -L "$WT_EXECUTABLE" ]; then
        echo "staged OpenSSH executable must be a regular non-symlink file: $WT_EXECUTABLE" >&2
        exit 65
    fi
    LC_ALL=C file -b "$WT_EXECUTABLE" >"$WT_FILE_INFO"
    if ! awk '
        BEGIN { ok = 0 }
        /Mach-O 64-bit executable/ { ok = 1 }
        END { exit(ok ? 0 : 1) }
    ' "$WT_FILE_INFO"; then
        echo "staged OpenSSH executable is not a Mach-O 64-bit executable: $WT_EXECUTABLE" >&2
        cat "$WT_FILE_INFO" >&2
        exit 65
    fi
    case "$WT_BUILD_ARCHITECTURE" in
        arm64)
            if ! awk 'BEGIN { ok = 0 } /arm64/ { ok = 1 } END { exit(ok ? 0 : 1) }' "$WT_FILE_INFO"; then
                echo "staged OpenSSH executable architecture is not arm64: $WT_EXECUTABLE" >&2
                exit 65
            fi
            ;;
        x86_64)
            if ! awk 'BEGIN { ok = 0 } /x86_64/ { ok = 1 } END { exit(ok ? 0 : 1) }' "$WT_FILE_INFO"; then
                echo "staged OpenSSH executable architecture is not x86_64: $WT_EXECUTABLE" >&2
                exit 65
            fi
            ;;
    esac
    if ! otool -L "$WT_EXECUTABLE" >"$WT_OTOOL_LIBS"; then
        echo "cannot inspect staged OpenSSH executable library dependencies: $WT_EXECUTABLE" >&2
        exit 65
    fi
    if awk '
        NR == 1 { next }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            dep = line
            sub(/[[:space:]].*$/, "", dep)
            if (dep ~ /libcrypto/ || dep ~ /libssl/) { rejected = 1 }
            if (dep ~ /^@rpath\// || dep ~ /^@loader_path\// || dep ~ /^@executable_path\//) { rejected = 1 }
            if (dep ~ /^\// && dep !~ /^\/usr\/lib\// && dep !~ /^\/System\/Library\//) { rejected = 1 }
        }
        END { exit(rejected ? 0 : 1) }
    ' "$WT_OTOOL_LIBS"; then
        echo "staged OpenSSH executable has a forbidden crypto dependency or non-system load path: $WT_EXECUTABLE" >&2
        cat "$WT_OTOOL_LIBS" >&2
        exit 65
    fi
    if ! otool -l "$WT_EXECUTABLE" >"$WT_OTOOL_LOAD"; then
        echo "cannot inspect staged OpenSSH executable load commands: $WT_EXECUTABLE" >&2
        exit 65
    fi
    if awk '
        $1 == "cmd" && $2 == "LC_RPATH" { rejected = 1 }
        END { exit(rejected ? 0 : 1) }
    ' "$WT_OTOOL_LOAD"; then
        echo "staged OpenSSH executable contains LC_RPATH: $WT_EXECUTABLE" >&2
        exit 65
    fi
done

WT_OPENSSH_LICENSE_SOURCE="$WT_OPENSSH_SOURCE_DIRECTORY/LICENCE"
if [ ! -f "$WT_OPENSSH_LICENSE_SOURCE" ] || [ -L "$WT_OPENSSH_LICENSE_SOURCE" ]; then
    echo "OpenSSH archive did not contain a regular LICENCE file" >&2
    exit 65
fi
install -m 0644 "$WT_OPENSSH_LICENSE_SOURCE" \
    "$WT_PACKAGE_ROOT/share/licenses/openssh/LICENCE"
install -m 0644 "$WT_OPENSSL_SOURCE_DIRECTORY/LICENSE.txt" \
    "$WT_PACKAGE_ROOT/share/licenses/openssl/LICENSE.txt"

WT_INSTALLED_SSH="$WT_INSTALL_PREFIX/bin/ssh"
WT_SSH_SHA256=$(digest_file "$WT_INSTALLED_SSH")
WT_SSH_KEYGEN_SHA256=$(digest_file "$WT_INSTALL_PREFIX/bin/ssh-keygen")

WT_VERSION_OUTPUT=$("$WT_INSTALLED_SSH" -V 2>&1 >/dev/null || true)
if [ "$WT_VERSION_OUTPUT" != "OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026" ]; then
    echo "staged ssh -V does not match the exact production version line" >&2
    printf 'got: %s\n' "$WT_VERSION_OUTPUT" >&2
    exit 65
fi
for WT_QUERY in kex key sig cipher; do
    WT_QUERY_OUTPUT=$("$WT_INSTALLED_SSH" -Q "$WT_QUERY")
    case "$WT_QUERY" in
        kex)
            WT_REQUIRED=mlkem768x25519-sha256
            ;;
        key|sig)
            WT_REQUIRED=ssh-mldsa44-ed25519@openssh.com
            ;;
        cipher)
            WT_REQUIRED=chacha20-poly1305@openssh.com
            ;;
    esac
    if ! printf '%s\n' "$WT_QUERY_OUTPUT" | awk -v required="$WT_REQUIRED" '
        $0 == required { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
        echo "staged ssh lacks required $WT_QUERY algorithm $WT_REQUIRED" >&2
        exit 65
    fi
done

WT_RECEIPT="$WT_PACKAGE_ROOT/share/openssh-source.txt"
{
    echo "receipt_version=1"
    echo "role=macos-client"
    echo "version=$OPENSSH_VERSION"
    echo "engine_version=OpenSSH_10.4p1"
    echo "source_url=$OPENSSH_SOURCE_URL"
    echo "source_sha256=$OPENSSH_SOURCE_SHA256"
    echo "release_key_fingerprint=$OPENSSH_RELEASE_KEY_FINGERPRINT"
    echo "artifact_profile_id=$WT_ARTIFACT_PROFILE_ID"
    echo "platform=darwin"
    echo "architecture=$WT_BUILD_ARCHITECTURE"
    echo "target_tuple=$WT_TARGET_TUPLE"
    echo "configure_prefix=$WT_OPENSSH_CONFIGURE_PREFIX"
    echo "install_prefix=/Library/Application Support/WarpTweet/libexec/openssh"
    echo "hardening=yes"
    echo "pie=yes"
    echo "kerberos5=no"
    echo "ldns=no"
    echo "libedit=no"
    echo "pam=no"
    echo "selinux=no"
    echo "zlib=no"
    echo "server_helpers=no"
    echo "ssh_path=/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh"
    echo "ssh_sha256=$WT_SSH_SHA256"
    echo "ssh_keygen_path=/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen"
    echo "ssh_keygen_sha256=$WT_SSH_KEYGEN_SHA256"
    echo "openssl_prefix=$OPENSSL_LOGICAL_PREFIX"
    echo "openssl_source_receipt_path=/Library/Application Support/WarpTweet/share/openssl-source.txt"
    echo "openssl_source_sha256=$OPENSSL_SOURCE_SHA256"
    echo "openssl_linkage=static"
    echo "macho_dynamic_policy=passed"
    echo "macos_deployment_target=$WT_MACOS_MIN_VERSION"
    echo "compiler_identity=$WT_COMPILER_IDENTITY"
    echo "tests=passed"
} >"$WT_RECEIPT"
chmod 0644 "$WT_RECEIPT"

WT_OPENSSL_RECEIPT="$WT_PACKAGE_ROOT/share/openssl-source.txt"
{
    echo "receipt_version=1"
    echo "version=$OPENSSL_VERSION"
    echo "source_url=$OPENSSL_SOURCE_URL"
    echo "source_sha256=$OPENSSL_SOURCE_SHA256"
    echo "release_key_fingerprint=$OPENSSL_RELEASE_KEY_FINGERPRINT"
    echo "platform=darwin"
    echo "architecture=$WT_BUILD_ARCHITECTURE"
    echo "artifact_profile_id=$WT_ARTIFACT_PROFILE_ID"
    echo "configure_target=$WT_OPENSSL_CONFIGURE_TARGET"
    echo "configure_prefix=$OPENSSL_LOGICAL_PREFIX"
    echo "openssl_config_directory=$OPENSSL_LOGICAL_CONFIG_DIRECTORY"
    echo "shared=no"
    echo "module=no"
    echo "dso=no"
    echo "pinshared=no"
    echo "tests=passed"
    echo "linkage=static"
    echo "static_libcrypto_sha256=$WT_OPENSSL_STATIC_CRYPTO_SHA256"
    echo "macos_deployment_target=$WT_MACOS_MIN_VERSION"
    echo "compiler_identity=$WT_COMPILER_IDENTITY"
    echo "license_path=/Library/Application Support/WarpTweet/share/licenses/openssl/LICENSE.txt"
} >"$WT_OPENSSL_RECEIPT"
chmod 0644 "$WT_OPENSSL_RECEIPT"

WT_HASHES="$WT_PACKAGE_ROOT/share/openssh-bundle.sha256"
(
    cd "$WT_STAGE_DIRECTORY"
    printf '%s\n' \
        "Library/Application Support/WarpTweet/libexec/openssh/bin/ssh" \
        "Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen" \
        "Library/Application Support/WarpTweet/share/licenses/openssh/LICENCE" \
        "Library/Application Support/WarpTweet/share/licenses/openssl/LICENSE.txt" \
        "Library/Application Support/WarpTweet/share/openssh-source.txt" \
        "Library/Application Support/WarpTweet/share/openssl-source.txt" | \
        LC_ALL=C sort | while IFS= read -r WT_FILE; do
            if command -v sha256sum >/dev/null 2>&1; then
                sha256sum "$WT_FILE"
            else
                shasum -a 256 "$WT_FILE"
            fi
        done
) >"$WT_HASHES"
chmod 0644 "$WT_HASHES"
WT_MANIFEST_LINES=$(wc -l <"$WT_HASHES" | tr -d '[:space:]')
if [ "$WT_MANIFEST_LINES" != 6 ]; then
    echo "macOS client bundle manifest must contain exactly six authenticated paths" >&2
    exit 65
fi

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
mv -hn -- "$WT_STAGE_DIRECTORY" "$WT_FINAL_STAGE_DIRECTORY"
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
echo "built and tested macOS client OpenSSH $OPENSSH_VERSION ($WT_ARTIFACT_PROFILE_ID) in $WT_FINAL_STAGE_DIRECTORY"
