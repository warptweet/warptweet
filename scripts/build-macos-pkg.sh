#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
umask 022

# Assemble a macOS client .pkg from a built controller, provisioner, and the
# authenticated Darwin OpenSSH client stage. Signing and notarization run only
# when explicit release identities are provided. The script never downloads
# payloads and never installs server helpers.

if [ "$#" -ne 4 ]; then
    echo "usage: $0 ABSOLUTE_OPENSSH_DARWIN_STAGE ABSOLUTE_CONTROLLER ABSOLUTE_PROVISIONER ABSOLUTE_OUTPUT_PKG" >&2
    exit 64
fi

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS package assembly requires Darwin" >&2
    exit 69
fi
if [ "$(id -u)" = "0" ]; then
    echo "macOS package assembly must not run as root" >&2
    exit 77
fi

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
WT_OPENSSH_STAGE_INPUT=$1
WT_CONTROLLER_INPUT=$2
WT_PROVISIONER_INPUT=$3
WT_OUTPUT_PKG_INPUT=$4
WT_VERSION=${WARPTWEET_VERSION:-0.1.0-dev}
WT_PACKAGE_ID=com.warptweet.client
WT_ARCH=$(uname -m)
case "$WT_ARCH" in
    arm64) WT_ARCH_TOKEN=darwin-arm64 ;;
    x86_64) WT_ARCH_TOKEN=darwin-amd64 ;;
    *)
        echo "unsupported package architecture: $WT_ARCH" >&2
        exit 65
        ;;
esac

for WT_INPUT_PATH in "$WT_OPENSSH_STAGE_INPUT" "$WT_CONTROLLER_INPUT" "$WT_PROVISIONER_INPUT" "$WT_OUTPUT_PKG_INPUT"; do
    case "$WT_INPUT_PATH" in
        /*) ;;
        *)
            echo "paths must be absolute" >&2
            exit 64
            ;;
    esac
    case "$WT_INPUT_PATH" in
        /|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
            echo "paths must be clean absolute paths using safe ASCII characters" >&2
            exit 64
            ;;
    esac
done

for WT_TOOL in chmod cp ditto install mkdir mktemp mv pkgbuild productbuild rm sed shasum; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        echo "required tool is unavailable: $WT_TOOL" >&2
        exit 69
    fi
done

WT_OPENSSH_STAGE=$WT_OPENSSH_STAGE_INPUT
WT_CONTROLLER=$WT_CONTROLLER_INPUT
WT_PROVISIONER=$WT_PROVISIONER_INPUT
WT_OUTPUT_PKG=$WT_OUTPUT_PKG_INPUT
WT_OUTPUT_PARENT=${WT_OUTPUT_PKG%/*}
if [ -z "$WT_OUTPUT_PARENT" ]; then
    WT_OUTPUT_PARENT=/
fi
if [ ! -d "$WT_OUTPUT_PARENT" ]; then
    echo "output parent directory must exist" >&2
    exit 66
fi
if [ -e "$WT_OUTPUT_PKG" ] || [ -L "$WT_OUTPUT_PKG" ]; then
    echo "output package must not already exist" >&2
    exit 73
fi
if [ ! -x "$WT_CONTROLLER" ] || [ -L "$WT_CONTROLLER" ]; then
    echo "controller must be a non-symlink executable" >&2
    exit 66
fi
if [ ! -x "$WT_PROVISIONER" ] || [ -L "$WT_PROVISIONER" ]; then
    echo "provisioner must be a non-symlink executable" >&2
    exit 66
fi

WT_STAGE_SSH="$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh"
WT_STAGE_KEYGEN="$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen"
WT_STAGE_MANIFEST="$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/share/openssh-bundle.sha256"
for WT_REQUIRED in "$WT_STAGE_SSH" "$WT_STAGE_KEYGEN" "$WT_STAGE_MANIFEST"; do
    if [ ! -f "$WT_REQUIRED" ] || [ -L "$WT_REQUIRED" ]; then
        echo "OpenSSH darwin stage is missing required file: $WT_REQUIRED" >&2
        exit 66
    fi
done
for WT_FORBIDDEN in \
    "$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec/openssh/sbin/sshd" \
    "$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec/openssh/libexec/sshd-auth" \
    "$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec/openssh/libexec/sshd-session"; do
    if [ -e "$WT_FORBIDDEN" ]; then
        echo "refusing server helper in darwin stage: $WT_FORBIDDEN" >&2
        exit 65
    fi
done

WT_WORK_PARENT=$(CDPATH= cd -- "$WT_OUTPUT_PARENT" && pwd -P)
WT_WORK=''
cleanup() {
    WT_STATUS=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WT_WORK" ] && [ -d "$WT_WORK" ]; then
        rm -rf -- "$WT_WORK" || true
    fi
    exit "$WT_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

WT_WORK=$(mktemp -d "$WT_WORK_PARENT/.wt-macos-pkg.XXXXXXXX")
chmod 0700 "$WT_WORK"
WT_ROOT="$WT_WORK/root"
WT_SCRIPTS="$WT_WORK/scripts"
WT_COMPONENT="$WT_WORK/component.pkg"
WT_UNSIGNED_PKG="$WT_WORK/unsigned.pkg"

mkdir -p \
    "$WT_ROOT/Library/Application Support/WarpTweet/bin" \
    "$WT_ROOT/Library/Application Support/WarpTweet/libexec/openssh/bin" \
    "$WT_ROOT/Library/Application Support/WarpTweet/share/licenses/openssh" \
    "$WT_ROOT/Library/Application Support/WarpTweet/share/licenses/openssl" \
    "$WT_ROOT/Library/LaunchDaemons" \
    "$WT_SCRIPTS"

# Copy authenticated OpenSSH client inventory.
ditto "$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/libexec" \
    "$WT_ROOT/Library/Application Support/WarpTweet/libexec"
ditto "$WT_OPENSSH_STAGE/Library/Application Support/WarpTweet/share" \
    "$WT_ROOT/Library/Application Support/WarpTweet/share"

install -m 0755 "$WT_CONTROLLER" \
    "$WT_ROOT/Library/Application Support/WarpTweet/bin/warptweet"
install -m 0755 "$WT_PROVISIONER" \
    "$WT_ROOT/Library/Application Support/WarpTweet/bin/warptweet-provisioner"
install -m 0755 "$WT_REPOSITORY_ROOT/packaging/macos/scripts/uninstall.sh" \
    "$WT_ROOT/Library/Application Support/WarpTweet/share/uninstall.sh"
install -m 0644 "$WT_REPOSITORY_ROOT/packaging/macos/launchd/com.warptweet.client.plist" \
    "$WT_ROOT/Library/LaunchDaemons/com.warptweet.client.plist"

install -m 0755 "$WT_REPOSITORY_ROOT/packaging/macos/scripts/preinstall" "$WT_SCRIPTS/preinstall"
install -m 0755 "$WT_REPOSITORY_ROOT/packaging/macos/scripts/postinstall" "$WT_SCRIPTS/postinstall"

# Final payload inventory checks before packaging.
for WT_BIN in \
    "$WT_ROOT/Library/Application Support/WarpTweet/bin/warptweet" \
    "$WT_ROOT/Library/Application Support/WarpTweet/bin/warptweet-provisioner" \
    "$WT_ROOT/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh" \
    "$WT_ROOT/Library/Application Support/WarpTweet/libexec/openssh/bin/ssh-keygen"; do
    if [ ! -f "$WT_BIN" ] || [ -L "$WT_BIN" ]; then
        echo "payload missing regular file: $WT_BIN" >&2
        exit 65
    fi
done
if [ -e "$WT_ROOT/Library/Application Support/WarpTweet/libexec/openssh/sbin/sshd" ]; then
    echo "payload unexpectedly contains sshd" >&2
    exit 65
fi

pkgbuild \
    --root "$WT_ROOT" \
    --scripts "$WT_SCRIPTS" \
    --identifier "$WT_PACKAGE_ID" \
    --version "$WT_VERSION" \
    --install-location / \
    "$WT_COMPONENT"

productbuild \
    --package "$WT_COMPONENT" \
    --identifier "$WT_PACKAGE_ID" \
    --version "$WT_VERSION" \
    "$WT_UNSIGNED_PKG"

WT_FINAL_SOURCE=$WT_UNSIGNED_PKG
if [ -n "${WARPTWEET_INSTALLER_IDENTITY:-}" ]; then
    if ! command -v productsign >/dev/null 2>&1; then
        echo "productsign is required when WARPTWEET_INSTALLER_IDENTITY is set" >&2
        exit 69
    fi
    WT_SIGNED_PKG="$WT_WORK/signed.pkg"
    productsign --sign "$WARPTWEET_INSTALLER_IDENTITY" "$WT_UNSIGNED_PKG" "$WT_SIGNED_PKG"
    WT_FINAL_SOURCE=$WT_SIGNED_PKG

    if [ -n "${WARPTWEET_NOTARY_PROFILE:-}" ]; then
        if ! command -v xcrun >/dev/null 2>&1; then
            echo "xcrun is required for notarization" >&2
            exit 69
        fi
        xcrun notarytool submit "$WT_SIGNED_PKG" \
            --keychain-profile "$WARPTWEET_NOTARY_PROFILE" \
            --wait
        xcrun stapler staple "$WT_SIGNED_PKG"
    fi
elif [ "${WARPTWEET_REQUIRE_SIGNED_PKG:-}" = "1" ]; then
    echo "WARPTWEET_INSTALLER_IDENTITY is required for release package signing" >&2
    exit 77
fi

if [ -e "$WT_OUTPUT_PKG" ] || [ -L "$WT_OUTPUT_PKG" ]; then
    echo "output package appeared before publication" >&2
    exit 73
fi
mv -hn -- "$WT_FINAL_SOURCE" "$WT_OUTPUT_PKG"
if [ ! -f "$WT_OUTPUT_PKG" ] || [ -L "$WT_OUTPUT_PKG" ]; then
    echo "failed to publish package" >&2
    exit 73
fi

WT_SHA256=$(shasum -a 256 "$WT_OUTPUT_PKG" | awk '{print $1}')
WT_RECEIPT="$WT_OUTPUT_PKG.sha256"
if [ -e "$WT_RECEIPT" ] || [ -L "$WT_RECEIPT" ]; then
    echo "package checksum path already exists" >&2
    exit 73
fi
printf '%s  %s\n' "$WT_SHA256" "$(basename "$WT_OUTPUT_PKG")" >"$WT_RECEIPT"

cat <<EOF
built macOS package
  path=$WT_OUTPUT_PKG
  package_id=$WT_PACKAGE_ID
  version=$WT_VERSION
  arch=$WT_ARCH_TOKEN
  sha256=$WT_SHA256
  signed=${WARPTWEET_INSTALLER_IDENTITY:+yes}
  notarized=${WARPTWEET_NOTARY_PROFILE:+yes}
EOF
