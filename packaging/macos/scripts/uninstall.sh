#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Idempotent uninstall for the WarpTweet macOS client package.
# Identity material is preserved unless the operator passes --destroy-identity.

WT_DESTROY_IDENTITY=0
for WT_ARG in "$@"; do
    case "$WT_ARG" in
        --destroy-identity)
            WT_DESTROY_IDENTITY=1
            ;;
        -h|--help)
            cat <<'EOF'
usage: uninstall.sh [--destroy-identity]

Stops WarpTweet client services, removes package executables and receipts, and
leaves identity/trust material in place unless --destroy-identity is supplied.
EOF
            exit 0
            ;;
        *)
            echo "unknown argument: $WT_ARG" >&2
            exit 64
            ;;
    esac
done

if [ "$(id -u)" != "0" ]; then
    echo "WarpTweet uninstall requires root" >&2
    exit 1
fi

WT_ROOT="/Library/Application Support/WarpTweet"
WT_STATE="$WT_ROOT/state"
WT_PLIST="/Library/LaunchDaemons/com.warptweet.client.plist"
WT_PKG_ID="com.warptweet.client"

if [ -f "$WT_PLIST" ]; then
    launchctl bootout system/com.warptweet.client >/dev/null 2>&1 || true
    launchctl unload "$WT_PLIST" >/dev/null 2>&1 || true
fi

# Stop any remaining controller processes owned by the package paths.
if [ -x "$WT_ROOT/bin/warptweet" ]; then
    pkill -f "$WT_ROOT/bin/warptweet" >/dev/null 2>&1 || true
fi

rm -f "$WT_PLIST"
rm -rf "$WT_ROOT/bin" "$WT_ROOT/libexec" "$WT_ROOT/share"

if [ "$WT_DESTROY_IDENTITY" -eq 1 ]; then
    printf '%s\n' "Destroying WarpTweet identity and trust state under $WT_STATE"
    printf '%s' "Type DESTROY to confirm: "
    read -r WT_CONFIRM
    if [ "$WT_CONFIRM" != "DESTROY" ]; then
        echo "identity destruction aborted" >&2
        exit 1
    fi
    rm -rf "$WT_STATE"
else
    echo "preserving identity and trust state under $WT_STATE"
fi

if pkgutil --pkg-info "$WT_PKG_ID" >/dev/null 2>&1; then
    pkgutil --forget "$WT_PKG_ID" >/dev/null
fi

# Remove empty package root only when no state remains.
if [ -d "$WT_ROOT" ]; then
    rmdir "$WT_ROOT/state/identity" 2>/dev/null || true
    rmdir "$WT_ROOT/state/trust" 2>/dev/null || true
    rmdir "$WT_ROOT/state" 2>/dev/null || true
    rmdir "$WT_ROOT" 2>/dev/null || true
fi

echo "WarpTweet macOS client package uninstalled"
