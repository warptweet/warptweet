#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$(id -u)" != "0" ]; then
    echo "warptweet prerm requires root" >&2
    exit 1
fi

# Debian: remove | deconfigure. RPM %preun: remaining count 0.
# Any other argument, including upgrade, must not disable the data plane.
uninstalling() {
    case "${1:-}" in
        remove | deconfigure | 0)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

list_tunnel_units() {
    {
        systemctl list-units --all --no-legend --plain 'warptweet-tunnel@*.service'
        systemctl list-unit-files --no-legend --plain 'warptweet-tunnel@*.service'
    } | awk '{ print $1 }' | sort -u
}

stop_disable() {
    WT_UNIT=$1
    if systemctl is-active --quiet "$WT_UNIT"; then
        systemctl stop "$WT_UNIT"
    fi
    if systemctl is-enabled --quiet "$WT_UNIT"; then
        systemctl disable "$WT_UNIT"
    fi
}

try_restart() {
    WT_UNIT=$1
    if systemctl is-active --quiet "$WT_UNIT"; then
        systemctl try-restart "$WT_UNIT"
    fi
}

if ! command -v systemctl >/dev/null 2>&1; then
    exit 0
fi

if ! uninstalling "${1:-}"; then
    systemctl daemon-reload
    list_tunnel_units | while read -r WT_UNIT; do
        [ -n "$WT_UNIT" ] || continue
        case "$WT_UNIT" in
            warptweet-tunnel@.service) ;;
            warptweet-tunnel@*.service) try_restart "$WT_UNIT" ;;
        esac
    done
    try_restart warptweet-provisioner.service
    try_restart warptweet-reconcile.service
    try_restart warptweet-enroll.service
    try_restart warptweet-sshd.service
    exit 0
fi

list_tunnel_units | while read -r WT_UNIT; do
    [ -n "$WT_UNIT" ] || continue
        case "$WT_UNIT" in
            warptweet-tunnel@.service) ;;
            warptweet-tunnel@*.service) stop_disable "$WT_UNIT" ;;
        esac
done
stop_disable warptweet-provisioner.service
stop_disable warptweet-reconcile.service
stop_disable warptweet-enroll.service
stop_disable warptweet-sshd.service

exit 0
