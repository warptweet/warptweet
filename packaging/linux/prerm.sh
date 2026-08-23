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

if ! command -v systemctl >/dev/null 2>&1; then
    exit 0
fi

WT_UPGRADE_UNITS=${WT_UPGRADE_UNITS:-/var/lib/warptweet/upgrade-active.units}

if ! uninstalling "${1:-}"; then
    umask 077
    WT_UPGRADE_DIR=$(dirname -- "$WT_UPGRADE_UNITS")
    mkdir -p "$WT_UPGRADE_DIR"
    : >"$WT_UPGRADE_UNITS"
    list_tunnel_units | while read -r WT_UNIT; do
        [ -n "$WT_UNIT" ] || continue
        case "$WT_UNIT" in
            warptweet-tunnel@.service) ;;
            warptweet-tunnel@*.service)
                if systemctl is-active --quiet "$WT_UNIT"; then
                    printf '%s\n' "$WT_UNIT" >>"$WT_UPGRADE_UNITS"
                fi
                ;;
        esac
    done
    for WT_UNIT in warptweet-provisioner.service warptweet-reconcile.service warptweet-mgmt.service warptweet-enroll.service warptweet-sshd.service warptweet-hostsign.service; do
        if systemctl is-active --quiet "$WT_UNIT"; then
            printf '%s\n' "$WT_UNIT" >>"$WT_UPGRADE_UNITS"
        fi
    done
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
stop_disable warptweet-mgmt.service
stop_disable warptweet-enroll.service
stop_disable warptweet-sshd.service
stop_disable warptweet-hostsign.service

exit 0
