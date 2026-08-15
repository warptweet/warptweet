#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$(id -u)" != "0" ]; then
    echo "warptweet prerm requires root" >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop 'warptweet-tunnel@*' >/dev/null 2>&1 || true
    systemctl stop warptweet-enroll >/dev/null 2>&1 || true
    systemctl disable warptweet-enroll >/dev/null 2>&1 || true
    systemctl stop warptweet-sshd >/dev/null 2>&1 || true
    systemctl disable warptweet-sshd >/dev/null 2>&1 || true
fi

exit 0
