#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Create dedicated tunnel and privilege-separation accounts for the fixed Linux
# layout. No network access. No classical recovery credentials.

if [ "$(id -u)" != "0" ]; then
    echo "warptweet postinst requires root" >&2
    exit 1
fi

ensure_group() {
    WT_NAME=$1
    if getent group "$WT_NAME" >/dev/null 2>&1; then
        return 0
    fi
    groupadd --system "$WT_NAME"
}

ensure_user() {
    WT_NAME=$1
    WT_HOME=$2
    WT_SHELL=$3
    if getent passwd "$WT_NAME" >/dev/null 2>&1; then
        return 0
    fi
    useradd --system --gid "$WT_NAME" --home-dir "$WT_HOME" --shell "$WT_SHELL" \
        --comment "WarpTweet service account" "$WT_NAME"
}

ensure_group warptweet
ensure_group warptweet-client
ensure_group warptweet-sshd
ensure_user warptweet /nonexistent /usr/sbin/nologin
ensure_user warptweet-client /nonexistent /usr/sbin/nologin
ensure_user warptweet-sshd /var/empty/warptweet-sshd /usr/sbin/nologin

install -d -o root -g root -m 0755 /opt/warptweet
install -d -o root -g root -m 0755 /etc/warptweet
install -d -o root -g root -m 0700 /etc/warptweet/enrollment
install -d -o root -g root -m 0755 /opt/warptweet/etc
install -d -o root -g root -m 0755 /opt/warptweet/etc/authorized_keys
install -d -o root -g root -m 0755 /var/empty/warptweet-sshd
install -d -o root -g root -m 0700 /var/lib/warptweet
install -d -o root -g root -m 0700 /var/lib/warptweet/invites
install -d -o root -g root -m 0700 /var/lib/warptweet/clients
install -d -o root -g root -m 0700 /var/lib/warptweet/server
install -d -o root -g root -m 0755 /run/warptweet
install -d -o root -g root -m 0750 /run/warptweet/server
touch /opt/warptweet/etc/authorized_keys/warptweet
chown root:root /opt/warptweet/etc/authorized_keys/warptweet
chmod 0644 /opt/warptweet/etc/authorized_keys/warptweet

# Public-key-only lock for the tunnel account where supported.
if command -v usermod >/dev/null 2>&1; then
    usermod -p '*NP*' warptweet >/dev/null 2>&1 || true
	usermod -L warptweet-client >/dev/null 2>&1 || true
	usermod -L warptweet-sshd >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Enable enrollment control plane when package-installed; start only after
    # warptweet host has written server.wt, host key, and enrollment state.
    systemctl enable warptweet-enroll.service >/dev/null 2>&1 || true
fi

exit 0
