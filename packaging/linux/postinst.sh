#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$(id -u)" != "0" ]; then
    echo "warptweet postinst requires root" >&2
    exit 1
fi

WT_HOST_UID=900
WT_HOST_GID=900
WT_SSHD_UID=901
WT_SSHD_GID=901
WT_CLIENT_UID=920
WT_CLIENT_GID=920
WT_OPERATOR_GID=923

fail() {
    echo "warptweet postinst: $1" >&2
    exit 1
}

account_field() {
    getent passwd "$1" | awk -F: -v field="$2" '{ print $field }'
}

group_field() {
    getent group "$1" | awk -F: -v field="$2" '{ print $field }'
}

ensure_group() {
    WT_NAME=$1
    WT_GID=$2
    if getent group "$WT_NAME" >/dev/null 2>&1; then
        WT_HAVE=$(group_field "$WT_NAME" 3)
        if [ "$WT_HAVE" != "$WT_GID" ]; then
            fail "group $WT_NAME exists with gid $WT_HAVE, want $WT_GID"
        fi
        return 0
    fi
    groupadd --system --gid "$WT_GID" "$WT_NAME"
}

ensure_user() {
    WT_NAME=$1
    WT_UID=$2
    WT_GID=$3
    WT_HOME=$4
    WT_SHELL=$5
    if getent passwd "$WT_NAME" >/dev/null 2>&1; then
        WT_HAVE_UID=$(account_field "$WT_NAME" 3)
        WT_HAVE_GID=$(account_field "$WT_NAME" 4)
        WT_HAVE_HOME=$(account_field "$WT_NAME" 6)
        WT_HAVE_SHELL=$(account_field "$WT_NAME" 7)
        if [ "$WT_HAVE_UID" != "$WT_UID" ] || [ "$WT_HAVE_GID" != "$WT_GID" ] ||
            [ "$WT_HAVE_HOME" != "$WT_HOME" ] || [ "$WT_HAVE_SHELL" != "$WT_SHELL" ]; then
            fail "user $WT_NAME exists with uid=$WT_HAVE_UID gid=$WT_HAVE_GID home=$WT_HAVE_HOME shell=$WT_HAVE_SHELL"
        fi
        return 0
    fi
    useradd --system --uid "$WT_UID" --gid "$WT_GID" --home-dir "$WT_HOME" \
        --shell "$WT_SHELL" --comment "WarpTweet service account" "$WT_NAME"
}

ensure_group warptweet "$WT_HOST_GID"
ensure_group warptweet-sshd "$WT_SSHD_GID"
ensure_group warptweet-client "$WT_CLIENT_GID"
ensure_group warptweet-operator "$WT_OPERATOR_GID"
ensure_user warptweet "$WT_HOST_UID" "$WT_HOST_GID" /nonexistent /usr/sbin/nologin
ensure_user warptweet-sshd "$WT_SSHD_UID" "$WT_SSHD_GID" /var/empty/warptweet-sshd /usr/sbin/nologin
ensure_user warptweet-client "$WT_CLIENT_UID" "$WT_CLIENT_GID" /nonexistent /usr/sbin/nologin

install -d -o root -g root -m 0755 /opt/warptweet
install -d -o root -g root -m 0755 /etc/warptweet
install -d -o root -g root -m 0700 /etc/warptweet/enrollment
install -d -o root -g root -m 0700 /var/lib/warptweet/ssh
install -d -o root -g root -m 0755 /var/lib/warptweet/authorized_keys
install -d -o root -g root -m 0755 /var/empty/warptweet-sshd
install -d -o root -g root -m 0755 /var/lib/warptweet
install -d -o root -g root -m 0700 /var/lib/warptweet/invites
install -d -o root -g root -m 0700 /var/lib/warptweet/clients
install -d -o root -g root -m 0700 /var/lib/warptweet/server
install -d -o root -g warptweet-sshd -m 0770 /var/lib/warptweet/sessions
install -d -o root -g warptweet-sshd -m 0750 /var/lib/warptweet/clients
install -d -o root -g root -m 0755 /run/warptweet
install -d -o root -g root -m 0750 /run/warptweet/server
install -d -o root -g root -m 0750 /run/warptweet/sshd
touch /var/lib/warptweet/authorized_keys/warptweet
chown root:root /var/lib/warptweet/authorized_keys/warptweet
chmod 0644 /var/lib/warptweet/authorized_keys/warptweet

command -v usermod >/dev/null 2>&1 || fail "usermod is required"
usermod -p '*NP*' warptweet
usermod -L warptweet-client
usermod -L warptweet-sshd

command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"
systemctl daemon-reload
systemctl enable warptweet-hostsign.service
systemctl enable warptweet-mgmt.service
systemctl enable --now warptweet-provisioner.service
systemctl enable warptweet-reconcile.service

WT_UPGRADE_UNITS=${WT_UPGRADE_UNITS:-/var/lib/warptweet/upgrade-active.units}
if [ -f "$WT_UPGRADE_UNITS" ]; then
    while IFS= read -r WT_UNIT; do
        [ -n "$WT_UNIT" ] || continue
        if systemctl is-active --quiet "$WT_UNIT"; then
            systemctl try-restart "$WT_UNIT"
        fi
    done <"$WT_UPGRADE_UNITS"
    rm -f "$WT_UPGRADE_UNITS"
fi

exit 0
