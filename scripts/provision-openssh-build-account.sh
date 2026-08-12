#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "${WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT:-}" != "1" ]; then
    echo "WARPTWEET_CI_OPENSSH_BUILD_ACCOUNT=1 is required" >&2
    exit 64
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 64
fi
if [ "$(uname -s)" != Linux ]; then
    echo "the OpenSSH regression build account is supported only on Linux" >&2
    exit 69
fi
if [ "$(id -u)" != "0" ]; then
    echo "the OpenSSH regression build account must be provisioned by root" >&2
    exit 77
fi

for WT_TOOL in awk chmod cmp getent getfacl id install mktemp mv rm setfacl stat sudo useradd visudo; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        echo "required account-provisioning tool is unavailable: $WT_TOOL" >&2
        exit 69
    fi
done

WT_BUILD_ACCOUNT=warptweet-build
WT_BUILD_GROUP=warptweet-build
WT_BUILD_HOME=/var/lib/warptweet-build
WT_BUILD_SHELL=/bin/sh
WT_UNPRIVILEGED_REGRESSION_ACCOUNT=nobody
WT_SUDOERS_DIRECTORY=/etc/sudoers.d
WT_SUDOERS_PATH=$WT_SUDOERS_DIRECTORY/warptweet-openssh-regress
WT_SUDOERS_TEMP=''

cleanup() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WT_SUDOERS_TEMP" ] &&
        { [ -e "$WT_SUDOERS_TEMP" ] || [ -L "$WT_SUDOERS_TEMP" ]; }; then
        case "$WT_SUDOERS_TEMP" in
            "$WT_SUDOERS_DIRECTORY"/.warptweet-openssh-regress.*)
                rm -f -- "$WT_SUDOERS_TEMP"
                ;;
            *)
                echo "warning: refusing to remove an unexpected sudoers temporary path" >&2
                if [ "$WT_CLEANUP_STATUS" -eq 0 ]; then
                    WT_CLEANUP_STATUS=1
                fi
                ;;
        esac
    fi
    exit "$WT_CLEANUP_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if getent passwd "$WT_BUILD_ACCOUNT" >/dev/null 2>&1 ||
    getent group "$WT_BUILD_GROUP" >/dev/null 2>&1; then
    echo "the dedicated OpenSSH regression account or group already exists" >&2
    exit 73
fi
for WT_ABSENT_PATH in "$WT_BUILD_HOME" "$WT_SUDOERS_PATH"; do
    if [ -e "$WT_ABSENT_PATH" ] || [ -L "$WT_ABSENT_PATH" ]; then
        echo "an OpenSSH regression account path already exists" >&2
        exit 73
    fi
done
if [ ! -d /var/lib ] || [ -L /var/lib ] ||
    [ "$(stat -c '%u:%g:%a' /var/lib 2>/dev/null || true)" != "0:0:755" ]; then
    echo "/var/lib must be the root-owned mode-0755 non-symlink build-home parent" >&2
    exit 77
fi
if [ ! -d "$WT_SUDOERS_DIRECTORY" ] || [ -L "$WT_SUDOERS_DIRECTORY" ]; then
    echo "the sudoers include directory is missing or unsafe" >&2
    exit 77
fi
if [ ! -x "$WT_BUILD_SHELL" ]; then
    echo "the OpenSSH regression account requires executable /bin/sh" >&2
    exit 69
fi
WT_NOBODY_ENTRY=$(getent passwd "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT") || {
    echo "the upstream cross-UID regression account is unavailable" >&2
    exit 69
}
if ! printf '%s\n' "$WT_NOBODY_ENTRY" | awk -F: '
    $1 == "nobody" && $3 ~ /^[0-9]+$/ && $3 != 0 && NF == 7 { found = 1 }
    END { exit(found ? 0 : 1) }
'; then
    echo "the upstream cross-UID regression account is invalid" >&2
    exit 77
fi

useradd \
    --system \
    --user-group \
    --no-create-home \
    --home-dir "$WT_BUILD_HOME" \
    --shell "$WT_BUILD_SHELL" \
    --password '*NP*' \
    "$WT_BUILD_ACCOUNT"
install -d \
    -o "$WT_BUILD_ACCOUNT" \
    -g "$WT_BUILD_GROUP" \
    -m 0700 \
    "$WT_BUILD_HOME" \
    "$WT_BUILD_HOME/go-build" \
    "$WT_BUILD_HOME/tmp"
setfacl -b \
    "$WT_BUILD_HOME" \
    "$WT_BUILD_HOME/go-build" \
    "$WT_BUILD_HOME/tmp"
chmod 0700 \
    "$WT_BUILD_HOME" \
    "$WT_BUILD_HOME/go-build" \
    "$WT_BUILD_HOME/tmp"

WT_SUDOERS_TEMP=$(mktemp "$WT_SUDOERS_DIRECTORY/.warptweet-openssh-regress.XXXXXXXX")
case "$WT_SUDOERS_TEMP" in
    "$WT_SUDOERS_DIRECTORY"/.warptweet-openssh-regress.*) ;;
    *)
        echo "mktemp returned a sudoers path outside the expected directory" >&2
        WT_SUDOERS_TEMP=''
        exit 70
        ;;
esac
printf '%s\n' \
    "$WT_BUILD_ACCOUNT ALL=(root,$WT_UNPRIVILEGED_REGRESSION_ACCOUNT) NOPASSWD: ALL" \
    >"$WT_SUDOERS_TEMP"
chmod 0440 "$WT_SUDOERS_TEMP"
visudo -cf "$WT_SUDOERS_TEMP" >/dev/null
mv -nT -- "$WT_SUDOERS_TEMP" "$WT_SUDOERS_PATH"
if [ -e "$WT_SUDOERS_TEMP" ] || [ -L "$WT_SUDOERS_TEMP" ]; then
    echo "the OpenSSH regression sudoers destination appeared during publication" >&2
    exit 73
fi
WT_SUDOERS_TEMP=''
if [ ! -f "$WT_SUDOERS_PATH" ] || [ -L "$WT_SUDOERS_PATH" ] ||
    [ "$(stat -c '%u:%g:%a' "$WT_SUDOERS_PATH" 2>/dev/null || true)" != "0:0:440" ]; then
    echo "the OpenSSH regression sudoers policy was not published safely" >&2
    exit 70
fi

WT_PASSWD_ENTRY=$(getent passwd "$WT_BUILD_ACCOUNT") || {
    echo "the dedicated OpenSSH regression passwd entry is unavailable" >&2
    exit 70
}
if ! printf '%s\n' "$WT_PASSWD_ENTRY" | awk -F: \
    -v account="$WT_BUILD_ACCOUNT" \
    -v home="$WT_BUILD_HOME" \
    -v shell="$WT_BUILD_SHELL" '
        $1 == account && $3 ~ /^[0-9]+$/ && $3 != 0 &&
        $4 ~ /^[0-9]+$/ && $6 == home && $7 == shell && NF == 7 { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "the dedicated OpenSSH regression passwd entry is invalid" >&2
    exit 70
fi
WT_BUILD_UID=$(printf '%s\n' "$WT_PASSWD_ENTRY" | awk -F: '{ print $3 }')
WT_BUILD_GID=$(printf '%s\n' "$WT_PASSWD_ENTRY" | awk -F: '{ print $4 }')
WT_GROUP_ENTRY=$(getent group "$WT_BUILD_GROUP") || {
    echo "the dedicated OpenSSH regression group entry is unavailable" >&2
    exit 70
}
if ! printf '%s\n' "$WT_GROUP_ENTRY" | awk -F: \
    -v group="$WT_BUILD_GROUP" \
    -v gid="$WT_BUILD_GID" '
        $1 == group && $3 == gid && $4 == "" && NF == 4 { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "the dedicated OpenSSH regression group entry is invalid" >&2
    exit 70
fi
if ! getent shadow "$WT_BUILD_ACCOUNT" | awk -F: \
    -v account="$WT_BUILD_ACCOUNT" '
        $1 == account && $2 == "*NP*" && NF == 9 { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "the dedicated OpenSSH regression account does not have the required non-password sentinel" >&2
    exit 70
fi
if [ "$(stat -c '%u:%g:%a' "$WT_BUILD_HOME" 2>/dev/null || true)" != "$WT_BUILD_UID:$WT_BUILD_GID:700" ]; then
    echo "the dedicated OpenSSH regression home is not private and account-owned" >&2
    exit 70
fi
WT_PRIVATE_DIRECTORY_ACL='user::rwx
group::---
other::---'
if [ "$(getfacl -cp "$WT_BUILD_HOME" 2>/dev/null || true)" != "$WT_PRIVATE_DIRECTORY_ACL" ] ||
    [ "$(id -Gn "$WT_BUILD_ACCOUNT")" != "$WT_BUILD_GROUP" ]; then
    echo "the dedicated OpenSSH regression home or group set is not private" >&2
    exit 70
fi
WT_EXPECTED_SUDOERS="$WT_BUILD_ACCOUNT ALL=(root,$WT_UNPRIVILEGED_REGRESSION_ACCOUNT) NOPASSWD: ALL"
if ! printf '%s\n' "$WT_EXPECTED_SUDOERS" | cmp -s - "$WT_SUDOERS_PATH"; then
    echo "the OpenSSH regression sudoers policy differs from the pinned policy" >&2
    exit 70
fi
if ! sudo -u "$WT_BUILD_ACCOUNT" -H sudo -n true >/dev/null 2>&1 ||
    ! sudo -u "$WT_BUILD_ACCOUNT" -H \
        sudo -n -u "$WT_UNPRIVILEGED_REGRESSION_ACCOUNT" true >/dev/null 2>&1; then
    echo "the dedicated OpenSSH regression account lacks its required non-interactive run-as policy" >&2
    exit 70
fi

echo "provisioned the dedicated ephemeral OpenSSH regression account"
