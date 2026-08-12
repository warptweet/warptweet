#!/bin/sh
set -eu

fail() {
    echo "fixed-layout server preflight: $*" >&2
    exit 1
}

if [ "${WARPTWEET_CI_FIXED_LAYOUT:-}" != "1" ]; then
    fail "WARPTWEET_CI_FIXED_LAYOUT=1 is required; this gate is only for an ephemeral CI runner"
fi
if [ "$(uname -s)" != "Linux" ]; then
    fail "Linux is required"
fi
if [ "$(id -u)" != "0" ]; then
    fail "root UID is required"
fi
if [ "$#" -ne 4 ]; then
    echo "usage: $0 ABSOLUTE_AUTHENTICATED_STAGE ABSOLUTE_CONTROLLER EXPECTED_BUNDLE_MANIFEST_SHA256 EXPECTED_CONTROLLER_SHA256" >&2
    exit 64
fi

WT_SOURCE_STAGE_DIRECTORY=$1
WT_SOURCE_CONTROLLER_INPUT=$2
WT_EXPECTED_BUNDLE_MANIFEST_SHA256=$3
WT_EXPECTED_CONTROLLER_SHA256=$4

for WT_DIGEST in "$WT_EXPECTED_BUNDLE_MANIFEST_SHA256" "$WT_EXPECTED_CONTROLLER_SHA256"; do
    if [ "${#WT_DIGEST}" -ne 64 ]; then
        fail "expected SHA-256 values must contain exactly 64 lowercase hexadecimal characters"
    fi
    case "$WT_DIGEST" in
        *[!0-9a-f]*)
            fail "expected SHA-256 values must contain exactly 64 lowercase hexadecimal characters"
            ;;
    esac
done

for WT_TOOL in awk chmod cmp cp getent id install mktemp realpath rm sed sha256sum stat uname useradd; do
    if ! command -v "$WT_TOOL" >/dev/null 2>&1; then
        fail "required tool is unavailable: $WT_TOOL"
    fi
done
if [ ! -x /usr/sbin/nologin ]; then
    fail "/usr/sbin/nologin is required"
fi

case "$WT_SOURCE_STAGE_DIRECTORY:$WT_SOURCE_CONTROLLER_INPUT" in
    /*:/*) ;;
    *)
        fail "stage and controller paths must be absolute"
        ;;
esac
if [ ! -d "$WT_SOURCE_STAGE_DIRECTORY" ] || [ -L "$WT_SOURCE_STAGE_DIRECTORY" ]; then
    fail "stage must be a regular non-symlink directory"
fi
if [ ! -f "$WT_SOURCE_CONTROLLER_INPUT" ] || [ -L "$WT_SOURCE_CONTROLLER_INPUT" ] || [ ! -x "$WT_SOURCE_CONTROLLER_INPUT" ]; then
    fail "controller must be a regular non-symlink executable"
fi
if [ "$(realpath -e -- "$WT_SOURCE_STAGE_DIRECTORY")" != "$WT_SOURCE_STAGE_DIRECTORY" ]; then
    fail "stage path must be clean, absolute, and physically resolved"
fi
if [ "$(realpath -e -- "$WT_SOURCE_CONTROLLER_INPUT")" != "$WT_SOURCE_CONTROLLER_INPUT" ]; then
    fail "controller path must be clean, absolute, and physically resolved"
fi

require_root_directory() {
    WT_ROOT_DIRECTORY=$1
    if [ ! -d "$WT_ROOT_DIRECTORY" ] || [ -L "$WT_ROOT_DIRECTORY" ]; then
        fail "required root directory is missing or unsafe: $WT_ROOT_DIRECTORY"
    fi
    if [ "$(realpath -e -- "$WT_ROOT_DIRECTORY")" != "$WT_ROOT_DIRECTORY" ]; then
        fail "required root directory is not physically resolved: $WT_ROOT_DIRECTORY"
    fi
    if [ "$(stat -c '%u:%g:%a' "$WT_ROOT_DIRECTORY")" != "0:0:755" ]; then
        fail "required root directory has unexpected ownership or mode: $WT_ROOT_DIRECTORY"
    fi
}

for WT_ROOT_DIRECTORY in /opt /etc /var /var/empty /run; do
    require_root_directory "$WT_ROOT_DIRECTORY"
done

if [ -e /opt/warptweet ] || [ -L /opt/warptweet ]; then
    fail "/opt/warptweet already exists; refusing to overwrite host state"
fi
if [ -e /etc/warptweet ] || [ -L /etc/warptweet ]; then
    fail "/etc/warptweet already exists; refusing to overwrite host state"
fi

umask 077
export LC_ALL=C

WT_BUNDLE_MANIFEST_RELATIVE=opt/warptweet/share/openssh-bundle.sha256
WT_EXECUTABLE_PATHS='opt/warptweet/libexec/openssh/bin/ssh
opt/warptweet/libexec/openssh/bin/ssh-keygen
opt/warptweet/libexec/openssh/libexec/sshd-auth
opt/warptweet/libexec/openssh/libexec/sshd-session
opt/warptweet/libexec/openssh/sbin/sshd'
WT_METADATA_PATHS='opt/warptweet/share/licenses/openssh/LICENCE
opt/warptweet/share/licenses/openssl/LICENSE.txt
opt/warptweet/share/openssh-source.txt
opt/warptweet/share/openssl-source.txt'
WT_EXPECTED_BUNDLE_PATHS="$WT_EXECUTABLE_PATHS
$WT_METADATA_PATHS"

verify_stage() {
    WT_VERIFY_STAGE=$1
    WT_VERIFY_MANIFEST="$WT_VERIFY_STAGE/$WT_BUNDLE_MANIFEST_RELATIVE"
    if [ ! -f "$WT_VERIFY_MANIFEST" ] || [ -L "$WT_VERIFY_MANIFEST" ]; then
        fail "authenticated stage bundle manifest is missing or unsafe"
    fi
    if [ "$(realpath -e -- "$WT_VERIFY_MANIFEST")" != "$WT_VERIFY_MANIFEST" ]; then
        fail "authenticated stage bundle manifest is not physically resolved"
    fi
    WT_ACTUAL_BUNDLE_PATHS=$(sed -n 's/^[0-9a-f]\{64\}  //p' "$WT_VERIFY_MANIFEST")
    if [ "$WT_ACTUAL_BUNDLE_PATHS" != "$WT_EXPECTED_BUNDLE_PATHS" ]; then
        fail "authenticated stage bundle manifest does not contain the exact nine fixed files"
    fi
    for WT_RELATIVE_PATH in $WT_EXPECTED_BUNDLE_PATHS; do
        WT_STAGE_FILE="$WT_VERIFY_STAGE/$WT_RELATIVE_PATH"
        if [ ! -f "$WT_STAGE_FILE" ] || [ -L "$WT_STAGE_FILE" ]; then
            fail "authenticated stage member is missing or unsafe: $WT_RELATIVE_PATH"
        fi
        if [ "$(realpath -e -- "$WT_STAGE_FILE")" != "$WT_STAGE_FILE" ]; then
            fail "authenticated stage member is not physically resolved: $WT_RELATIVE_PATH"
        fi
    done
    for WT_RELATIVE_PATH in $WT_EXECUTABLE_PATHS; do
        if [ ! -x "$WT_VERIFY_STAGE/$WT_RELATIVE_PATH" ]; then
            fail "authenticated stage executable is not executable: $WT_RELATIVE_PATH"
        fi
    done
    (
        cd "$WT_VERIFY_STAGE"
        sha256sum --check --strict "$WT_BUNDLE_MANIFEST_RELATIVE" >/dev/null
    ) || fail "authenticated stage bundle verification failed"
}

verify_stage "$WT_SOURCE_STAGE_DIRECTORY"
WT_SOURCE_BUNDLE_MANIFEST="$WT_SOURCE_STAGE_DIRECTORY/$WT_BUNDLE_MANIFEST_RELATIVE"
WT_SOURCE_BUNDLE_MANIFEST_SHA256=$(sha256sum "$WT_SOURCE_BUNDLE_MANIFEST" | awk '{print $1}')
WT_SOURCE_CONTROLLER_SHA256=$(sha256sum "$WT_SOURCE_CONTROLLER_INPUT" | awk '{print $1}')
if [ "$WT_SOURCE_BUNDLE_MANIFEST_SHA256" != "$WT_EXPECTED_BUNDLE_MANIFEST_SHA256" ]; then
    fail "authenticated stage bundle manifest does not match the caller-bound digest"
fi
if [ "$WT_SOURCE_CONTROLLER_SHA256" != "$WT_EXPECTED_CONTROLLER_SHA256" ]; then
    fail "controller does not match the caller-bound digest"
fi

WT_SNAPSHOT_PARENT=/run
WT_SNAPSHOT_PARENT_ID=$(stat -c '%d:%i' "$WT_SNAPSHOT_PARENT") ||
    fail "cannot identify the root-owned snapshot parent"
WT_SNAPSHOT_ROOT=''
WT_SNAPSHOT_ROOT_ID=''
cleanup_snapshot() {
    WT_CLEANUP_STATUS=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WT_SNAPSHOT_ROOT" ] && { [ -e "$WT_SNAPSHOT_ROOT" ] || [ -L "$WT_SNAPSHOT_ROOT" ]; }; then
        WT_CURRENT_PARENT_ID=$(stat -c '%d:%i' "$WT_SNAPSHOT_PARENT" 2>/dev/null || true)
        WT_CURRENT_SNAPSHOT_ID=$(stat -c '%d:%i' "$WT_SNAPSHOT_ROOT" 2>/dev/null || true)
        if [ "$WT_CURRENT_PARENT_ID" != "$WT_SNAPSHOT_PARENT_ID" ] ||
            [ "$WT_CURRENT_SNAPSHOT_ID" != "$WT_SNAPSHOT_ROOT_ID" ] ||
            [ ! -d "$WT_SNAPSHOT_ROOT" ] || [ -L "$WT_SNAPSHOT_ROOT" ]; then
            echo "fixed-layout server preflight: refusing to remove a substituted snapshot directory" >&2
            WT_CLEANUP_STATUS=1
        elif ! rm -rf -- "$WT_SNAPSHOT_ROOT"; then
            echo "fixed-layout server preflight: cannot remove the private snapshot directory" >&2
            WT_CLEANUP_STATUS=1
        fi
    fi
    exit "$WT_CLEANUP_STATUS"
}
trap cleanup_snapshot EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

WT_SNAPSHOT_ROOT=$(mktemp -d "$WT_SNAPSHOT_PARENT/warptweet-fixed-layout.XXXXXXXXXX") ||
    fail "cannot create the root-owned private snapshot"
chmod 0700 "$WT_SNAPSHOT_ROOT"
WT_SNAPSHOT_ROOT_ID=$(stat -c '%d:%i' "$WT_SNAPSHOT_ROOT") ||
    fail "cannot identify the root-owned private snapshot"
WT_SNAPSHOT_STAGE="$WT_SNAPSHOT_ROOT/stage"
WT_SNAPSHOT_CONTROLLER="$WT_SNAPSHOT_ROOT/warptweet-controller"
install -d -o root -g root -m 0755 \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/libexec/openssh/bin" \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/libexec/openssh/libexec" \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/libexec/openssh/sbin" \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/share/licenses/openssh" \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/share/licenses/openssl" \
    "$WT_SNAPSHOT_STAGE/opt/warptweet/share"

copy_snapshot_file() {
    WT_COPY_SOURCE=$1
    WT_COPY_DESTINATION=$2
    WT_COPY_MODE=$3
    cp --no-dereference --reflink=never -- "$WT_COPY_SOURCE" "$WT_COPY_DESTINATION" ||
        fail "cannot copy a caller artifact into the private snapshot"
    if [ ! -f "$WT_COPY_DESTINATION" ] || [ -L "$WT_COPY_DESTINATION" ]; then
        fail "private snapshot contains a non-regular copied artifact"
    fi
    chmod "$WT_COPY_MODE" "$WT_COPY_DESTINATION"
}

for WT_RELATIVE_PATH in $WT_EXECUTABLE_PATHS; do
    copy_snapshot_file \
        "$WT_SOURCE_STAGE_DIRECTORY/$WT_RELATIVE_PATH" \
        "$WT_SNAPSHOT_STAGE/$WT_RELATIVE_PATH" \
        0755
done
for WT_RELATIVE_PATH in $WT_METADATA_PATHS; do
    copy_snapshot_file \
        "$WT_SOURCE_STAGE_DIRECTORY/$WT_RELATIVE_PATH" \
        "$WT_SNAPSHOT_STAGE/$WT_RELATIVE_PATH" \
        0644
done
copy_snapshot_file \
    "$WT_SOURCE_BUNDLE_MANIFEST" \
    "$WT_SNAPSHOT_STAGE/$WT_BUNDLE_MANIFEST_RELATIVE" \
    0644
copy_snapshot_file "$WT_SOURCE_CONTROLLER_INPUT" "$WT_SNAPSHOT_CONTROLLER" 0755

WT_STAGE_DIRECTORY=$WT_SNAPSHOT_STAGE
WT_CONTROLLER_INPUT=$WT_SNAPSHOT_CONTROLLER
WT_BUNDLE_MANIFEST="$WT_STAGE_DIRECTORY/$WT_BUNDLE_MANIFEST_RELATIVE"
verify_stage "$WT_STAGE_DIRECTORY"
if [ "$(sha256sum "$WT_BUNDLE_MANIFEST" | awk '{print $1}')" != "$WT_EXPECTED_BUNDLE_MANIFEST_SHA256" ]; then
    fail "root-owned bundle snapshot does not match the caller-bound digest"
fi
if [ "$(sha256sum "$WT_CONTROLLER_INPUT" | awk '{print $1}')" != "$WT_EXPECTED_CONTROLLER_SHA256" ]; then
    fail "root-owned controller snapshot does not match the caller-bound digest"
fi

WT_PRIVSEP_USER=warptweet-sshd
WT_PRIVSEP_GROUP=warptweet-sshd
WT_PRIVSEP_DIRECTORY=/var/empty/warptweet-sshd
WT_CREATE_PRIVSEP_ACCOUNT=0
if WT_PRIVSEP_ENTRY=$(getent passwd "$WT_PRIVSEP_USER"); then
    IFS=: read -r WT_ACCOUNT_NAME WT_ACCOUNT_PASSWORD WT_ACCOUNT_UID WT_ACCOUNT_GID WT_ACCOUNT_GECOS WT_ACCOUNT_HOME WT_ACCOUNT_SHELL <<EOF
$WT_PRIVSEP_ENTRY
EOF
    if [ "$WT_ACCOUNT_NAME" != "$WT_PRIVSEP_USER" ] ||
        [ "$WT_ACCOUNT_UID" = "0" ] ||
        [ "$WT_ACCOUNT_HOME" != "$WT_PRIVSEP_DIRECTORY" ] ||
        [ "$WT_ACCOUNT_SHELL" != "/usr/sbin/nologin" ]; then
        fail "existing privilege-separation account does not match the fixed CI contract"
    fi
    WT_PRIVSEP_GROUP_ENTRY=$(getent group "$WT_PRIVSEP_GROUP") ||
        fail "existing privilege-separation account has no matching group"
    IFS=: read -r WT_GROUP_NAME WT_GROUP_PASSWORD WT_GROUP_GID WT_GROUP_MEMBERS <<EOF
$WT_PRIVSEP_GROUP_ENTRY
EOF
    if [ "$WT_GROUP_NAME" != "$WT_PRIVSEP_GROUP" ] || [ "$WT_GROUP_GID" != "$WT_ACCOUNT_GID" ]; then
        fail "existing privilege-separation group does not match the fixed CI contract"
    fi
else
    if getent group "$WT_PRIVSEP_GROUP" >/dev/null 2>&1; then
        fail "privilege-separation group exists without its fixed account"
    fi
    WT_CREATE_PRIVSEP_ACCOUNT=1
fi
WT_CREATE_PRIVSEP_DIRECTORY=0
if [ -e "$WT_PRIVSEP_DIRECTORY" ] || [ -L "$WT_PRIVSEP_DIRECTORY" ]; then
    if [ ! -d "$WT_PRIVSEP_DIRECTORY" ] || [ -L "$WT_PRIVSEP_DIRECTORY" ]; then
        fail "existing privilege-separation path is not a regular directory"
    fi
    if [ "$(stat -c '%u:%g:%a' "$WT_PRIVSEP_DIRECTORY")" != "0:0:755" ]; then
        fail "existing privilege-separation directory has unsafe ownership or mode"
    fi
    if [ "$(realpath -e -- "$WT_PRIVSEP_DIRECTORY")" != "$WT_PRIVSEP_DIRECTORY" ]; then
        fail "existing privilege-separation directory is not physically resolved"
    fi
else
    WT_CREATE_PRIVSEP_DIRECTORY=1
fi

WT_TUNNEL_USER=warptweet
if getent passwd "$WT_TUNNEL_USER" >/dev/null 2>&1 || getent group "$WT_TUNNEL_USER" >/dev/null 2>&1; then
    fail "dedicated test account already exists; refusing to reuse host state"
fi
if [ "$WT_CREATE_PRIVSEP_ACCOUNT" -eq 1 ]; then
    useradd \
        --system \
        --user-group \
        --no-create-home \
        --home-dir "$WT_PRIVSEP_DIRECTORY" \
        --shell /usr/sbin/nologin \
        "$WT_PRIVSEP_USER"
fi
if [ "$WT_CREATE_PRIVSEP_DIRECTORY" -eq 1 ]; then
    install -d -o root -g root -m 0755 "$WT_PRIVSEP_DIRECTORY"
fi
useradd \
    --system \
    --user-group \
    --no-create-home \
    --home-dir /nonexistent \
    --password '*NP*' \
    --shell /usr/sbin/nologin \
    "$WT_TUNNEL_USER"

install -d -o root -g root -m 0755 \
    /opt/warptweet \
    /opt/warptweet/bin \
    /opt/warptweet/etc \
    /opt/warptweet/etc/authorized_keys \
    /opt/warptweet/libexec \
    /opt/warptweet/libexec/openssh \
    /opt/warptweet/libexec/openssh/bin \
    /opt/warptweet/libexec/openssh/libexec \
    /opt/warptweet/libexec/openssh/sbin \
    /opt/warptweet/share \
    /opt/warptweet/share/licenses \
    /opt/warptweet/share/licenses/openssh \
    /opt/warptweet/share/licenses/openssl \
    /etc/warptweet

for WT_RELATIVE_PATH in $WT_EXECUTABLE_PATHS; do
    install -o root -g root -m 0755 \
        "$WT_STAGE_DIRECTORY/$WT_RELATIVE_PATH" \
        "/$WT_RELATIVE_PATH"
done
for WT_RELATIVE_PATH in $WT_METADATA_PATHS; do
    install -o root -g root -m 0644 \
        "$WT_STAGE_DIRECTORY/$WT_RELATIVE_PATH" \
        "/$WT_RELATIVE_PATH"
done
install -o root -g root -m 0644 \
    "$WT_BUNDLE_MANIFEST" \
    /opt/warptweet/share/openssh-bundle.sha256
install -o root -g root -m 0755 "$WT_CONTROLLER_INPUT" /opt/warptweet/bin/warptweet
if [ "$(sha256sum /opt/warptweet/share/openssh-bundle.sha256 | awk '{print $1}')" != "$WT_EXPECTED_BUNDLE_MANIFEST_SHA256" ]; then
    fail "installed bundle manifest does not match the caller-bound digest"
fi
if [ "$(sha256sum /opt/warptweet/bin/warptweet | awk '{print $1}')" != "$WT_EXPECTED_CONTROLLER_SHA256" ]; then
    fail "installed controller does not match the caller-bound digest"
fi
(
    cd /
    sha256sum --check --strict opt/warptweet/share/openssh-bundle.sha256 >/dev/null
) || fail "installed OpenSSH bundle failed authentication before execution"

WT_KEYGEN=/opt/warptweet/libexec/openssh/bin/ssh-keygen
WT_HOST_KEY=/opt/warptweet/etc/ssh_host_mldsa44_ed25519_key
WT_CLIENT_KEY=/opt/warptweet/etc/.ci_client_mldsa44_ed25519_key
"$WT_KEYGEN" -q -t mldsa44-ed25519 -N '' -C warptweet-ci-host -f "$WT_HOST_KEY"
"$WT_KEYGEN" -q -t mldsa44-ed25519 -N '' -C warptweet-ci-client -f "$WT_CLIENT_KEY"
if cmp -s "$WT_HOST_KEY.pub" "$WT_CLIENT_KEY.pub"; then
    fail "host and client composite public keys must be distinct"
fi
chmod 0600 "$WT_HOST_KEY" "$WT_CLIENT_KEY"
chmod 0644 "$WT_HOST_KEY.pub" "$WT_CLIENT_KEY.pub"

WT_SSHD=/opt/warptweet/libexec/openssh/sbin/sshd
WT_INSTALLED_BUNDLE_MANIFEST=/opt/warptweet/share/openssh-bundle.sha256
WT_SSHD_SHA256=$(sha256sum "$WT_SSHD" | awk '{print $1}')
WT_BUNDLE_SHA256=$(sha256sum "$WT_INSTALLED_BUNDLE_MANIFEST" | awk '{print $1}')
WT_SERVER_MANIFEST=/etc/warptweet/server.wt
{
    printf '%s\n' '{'
    printf '%s\n' '  "kind": "warptweet.server-gateway",'
    printf '%s\n' '  "schema_version": 1,'
    printf '%s\n' '  "profile_id": "warptweet-tcp1-openssh10.4p1-openssl3.5.7-mlkem768x25519-mldsa44-ed25519",'
    printf '  "sshd_binary_sha256": "%s",\n' "$WT_SSHD_SHA256"
    printf '  "openssh_bundle_manifest_sha256": "%s",\n' "$WT_BUNDLE_SHA256"
    printf '%s\n' '  "listen": {"address": "127.0.0.1", "port": 2222},'
    printf '%s\n' '  "target": {"address": "127.0.0.1", "port": 5432},'
    printf '%s\n' '  "dedicated_user": "warptweet",'
    printf '%s\n' '  "host_key_path": "/opt/warptweet/etc/ssh_host_mldsa44_ed25519_key",'
    printf '%s\n' '  "authorized_keys_path": "/opt/warptweet/etc/authorized_keys/warptweet"'
    printf '%s\n' '}'
} >"$WT_SERVER_MANIFEST"
chmod 0644 "$WT_SERVER_MANIFEST"

/opt/warptweet/bin/warptweet render-server \
    --config "$WT_SERVER_MANIFEST" \
    >/opt/warptweet/etc/sshd_config
chmod 0644 /opt/warptweet/etc/sshd_config
/opt/warptweet/bin/warptweet render-authorized-key \
    --config "$WT_SERVER_MANIFEST" \
    --public-key "$WT_CLIENT_KEY.pub" \
    >/opt/warptweet/etc/authorized_keys/warptweet
chmod 0644 /opt/warptweet/etc/authorized_keys/warptweet

rm -f -- "$WT_CLIENT_KEY" "$WT_CLIENT_KEY.pub"

WT_REPORT=$(/opt/warptweet/bin/warptweet doctor-server --config "$WT_SERVER_MANIFEST")
case "$WT_REPORT" in
    *'"status":"preflight_ready"'*) ;;
    *) fail "doctor-server did not report preflight_ready" ;;
esac
case "$WT_REPORT" in
    *'"role":"server"'*) ;;
    *) fail "doctor-server did not report the server role" ;;
esac
case "$WT_REPORT" in
    *'"engine_version":"OpenSSH_10.4p1"'*) ;;
    *) fail "doctor-server reported an unexpected engine version" ;;
esac
case "$WT_REPORT" in
    *'"authorized_key_count":1'*) ;;
    *) fail "doctor-server did not validate exactly one managed client key" ;;
esac
case "$WT_REPORT" in
    *"\"sshd_sha256\":\"$WT_SSHD_SHA256\""*) ;;
    *) fail "doctor-server reported an unexpected sshd digest" ;;
esac
case "$WT_REPORT" in
    *"\"openssh_bundle_manifest_sha256\":\"$WT_BUNDLE_SHA256\""*) ;;
    *) fail "doctor-server reported an unexpected bundle digest" ;;
esac

printf '%s\n' "$WT_REPORT"
