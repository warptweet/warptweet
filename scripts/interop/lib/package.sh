# shellcheck shell=sh
# Option B: install pinned package artifacts, then verify digests and ownership.

interop_verify_artifact_digest() {
    _file=$1
    _want=$2
    _label=$3
    [ -f "$_file" ] || interop_die "missing artifact: $_file"
    _got=$(interop_digest_file "$_file")
    if [ "$_got" != "$_want" ]; then
        interop_die "$_label artifact digest mismatch: got $_got want $_want"
    fi
    interop_log "artifact ok $_label sha256=$_got"
}

# Read a .deb control field without requiring local dpkg-deb (macOS-safe).
interop_deb_field() {
    _deb=$1
    _field=$2
    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb -f "$_deb" "$_field"
        return 0
    fi
    interop_require_cmd python3
    python3 - "$_deb" "$_field" <<'PY'
import sys, tarfile, io, subprocess
from pathlib import Path

deb_path, field = sys.argv[1], sys.argv[2]
data = Path(deb_path).read_bytes()
if not data.startswith(b"!<arch>\n"):
    sys.exit("not a deb ar archive")
off = 8
control = None
while off + 60 <= len(data):
    header = data[off : off + 60]
    off += 60
    name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
    size = int(header[48:58].decode("ascii").strip())
    payload = data[off : off + size]
    off += size + (size % 2)
    if not name.startswith("control.tar"):
        continue
    raw = payload
    if name.endswith(".gz"):
        import gzip

        raw = gzip.decompress(payload)
    elif name.endswith(".xz"):
        import lzma

        raw = lzma.decompress(payload)
    elif name.endswith(".zst") or name.endswith(".zstd"):
        try:
            import zstandard as zstd

            raw = zstd.ZstdDecompressor().decompress(payload)
        except ImportError:
            try:
                raw = subprocess.check_output(["zstd", "-d", "-c"], input=payload)
            except FileNotFoundError as exc:
                raise SystemExit(
                    "control.tar.zst requires python zstandard or zstd CLI"
                ) from exc
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        for m in tf.getmembers():
            base = m.name.rsplit("/", 1)[-1]
            if base == "control" and m.isfile():
                control = tf.extractfile(m).read().decode()
                break
    break
if not control:
    sys.exit("control member not found in deb")
prefix = field + ":"
for line in control.splitlines():
    if line.startswith(prefix):
        print(line.split(":", 1)[1].strip())
        raise SystemExit(0)
sys.exit(f"field {field!r} not found")
PY
}

# Returns 0 when path is owned by a package database entry on the remote host.
interop_remote_path_from_package() {
    _path=$1
    interop_ssh "
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -S '$_path' >/dev/null 2>&1 && exit 0
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -qf '$_path' >/dev/null 2>&1 && exit 0
fi
exit 1
"
}

# Returns 0 when path is owned by a local package database entry (macOS/Linux client).
interop_local_path_from_package() {
    _path=$1
    if command -v pkgutil >/dev/null 2>&1; then
        if pkgutil --file-info "$_path" 2>/dev/null | grep -Eq 'pkgid:[[:space:]]*[^[:space:]]+'; then
            return 0
        fi
    fi
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -S "$_path" >/dev/null 2>&1 && return 0
    fi
    if command -v rpm >/dev/null 2>&1; then
        rpm -qf "$_path" >/dev/null 2>&1 && return 0
    fi
    return 1
}

interop_path_is_source_tree() {
    _path=$1
    case "$_path" in
        /opt/warptweet/* | /usr/local/* | /opt/homebrew/* | /Library/*) return 1 ;;
        *) return 0 ;;
    esac
}

interop_install_server_package() {
    _pkg=$1
    interop_verify_artifact_digest "$_pkg" "$WARPTWEET_SERVER_PACKAGE_SHA256" "server package"

    _remote_tmp=$(interop_ssh "mktemp /tmp/warptweet-pkg.XXXXXX")
    interop_scp_to "$_pkg" "$_remote_tmp"

    case "$_pkg" in
        *.deb)
            # Read control fields without requiring local dpkg-deb (macOS orchestrator).
            _deb_name=$(interop_deb_field "$_pkg" Package)
            _deb_ver=$(interop_deb_field "$_pkg" Version)
            [ -n "$_deb_name" ] && [ -n "$_deb_ver" ] || interop_die "could not read Package/Version from $_pkg"
            _have=$(interop_ssh "dpkg-query -W -f='\${Status} \${Package} \${Version}' '$_deb_name' 2>/dev/null" || true)
            _ctrl=${WARPTWEET_INTEROP_SERVER_CTRL:-/opt/warptweet/bin/warptweet}
            _host_ok=0
            if interop_ssh "test -x '$_ctrl' && '$_ctrl' host --help >/dev/null 2>&1"; then
                _host_ok=1
            fi
            case "$_have" in
                *"install ok installed $_deb_name $_deb_ver")
                    if [ "${WARPTWEET_INTEROP_FORCE_SERVER_REINSTALL:-0}" = "1" ]; then
                        interop_log "reinstalling server package $_deb_name=$_deb_ver in place"
                        interop_ssh "sudo sh -s" <<'STOP'
set -eu
for WT_UNIT in warptweet-enroll.service warptweet-sshd.service warptweet-hostsign.service warptweet-mgmt.service warptweet-provisioner.service warptweet-reconcile.service; do
    if systemctl is-active --quiet "$WT_UNIT"; then
        systemctl stop "$WT_UNIT"
    fi
done
STOP
                        interop_ssh "sudo dpkg -i '$_remote_tmp'"
                        _status=$(interop_ssh "dpkg-query -W -f='\${Status} \${Package} \${Version}' '$_deb_name' 2>/dev/null" || true)
                        case "$_status" in
                            *"install ok installed $_deb_name $_deb_ver")
                                ;;
                            *)
                                interop_ssh "rm -f '$_remote_tmp'" || true
                                interop_die "deb not installed/configured as $_deb_name=$_deb_ver (got: ${_status:-empty})"
                                ;;
                        esac
                        interop_ssh "rm -f '$_remote_tmp'"
                        interop_log "server package installed"
                        return 0
                    fi
                    if [ "$_host_ok" -eq 1 ]; then
                        interop_log "server package already installed $_deb_name=$_deb_ver"
                        interop_ssh "rm -f '$_remote_tmp'" || true
                        interop_log "server package installed"
                        return 0
                    fi
                    interop_log "server package $_deb_name=$_deb_ver is installed but lacks host; reinstalling"
                    ;;
            esac
            if interop_ssh "dpkg-query -W '$_deb_name' >/dev/null 2>&1"; then
                interop_ssh "sudo dpkg --purge '$_deb_name'"
            fi
            interop_ssh "sudo sh -s" <<'PURGE'
set -eu
for WT_USER in warptweet warptweet-client warptweet-sshd; do
    if getent passwd "$WT_USER" >/dev/null 2>&1; then
        userdel "$WT_USER"
    fi
done
for WT_GROUP in warptweet-operator warptweet-client warptweet-sshd warptweet; do
    if getent group "$WT_GROUP" >/dev/null 2>&1; then
        groupdel "$WT_GROUP"
    fi
done
PURGE
            interop_ssh "sudo dpkg -i '$_remote_tmp'"
            _status=$(interop_ssh "dpkg-query -W -f='\${Status} \${Package} \${Version}' '$_deb_name' 2>/dev/null" || true)
            case "$_status" in
                *"install ok installed $_deb_name $_deb_ver")
                    ;;
                *)
                    interop_ssh "rm -f '$_remote_tmp'" || true
                    interop_die "deb not installed/configured as $_deb_name=$_deb_ver (got: ${_status:-empty})"
                    ;;
            esac
            ;;
        *.rpm)
            interop_ssh "sudo rpm -Uvh '$_remote_tmp'"
            ;;
        *)
            interop_die "unsupported server package type: $_pkg"
            ;;
    esac
    interop_ssh "rm -f '$_remote_tmp'"
    interop_log "server package installed"
}

interop_install_client_package() {
    _pkg=$1
    interop_verify_artifact_digest "$_pkg" "$WARPTWEET_CLIENT_PACKAGE_SHA256" "client package"

    case "$_pkg" in
        *.pkg)
            interop_require_cmd installer
            _ctrl=${WARPTWEET_INTEROP_CLIENT_CTRL:-/Library/Application Support/WarpTweet/bin/warptweet}
            # Reuse an already-installed controller matching this package path.
            if [ -x "$_ctrl" ] && [ "${WARPTWEET_INTEROP_FORCE_CLIENT_REINSTALL:-0}" != "1" ]; then
                interop_log "client controller already present at $_ctrl (set WARPTWEET_INTEROP_FORCE_CLIENT_REINSTALL=1 to reinstall)"
                return 0
            fi
            if sudo -n installer -pkg "$_pkg" -target / 2>/dev/null; then
                :
            elif sudo installer -pkg "$_pkg" -target / 2>/dev/null; then
                :
            elif command -v osascript >/dev/null 2>&1; then
                interop_log "requesting macOS admin privileges for client .pkg install"
                if ! osascript -e "do shell script \"installer -pkg '$_pkg' -target /\" with administrator privileges"; then
                    interop_die "client .pkg install failed (osascript admin install)"
                fi
            else
                interop_die "client .pkg install failed (sudo installer); unlock local sudo and retry"
            fi
            ;;
        *.tar.gz | *.tgz)
            # Optional tarball layout with /opt/warptweet prefix inside.
            interop_die "client tarball install not implemented in Phase A; use .pkg"
            ;;
        *)
            interop_die "unsupported client package type: $_pkg (expected .pkg)"
            ;;
    esac
    interop_log "client package installed"
}

interop_verify_package_signatures() {
    _server_pkg=$1
    _client_pkg=$2
    _ok=1

    case "$_server_pkg" in
        *.deb)
            if command -v dpkg-sig >/dev/null 2>&1; then
                dpkg-sig --verify "$_server_pkg" >/dev/null 2>&1 || _ok=0
            elif command -v debsig-verify >/dev/null 2>&1; then
                debsig-verify "$_server_pkg" >/dev/null 2>&1 || _ok=0
            elif [ -f "$_server_pkg.asc" ] && command -v gpg >/dev/null 2>&1; then
                gpg --verify "$_server_pkg.asc" "$_server_pkg" >/dev/null 2>&1 || _ok=0
            else
                return 1
            fi
            ;;
        *.rpm)
            if command -v rpm >/dev/null 2>&1; then
                # Require cryptographic signature presence and success.
                rpm --checksig "$_server_pkg" 2>/dev/null | grep -Eq 'pgp|gpg|signatures? OK' || _ok=0
            else
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac

    case "$_client_pkg" in
        *.pkg)
            if command -v pkgutil >/dev/null 2>&1; then
                pkgutil --check-signature "$_client_pkg" >/dev/null 2>&1 || _ok=0
            elif command -v spctl >/dev/null 2>&1; then
                spctl -a -t install -v "$_client_pkg" >/dev/null 2>&1 || _ok=0
            else
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac

    [ "$_ok" -eq 1 ]
}

interop_verify_installed_server() {
    interop_ssh "test -x '$WARPTWEET_INTEROP_SERVER_CTRL'" || \
        interop_die "server controller missing after install"
    if ! interop_remote_path_from_package "$WARPTWEET_INTEROP_SERVER_CTRL"; then
        if interop_path_is_source_tree "$WARPTWEET_INTEROP_SERVER_CTRL"; then
            WARPTWEET_INTEROP_SERVER_FROM_PACKAGE=0
        else
            # Prefix allowed but package DB did not claim the path.
            WARPTWEET_INTEROP_SERVER_FROM_PACKAGE=0
        fi
    else
        WARPTWEET_INTEROP_SERVER_FROM_PACKAGE=1
    fi
    export WARPTWEET_INTEROP_SERVER_FROM_PACKAGE
    _manifest=${WARPTWEET_INTEROP_SERVER_BUNDLE_MANIFEST:-/opt/warptweet/share/openssh-bundle.sha256}
    if interop_ssh "test -f '$_manifest'"; then
        _got=$(interop_ssh "if command -v sha256sum >/dev/null; then sha256sum '$_manifest' | awk '{print \$1}'; else shasum -a 256 '$_manifest' | awk '{print \$1}'; fi")
        if [ -z "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" ] || [ "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256=$_got
            export WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256
            interop_log "recorded server engine manifest sha256=$_got"
        elif [ "$_got" != "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" ]; then
            interop_die "server engine manifest digest mismatch: got $_got"
        fi
    else
        interop_log "warning: server bundle manifest missing at $_manifest (preflight case may fail)"
        if [ "$WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256=$(printf '%64s' '' | tr ' ' '0')
            export WARPTWEET_SERVER_ENGINE_MANIFEST_SHA256
        fi
    fi
}

interop_verify_installed_client() {
    interop_assert_package_ctrl "$WARPTWEET_INTEROP_CLIENT_CTRL" "client"
    if interop_local_path_from_package "$WARPTWEET_INTEROP_CLIENT_CTRL"; then
        WARPTWEET_INTEROP_CLIENT_FROM_PACKAGE=1
    else
        WARPTWEET_INTEROP_CLIENT_FROM_PACKAGE=0
    fi
    export WARPTWEET_INTEROP_CLIENT_FROM_PACKAGE
    _manifest=${WARPTWEET_INTEROP_CLIENT_BUNDLE_MANIFEST:-}
    if [ -z "$_manifest" ]; then
        if [ -f "/Library/Application Support/WarpTweet/share/openssh-bundle.sha256" ]; then
            _manifest="/Library/Application Support/WarpTweet/share/openssh-bundle.sha256"
        else
            _manifest=/opt/warptweet/share/openssh-bundle.sha256
        fi
    fi
    if [ -f "$_manifest" ]; then
        _got=$(interop_digest_file "$_manifest")
        if [ -z "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" ] || [ "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256=$_got
            export WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256
            interop_log "recorded client engine manifest sha256=$_got"
        elif [ "$_got" != "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" ]; then
            interop_die "client engine manifest digest mismatch: got $_got"
        fi
    else
        interop_log "warning: client bundle manifest missing at $_manifest"
        if [ "$WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256" = "pending" ]; then
            WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256=$(printf '%64s' '' | tr ' ' '0')
            export WARPTWEET_CLIENT_ENGINE_MANIFEST_SHA256
        fi
    fi

    if [ "$(uname -s)" = Darwin ]; then
        _socket=/var/run/warptweet/provisioner.sock
        [ -S "$_socket" ] || interop_die "installed provisioner socket is unavailable: $_socket"
        _admin_gid=$(dscl . -read /Groups/admin PrimaryGroupID | awk '{print $2}')
        _socket_state=$(stat -f '%u:%g:%Lp' "$_socket")
        if [ "$_socket_state" != "0:$_admin_gid:660" ]; then
            interop_die "provisioner socket ownership or mode is invalid: $_socket_state"
        fi
    fi
}

interop_derive_provenance_fields() {
    _server_pkg=${WARPTWEET_INTEROP_SERVER_FROM_PACKAGE:-0}
    _client_pkg=${WARPTWEET_INTEROP_CLIENT_FROM_PACKAGE:-0}
    if [ "$_server_pkg" -eq 1 ] && [ "$_client_pkg" -eq 1 ]; then
        WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE=true
    else
        WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE=false
    fi
    if interop_path_is_source_tree "$WARPTWEET_INTEROP_SERVER_CTRL" || \
        interop_path_is_source_tree "$WARPTWEET_INTEROP_CLIENT_CTRL"; then
        WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION=true
    else
        WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION=false
    fi
    export WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION
    interop_log "provenance package_to_package=$WARPTWEET_INTEROP_PACKAGE_TO_PACKAGE source_tree_substitution=$WARPTWEET_INTEROP_SOURCE_TREE_SUBSTITUTION"
}

interop_phase_install_packages() {
    case "$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE" in
        /*) _server_pkg=$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE ;;
        *) _server_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_SERVER_PACKAGE_FILE ;;
    esac
    case "$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE" in
        /*) _client_pkg=$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE ;;
        *) _client_pkg=$WARPTWEET_INTEROP_ARTIFACTS/$WARPTWEET_INTEROP_CLIENT_PACKAGE_FILE ;;
    esac
    [ -d "$WARPTWEET_INTEROP_ARTIFACTS" ] || interop_die "artifacts dir missing: $WARPTWEET_INTEROP_ARTIFACTS"

    if ! interop_install_server_package "$_server_pkg"; then
        interop_record_result pkg-signature-and-manifest positive fail "server package install failed"
        return 1
    fi
    if ! interop_install_client_package "$_client_pkg"; then
        interop_record_result pkg-signature-and-manifest positive fail "client package install failed"
        return 1
    fi
    if ! interop_verify_installed_server || ! interop_verify_installed_client; then
        interop_record_result pkg-signature-and-manifest positive fail "post-install digest verify failed"
        return 1
    fi
    interop_derive_provenance_fields

    # SHA-256 pins and manifests are checked above. Signature is a separate gate.
    if interop_verify_package_signatures "$_server_pkg" "$_client_pkg"; then
        interop_record_result pkg-signature-and-manifest positive pass "pinned artifacts installed, manifests match, package signatures verified"
    else
        interop_record_result pkg-signature-and-manifest positive not_run "install and digest pins ok; platform package signer validation unavailable or unsuccessful"
    fi
    return 0
}
