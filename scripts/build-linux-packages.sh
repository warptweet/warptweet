#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
umask 022

# Assemble Linux server package trees for amd64/arm64 from a staged OpenSSH
# bundle and built controller. Produces .deb and/or .rpm when packaging tools
# are available. Never downloads payloads and never weakens the fixed layout.

if [ "$#" -ne 3 ]; then
    echo "usage: $0 ABSOLUTE_OPENSSH_STAGE ABSOLUTE_CONTROLLER ABSOLUTE_OUTPUT_DIRECTORY" >&2
    exit 64
fi

if [ "$(uname -s)" != Linux ]; then
    echo "Linux package assembly requires Linux" >&2
    exit 69
fi
if [ "$(id -u)" = "0" ]; then
    echo "Linux package assembly must not run as root" >&2
    exit 77
fi

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
WT_STAGE_INPUT=$1
WT_CONTROLLER_INPUT=$2
WT_OUTPUT_INPUT=$3
WT_VERSION=${WARPTWEET_VERSION:-0.1.0-dev}
WT_ARCH=$(uname -m)
case "$WT_ARCH" in
    x86_64) WT_DEB_ARCH=amd64; WT_RPM_ARCH=x86_64 ;;
    aarch64) WT_DEB_ARCH=arm64; WT_RPM_ARCH=aarch64 ;;
    *)
        echo "unsupported architecture: $WT_ARCH" >&2
        exit 65
        ;;
esac

for WT_PATH in "$WT_STAGE_INPUT" "$WT_CONTROLLER_INPUT" "$WT_OUTPUT_INPUT"; do
    case "$WT_PATH" in
        /*) ;;
        *)
            echo "paths must be absolute" >&2
            exit 64
            ;;
    esac
done
if [ ! -x "$WT_CONTROLLER_INPUT" ] || [ -L "$WT_CONTROLLER_INPUT" ]; then
    echo "controller must be a non-symlink executable" >&2
    exit 66
fi
if [ ! -d "$WT_STAGE_INPUT/opt/warptweet/libexec/openssh" ]; then
    echo "OpenSSH stage missing fixed layout under opt/warptweet/libexec/openssh" >&2
    exit 66
fi
if [ -e "$WT_OUTPUT_INPUT" ] || [ -L "$WT_OUTPUT_INPUT" ]; then
    echo "output directory must not already exist" >&2
    exit 73
fi

mkdir -m 0755 "$WT_OUTPUT_INPUT"
WT_ROOT="$WT_OUTPUT_INPUT/root"
mkdir -p \
    "$WT_ROOT/opt/warptweet/bin" \
    "$WT_ROOT/opt/warptweet/libexec" \
    "$WT_ROOT/opt/warptweet/etc/authorized_keys" \
    "$WT_ROOT/opt/warptweet/share" \
    "$WT_ROOT/etc/warptweet" \
    "$WT_ROOT/etc/warptweet/enrollment" \
    "$WT_ROOT/lib/systemd/system" \
    "$WT_ROOT/var/empty/warptweet-sshd" \
    "$WT_ROOT/var/lib/warptweet/invites" \
    "$WT_ROOT/var/lib/warptweet/clients" \
    "$WT_ROOT/var/lib/warptweet/server" \
    "$WT_ROOT/run/warptweet/server"

# Copy staged OpenSSH server inventory.
cp -a "$WT_STAGE_INPUT/opt/warptweet/." "$WT_ROOT/opt/warptweet/"
install -m 0755 "$WT_CONTROLLER_INPUT" "$WT_ROOT/opt/warptweet/bin/warptweet"
install -m 0644 "$WT_REPOSITORY_ROOT/packaging/systemd/warptweet-sshd.service" \
    "$WT_ROOT/lib/systemd/system/warptweet-sshd.service"
install -m 0644 "$WT_REPOSITORY_ROOT/packaging/systemd/warptweet-enroll.service" \
    "$WT_ROOT/lib/systemd/system/warptweet-enroll.service"
install -m 0644 "$WT_REPOSITORY_ROOT/packaging/systemd/warptweet-tunnel@.service" \
    "$WT_ROOT/lib/systemd/system/warptweet-tunnel@.service"
install -m 0755 "$WT_REPOSITORY_ROOT/packaging/linux/postinst.sh" \
    "$WT_OUTPUT_INPUT/postinst.sh"
install -m 0755 "$WT_REPOSITORY_ROOT/packaging/linux/prerm.sh" \
    "$WT_OUTPUT_INPUT/prerm.sh"

# Refuse missing server binaries and accidental absence of client tools used by
# server key derivation.
for WT_REQUIRED in \
    "$WT_ROOT/opt/warptweet/libexec/openssh/sbin/sshd" \
    "$WT_ROOT/opt/warptweet/libexec/openssh/bin/ssh-keygen" \
    "$WT_ROOT/opt/warptweet/libexec/openssh/libexec/sshd-auth" \
    "$WT_ROOT/opt/warptweet/libexec/openssh/libexec/sshd-session" \
    "$WT_ROOT/opt/warptweet/share/openssh-bundle.sha256"; do
    if [ ! -e "$WT_REQUIRED" ]; then
        echo "package root missing required path: $WT_REQUIRED" >&2
        exit 65
    fi
done

cat >"$WT_OUTPUT_INPUT/control" <<EOF
Package: warptweet
Version: $WT_VERSION
Section: net
Priority: optional
Architecture: $WT_DEB_ARCH
Maintainer: WarpTweet Maintainers <security@warptweet.com>
Depends: adduser, systemd
Description: WarpTweet managed-endpoint post-quantum TCP tunnel host
 WarpTweet installs a fixed-layout OpenSSH host and controller for one
 declared local-forward target. Classical fallback is not provided.
EOF

cat >"$WT_OUTPUT_INPUT/warptweet.spec" <<EOF
Name: warptweet
Version: ${WT_VERSION%%-*}
Release: 1%{?dist}
Summary: WarpTweet managed-endpoint post-quantum TCP tunnel host
License: Apache-2.0
URL: https://warptweet.com/
BuildArch: $WT_RPM_ARCH

%description
WarpTweet installs a fixed-layout OpenSSH host and controller for one
declared local-forward target. Classical fallback is not provided.

%install
mkdir -p %{buildroot}
cp -a $WT_ROOT/. %{buildroot}/

%files
/opt/warptweet
/etc/warptweet
/lib/systemd/system/warptweet-sshd.service
/lib/systemd/system/warptweet-enroll.service
/lib/systemd/system/warptweet-tunnel@.service
/var/empty/warptweet-sshd
/var/lib/warptweet
/run/warptweet

%post
/bin/sh /opt/warptweet/share/linux-postinst.sh || true

%preun
/bin/sh /opt/warptweet/share/linux-prerm.sh || true
EOF

install -m 0755 "$WT_REPOSITORY_ROOT/packaging/linux/postinst.sh" \
    "$WT_ROOT/opt/warptweet/share/linux-postinst.sh"
install -m 0755 "$WT_REPOSITORY_ROOT/packaging/linux/prerm.sh" \
    "$WT_ROOT/opt/warptweet/share/linux-prerm.sh"

if command -v dpkg-deb >/dev/null 2>&1; then
    WT_DEB_ROOT="$WT_OUTPUT_INPUT/deb"
    mkdir -p "$WT_DEB_ROOT/DEBIAN"
    cp -a "$WT_ROOT/." "$WT_DEB_ROOT/"
    install -m 0644 "$WT_OUTPUT_INPUT/control" "$WT_DEB_ROOT/DEBIAN/control"
    install -m 0755 "$WT_OUTPUT_INPUT/postinst.sh" "$WT_DEB_ROOT/DEBIAN/postinst"
    install -m 0755 "$WT_OUTPUT_INPUT/prerm.sh" "$WT_DEB_ROOT/DEBIAN/prerm"
    dpkg-deb --root-owner-group --build "$WT_DEB_ROOT" \
        "$WT_OUTPUT_INPUT/warptweet_${WT_VERSION}_${WT_DEB_ARCH}.deb"
fi

if command -v rpmbuild >/dev/null 2>&1; then
    WT_RPM_TOP="$WT_OUTPUT_INPUT/rpmbuild"
    mkdir -p "$WT_RPM_TOP/BUILD" "$WT_RPM_TOP/RPMS" "$WT_RPM_TOP/SOURCES" "$WT_RPM_TOP/SPECS"
    # rpmbuild packaging is environment-specific; emit the spec and root for
    # release automation even when rpmbuild is incomplete.
    cp "$WT_OUTPUT_INPUT/warptweet.spec" "$WT_RPM_TOP/SPECS/warptweet.spec"
fi

cat >"$WT_OUTPUT_INPUT/MANIFEST.txt" <<EOF
version=$WT_VERSION
arch=$WT_ARCH
deb_arch=$WT_DEB_ARCH
rpm_arch=$WT_RPM_ARCH
controller=opt/warptweet/bin/warptweet
sshd=opt/warptweet/libexec/openssh/sbin/sshd
bundle_manifest=opt/warptweet/share/openssh-bundle.sha256
EOF

echo "built Linux package tree in $WT_OUTPUT_INPUT"
