# Static OpenSSL

The Linux production bundle builds OpenSSL 3.5.7 from its authenticated source
archive and statically links libcrypto into all OpenSSH executables that use it.

The OpenSSL archive must match the pinned SHA-256 and a valid upstream signature
whose primary certificate fingerprint is the pinned OpenSSL signing identity.
The build runs the OpenSSL tests before configuring OpenSSH.

The 3.5.7 artifact is signed by upstream's retired but still authoritative
primary key `BA5473A2B0587B07FB27CF2D216094DFD0CB81EF`. Verification requires
that exact fingerprint as both the `VALIDSIG` signer and primary identity.

OpenSSL is configured with the fixed logical prefix
`/opt/warptweet/libexec/openssl-static` and with shared libraries, dynamically
loaded modules, DSO loading, and shared-library pinning disabled. The private
installation prefix is a build input only and is not shipped as a runtime
library tree.

The authenticated OpenSSL receipt records the Linux architecture and SHA-256
of the private `libcrypto.a` used for linkage. The OpenSSH receipt records the
target tuple reported by the authenticated OpenSSH `config.guess` input.

Every staged OpenSSH executable is inspected with `readelf`. A build fails if
an executable has a `DT_NEEDED` dependency on libcrypto or libssl, or contains
an RPATH or RUNPATH. The authenticated manifest contains exactly the five
OpenSSH executables, both source receipts, and both upstream license files.

Client runtime preflight independently enforces the current profile at the
fixed `/opt/warptweet/libexec/openssh/bin/ssh` path. On Linux it requires a
root-owned executable and root-owned, non-symlink ancestry that is not group or
world writable. It parses the already-open file as ET_EXEC or ET_DYN ELF,
rejects dynamic libcrypto or libssl and RPATH or RUNPATH, rehashes the same held
file after inspection, and compares size, modification time, and digest. It
then requires empty `ssh -V` stdout and exact stderr
`OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026\n`. All preflight subprocesses and the
client launch receive only `LANG=C` and `LC_ALL=C`.

This production build accepts only native Linux `x86_64` and `aarch64`
endpoints, and requires the authenticated OpenSSH target tuple to match the
native architecture. CI is configured to build and exercise the bundle on
native x86-64 and ARM64 Ubuntu runners. That configuration is not evidence that
either hosted job passed.

The macOS client engine uses the same authenticated OpenSSL source pin and
static-linkage policy through `scripts/build-openssh-darwin.sh`. It stages only
the client inventory under the Application Support layout and inspects Mach-O
load commands instead of ELF dynamic metadata. See
[2026-08-12_macos-openssh-engine.md](2026-08-12_macos-openssh-engine.md).
