# Installed server gate

Status: implemented control-plane boundary, 2026-08-10

`warptweet doctor-server` is the mandatory local gate before the packaged WarpTweet `sshd` starts or reloads. It validates one `warptweet.server-gateway` v1 manifest against the fixed Linux installation. It does not start a listener, connect to a client, or establish tunnel readiness.

The Linux account check requires the dedicated tunnel account to use the exact OpenSSH public-key-only `*NP*` shadow sentinel, `/nonexistent` home, and `/usr/sbin/nologin` shell. The separate `warptweet-sshd` privilege-separation account must retain OpenSSH's Linux `!` lock prefix and use its fixed empty directory. Validation classifies the bounded shadow input without retaining or reporting password-field values.

## Fixed installation

The production gate accepts no caller-selected engine or helper paths. It requires:

```text
/opt/warptweet/libexec/openssh/bin/ssh
/opt/warptweet/libexec/openssh/bin/ssh-keygen
/opt/warptweet/libexec/openssh/sbin/sshd
/opt/warptweet/libexec/openssh/libexec/sshd-auth
/opt/warptweet/libexec/openssh/libexec/sshd-session
/opt/warptweet/share/openssh-source.txt
/opt/warptweet/share/openssl-source.txt
/opt/warptweet/share/licenses/openssh/LICENCE
/opt/warptweet/share/licenses/openssl/LICENSE.txt
/opt/warptweet/share/openssh-bundle.sha256
/opt/warptweet/etc/sshd_config
/opt/warptweet/etc/ssh_host_mldsa44_ed25519_key
/opt/warptweet/etc/authorized_keys/<dedicated-user>
/var/empty/warptweet-sshd
```

Critical files must be regular non-symlink files, root-owned on Linux, within their size limits, and not group or world writable. The host private key has the stricter no-group-or-world-access rule. The bundle manifest must list exactly the five OpenSSH executables, both authenticated source receipts, and both upstream license files in canonical sorted `sha256sum` form.

## Proof sequence

The gate performs these checks in order:

1. Strictly decode and validate the server v1 `.wt` policy.
2. Snapshot the fixed files through verified descriptors and compare the manifest-declared `sshd` and bundle-manifest digests.
3. Verify every exact bundle member, both pinned source receipts, their cross-bindings, the native Linux target, and static OpenSSL digest evidence.
4. Require the exact `OpenSSH_10.4p1, OpenSSL 3.5.7 9 Jun 2026` version output and reject dynamic libcrypto, dynamic libssl, RPATH, or RUNPATH on every retained executable.
5. Require the installed `sshd_config` bytes to equal WarpTweet's deterministic renderer output.
6. Validate host-key metadata, then ask the bundled `ssh-keygen` to derive and structurally validate the composite public key.
7. Require exactly one byte-for-byte canonical managed client authorization bound to the declared target.
8. Run the bundled `sshd -t` and reject any diagnostic output.
9. Run the bundled `sshd -T`, then compare every security-critical effective option with the manifest and immutable cryptographic profile.
10. Re-snapshot every tracked non-secret asset and host-key metadata before returning success.

The authenticated OpenSSH receipt also pins Kerberos and PAM support as absent.
In this build, GSSAPI is compiled only through the disabled Kerberos branch.
WarpTweet therefore omits the unsupported `GSSAPIAuthentication`,
`KerberosAuthentication`, and `UsePAM` directives. The fixed bundle cannot
provide those authentication mechanisms, while the rendered and effective
policy still requires composite public-key authentication and explicitly
disables password, keyboard-interactive, and host-based authentication.

The WarpTweet controller never reads, hashes, serializes, or logs host private-key bytes. The bundled `ssh-keygen -y` subprocess necessarily reads the key to derive its public key; only that public output is returned to the controller and used for the reported digest.

## Activation

```sh
/opt/warptweet/bin/warptweet doctor-server \
  --config /etc/warptweet/server.wt
```

Success reports `"status":"preflight_ready"` and `"role":"server"`. The packaged `warptweet-sshd.service` runs this command before both start and reload. Missing files are unit assertion failures rather than silently skipped services.

## Ephemeral CI rehearsal

The Ubuntu CI workflow is configured to run `scripts/test-server-preflight.sh` against the real authenticated OpenSSH stage. The script is deliberately unavailable as a general installation helper. Execution requires Linux, root UID, the explicit `WARPTWEET_CI_FIXED_LAYOUT=1` guard, and caller-bound SHA-256 values for both the bundle manifest and controller. Both input paths must be clean absolute non-symlink paths, and the script refuses to proceed if `/opt/warptweet` or `/etc/warptweet` already exists. Before any account or installation mutation, it validates the fixed root ancestors, copies only the exact inputs into a root-owned mode-0700 snapshot under `/run`, verifies that snapshot against both caller digests and the nine-file manifest, and installs solely from the snapshot. Cleanup removes only that identity-checked private snapshot.

When run, the rehearsal validates the exact nine-member authenticated bundle manifest and every listed stage file, then copies only those members into its root-owned snapshot. It installs only the fixed WarpTweet tree and privilege-separation directory, provisions dedicated CI accounts, generates distinct composite host and client keys, computes the real v1 digests, and uses the built controller to render `sshd_config` and the managed authorization. It then runs `doctor-server` as root and asserts the non-secret `preflight_ready` server report. It never invokes an `sshd` listener. Installed files and test accounts are intentionally left for disposal with the ephemeral hosted runner rather than risking cleanup of host state. A passing hosted run has not yet been observed from this workspace.

## Remaining release evidence

This gate proves the installed local server policy and makes `sshd -t` and `sshd -T` parser drift a CI failure. It does not prove a live client handshake, negotiated algorithms, authentication, forwarding readiness, rekey behavior, target reachability, denial of unauthorized channels, or Linux service confinement. Those remain two-endpoint release gates.
