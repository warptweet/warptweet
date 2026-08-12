# OpenSSH build account

The production bundle lane runs only on a disposable Linux CI runner. It uses
the dedicated `warptweet-build` account, its matching sole group, and a private
mode-0700 home at `/var/lib/warptweet-build`. Source authentication, compilation,
upstream tests, and staging all run as that non-root account. The build script
rejects UID 0, any other identity, a non-private home, extended home ACLs,
sources or output outside that home, and the upstream
`TEST_SSH_UNSAFE_PERMISSIONS` bypass.

The build script fixes its umask at `022` and creates a short private build
root beneath that home. It rejects an OpenSSH regression directory longer than
81 bytes. The bound leaves room for `forward-control.sh` to append
`/ctl-sock` and OpenSSH's 17-byte temporary control-socket suffix within
Linux's 107-byte Unix-domain socket pathname limit.

The account has the exact shadow sentinel `*NP*`. The provisioner and build
validate it without writing the shadow entry to output. This sentinel disables
password authentication without making OpenSSH reject the account before
public-key regression authentication.

The account shell is `/bin/sh`, not `nologin`. OpenSSH regressions execute
remote `true`, shell commands, SCP, and SFTP as the current build user. A
non-executable login shell makes those upstream tests invalid.

The pinned suite receives `SUDO=sudo`. It starts the freshly built `sshd` as
root, runs shell fragments for privileged fixtures, changes ownership, signals
test daemons, and runs `ssh-add` as `nobody`. Those operations make a truthful
command-path sudo allowlist impossible. The sudoers entry therefore permits all
commands only as `root` or `nobody`, only for `warptweet-build`, and only inside
the disposable runner. This policy must not be installed on a persistent build
host or a production endpoint.

The `agent-getpeereid` test must execute the built `ssh-add` as `nobody`. During
`make tests`, the build grants a named `nobody` ACL with traverse-only permission
on the verified home, build root, and source-root ancestors. It grants no read,
directory listing, or write permission. The ACL is removed and mode 0700 is
restored before staging continues, including the test-failure cleanup path.

`scripts/provision-openssh-build-account.sh` is CI opt-in and refuses existing
account, group, home, or sudoers targets. A successful gate still requires a
real run on both supported hosted-runner architectures; static repository tests
prove the policy wiring, not Linux account or ACL behavior.
