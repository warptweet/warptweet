# Fixed client layout

Client manifest v1 contains no caller-selected filesystem path. The manifest
contains the exact `ssh` digest, endpoint policy, tunnel declarations, and
supervision policy. Production derives all executable, identity, trust, and
manifest paths from the installed WarpTweet layout.

## Linux paths

| Path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/warptweet` | `root:root` | `0755` | Managed client state root |
| `/etc/warptweet/client.wt` | `root:warptweet-client` | `0440` | Production client manifest |
| `/etc/warptweet/identity` | `root:warptweet-client` | `0750` | Identity directory |
| `/etc/warptweet/identity/client` | `root:warptweet-client` | `0440` | Composite client private key |
| `/etc/warptweet/trust` | `root:warptweet-client` | `0750` | Host-trust directory |
| `/etc/warptweet/trust/known_hosts` | `root:warptweet-client` | `0440` | Canonical managed host pins |
| `/etc/warptweet/trust/known_hosts.empty` | `root:warptweet-client` | `0440` | Exactly empty ambient trust store |

`warptweet-client` has a dedicated nonzero UID and matching primary group. No
other account belongs to that group. The service account can read active state
but cannot write, replace, rename, chmod, or relink it.

Each managed path is opened through a retained descriptor walk. Every ancestor
must be a real directory with the expected owner and mode. Managed files must
be regular non-symlinks with one link, exact ownership and mode, no special
bits, and no access ACL. Managed directories must have no access or default
ACL. Trust contents and metadata are checked again immediately before launch.
The controller never reads or hashes client private-key contents.

## Execution boundary

OpenSSH receives `-F none` and the complete ordered policy as closed `-o`
arguments. WarpTweet does not write or execute a generated SSH configuration.
The diagnostic `render-client` command is generated from the same typed option
list but its output is never used as launch input.

The only writable client runtime state is the one-shot readiness control socket
at the fixed pathname `/run/warptweet/tunnels/<tunnel-id>/c`. The directory is
fixed by the install layout and contains no manifest, configuration, key, or
trust data. After the exact `ssh -O check` binds the remembered socket inode to
the foreground child PID, WarpTweet revalidates the same inode and pathname,
unlinks it relative to the retained directory descriptor, verifies its absence,
closes the descriptor anchor, and confirms that the child remains alive before
Ready. The external unlink does not send OpenSSH a mux request or signal. The
master retains its already-open listener descriptor, transport, and local
forward, while the runtime directory is empty and the mux pathname is
unreachable.

Candidate manifests may be inspected with `validate`, `render-client`, and
`render-known-host` from another clean `.wt` path. Network-capable `doctor` and
`run` require `/etc/warptweet/client.wt` and the complete fixed Linux state.
The first public client manifest schema is version 1.

## Provisioning

Only a privileged provisioner may activate client state. It writes a complete
candidate file in the destination directory, applies exact metadata, calls
`fsync`, validates the candidate, atomically renames it into place, and calls
`fsync` on the directory. Active files are never edited in place. A future
fleet generation or rollback counter must be bound to an external monotonic
authority; a self-asserted manifest counter is not sufficient.
