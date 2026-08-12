# Client readiness

WarpTweet marks a tunnel ready only after the foreground OpenSSH process proves
that authentication completed and its exact local-forward listener was
created. Process existence is not readiness, and readiness does not claim that
the configured forwarding target accepts connections.

## Witness

Each attempt uses the fixed one-shot OpenSSH control pathname `c` beneath the
fixed mode-0700 runtime directory
`/run/warptweet/tunnels/<tunnel-id>`. The pathname must be absent before launch.
The closed client policy enables `ControlMaster` only for this witness and keeps
`ControlPersist` and `ForkAfterAuthentication` disabled.

Pinned OpenSSH 10.4p1 creates the mux listener after host and user
authentication and after local forwarding setup. `ExitOnForwardFailure=yes`
makes listener-creation failure fatal before the mux listener is published.
WarpTweet therefore performs this bounded sequence:

1. Start one foreground `ssh` child and retain its PID.
2. Validate that the private path names a mode-0600 Unix-domain socket owned by
   the service UID through both the retained directory descriptor and the live
   absolute path. Remember that socket inode identity.
3. Execute the pinned `ssh -O check` client with `-F none` and the exact socket.
4. Strictly parse `Master running (pid=N)` and require `N` to equal the
   foreground child PID.
5. Revalidate immediately that both the retained descriptor and live pathname
   still identify the same remembered socket inode.
6. Unlink that exact pathname relative to the retained directory descriptor,
   then verify through both anchored and absolute views that it is absent.
7. Close the retained directory descriptor.
8. Recheck that the child has not exited, then publish the Ready event.

WarpTweet never invokes `ssh -O stop` for retirement. With a foreground
`SessionType=none` master, that mux operation can mark the session closed and
terminate the tunnel. A Unix unlink performed externally removes only the
directory entry. It does not send OpenSSH a mux request and does not signal the
process. OpenSSH keeps its already-open listener descriptor, SSH transport, and
local forward, while new mux clients can no longer reach the retired pathname.

Any PID mismatch, malformed successful response, unexpected control output,
socket or directory substitution, inode mismatch, descriptor-relative unlink
failure, lingering pathname, descriptor-close failure, child exit, readiness
publication failure, or startup timeout terminates and reaps the child without
reporting Ready.

## Service lifecycle

The packaged client unit uses `Type=notify`, `NotifyAccess=main`, the dedicated
`warptweet-client` identity, and controller `--once` mode. The controller sends
`READY=1` only at the authenticated-forward boundary. It sends `STOPPING=1`
after a previously published Ready state when the controller exits. systemd
owns restart policy, so the package does not layer controller retries beneath
service retries.

The typed lifecycle is Preparing, Starting, AwaitingReadiness, Ready, Backoff,
Stopping, Stopped, or Failed. Restart stability is measured from Ready, not
from process creation. Direct command-line use without `NOTIFY_SOCKET` retains
the same readiness gate but performs no service-manager notification.

Target reachability is a separate application-health fact. A successful Ready
event records target health as `not_checked`. Opening a channel to the target
would conflate authentication and listener readiness with application health,
and could itself have side effects.
