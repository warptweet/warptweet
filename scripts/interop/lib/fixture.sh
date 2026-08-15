# shellcheck shell=sh
# Deterministic echo fixture on the remote server loopback.

interop_fixture_remote_dir() {
    printf '%s' "/var/tmp/warptweet-interop-fixture"
}

interop_cleanup_echo_fixture() {
    _remote_dir=$(interop_fixture_remote_dir)
    _pid_file="$_remote_dir/echo.pid"
    # Best-effort: validate recorded PID, terminate remote fixture, drop pid file.
    interop_ssh "if [ -f '$_pid_file' ]; then
  _pid=\$(sudo cat '$_pid_file' 2>/dev/null || true)
  case \"\$_pid\" in
    ''|*[!0-9]*) ;;
    *)
      if [ \"\$_pid\" -gt 1 ] 2>/dev/null; then
        sudo kill \"\$_pid\" >/dev/null 2>&1 || true
        sudo kill -9 \"\$_pid\" >/dev/null 2>&1 || true
      fi
      ;;
  esac
  sudo rm -f '$_pid_file'
fi" >/dev/null 2>&1 || true
}

interop_ensure_echo_fixture() {
    _port=$1
    _remote_dir=$(interop_fixture_remote_dir)
    _local_py="$WARPTWEET_INTEROP_ROOT/fixtures/echo_target.py"

    [ -f "$_local_py" ] || interop_die "missing echo fixture script: $_local_py"

    interop_ssh "sudo mkdir -p '$_remote_dir' && sudo chmod 0755 '$_remote_dir'"
    interop_scp_to "$_local_py" "/tmp/echo_target.py"
    interop_ssh "sudo mv /tmp/echo_target.py '$_remote_dir/echo_target.py' && sudo chmod 0755 '$_remote_dir/echo_target.py'"

    # Stop prior fixture if any (PID file only). Do not pkill -f a pattern that
    # appears in the remote shell command line; that kills the SSH session (255).
    interop_cleanup_echo_fixture
    interop_ssh "if command -v fuser >/dev/null 2>&1; then sudo fuser -k '${_port}/tcp' >/dev/null 2>&1 || true; fi"

    # Record the python PID (not the shell): use \$\$ after exec-free background.
    interop_ssh "sudo sh -c 'nohup python3 \"$_remote_dir/echo_target.py\" --port \"$_port\" --bind 127.0.0.1 >\"$_remote_dir/echo.log\" 2>&1 & echo \$! >\"$_remote_dir/echo.pid\"'"

    # Ensure remote fixture is torn down on success and failure paths.
    trap 'interop_cleanup_echo_fixture' EXIT INT TERM HUP

    # Probe readiness via remote loopback.
    _ok=0
    _i=0
    while [ "$_i" -lt 40 ]; do
        if interop_ssh "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',$_port),1);s.sendall(b'ping');s.close()\"" >/dev/null 2>&1; then
            _ok=1
            break
        fi
        _i=$((_i + 1))
        sleep 0.1
    done
    if [ "$_ok" -ne 1 ]; then
        interop_die "echo fixture not accepting on remote 127.0.0.1:$_port"
    fi
    interop_log "echo fixture ready on remote 127.0.0.1:$_port"
}

interop_payload_through_local() {
    _listen=$1
    _payload=${2:-warptweet-interop-payload-v1}
    interop_require_cmd python3
    python3 - "$_listen" "$_payload" <<'PY'
import socket, sys
listen, payload = sys.argv[1], sys.argv[2]
host, port_s = listen.rsplit(":", 1)
port = int(port_s)
data = (payload + "\n").encode()
s = socket.create_connection((host, port), timeout=5)
s.sendall(data)
s.shutdown(socket.SHUT_WR)
buf = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
s.close()
if buf != data:
    sys.stderr.write(f"payload mismatch got={buf!r} want={data!r}\n")
    sys.exit(1)
print(buf.decode(), end="")
PY
}
