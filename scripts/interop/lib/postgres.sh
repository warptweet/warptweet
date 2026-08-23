# shellcheck shell=sh
# Idempotent loopback Postgres on the remote interop host.

interop_postgres_compose_dir() {
    printf '%s' "/var/tmp/warptweet-interop-postgres"
}

interop_ensure_remote_docker() {
    # Fresh Ubuntu VPS: wait out cloud-init/apt, install Engine + Compose,
    # start the daemon. Safe to re-run after the box is destroyed and replaced.
    interop_ssh "sudo sh -s" <<'REMOTE'
set -eu
LC_ALL=C
export LC_ALL
export DEBIAN_FRONTEND=noninteractive

wait_for_apt() {
    _i=0
    while [ "$_i" -lt 60 ]; do
        if apt-get update -qq; then
            return 0
        fi
        _i=$((_i + 1))
        sleep 2
    done
    echo "apt-get update still locked after 2 minutes" >&2
    return 1
}

apt_install() {
    _i=0
    while [ "$_i" -lt 15 ]; do
        if apt-get install -y -qq "$@"; then
            return 0
        fi
        _i=$((_i + 1))
        sleep 2
    done
    echo "apt-get install failed: $*" >&2
    return 1
}

docker_candidate() {
    apt-cache policy docker.io 2>/dev/null | awk '/Candidate:/ {print $2; exit}'
}

if command -v cloud-init >/dev/null 2>&1; then
    cloud-init status --wait >/dev/null 2>&1 || true
fi

wait_for_apt
apt_install ca-certificates curl gnupg python3 iproute2 iptables

if ! command -v docker >/dev/null 2>&1; then
    _cand=$(docker_candidate)
    # Distro Engine first (reproducible on a stock Ubuntu image).
    if [ -n "$_cand" ] && [ "$_cand" != "(none)" ] && apt_install docker.io; then
        :
    else
        echo "docker.io unavailable (candidate=${_cand:-none}); installing Docker CE from download.docker.com" >&2
        install -m 0755 -d /etc/apt/keyrings
        curl --proto '=https' --tlsv1.2 --fail --location \
            https://download.docker.com/linux/ubuntu/gpg \
            -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        . /etc/os-release
        printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
            "$(dpkg --print-architecture)" "$VERSION_CODENAME" \
            >/etc/apt/sources.list.d/docker.list
        wait_for_apt
        apt_install docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
fi
apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 || \
    apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || true

if ! getent group docker >/dev/null 2>&1; then
    groupadd --system docker
fi
if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" >/dev/null 2>&1; then
    usermod -aG docker "$SUDO_USER" >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable docker >/dev/null 2>&1 || true
    systemctl enable containerd >/dev/null 2>&1 || true
    systemctl start containerd >/dev/null 2>&1 || true
    systemctl start docker
fi

_i=0
while [ "$_i" -lt 60 ]; do
    if docker info >/dev/null 2>&1; then
        echo "docker ready"
        docker version --format '{{.Server.Version}}' 2>/dev/null || true
        if docker compose version >/dev/null 2>&1; then
            echo "docker compose plugin ready"
        elif command -v docker-compose >/dev/null 2>&1; then
            echo "docker-compose v1 ready"
        else
            echo "docker compose plugin missing; interop will use docker run"
        fi
        exit 0
    fi
    _i=$((_i + 1))
    sleep 1
done
echo "docker daemon did not become ready" >&2
journalctl -u docker.service -n 40 --no-pager >&2 || true
exit 1
REMOTE
}

interop_ensure_loopback_postgres() {
    _port=${1:-5432}
    _remote_dir=$(interop_postgres_compose_dir)
    _local_compose="$WARPTWEET_INTEROP_ROOT/fixtures/postgres/compose.yaml"
    [ -f "$_local_compose" ] || interop_die "missing $_local_compose"

    interop_ensure_remote_docker
    interop_ssh "sudo mkdir -p '$_remote_dir' && sudo chmod 0755 '$_remote_dir'"
    interop_scp_to "$_local_compose" "/tmp/warptweet-postgres-compose.yaml"
    interop_ssh "sudo mv /tmp/warptweet-postgres-compose.yaml '$_remote_dir/compose.yaml' && sudo chmod 0644 '$_remote_dir/compose.yaml'"

    interop_ssh "sudo sh -s" <<REMOTE
set -eu
cd '$_remote_dir'
if docker inspect -f '{{.State.Running}}' warptweet-interop-postgres 2>/dev/null | grep -qx true; then
    echo "postgres container already running"
elif docker inspect warptweet-interop-postgres >/dev/null 2>&1; then
    docker start warptweet-interop-postgres
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f compose.yaml up -d
elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f compose.yaml up -d
else
    docker pull postgres:16.10-alpine
    docker run -d --name warptweet-interop-postgres --restart unless-stopped \
        -e POSTGRES_USER=warptweet \
        -e POSTGRES_PASSWORD=warptweet-interop \
        -e POSTGRES_DB=warptweet \
        -p 127.0.0.1:${_port}:5432 \
        postgres:16.10-alpine
fi
REMOTE

    _ok=0
    _i=0
    while [ "$_i" -lt 60 ]; do
        if interop_ssh "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',$_port),2);s.close()\"" >/dev/null 2>&1; then
            _ok=1
            break
        fi
        _i=$((_i + 1))
        sleep 1
    done
    if [ "$_ok" -ne 1 ]; then
        interop_log "loopback postgres not accepting on remote 127.0.0.1:$_port"
        return 1
    fi
    interop_log "loopback postgres ready on remote 127.0.0.1:$_port"
}

interop_payload_through_postgres() {
    _listen=$1
    interop_require_cmd python3
    python3 "$WARPTWEET_INTEROP_ROOT/fixtures/postgres_probe.py" "$_listen" warptweet warptweet
}

interop_payload_current() {
    _listen=$1
    if [ "${WARPTWEET_INTEROP_PAYLOAD:-echo}" = postgres ]; then
        interop_payload_through_postgres "$_listen"
    else
        interop_payload_through_local "$_listen" "warptweet-interop-payload-v1"
    fi
}

# Revoke leftover grants and cancel issued invites so a lab host can change
# --to (echo 18432 → Postgres 5432) after a previous interop run.
interop_reset_host_grants() {
    interop_ssh "sudo sh -s" <<'REMOTE'
set -eu
CTRL=/opt/warptweet/bin/warptweet
[ -x "$CTRL" ] || exit 0
# Revoke needs the data-plane control socket so Terminate can drop sessions.
if command -v systemctl >/dev/null 2>&1; then
    systemctl start warptweet-hostsign.service >/dev/null 2>&1 || true
    systemctl start warptweet-sshd.service >/dev/null 2>&1 || true
    sleep 1
fi
if [ -d /var/lib/warptweet/clients ]; then
    for f in /var/lib/warptweet/clients/*.json; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .json)
        "$CTRL" server revoke "$id" || true
        "$CTRL" server revoke "$id" || true
    done
fi
if [ -d /var/lib/warptweet/invites ]; then
    for f in /var/lib/warptweet/invites/*.json; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .json)
        "$CTRL" server revoke "$id" || true
    done
fi
REMOTE
}
