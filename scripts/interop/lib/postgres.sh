# shellcheck shell=sh
# Idempotent loopback Postgres on the remote interop host.

interop_postgres_compose_dir() {
    printf '%s' "/var/tmp/warptweet-interop-postgres"
}

interop_ensure_remote_docker() {
    interop_ssh "sudo sh -s" <<'REMOTE'
set -eu
LC_ALL=C
export LC_ALL
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "docker already usable"
    exit 0
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
if ! command -v docker >/dev/null 2>&1; then
    apt-get install -y -qq docker.io
fi
if ! getent group docker >/dev/null 2>&1; then
    groupadd --system docker
fi
systemctl enable --now docker
docker info >/dev/null
echo "docker ready"
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
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    sudo docker compose -f compose.yaml up -d
elif command -v docker-compose >/dev/null 2>&1; then
    sudo docker-compose -f compose.yaml up -d
else
    # docker.io on Ubuntu may lack the compose plugin. Recreate the pinned container.
    sudo docker rm -f warptweet-interop-postgres >/dev/null 2>&1 || true
    sudo docker pull postgres:16.10-alpine
    sudo docker run -d --name warptweet-interop-postgres --restart unless-stopped \
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
if [ -d /var/lib/warptweet/clients ]; then
    for f in /var/lib/warptweet/clients/*.json; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .json)
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
