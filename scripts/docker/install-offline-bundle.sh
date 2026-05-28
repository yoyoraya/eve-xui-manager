#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ "${EUID}" -ne 0 ]; then
    echo "ERR: run as root: sudo bash install.sh" >&2
    exit 1
fi

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERR: '$1' is required on this server." >&2
        echo "Install Docker Engine + Docker Compose plugin first, then rerun this installer." >&2
        exit 1
    fi
}

random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        date +%s%N | sha256sum | awk '{print $1}'
    fi
}

prompt_default() {
    local var_name="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local value

    if [ -n "${!var_name:-}" ]; then
        return
    fi

    if [ -n "$default_value" ]; then
        read -r -p "$prompt [$default_value]: " value
        value="${value:-$default_value}"
    else
        read -r -p "$prompt: " value
    fi

    printf -v "$var_name" '%s' "$value"
}

need_cmd docker

if ! docker compose version >/dev/null 2>&1; then
    echo "ERR: Docker Compose plugin is required." >&2
    exit 1
fi

install_eve_cli() {
    local src="./eve"
    local dst="/usr/local/bin/eve"
    local cfg="/etc/eve-docker.conf"

    if [ -f "$src" ]; then
        cp "$src" "$dst"
        chmod +x "$dst"
        cat > "$cfg" <<EOF
INSTALL_DIR=$(pwd)
COMPOSE_FILE=$(pwd)/docker-compose.yml
ENV_FILE=$(pwd)/.env
EOF
        chmod 644 "$cfg"
        echo "OK: installed eve CLI to $dst"
    else
        echo "WARN: eve CLI not found next to install.sh (skipping)" >&2
    fi
}

write_caddyfile() {
    local ssl_mode="$1"

    mkdir -p docker

    case "$ssl_mode" in
        letsencrypt)
            cat > docker/Caddyfile <<'EOF'
{
    email {$LETSENCRYPT_EMAIL}
}

{$DOMAIN} {
    encode gzip zstd
    reverse_proxy app:5000
}
EOF
            ;;
        internal)
            cat > docker/Caddyfile <<'EOF'
{
    email {$LETSENCRYPT_EMAIL}
}

{$DOMAIN} {
    tls internal
    encode gzip zstd
    reverse_proxy app:5000
}
EOF
            ;;
        http)
            # HTTP-only, no redirects, no ACME.
            cat > docker/Caddyfile <<'EOF'
{
    auto_https off
}

http://{$DOMAIN} {
    encode gzip zstd
    reverse_proxy app:5000
}
EOF
            ;;
        *)
            echo "ERR: invalid SSL_MODE: $ssl_mode (use: letsencrypt | internal | http)" >&2
            exit 1
            ;;
    esac
}

if [ ! -f docker-images.tar ]; then
    echo "ERR: docker-images.tar not found next to install.sh" >&2
    exit 1
fi

echo "-- Loading Docker images"
docker load -i docker-images.tar

if [ ! -f .env ]; then
    echo "-- Creating .env"
    prompt_default DOMAIN "Domain or IP for this server (example: panel.example.com)"
    prompt_default SSL_MODE "SSL mode (letsencrypt|internal|http)" "letsencrypt"
    prompt_default LETSENCRYPT_EMAIL "Let's Encrypt email (optional)" "admin@${DOMAIN}"
    prompt_default POSTGRES_PASSWORD "PostgreSQL password" "$(random_secret)"
    prompt_default INITIAL_ADMIN_USERNAME "Initial admin username" "admin"
    prompt_default INITIAL_ADMIN_PASSWORD "Initial admin password" "$(random_secret)"

    write_caddyfile "$SSL_MODE"

    cat > .env <<EOF
DOMAIN=${DOMAIN}
SSL_MODE=${SSL_MODE}
LETSENCRYPT_EMAIL=${LETSENCRYPT_EMAIL}
EVE_IMAGE=${EVE_IMAGE:-ghcr.io/yoyoraya/eve-xui-manager:latest}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
INITIAL_ADMIN_USERNAME=${INITIAL_ADMIN_USERNAME}
INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}
GUNICORN_WORKERS=${GUNICORN_WORKERS:-3}
GUNICORN_THREADS=${GUNICORN_THREADS:-4}
GUNICORN_TIMEOUT=${GUNICORN_TIMEOUT:-120}
SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE:-true}
EOF
    chmod 600 .env
else
    echo "-- Existing .env found; keeping it"
    # Backfill: if SSL_MODE exists, (re)generate the Caddyfile so changes apply.
    SSL_MODE_EXISTING="$(grep -E '^SSL_MODE=' .env | tail -n 1 | cut -d= -f2- || true)"
    if [ -n "$SSL_MODE_EXISTING" ]; then
        write_caddyfile "$SSL_MODE_EXISTING"
    fi
fi

echo "-- Starting Eve"
docker compose up -d

install_eve_cli

echo
echo "OK: Eve is starting."
echo "Status: docker compose ps"
echo "Logs:   docker compose logs -f app"
