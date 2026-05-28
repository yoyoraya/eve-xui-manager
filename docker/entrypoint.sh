#!/bin/sh
set -eu

cd /app

mkdir -p /app/instance /app/static/uploads /app/static/app-files

SECRETS_FILE="/app/instance/docker-secrets.env"

generate_hex() {
    python - "$1" <<'PY'
import secrets
import sys
print(secrets.token_hex(int(sys.argv[1])))
PY
}

generate_fernet() {
    python - <<'PY'
import base64
import os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
}

if [ ! -f "$SECRETS_FILE" ]; then
    {
        printf 'SESSION_SECRET=%s\n' "$(generate_hex 32)"
        printf 'SERVER_PASSWORD_KEY=%s\n' "$(generate_fernet)"
    } > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
fi

set -a
. "$SECRETS_FILE"
set +a

export SESSION_SECRET="${SESSION_SECRET:-$(generate_hex 32)}"
export SERVER_PASSWORD_KEY="${SERVER_PASSWORD_KEY:-$(generate_fernet)}"
export API_PORT="${API_PORT:-5000}"
export FLASK_ENV="${FLASK_ENV:-production}"
export DISABLE_BACKGROUND_THREADS="${DISABLE_BACKGROUND_THREADS:-true}"

if [ -n "${DATABASE_URL:-}" ] && echo "$DATABASE_URL" | grep -qi '^postgresql'; then
    echo "Waiting for PostgreSQL..."
    until pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; do
        sleep 2
    done
fi

if [ -f init_db.py ]; then
    python init_db.py
fi

if [ -f migrations.py ]; then
    python migrations.py
fi

export DISABLE_BACKGROUND_THREADS="${RUN_BACKGROUND_THREADS_DISABLED:-false}"

exec gunicorn \
    --workers "${GUNICORN_WORKERS:-3}" \
    --threads "${GUNICORN_THREADS:-4}" \
    --worker-class gthread \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
    --bind "0.0.0.0:${API_PORT}" \
    app:app
