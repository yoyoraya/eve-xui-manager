#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# Standalone OFFLINE Redis add-on for an existing Eve X-UI Manager install.
#
# Use this on an air-gapped server that already has Eve installed, to add the
# shared Redis cache WITHOUT rebuilding/transferring the full offline bundle.
#
# Usage (on the server, as root):
#   tar -xzf redis-offline-jammy.tar.gz -C /root/redis-addon
#   cd /root/redis-addon
#   sudo bash install-redis-offline.sh
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail

APP_DIR="${APP_DIR:-/opt/eve-xui-manager}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
SERVICE="${SERVICE:-eve-manager}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
err()  { echo -e "  ${RED}✗${NC} $*"; }

if [ "$(id -u)" -ne 0 ]; then
  err "Run as root:  sudo bash install-redis-offline.sh"
  exit 1
fi

echo "── Offline Redis add-on ──"

# 1) Install redis-server .deb files (with bundled dependencies) via dpkg
if ls "$HERE"/apt/*.deb >/dev/null 2>&1; then
  warn "Installing Redis packages (offline via dpkg)..."
  export DEBIAN_FRONTEND=noninteractive
  dpkg -i --force-confnew "$HERE"/apt/*.deb >/dev/null 2>&1 || true
  dpkg --configure -a   >/dev/null 2>&1 || true
  ok "Redis packages installed"
else
  warn "No .deb files found in $HERE/apt — assuming Redis is already present."
fi

# 2) Enable + start the service
systemctl enable redis-server  >/dev/null 2>&1 || true
systemctl restart redis-server >/dev/null 2>&1 || true
if systemctl is-active --quiet redis-server 2>/dev/null; then
  ok "redis-server is running"
else
  err "redis-server did not start — check: systemctl status redis-server"
fi

# 3) Install the Python 'redis' wheel into the app venv
if [ -d "$APP_DIR/venv" ] && ls "$HERE"/wheels/*.whl >/dev/null 2>&1; then
  warn "Installing Python 'redis' into the app venv..."
  "$APP_DIR/venv/bin/pip" install --no-index --find-links="$HERE/wheels" redis >/dev/null 2>&1 \
    && ok "Python redis installed" || warn "pip install redis failed (may already be present)"
else
  warn "App venv or wheels not found — skipping Python redis install."
fi

# 4) Point the app at Redis (only if not already set)
if [ -f "$ENV_FILE" ]; then
  if grep -q '^REDIS_URL=' "$ENV_FILE"; then
    ok "REDIS_URL already present in .env"
  else
    echo "REDIS_URL=redis://127.0.0.1:6379/0" >> "$ENV_FILE"
    ok "Added REDIS_URL to $ENV_FILE"
  fi
else
  warn "$ENV_FILE not found — add this line manually: REDIS_URL=redis://127.0.0.1:6379/0"
fi

# 5) Restart the app so workers pick up Redis
systemctl restart "$SERVICE" >/dev/null 2>&1 || true
ok "Restarted $SERVICE"

# 6) Verify
echo
if command -v redis-cli >/dev/null 2>&1; then
  PONG="$(redis-cli ping 2>/dev/null || true)"
  if [ "$PONG" = "PONG" ]; then
    ok "Redis reachable (redis-cli ping → PONG)"
  else
    warn "redis-cli ping did not return PONG"
  fi
fi
echo -e "  ${GREEN}Done.${NC} Check logs:  journalctl -u $SERVICE -f   (look for '[Redis] connected')"
