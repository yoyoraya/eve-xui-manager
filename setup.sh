#!/bin/bash

#############################################################
# Eve X-UI Manager | Quick Install Script
# Supports Ubuntu 20.04 / 22.04 / 24.04
#############################################################

set -euo pipefail

# ------------------------- Styling -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }

# ------------------------- Config --------------------------
APP_NAME="Eve X-UI Manager"
SERVICE_NAME="eve-manager"
APP_USER="evemgr"
APP_DIR="/opt/eve-xui-manager"
REPO_URL="https://github.com/yoyoraya/eve-xui-manager.git"
PYTHON_VERSION="3.11"
APP_PORT="5000"
ENV_FILE="$APP_DIR/.env"
LOG_DIR="/var/log/$SERVICE_NAME"
DOMAIN="${1:-}"   # optional arg1
ENVIRONMENT="${2:-production}"

DB_NAME="eve_manager_db"
DB_USER="eve_manager"
DB_PASS="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
SESSION_SECRET="$(tr -dc 'A-Fa-f0-9' < /dev/urandom | head -c 64)"
ADMIN_USERNAME_DEFAULT="admin"
ADMIN_USERNAME="$ADMIN_USERNAME_DEFAULT"
ADMIN_PASS="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)"

reset_admin_defaults() {
    ADMIN_USERNAME="$ADMIN_USERNAME_DEFAULT"
    ADMIN_PASS="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)"
}

# ----------------------- Prerequisites ----------------------
require_root() {
    if [ "${EUID}" -ne 0 ]; then
        print_error "Run this installer as root or with sudo"
        exit 1
    fi
}

ask_domain() {
    if [ -z "$DOMAIN" ]; then
        read -rp "Enter your domain or server IP (e.g. panel.example.com): " DOMAIN
    fi
    if [ -z "$DOMAIN" ]; then
        print_error "Domain/IP is required"
        exit 1
    fi
}

prompt_admin_credentials() {
    print_header "Super Admin Credentials"
    read -rp "Enter super admin username [${ADMIN_USERNAME_DEFAULT}]: " input_username
    if [ -n "${input_username}" ]; then
        ADMIN_USERNAME="${input_username}"
    fi

    while true; do
        read -rsp "Enter password for ${ADMIN_USERNAME} (leave empty for generated): " pass1
        echo
        if [ -z "$pass1" ]; then
            print_warning "Using generated password: ${ADMIN_PASS}"
            break
        fi
        read -rsp "Confirm password: " pass2
        echo
        if [ "$pass1" != "$pass2" ]; then
            print_error "Passwords do not match. Try again."
            continue
        fi
        if [ -z "$pass1" ]; then
            print_error "Password cannot be empty."
            continue
        fi
        ADMIN_PASS="$pass1"
        break
    done
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            print_warning "Script optimized for Ubuntu, detected $PRETTY_NAME"
        else
            print_success "Detected $PRETTY_NAME"
        fi
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
}

ensure_python_pkg() {
    if command -v "python${PYTHON_VERSION}" >/dev/null 2>&1; then
        return
    fi
    print_warning "python${PYTHON_VERSION} not found, installing..."
    apt-get install -y -qq software-properties-common
    add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq "python${PYTHON_VERSION}" "python${PYTHON_VERSION}-venv" "python${PYTHON_VERSION}-dev"
}

# -------------------- Installation Steps -------------------
update_system() {
    print_header "Step 1: Update system"
    apt-get update -qq
    apt-get upgrade -y -qq
    print_success "Packages updated"
}

install_dependencies() {
    print_header "Step 2: Install dependencies"
    apt-get install -y -qq \
        python3-pip \
        git \
        curl \
        wget \
        nginx \
        postgresql postgresql-contrib \
        libpq-dev \
        build-essential \
        supervisor \
        ufw \
        openssl \
        software-properties-common
    print_success "Dependencies installed"
}

create_app_user() {
    print_header "Step 3: Create service account"
    if id "$APP_USER" >/dev/null 2>&1; then
        print_warning "User $APP_USER already exists"
    else
        useradd --system --shell /bin/bash --home "$APP_DIR" "$APP_USER"
        print_success "Created user $APP_USER"
    fi
}

prepare_directories() {
    print_header "Step 4: Prepare directories"
    mkdir -p "$APP_DIR" "$LOG_DIR"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"
    chmod 750 "$APP_DIR"
    print_success "Directories ready"
}

setup_database() {
    print_header "Step 5: Configure PostgreSQL"
    systemctl enable postgresql >/dev/null 2>&1 || true
    systemctl start postgresql || true

    sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"

    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null
    print_success "Database ready"
    print_warning "DB user: ${DB_USER} | DB name: ${DB_NAME}"
}

clone_or_update_repo() {
    print_header "Step 6: Fetch application"
    if [ -d "$APP_DIR/.git" ]; then
        print_warning "Repository exists, pulling latest changes"
        sudo -u "$APP_USER" git -C "$APP_DIR" fetch --all
        sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard origin/main
    else
        sudo -u "$APP_USER" git clone "$REPO_URL" "$APP_DIR"
    fi
    print_success "Source code synced"
}

setup_python_env() {
    print_header "Step 7: Python virtual environment"
    PY_BIN="python${PYTHON_VERSION}"
    if [ ! -x "$(command -v $PY_BIN)" ]; then
        PY_BIN="python3"
    fi
    sudo -u "$APP_USER" "$PY_BIN" -m venv "$APP_DIR/venv"
    sudo -u "$APP_USER" bash -c "source $APP_DIR/venv/bin/activate && pip install --upgrade pip setuptools wheel >/dev/null"

    sudo -u "$APP_USER" bash -c "cd $APP_DIR && source venv/bin/activate && if [ -f requirements.txt ]; then pip install -r requirements.txt; else pip install .; fi >/dev/null"

    # Ensure gunicorn and psycopg2-binary even if pyproject changes
    sudo -u "$APP_USER" bash -c "source $APP_DIR/venv/bin/activate && pip install gunicorn psycopg2-binary >/dev/null"
    print_success "Virtual environment configured"
}

create_env_file() {
    print_header "Step 8: Environment variables"
    if [ -f "$ENV_FILE" ]; then
        print_warning "Existing .env detected, keeping current values"
        return
    fi
    cat > "$ENV_FILE" <<EOF
FLASK_ENV=${ENVIRONMENT}
DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}
SESSION_SECRET=${SESSION_SECRET}
INITIAL_ADMIN_USERNAME=${ADMIN_USERNAME}
INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}
API_PORT=${APP_PORT}
EOF
    chown "$APP_USER:$APP_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    print_success ".env created at $ENV_FILE"
    print_warning "Super admin credentials -> user: ${ADMIN_USERNAME} | pass: ${ADMIN_PASS}"
}

initialize_database() {
    print_header "Step 9: Database migration"
    sudo -u "$APP_USER" bash -c "cd $APP_DIR && source venv/bin/activate && set -a && source .env && python - <<'PY'
from app import app, db
with app.app_context():
    db.create_all()
    print('✓ Tables are up to date and default data seeded')
PY"
}

create_systemd_service() {
    print_header "Step 10: Systemd service"
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Eve X-UI Manager
After=network.target postgresql.service
Wants=postgresql.service

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:${APP_PORT} --timeout 120 app:app
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/gunicorn.log
StandardError=append:${LOG_DIR}/gunicorn-error.log

[Install]
WantedBy=multi-user.target
EOF
    touch "${LOG_DIR}/gunicorn.log" "${LOG_DIR}/gunicorn-error.log"
    chown "$APP_USER:$APP_USER" "${LOG_DIR}"/*
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl restart ${SERVICE_NAME}
    print_success "systemd service active"
}

configure_nginx() {
    print_header "Step 11: Nginx reverse proxy"
    cat > /etc/nginx/sites-available/${SERVICE_NAME} <<EOF
upstream eve_xui_manager {
    server 127.0.0.1:${APP_PORT};
}

server {
    listen 80;
    server_name ${DOMAIN};

    client_max_body_size 20M;
    proxy_read_timeout 120s;

    location /static/ {
        alias ${APP_DIR}/static/;
    }

    location / {
        proxy_pass http://eve_xui_manager;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
EOF

    ln -sf /etc/nginx/sites-available/${SERVICE_NAME} /etc/nginx/sites-enabled/${SERVICE_NAME}
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl restart nginx
    print_success "Nginx configured for ${DOMAIN}"
}

configure_firewall() {
    print_header "Step 12: Firewall rules"
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        ufw allow 22/tcp >/dev/null 2>&1 || true
        print_success "UFW rules applied (ensure ufw is enabled if desired)"
    else
        print_warning "UFW not installed, skipping firewall config"
    fi
}

quick_update() {
    print_header "Quick Update"
    if [ ! -d "$APP_DIR/.git" ]; then
        print_error "Application not found at $APP_DIR. Run full install first."
        return
    fi
    clone_or_update_repo
    setup_python_env
    initialize_database
    if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
        systemctl restart ${SERVICE_NAME}
        print_success "Service ${SERVICE_NAME} restarted"
    else
        print_warning "Systemd service ${SERVICE_NAME} not found. Start the app manually if needed."
    fi
}

print_summary() {
    print_header "Installation Complete"
    echo -e "${GREEN}Dashboard URL:${NC} http://${DOMAIN}"
    echo -e "${GREEN}Admin Username:${NC} ${ADMIN_USERNAME}"
    echo -e "${GREEN}Admin Password:${NC} ${ADMIN_PASS}"
    echo -e "${YELLOW}Change the admin password after first login!${NC}"
    echo ""
    echo "Service commands:"
    echo "  systemctl restart ${SERVICE_NAME}"
    echo "  journalctl -u ${SERVICE_NAME} -f"
    echo "Logs: ${LOG_DIR}/gunicorn.log"
}

run_full_install() {
    reset_admin_defaults
    ask_domain
    prompt_admin_credentials
    detect_os
    update_system
    install_dependencies
    ensure_python_pkg
    create_app_user
    prepare_directories
    setup_database
    clone_or_update_repo
    setup_python_env
    create_env_file
    initialize_database
    create_systemd_service
    configure_nginx
    configure_firewall
    print_summary
}

pause_prompt() {
    read -rp "Press Enter to return to the menu... " _
}

# -------------------------- Main ---------------------------
main() {
    require_root
    while true; do
        clear
        print_header "Eve X-UI Manager | Setup Menu"
        echo "1) Install / Update"
        echo "2) Update code & restart service"
        echo "3) Exit"
        read -rp "Select an option: " choice
        case "$choice" in
            1)
                run_full_install
                pause_prompt
                ;;
            2)
                quick_update
                pause_prompt
                ;;
            3)
                print_success "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid selection"
                sleep 1
                ;;
        esac
    done
}

main "$@"