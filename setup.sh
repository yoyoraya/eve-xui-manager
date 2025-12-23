#!/bin/bash

#############################################################
# Eve X-UI Manager | Quick Install Script
# Fixed for Ubuntu 20.04/22.04 Python installation issues
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

generate_secret() {
    local length="$1"
    local mode="${2:-alnum}"
    if ! command -v python3 >/dev/null 2>&1; then
        if [ "$mode" = "hex" ]; then
            openssl rand -hex $((length/2 + 1)) | cut -c1-${length}
        else
            openssl rand -base64 $((length*2)) | tr -dc 'A-Za-z0-9' | head -c ${length}
        fi
        return
    fi
    python3 - "$length" "$mode" <<'PY'
import secrets, string, sys
length = int(sys.argv[1])
mode = sys.argv[2]
if mode == 'hex':
    alphabet = '0123456789abcdef'
elif mode == 'alnum':
    alphabet = string.ascii_letters + string.digits
else:
    alphabet = mode
print(''.join(secrets.choice(alphabet) for _ in range(length)))
PY
}

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
DOMAIN="${1:-}"
ENVIRONMENT="${2:-production}"

DB_NAME="eve_manager_db"
DB_USER="eve_manager"
DB_PASS="$(generate_secret 20 alnum)"
SESSION_SECRET="$(generate_secret 64 hex)"
ADMIN_USERNAME_DEFAULT="admin"
ADMIN_USERNAME="$ADMIN_USERNAME_DEFAULT"
ADMIN_PASS="$(generate_secret 12 alnum)"

reset_admin_defaults() {
    ADMIN_USERNAME="$ADMIN_USERNAME_DEFAULT"
    ADMIN_PASS="$(generate_secret 12 alnum)"
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
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y software-properties-common gnupg ca-certificates curl lsb-release ubuntu-keyring
    add-apt-repository universe -y
    rm -f /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.list
    if ! add-apt-repository -y ppa:deadsnakes/ppa; then
        print_warning "Standard PPA add failed, switching to manual method..."
    fi
    apt-get update
    if ! apt-cache show "python${PYTHON_VERSION}" >/dev/null 2>&1; then
        print_warning "Package python${PYTHON_VERSION} not found in PPA. Forcing manual entry..."
        echo "deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/deadsnakes-manual.list
        apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F23C5A6CF475977595C89F51BA6932366A755776
        apt-get update
    fi
    print_warning "Installing Python ${PYTHON_VERSION}..."
    if ! apt-get install -y "python${PYTHON_VERSION}" "python${PYTHON_VERSION}-venv" "python${PYTHON_VERSION}-dev"; then
        print_warning "Failed to install ${PYTHON_VERSION}. Trying Python 3.10 as fallback..."
        PYTHON_VERSION="3.10"
        if ! apt-get install -y "python${PYTHON_VERSION}" "python${PYTHON_VERSION}-venv" "python${PYTHON_VERSION}-dev"; then
            print_error "Failed to install Python automatically. Please install python3.11 manually."
            exit 1
        fi
    fi
}

# -------------------- Installation Steps -------------------
update_system() {
    print_header "Step 1: Update system"
    apt-get update -qq
    print_success "Packages list updated"
}

install_dependencies() {
    print_header "Step 2: Install dependencies"
    apt-get install -y -qq \
        python3-pip \
        git \
        curl \
        wget \
        nginx \
        build-essential \
        supervisor \
        ufw \
        openssl \
        certbot \
        python3-certbot-nginx
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
    mkdir -p "$APP_DIR" "$LOG_DIR" "$APP_DIR/instance"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"
    chmod 750 "$APP_DIR"
    print_success "Directories ready"
}

clone_or_update_repo() {
    print_header "Step 6: Fetch application"
    git config --global --add safe.directory "$APP_DIR" || true
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    if [ -d "$APP_DIR/.git" ]; then
        print_warning "Repository exists, pulling latest changes"
        sudo -u "$APP_USER" git -C "$APP_DIR" fetch --all
        sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard origin/main
    elif [ -d "$APP_DIR" ] && [ "$(ls -A $APP_DIR)" ]; then
        print_warning "Directory $APP_DIR exists but is not a git repo. Backing up..."
        mv "$APP_DIR" "${APP_DIR}.bak.$(date +%s)"
        mkdir -p "$APP_DIR"
        chown "$APP_USER:$APP_USER" "$APP_DIR"
        sudo -u "$APP_USER" git clone "$REPO_URL" "$APP_DIR"
    else
        mkdir -p "$APP_DIR"
        chown "$APP_USER:$APP_USER" "$APP_DIR"
        sudo -u "$APP_USER" git clone "$REPO_URL" "$APP_DIR"
    fi
    print_success "Source code synced"
}

run_migrations() {
    print_header "Running Database Initialization & Migrations"
    if [ -f "$APP_DIR/init_db.py" ]; then
        print_header "Initializing Database Tables..."
        sudo -u "$APP_USER" bash -c "set -a; [ -f $ENV_FILE ] && source $ENV_FILE || true; set +a; source $APP_DIR/venv/bin/activate 2>/dev/null || true && cd $APP_DIR && export DISABLE_BACKGROUND_THREADS=true && INITIAL_ADMIN_USERNAME='${ADMIN_USERNAME}' INITIAL_ADMIN_PASSWORD='${ADMIN_PASS}' python3 init_db.py"
    fi
    if [ -f "$APP_DIR/migrations.py" ]; then
        print_header "Checking for Schema Updates..."
        sudo -u "$APP_USER" bash -c "set -a; [ -f $ENV_FILE ] && source $ENV_FILE || true; set +a; source $APP_DIR/venv/bin/activate 2>/dev/null || true && cd $APP_DIR && export DISABLE_BACKGROUND_THREADS=true && python3 migrations.py"
        print_success "Database check completed"
    fi
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
    sudo -u "$APP_USER" bash -c "source $APP_DIR/venv/bin/activate && pip install gunicorn psycopg2-binary >/dev/null"
    print_success "Virtual environment configured"
    run_migrations
}

create_env_file() {
    print_header "Step 8: Environment variables"
    if [ -f "$ENV_FILE" ]; then
        print_warning "Existing .env detected, keeping current values"
        return
    fi
    cat > "$ENV_FILE" <<EOF
FLASK_ENV=${ENVIRONMENT}
SESSION_SECRET=${SESSION_SECRET}
INITIAL_ADMIN_USERNAME=${ADMIN_USERNAME}
INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}
API_PORT=${APP_PORT}
EOF
    chown "$APP_USER:$APP_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    print_success "Environment file created"
}

setup_systemd() {
    print_header "Step 9: Systemd service"
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Eve X-UI Manager
After=network.target

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=${ENV_FILE}
# Recommended: increase workers if you have >1 CPU core
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 3 --threads 4 --worker-class gthread --bind 0.0.0.0:${APP_PORT} app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl restart ${SERVICE_NAME}
    print_success "Service started"
}

setup_nginx() {
    print_header "Step 10: Nginx configuration (with Gzip)"
    
    # Ensure domain exists to prevent errors during update
    if [ -z "$DOMAIN" ]; then
        if [ -f "/etc/nginx/sites-available/${SERVICE_NAME}" ]; then
            # Try to read domain from previous config
            DOMAIN=$(grep "server_name" /etc/nginx/sites-available/${SERVICE_NAME} | head -n 1 | awk '{print $2}' | tr -d ';')
        fi
        # If still empty, ask
        if [ -z "$DOMAIN" ]; then
             ask_domain
        fi
    fi

    rm -f /etc/nginx/sites-enabled/default
    cat > /etc/nginx/sites-available/${SERVICE_NAME} <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    # --- Gzip Compression Settings ---
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types
        application/atom+xml
        application/geo+json
        application/javascript
        application/x-javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rdf+xml
        application/rss+xml
        application/xhtml+xml
        application/xml
        font/eot
        font/otf
        font/ttf
        image/svg+xml
        text/css
        text/javascript
        text/plain
        text/xml;
    # ---------------------------------

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/${SERVICE_NAME} /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
    print_success "Nginx configured with Gzip enabled"
}

setup_certbot_ssl() {
    print_header "Step 11: SSL Configuration"
    if [ -z "$DOMAIN" ]; then
        ask_domain
    fi
    print_warning "Requesting SSL for $DOMAIN..."
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --redirect
    print_success "SSL Certificate installed!"
}

# -------------------------------------------------------------
# AUTOMATED MIGRATION TO POSTGRESQL
# -------------------------------------------------------------
migrate_to_postgres() {
    print_header "Starting Migration to PostgreSQL..."

    # 1. Install PostgreSQL
    print_warning "Installing PostgreSQL packages..."
    apt-get update -qq
    apt-get install -y postgresql postgresql-contrib libpq-dev

    # 2. Fix app.py logic bug
    print_warning "Patching app.py to support DATABASE_URL..."
    # The regex removes the bad check: ' or db_url.startswith(\"postgresql://\")'
    if [ -f "$APP_DIR/app.py" ]; then
        sed -i 's/or db_url.startswith("postgresql:\/\/")//g' "$APP_DIR/app.py"
        print_success "Patched app.py successfully."
    else
        print_error "app.py not found in $APP_DIR"
        exit 1
    fi

    # 3. Setup Database Credentials
    read -rp "Enter new DB Password for 'eve_manager' user [leave blank to generate]: " DB_PASS_INPUT
    if [ -z "$DB_PASS_INPUT" ]; then
        MIG_DB_PASS="$(generate_secret 16 alnum)"
    else
        MIG_DB_PASS="$DB_PASS_INPUT"
    fi

    print_warning "Configuring PostgreSQL Database..."
    # Create DB and User safely
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME};" || true
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${MIG_DB_PASS}';" || true
    sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${MIG_DB_PASS}';" || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" || true
    
    # 4. Update .env
    print_warning "Updating .env file..."
    NEW_DB_URL="postgresql://${DB_USER}:${MIG_DB_PASS}@localhost/${DB_NAME}"
    
    # Ensure DATABASE_URL is updated or added
    if grep -q "DATABASE_URL" "$ENV_FILE"; then
        sed -i "s|^DATABASE_URL=.*|DATABASE_URL=${NEW_DB_URL}|" "$ENV_FILE"
    else
        echo "DATABASE_URL=${NEW_DB_URL}" >> "$ENV_FILE"
    fi
    chown "$APP_USER:$APP_USER" "$ENV_FILE"

    # 5. Run repo-tracked Migration Script
    print_warning "Executing migration script..."
    if [ ! -f "$APP_DIR/migrate_db.py" ]; then
        print_error "migrate_db.py not found in $APP_DIR (update code first)."
        exit 1
    fi
    # Export variables from .env so python script can see DATABASE_URL, etc.
    sudo -u "$APP_USER" bash -c "set -a; source $ENV_FILE; set +a; source $APP_DIR/venv/bin/activate && cd $APP_DIR && python3 migrate_db.py"

    # 7. Cleanup & Restart
    print_warning "Restarting Service..."
    systemctl restart ${SERVICE_NAME}
    
    print_success "Migration to PostgreSQL Complete!"
    echo -e "DB User: ${DB_USER}"
    echo -e "DB Pass: ${MIG_DB_PASS}"
}

update_self() {
    print_header "Updating Installer Script..."
    curl -o "$0" -fsSL "${REPO_URL%.git}/raw/main/setup.sh"
    chmod +x "$0"
    print_success "Script updated! Please re-run."
    exit 0
}

show_menu() {
    echo
    echo -e "${BLUE}Eve X-UI Manager Installer (Fixed)${NC}"
    echo "1) Install / Re-install (Full)"
    echo "2) Update Application Code"
    echo "3) Configure SSL (Certbot)"
    echo "4) Update this script"
    echo "5) Uninstall Project"
    echo -e "${YELLOW}7) Migrate to PostgreSQL (Automatic)${NC}"
    echo "8) Exit"
    read -rp "Select an option: " choice
    case $choice in
        1)
            require_root
            detect_os
            ask_domain
            prompt_admin_credentials
            update_system
            ensure_python_pkg
            install_dependencies
            create_app_user
            prepare_directories
            clone_or_update_repo
            setup_python_env
            create_env_file
            setup_systemd
            setup_nginx
            print_header "Installation Complete!"
            echo -e "URL:      http://${DOMAIN}"
            echo -e "Admin:    ${ADMIN_USERNAME}"
            echo -e "Password: ${ADMIN_PASS}"
            echo -e "Logs:     journalctl -u ${SERVICE_NAME} -f"
            ;;
        2)
            require_root
            detect_os
            clone_or_update_repo
            setup_python_env
            setup_nginx
            systemctl restart ${SERVICE_NAME}
            print_success "Updated, Gzip checked, and service restarted"
            ;;
        3) require_root; setup_certbot_ssl ;;
        4) update_self ;;
        5)
            require_root
            uninstall_project
            ;;
        7)
            require_root
            migrate_to_postgres
            ;;
        6|8) exit 0 ;;
        *) print_error "Invalid option" ;;
    esac
}
uninstall_project() {
    print_header "Uninstalling Eve X-UI Manager"
    systemctl stop ${SERVICE_NAME} || true
    systemctl disable ${SERVICE_NAME} || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    rm -rf "$LOG_DIR"
    rm -f /etc/nginx/sites-enabled/${SERVICE_NAME}
    rm -f /etc/nginx/sites-available/${SERVICE_NAME}
    nginx -t && systemctl restart nginx
    userdel -r ${APP_USER} 2>/dev/null || true
    print_success "Eve X-UI Manager and related files removed."
}

if [ $# -gt 0 ]; then
    require_root
    detect_os
    reset_admin_defaults
    update_system
    ensure_python_pkg
    install_dependencies
    create_app_user
    prepare_directories
    clone_or_update_repo
    setup_python_env
    create_env_file
    setup_systemd
    setup_nginx
    print_header "Installation Complete!"
    echo -e "URL:      http://${DOMAIN}"
    echo -e "Admin:    ${ADMIN_USERNAME}"
    echo -e "Password: ${ADMIN_PASS}"
else
    show_menu
fi
