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
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

print_header() {
    echo
    echo -e "${CYAN}${BOLD}  ── $1 ──${NC}"
    echo
}

print_success() { echo -e "  ${GREEN}✓${NC} $1"; }
print_error()   { echo -e "  ${RED}✗${NC} $1"; }
print_warning() { echo -e "  ${YELLOW}⚠${NC} $1"; }

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

generate_fernet_key() {
    # Fernet key: urlsafe base64 of 32 random bytes
    if ! command -v python3 >/dev/null 2>&1; then
        # Fallback: openssl random -> base64 -> urlsafe transform (keep '=' padding)
        # 32 bytes -> 44 chars base64 including '=' padding
        openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
        return 0
    fi
    python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
}

ensure_server_password_key() {
    local ENV_PATH="$ENV_FILE"

    # Ensure .env exists
    if [ ! -f "$ENV_PATH" ]; then
        echo "✓ Creating $ENV_PATH"
        sudo touch "$ENV_PATH"
    fi

    # Secure permissions
    sudo chmod 600 "$ENV_PATH"

    # If key exists and not empty, do nothing
    if sudo grep -qE '^[[:space:]]*SERVER_PASSWORD_KEY=' "$ENV_PATH"; then
        local val
        val="$(sudo awk -F= '/^[[:space:]]*SERVER_PASSWORD_KEY=/{print $2; exit}' "$ENV_PATH" | tr -d '[:space:]')"
        if [ -n "$val" ]; then
            echo "✓ SERVER_PASSWORD_KEY already set in .env"
            return 0
        fi
    fi

    echo "⚠ SERVER_PASSWORD_KEY missing — generating..."
    local KEY="$(generate_fernet_key)"

    if [ -z "$KEY" ]; then
        echo "✗ Failed to generate SERVER_PASSWORD_KEY" >&2
        return 1
    fi

    # Write/replace line safely
    if sudo grep -qE '^[[:space:]]*SERVER_PASSWORD_KEY=' "$ENV_PATH"; then
        sudo sed -i "s|^[[:space:]]*SERVER_PASSWORD_KEY=.*|SERVER_PASSWORD_KEY=${KEY}|g" "$ENV_PATH"
    else
        echo "" | sudo tee -a "$ENV_PATH" >/dev/null
        echo "SERVER_PASSWORD_KEY=${KEY}" | sudo tee -a "$ENV_PATH" >/dev/null
    fi

    echo "✓ SERVER_PASSWORD_KEY written to .env"
}

ensure_systemd_envfile_evemanager() {
    local SERVICE="${SERVICE_NAME}.service"
    local ENV_PATH="$ENV_FILE"

    # If service exists, ensure it loads .env
    if systemctl list-unit-files | grep -qE "^${SERVICE}\\b"; then
        sudo mkdir -p "/etc/systemd/system/${SERVICE}.d"
        cat <<EOF | sudo tee "/etc/systemd/system/${SERVICE}.d/override.conf" >/dev/null
[Service]
EnvironmentFile=${ENV_PATH}
EOF
        sudo systemctl daemon-reload
        sudo systemctl restart "${SERVICE}" >/dev/null 2>&1 || true
        echo "✓ systemd override set for ${SERVICE}: EnvironmentFile=${ENV_PATH}"
    else
        echo "ℹ ${SERVICE} not found (skipping systemd envfile override)"
    fi
}

# ------------------------- Config --------------------------
APP_NAME="Eve X-UI Manager"
SERVICE_NAME="eve-manager"
APP_USER="evemgr"
APP_DIR="/opt/eve-xui-manager"
REPO_URL="${EVE_REPO_URL:-https://github.com/yoyoraya/eve-xui-manager.git}"
PYTHON_VERSION="3.11"
APP_PORT="5000"
ENV_FILE="$APP_DIR/.env"
LOG_DIR="/var/log/$SERVICE_NAME"
SELF_SIGNED_SSL_DIR="/etc/ssl/eve-manager"
DOMAIN="${1:-}"
ENVIRONMENT="${2:-production}"
INSTALL_SOURCE="github"  # Can be "github" or "zip"
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd -P 2>/dev/null || pwd)"
OFFLINE_MODE="${EVE_OFFLINE_MODE:-false}"
OFFLINE_ROOT="${EVE_OFFLINE_ROOT:-}"

DB_NAME="eve_manager_db"
DB_USER="eve_manager"
DB_PASS="$(generate_secret 20 alnum)"
SESSION_SECRET="$(generate_secret 64 hex)"
SERVER_PASSWORD_KEY="$(generate_fernet_key)"
ADMIN_USERNAME_DEFAULT="admin"
ADMIN_USERNAME="$ADMIN_USERNAME_DEFAULT"
ADMIN_PASS="$(generate_secret 12 alnum)"
DB_TYPE="postgres"      # default recommendation; set by ask_database_type()
DATABASE_URL=""         # set by setup_postgresql_for_install() when DB_TYPE=postgres

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

ask_database_type() {
    echo
    print_header "Database Selection"
    echo
    echo -e "  ${GREEN}1) PostgreSQL${NC}  ${YELLOW}← Recommended by Eve${NC}"
    echo    "     ✅ Handles concurrent users and high traffic without locking"
    echo    "     ✅ Safe for production — supports multiple resellers simultaneously"
    echo    "     ✅ Advanced backup, point-in-time recovery & monitoring tools"
    echo    "     ✅ Better performance as data grows over time"
    echo    "     ✅ Future-proof: supports read replicas and connection pooling"
    echo    "     ⚠  Requires installing PostgreSQL server on this machine"
    echo
    echo -e "  ${BLUE}2) SQLite${NC}"
    echo    "     ✅ Zero configuration — works immediately out of the box"
    echo    "     ✅ Lightweight, no separate database process needed"
    echo    "     ✅ Fine for testing or a small single-user setup"
    echo    "     ⚠  Can lock under concurrent writes (multiple resellers)"
    echo    "     ⚠  Not recommended for production with heavy traffic"
    echo
    echo -e "  ${YELLOW}💡 Our recommendation: PostgreSQL — more reliable and scalable for production.${NC}"
    echo    "     You can always migrate later via the installer menu (option 7)."
    echo
    read -rp "  Use PostgreSQL? [Y/n]: " _db_choice
    _db_choice="${_db_choice:-Y}"
    if [[ "$_db_choice" =~ ^[Yy]$ ]]; then
        DB_TYPE="postgres"
        print_success "PostgreSQL selected ✓"
    else
        DB_TYPE="sqlite"
        print_warning "SQLite selected — suitable for testing / single-user only"
    fi
    echo
}

ask_install_source() {
    echo
    print_header "Application Source"
    echo
    echo -e "  ${GREEN}1) GitHub${NC}  ${YELLOW}← Recommended (latest version)${NC}"
    echo    "     ✅ Always downloads the latest stable version"
    echo    "     ✅ Automatically resolves all dependencies"
    echo    "     ⚠  Requires internet connection"
    echo
    echo -e "  ${BLUE}2) ZIP File${NC}  ${YELLOW}(Offline / Cached)${NC}"
    echo    "     ✅ Works without internet connection"
    echo    "     ✅ Fast local installation from pre-downloaded ZIP"
    echo    "     ✅ Optional: include wheels/ folder for fully offline pip install"
    echo    "     ℹ  Upload ZIP via SCP/SFTP first"
    echo
    read -rp "  Install from GitHub or ZIP? [1/2] [default: 1]: " _source_choice
    _source_choice="${_source_choice:-1}"
    
    if [ "$_source_choice" = "2" ]; then
        INSTALL_SOURCE="zip"
        print_success "ZIP source selected"
    else
        INSTALL_SOURCE="github"
        print_success "GitHub source selected"
    fi
    echo
}


setup_postgresql_for_install() {
    print_header "Installing & Configuring PostgreSQL"
    if ! is_offline_mode; then
        wait_for_apt
        apt-get install -y postgresql postgresql-contrib libpq-dev
    else
        print_warning "Offline mode: PostgreSQL must already be installed from the apt bundle"
    fi

    # Ensure service is running
    systemctl enable postgresql >/dev/null 2>&1 || true
    systemctl start  postgresql >/dev/null 2>&1 || true

    # Regenerate a fresh password for this install
    DB_PASS="$(generate_secret 20 alnum)"

    print_warning "Creating database '${DB_NAME}' and user '${DB_USER}'..."
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME};"                                                                    || true
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"                                            || true
    sudo -u postgres psql -c "ALTER  USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"                                            || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"                                    || true
    sudo -u postgres psql -c "ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};"                                                || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER SCHEMA public OWNER TO ${DB_USER};"                                      || true
    sudo -u postgres psql -d "${DB_NAME}" -c "GRANT USAGE, CREATE ON SCHEMA public TO ${DB_USER};"                          || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO ${DB_USER};" || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${DB_USER};" || true

    DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@localhost/${DB_NAME}"
    print_success "PostgreSQL ready: ${DB_NAME}"
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
    wait_for_apt
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

# -------------------- APT Lock Helper -------------------
wait_for_apt() {
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -eq 0 ]; then
            print_warning "Another package manager is running, waiting..."
        fi
        sleep 5
        waited=$((waited + 5))
        if [ $waited -ge 300 ]; then
            print_warning "Waited 5 minutes — force-killing stuck dpkg lock..."
            kill "$(fuser /var/lib/dpkg/lock-frontend 2>/dev/null)" 2>/dev/null || true
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
            dpkg --configure -a 2>/dev/null || true
            break
        fi
    done
    # Fix corrupt dpkg updates if any
    if ls /var/lib/dpkg/updates/*.dpkg-new >/dev/null 2>&1 || \
       grep -rlq '#padding' /var/lib/dpkg/updates/ 2>/dev/null; then
        print_warning "Corrupt dpkg update files detected — cleaning..."
        rm -f /var/lib/dpkg/updates/*
        dpkg --configure -a 2>/dev/null || true
    fi
}

# ──────────────────────────────────────────────────────────────
# Offline mode helpers
# ──────────────────────────────────────────────────────────────

is_offline_mode() {
    [ "${OFFLINE_MODE}" = "true" ] || [ "${OFFLINE_MODE}" = "1" ]
}

get_os_codename() {
    local codename=""
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        codename="${VERSION_CODENAME:-}"
        [ -z "$codename" ] && codename="${UBUNTU_CODENAME:-}"
    fi
    if [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1; then
        codename="$(lsb_release -cs 2>/dev/null || true)"
    fi
    echo "$codename"
}

resolve_offline_root() {
    local candidates=()
    [ -n "${OFFLINE_ROOT:-}" ] && candidates+=("$OFFLINE_ROOT")
    candidates+=("$SCRIPT_DIR/offline" "$PWD/offline" "$APP_DIR/offline")

    for candidate in "${candidates[@]}"; do
        if [ -d "$candidate" ]; then
            OFFLINE_ROOT="$(cd "$candidate" && pwd -P)"
            print_success "Offline bundle found: $OFFLINE_ROOT"
            return 0
        fi
    done

    print_warning "Offline bundle folder not found automatically."
    read -rp "  Enter full path to offline/ folder (from the extracted bundle): " OFFLINE_ROOT
    OFFLINE_ROOT="${OFFLINE_ROOT// /}"
    if [ -z "$OFFLINE_ROOT" ] || [ ! -d "$OFFLINE_ROOT" ]; then
        print_error "Offline bundle not found: ${OFFLINE_ROOT:-<none>}"
        print_error "Extract the offline bundle first and run setup.sh from inside it."
        return 1
    fi
    OFFLINE_ROOT="$(cd "$OFFLINE_ROOT" && pwd -P)"
    print_success "Offline bundle: $OFFLINE_ROOT"
}

offline_deb_dir() {
    local codename arch
    codename="$(get_os_codename)"
    arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
    for dir in \
        "$OFFLINE_ROOT/apt/${codename}-${arch}" \
        "$OFFLINE_ROOT/apt/${codename}" \
        "$OFFLINE_ROOT/apt/ubuntu-${codename}-${arch}"; do
        if [ -d "$dir" ] && ls "$dir"/*.deb >/dev/null 2>&1; then
            echo "$dir"
            return 0
        fi
    done
    # Fall back to any single available apt bundle
    if [ -d "$OFFLINE_ROOT/apt" ]; then
        local match
        match="$(find "$OFFLINE_ROOT/apt" -maxdepth 1 -mindepth 1 -type d -name "*-${arch}" 2>/dev/null | sort | head -1 || true)"
        if [ -n "$match" ] && ls "$match"/*.deb >/dev/null 2>&1; then
            print_warning "Expected apt bundle for '${codename}-${arch}', using: $(basename "$match")"
            echo "$match"
            return 0
        fi
    fi
    return 1
}

install_offline_apt_dependencies() {
    print_header "Installing Offline System Packages"
    resolve_offline_root

    local arch codename deb_dir
    arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
    codename="$(get_os_codename)"
    if [ "$arch" != "amd64" ]; then
        print_error "Offline bundle supports amd64 only; detected: $arch"
        return 1
    fi

    deb_dir="$(offline_deb_dir 2>/dev/null || true)"
    if [ -z "$deb_dir" ] || ! ls "$deb_dir"/*.deb >/dev/null 2>&1; then
        print_error "No .deb packages found for Ubuntu ${codename:-unknown} / $arch"
        echo "  Expected: $OFFLINE_ROOT/apt/${codename}-${arch}/*.deb"
        [ -d "$OFFLINE_ROOT/apt" ] && find "$OFFLINE_ROOT/apt" -maxdepth 1 -mindepth 1 -type d -printf '    available: %f\n' 2>/dev/null | sort || true
        echo "  Rebuild the bundle on an online machine: bash prepare-offline-bundle.sh ."
        return 1
    fi

    local deb_count
    deb_count="$(find "$deb_dir" -name '*.deb' | wc -l)"
    print_warning "Installing $deb_count .deb files from $deb_dir (fully offline via dpkg)"
    export DEBIAN_FRONTEND=noninteractive
    wait_for_apt

    # Two-pass dpkg install handles circular/ordering issues without going online.
    dpkg -i --force-depends --force-confnew --force-overwrite "$deb_dir"/*.deb 2>&1 | \
        grep -v '^(Selecting\|Preparing\|Unpacking\|Setting\|Processing\|update-alter)' || true
    dpkg --configure -a 2>&1 || true

    print_warning "Resolving deferred package configuration (pass 2)..."
    dpkg -i --force-depends --force-confnew --force-overwrite "$deb_dir"/*.deb 2>&1 | \
        grep -v '^(Selecting\|Preparing\|Unpacking\|Setting\|Processing\|update-alter)' || true
    dpkg --configure -a 2>&1 || true

    if dpkg -s nginx >/dev/null 2>&1; then
        print_success "System packages installed (nginx ready)"
        return 0
    fi

    print_error "Offline apt install failed — nginx not found after install"
    print_warning "Rebuild the bundle: bash prepare-offline-bundle.sh --profile profile.txt ."
    return 1
}

install_offline_python_runtime() {
    resolve_offline_root

    local runtime_dir="$APP_DIR/.python/runtime"
    local py_bin
    py_bin="$(find "$runtime_dir" -path '*/bin/python3.11' -type f 2>/dev/null | head -1 || true)"
    if [ -n "$py_bin" ]; then
        OFFLINE_PY_BIN="$py_bin"
        return 0
    fi

    local archive=""
    for candidate in \
        "$SCRIPT_DIR/offline/python/python-3.11-linux-x86_64.tar.gz" \
        "$OFFLINE_ROOT/python/python-3.11-linux-x86_64.tar.gz" \
        "$APP_DIR/offline/python/python-3.11-linux-x86_64.tar.gz"; do
        if [ -f "$candidate" ]; then
            archive="$candidate"
            break
        fi
    done

    if [ -z "$archive" ]; then
        print_error "Bundled Python 3.11 runtime not found"
        echo "  Expected: offline/python/python-3.11-linux-x86_64.tar.gz"
        echo "  Rebuild the bundle: bash prepare-offline-bundle.sh ."
        return 1
    fi

    print_warning "Extracting bundled Python 3.11 runtime..."
    rm -rf "$runtime_dir"
    mkdir -p "$runtime_dir"
    tar -xzf "$archive" -C "$runtime_dir" --strip-components=1
    py_bin="$(find "$runtime_dir" -path '*/bin/python3.11' -type f 2>/dev/null | head -1 || true)"
    if [ -z "$py_bin" ]; then
        print_error "Bundled Python runtime is invalid (python3.11 binary not found)"
        return 1
    fi
    chown -R "$APP_USER:$APP_USER" "$APP_DIR/.python"
    OFFLINE_PY_BIN="$py_bin"
    print_success "Python 3.11 runtime extracted: $py_bin"
}

clone_or_update_repo_from_local_bundle() {
    print_header "Step 6: Copy application from offline bundle"

    local SOURCE_DIR="$SCRIPT_DIR"
    if [ ! -f "$SOURCE_DIR/app.py" ]; then
        SOURCE_DIR="$(cd "$OFFLINE_ROOT/.." >/dev/null 2>&1 && pwd -P || true)"
    fi

    if [ -z "$SOURCE_DIR" ] || [ ! -f "$SOURCE_DIR/app.py" ]; then
        print_warning "Cannot find app.py in bundle directory; falling back to ZIP extraction."
        clone_or_update_repo_from_zip
        return
    fi

    if [ -d "$APP_DIR" ] && [ "$(ls -A "$APP_DIR" 2>/dev/null)" ]; then
        print_warning "Backing up $APP_DIR ..."
        mv "$APP_DIR" "${APP_DIR}.bak.$(date +%s)"
    fi

    mkdir -p "$APP_DIR"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a \
            --exclude='.git/' --exclude='.venv/' --exclude='venv/' \
            --exclude='env/' --exclude='__pycache__/' \
            --exclude='instance/' --exclude='.env' \
            "$SOURCE_DIR/" "$APP_DIR/"
    else
        cp -r "$SOURCE_DIR"/* "$APP_DIR/" 2>/dev/null || true
        cp -r "$SOURCE_DIR"/.[!.]* "$APP_DIR/" 2>/dev/null || true
        rm -rf "$APP_DIR/.git" "$APP_DIR/.venv" "$APP_DIR/venv" "$APP_DIR/__pycache__"
    fi
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    print_success "Source code copied from offline bundle"
}

# -------------------- Installation Steps -------------------
update_system() {
    print_header "Step 1: Update system"
    wait_for_apt
    apt-get update -qq
    print_success "Packages list updated"
}

install_dependencies() {
    print_header "Step 2: Install dependencies"
    if is_offline_mode; then
        install_offline_apt_dependencies
        return
    fi
    wait_for_apt
    apt-get install -y -qq \
        python3-pip \
        git \
        curl \
        wget \
        rsync \
        nginx \
        build-essential \
        supervisor \
        ufw \
        openssl \
        certbot \
        python3-certbot-nginx \
        postgresql-client \
        libmagic1
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

clone_or_update_repo_from_zip() {
    print_header "Step 6: Extract application from ZIP"
    
    local ZIP_PATH="${1:-}"
    
    # Auto-detect ZIP in common locations if not provided
    if [ -z "$ZIP_PATH" ]; then
        for _f in "/root/eve-install.zip" "/root/eve.zip" "$HOME/eve-install.zip" "$HOME/eve.zip" "/tmp/eve-install.zip" "/tmp/eve.zip"; do
            if [ -f "$_f" ]; then
                ZIP_PATH="$_f"
                print_success "Auto-detected ZIP: $ZIP_PATH"
                break
            fi
        done
    fi

    if [ -z "$ZIP_PATH" ]; then
        ZIP_PATH=$(find /root /tmp -maxdepth 1 -name "eve*.zip" 2>/dev/null | sort | head -1 || true)
        if [ -n "$ZIP_PATH" ]; then
            print_success "Found ZIP: $ZIP_PATH"
        fi
    fi

    if [ -z "$ZIP_PATH" ]; then
        read -rp "  Enter full path to ZIP file: " ZIP_PATH
        ZIP_PATH="${ZIP_PATH// /}"
    fi

    if [ -z "$ZIP_PATH" ] || [ ! -f "$ZIP_PATH" ]; then
        print_error "ZIP not found: ${ZIP_PATH:-<none>}"
        echo
        echo -e "  ${DIM}How to upload:   scp eve-install.zip root@YOUR_SERVER:/root/${NC}"
        echo
        return 1
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        print_warning "unzip not installed — installing..."
        apt-get install -y -qq unzip
    fi

    local TMPDIR
    TMPDIR=$(mktemp -d /tmp/eve-install-XXXXXX)
    print_warning "Extracting $ZIP_PATH ..."
    if ! unzip -q "$ZIP_PATH" -d "$TMPDIR"; then
        print_error "Failed to extract ZIP"
        rm -rf "$TMPDIR"
        return 1
    fi

    # GitHub source ZIPs contain one sub-folder (e.g. eve-xui-manager-main/)
    local EXTRACT_ROOT="$TMPDIR"
    local _subdirs
    _subdirs=$(find "$TMPDIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
    if [ "$_subdirs" -eq 1 ]; then
        EXTRACT_ROOT=$(find "$TMPDIR" -maxdepth 1 -mindepth 1 -type d | head -1)
    fi

    if [ ! -f "$EXTRACT_ROOT/app.py" ]; then
        print_error "Invalid ZIP — app.py not found inside archive"
        rm -rf "$TMPDIR"
        return 1
    fi

    # Backup if directory exists
    if [ -d "$APP_DIR" ] && [ "$(ls -A $APP_DIR)" ]; then
        print_warning "Directory $APP_DIR exists. Backing up..."
        mv "$APP_DIR" "${APP_DIR}.bak.$(date +%s)"
    fi

    mkdir -p "$APP_DIR"
    chown "$APP_USER:$APP_USER" "$APP_DIR"
    
    print_warning "Extracting files to $APP_DIR ..."
    cp -r "$EXTRACT_ROOT"/* "$APP_DIR/" 2>/dev/null || true
    cp -r "$EXTRACT_ROOT"/.[^.]* "$APP_DIR/" 2>/dev/null || true
    
    # Verify wheels folder was copied
    if [ -d "$EXTRACT_ROOT/wheels" ]; then
        print_warning "Wheels folder detected, ensuring it's copied..."
        if [ -d "$APP_DIR/wheels" ]; then
            WHEELS_COUNT=$(find "$APP_DIR/wheels" -type f 2>/dev/null | wc -l)
            print_success "Copied $WHEELS_COUNT files from wheels/"
        fi
    fi
    
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    
    rm -rf "$TMPDIR"
    print_success "Source code extracted from ZIP"
}

clone_or_update_repo() {
    print_header "Step 6: Fetch application"
    git config --global --add safe.directory "$APP_DIR" || true
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    if [ -d "$APP_DIR/.git" ]; then
        print_warning "Repository exists, pulling latest changes"
        # Fetch can appear to "hang" on slow/blocked networks. Show progress and time out.
        if command -v timeout >/dev/null 2>&1; then
            if ! sudo -u "$APP_USER" env GIT_TERMINAL_PROMPT=0 timeout 240 git -C "$APP_DIR" fetch --all --prune --tags --progress; then
                print_error "git fetch failed or timed out (240s)"
                echo "Troubleshooting:" 
                echo "  - Check connectivity: curl -I https://github.com" 
                echo "  - Check DNS: resolvectl status (or /etc/resolv.conf)" 
                echo "  - If GitHub is blocked/slow, try VPN or set a faster DNS (1.1.1.1 / 8.8.8.8)." 
                echo "  - You can override repo URL: EVE_REPO_URL=<mirror-url> bash setup.sh" 
                exit 1
            fi
        else
            if ! sudo -u "$APP_USER" env GIT_TERMINAL_PROMPT=0 git -C "$APP_DIR" fetch --all --prune --tags --progress; then
                print_error "git fetch failed"
                echo "Troubleshooting:" 
                echo "  - Check connectivity: curl -I https://github.com" 
                echo "  - If GitHub is blocked/slow, try VPN or set a faster DNS." 
                echo "  - You can override repo URL: EVE_REPO_URL=<mirror-url> bash setup.sh" 
                exit 1
            fi
        fi
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
    local PY_BIN="python${PYTHON_VERSION}"

    if is_offline_mode; then
        install_offline_python_runtime
        PY_BIN="${OFFLINE_PY_BIN:-$PY_BIN}"
    elif [ ! -x "$(command -v "$PY_BIN")" ]; then
        PY_BIN="python3"
    fi

    # Create venv
    if [ ! -d "$APP_DIR/venv" ]; then
        print_warning "Creating Python virtual environment..."
        sudo -u "$APP_USER" "$PY_BIN" -m venv "$APP_DIR/venv" || {
            print_error "Failed to create virtual environment"
            return 1
        }
    else
        print_warning "Virtual environment already exists, updating..."
    fi

    # Resolve wheels directory
    local WHEELS_DIR=""
    for _wd in \
        "$APP_DIR/offline/wheels/cp311-linux-x86_64" \
        "${OFFLINE_ROOT:-__none__}/wheels/cp311-linux-x86_64" \
        "$SCRIPT_DIR/offline/wheels/cp311-linux-x86_64" \
        "$APP_DIR/wheels"; do
        if [ -d "$_wd" ] && ls "$_wd"/*.whl >/dev/null 2>&1; then
            WHEELS_DIR="$_wd"
            break
        fi
    done
    local WHEELS_COUNT=0
    [ -n "$WHEELS_DIR" ] && WHEELS_COUNT="$(find "$WHEELS_DIR" -name '*.whl' 2>/dev/null | wc -l)"

    print_warning "Checking dependencies: requirements.txt"

    # ── OFFLINE MODE: wheels only, no internet ──────────────────
    if is_offline_mode; then
        if [ "$WHEELS_COUNT" -le 10 ]; then
            print_error "Offline wheelhouse not found or incomplete ($WHEELS_COUNT files)"
            echo "  Expected: offline/wheels/cp311-linux-x86_64/*.whl"
            echo "  Rebuild: bash prepare-offline-bundle.sh ."
            return 1
        fi
        print_success "Found $WHEELS_COUNT bundled wheels"
        print_warning "Installing Python packages from offline wheelhouse..."
        sudo -u "$APP_USER" bash -c "
            cd '$APP_DIR'
            source venv/bin/activate
            pip install --no-index --find-links='$WHEELS_DIR' pip setuptools wheel 2>&1 | tail -5
            pip install --no-index --find-links='$WHEELS_DIR' -r requirements.txt 2>&1 | tail -20
            pip install --no-index --find-links='$WHEELS_DIR' gunicorn psycopg2-binary 2>&1 | tail -5
        " || {
            print_error "Offline Python package installation failed"
            return 1
        }
        print_success "Python packages installed from offline wheelhouse"
    else
        # ── ONLINE MODE: try wheels first, then mirrors ─────────────
        local OFFLINE_SUCCESS=0

        if [ "$WHEELS_COUNT" -gt 10 ]; then
            print_success "Found $WHEELS_COUNT wheels — attempting offline install first"
            if sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && source venv/bin/activate && \
                pip install --no-cache-dir --no-index --find-links='$WHEELS_DIR' -r requirements.txt 2>&1 | tail -20"; then
                print_success "Offline installation succeeded"
                OFFLINE_SUCCESS=1
            else
                print_warning "Offline install failed, trying online..."
            fi
        fi

        if [ "$OFFLINE_SUCCESS" -ne 1 ]; then
            print_warning "Attempting online install (120s timeout)..."
            if ! sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && source venv/bin/activate && \
                    pip install --default-timeout=120 --retries 10 -r requirements.txt 2>&1 | tail -20"; then
                print_warning "PyPI failed — trying Aliyun mirror..."
                if ! sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && source venv/bin/activate && \
                        pip install -i https://mirrors.aliyun.com/pypi/simple/ \
                        --default-timeout=120 --retries 10 -r requirements.txt 2>&1 | tail -20"; then
                    print_warning "Aliyun failed — trying Tsinghua mirror..."
                    sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && source venv/bin/activate && \
                        pip install -i https://pypi.tuna.tsinghua.edu.cn/simple \
                        --default-timeout=120 --retries 10 -r requirements.txt 2>&1 | tail -20" || {
                        print_error "All pip install methods failed"
                        return 1
                    }
                fi
            fi
        fi

        print_warning "Installing gunicorn and psycopg2..."
        sudo -u "$APP_USER" bash -c "source '$APP_DIR/venv/bin/activate' && \
            pip install --default-timeout=120 --retries 10 gunicorn psycopg2-binary 2>&1" | tail -5 || \
            print_warning "gunicorn/psycopg2 install failed (may retry later)"
    fi

    # Verify
    local INSTALLED_PACKAGES
    INSTALLED_PACKAGES="$(sudo -u "$APP_USER" bash -c "source '$APP_DIR/venv/bin/activate' && pip list 2>/dev/null | wc -l")"
    print_success "Virtual environment configured with $INSTALLED_PACKAGES packages"

    if [ "${SKIP_DB_MIGRATIONS:-}" != "true" ]; then
        run_migrations
    else
        print_warning "Skipping migrations (will run after restore)"
    fi
}

create_env_file() {
    print_header "Step 8: Environment variables"
    if [ -f "$ENV_FILE" ]; then
        print_warning "Existing .env detected, keeping current values"
        # Backfill required secrets without overwriting existing values
        if ! grep -q '^SESSION_SECRET=' "$ENV_FILE"; then
            echo "SESSION_SECRET=${SESSION_SECRET}" >> "$ENV_FILE"
        fi
        if ! grep -q '^SERVER_PASSWORD_KEY=' "$ENV_FILE"; then
            echo "SERVER_PASSWORD_KEY=${SERVER_PASSWORD_KEY}" >> "$ENV_FILE"
        fi
        chown "$APP_USER:$APP_USER" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        print_success "Environment file updated (missing keys added)"
        return
    fi
    cat > "$ENV_FILE" <<EOF
FLASK_ENV=${ENVIRONMENT}
SESSION_SECRET=${SESSION_SECRET}
SERVER_PASSWORD_KEY=${SERVER_PASSWORD_KEY}
INITIAL_ADMIN_USERNAME=${ADMIN_USERNAME}
INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}
API_PORT=${APP_PORT}
EOF
    # Append DATABASE_URL only when PostgreSQL was selected
    if [ -n "${DATABASE_URL:-}" ]; then
        echo "DATABASE_URL=${DATABASE_URL}" >> "$ENV_FILE"
    fi
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
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 3 --threads 4 --worker-class gthread --timeout 120 --graceful-timeout 30 --bind 0.0.0.0:${APP_PORT} app:app
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
    SSL_FULLCHAIN="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    SSL_PRIVKEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    SELF_SIGNED_CERT="${SELF_SIGNED_SSL_DIR}/cert.pem"
    SELF_SIGNED_KEY="${SELF_SIGNED_SSL_DIR}/privkey.pem"

    if [ -f "$SSL_FULLCHAIN" ] && [ -f "$SSL_PRIVKEY" ]; then
        # --- Let's Encrypt SSL ---
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

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate ${SSL_FULLCHAIN};
    ssl_certificate_key ${SSL_PRIVKEY};
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

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

    client_max_body_size 512m;

    # SSE endpoints — must NOT be buffered by nginx
    location ~* /stream\$ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;
    }
}
EOF
    elif [ -f "$SELF_SIGNED_CERT" ] && [ -f "$SELF_SIGNED_KEY" ]; then
        # --- Self-Signed SSL ---
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

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate ${SELF_SIGNED_CERT};
    ssl_certificate_key ${SELF_SIGNED_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

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

    client_max_body_size 512m;

    # SSE endpoints — must NOT be buffered by nginx
    location ~* /stream\$ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;
    }
}
EOF
    else
        # --- HTTP only (no SSL) ---
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

    client_max_body_size 512m;

    # SSE endpoints — must NOT be buffered by nginx
    location ~* /stream\$ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;
    }
}
EOF
    fi
    ln -sf /etc/nginx/sites-available/${SERVICE_NAME} /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
    print_success "Nginx configured with Gzip enabled"
}

setup_certbot_ssl() {
    print_header "Step 11: SSL Configuration (Let's Encrypt)"
    if [ -z "$DOMAIN" ]; then
        ask_domain
    fi
    print_warning "Requesting SSL for $DOMAIN..."
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --redirect
    print_success "SSL Certificate installed!"
}

setup_self_signed_ssl() {
    print_header "Step 11: SSL Configuration (Self-Signed)"
    if [ -z "$DOMAIN" ]; then
        ask_domain
    fi

    local CERT_FILE="${SELF_SIGNED_SSL_DIR}/cert.pem"
    local KEY_FILE="${SELF_SIGNED_SSL_DIR}/privkey.pem"

    mkdir -p "$SELF_SIGNED_SSL_DIR"
    chmod 700 "$SELF_SIGNED_SSL_DIR"

    print_warning "Generating self-signed certificate for ${DOMAIN} (valid 10 years)..."

    # Build a temp OpenSSL config to support SAN (works for both domain names and IPs)
    local TMPCONF
    TMPCONF="$(mktemp /tmp/openssl_san_XXXXXX.cnf)"

    cat > "$TMPCONF" <<SSLCONF
[req]
prompt = no
distinguished_name = req_dn
x509_extensions = v3_req

[req_dn]
CN = ${DOMAIN}
O  = Eve X-UI Manager

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
SSLCONF

    # Detect if DOMAIN is an IP address; add IP SAN or DNS SAN accordingly
    if [[ "${DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "IP.1 = ${DOMAIN}" >> "$TMPCONF"
    else
        echo "DNS.1 = ${DOMAIN}" >> "$TMPCONF"
    fi

    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -config "$TMPCONF" 2>/dev/null

    rm -f "$TMPCONF"

    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"

    print_success "Self-signed certificate generated: ${CERT_FILE}"
    print_warning "Updating Nginx to use self-signed certificate..."
    setup_nginx
    print_success "Nginx configured with self-signed SSL."
    echo
    print_warning "IMPORTANT: Browsers will show a security warning because the certificate is not issued"
    print_warning "by a trusted CA. Click 'Advanced' → 'Accept the risk' to proceed."
    echo -e "  Domain : ${DOMAIN}"
    echo -e "  Cert   : ${CERT_FILE}"
    echo -e "  Key    : ${KEY_FILE}"
}

# -------------------------------------------------------------
# AUTOMATED MIGRATION TO POSTGRESQL
# -------------------------------------------------------------
migrate_to_postgres() {
    print_header "Starting Migration to PostgreSQL..."

    # 1. Install PostgreSQL
    print_warning "Installing PostgreSQL packages..."
    wait_for_apt
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
    sudo -u postgres psql -c "ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};" || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER SCHEMA public OWNER TO ${DB_USER};" || true
    sudo -u postgres psql -d "${DB_NAME}" -c "GRANT USAGE, CREATE ON SCHEMA public TO ${DB_USER};" || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${DB_USER};" || true
    sudo -u postgres psql -d "${DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${DB_USER};" || true
    
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

# -------------------------------------------------------------
# REMOTE SERVER MIGRATION (SSH) - FULL AUTO
# -------------------------------------------------------------
remote_db_migration() {
    print_header "Remote Migration (SSH)"

    # Ensure DB server available on new host
    print_warning "Installing PostgreSQL server/client..."
    wait_for_apt
    apt-get update -qq
    apt-get install -y postgresql postgresql-contrib libpq-dev postgresql-client

    read -rp "Old server SSH (user@host): " OLD_SSH
    read -rp "Old server SSH port [22]: " OLD_SSH_PORT
    OLD_SSH_PORT=${OLD_SSH_PORT:-22}
    read -rp "Old app dir [/opt/eve-xui-manager]: " OLD_APP_DIR
    OLD_APP_DIR=${OLD_APP_DIR:-/opt/eve-xui-manager}
    OLD_ENV_PATH="${OLD_APP_DIR}/.env"

    if [ -z "$OLD_SSH" ]; then
        print_error "Old SSH host is required"
        exit 1
    fi

    print_warning "Reading old .env (DATABASE_URL, SERVER_PASSWORD_KEY)..."
    OLD_DB_URL=$(ssh -p "$OLD_SSH_PORT" "$OLD_SSH" "grep -E '^DATABASE_URL=' '$OLD_ENV_PATH' | tail -n 1 | cut -d= -f2-" || true)
    OLD_SPK=$(ssh -p "$OLD_SSH_PORT" "$OLD_SSH" "grep -E '^SERVER_PASSWORD_KEY=' '$OLD_ENV_PATH' | tail -n 1 | cut -d= -f2-" || true)

    if [ -z "$OLD_DB_URL" ]; then
        print_warning "DATABASE_URL not found; please enter it manually."
        read -rp "Old DATABASE_URL: " OLD_DB_URL
    fi

    if [ -z "$OLD_DB_URL" ]; then
        print_error "DATABASE_URL is required for migration"
        exit 1
    fi

    # Ensure SERVER_PASSWORD_KEY is preserved (needed to decrypt server passwords)
    if [ -n "$OLD_SPK" ]; then
        if grep -q '^SERVER_PASSWORD_KEY=' "$ENV_FILE"; then
            sed -i "s|^SERVER_PASSWORD_KEY=.*|SERVER_PASSWORD_KEY=${OLD_SPK}|" "$ENV_FILE"
        else
            echo "SERVER_PASSWORD_KEY=${OLD_SPK}" >> "$ENV_FILE"
        fi
        chmod 600 "$ENV_FILE"
        print_success "SERVER_PASSWORD_KEY synced from old server"
    else
        print_warning "SERVER_PASSWORD_KEY not found on old server (.env)."
    fi

    # Set local DB credentials
    read -rp "New DB name [${DB_NAME}]: " NEW_DB_NAME
    NEW_DB_NAME=${NEW_DB_NAME:-$DB_NAME}
    read -rp "New DB user [${DB_USER}]: " NEW_DB_USER
    NEW_DB_USER=${NEW_DB_USER:-$DB_USER}
    read -rp "New DB password for '${NEW_DB_USER}' [leave blank to generate]: " NEW_DB_PASS_INPUT
    if [ -z "$NEW_DB_PASS_INPUT" ]; then
        NEW_DB_PASS="$(generate_secret 20 alnum)"
    else
        NEW_DB_PASS="$NEW_DB_PASS_INPUT"
    fi

    print_warning "Creating local PostgreSQL DB/user..."
    # -H avoids noisy "could not change directory to /root" messages under sudo.
    sudo -H -u postgres psql -c "CREATE DATABASE ${NEW_DB_NAME};" || true
    sudo -H -u postgres psql -c "CREATE USER ${NEW_DB_USER} WITH PASSWORD '${NEW_DB_PASS}';" || true
    sudo -H -u postgres psql -c "ALTER USER ${NEW_DB_USER} WITH PASSWORD '${NEW_DB_PASS}';" || true
    sudo -H -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${NEW_DB_NAME} TO ${NEW_DB_USER};" || true
    sudo -H -u postgres psql -c "ALTER DATABASE ${NEW_DB_NAME} OWNER TO ${NEW_DB_USER};" || true
    sudo -H -u postgres psql -d "${NEW_DB_NAME}" -c "ALTER SCHEMA public OWNER TO ${NEW_DB_USER};" || true
    sudo -H -u postgres psql -d "${NEW_DB_NAME}" -c "GRANT USAGE, CREATE ON SCHEMA public TO ${NEW_DB_USER};" || true
    sudo -H -u postgres psql -d "${NEW_DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${NEW_DB_USER};" || true
    sudo -H -u postgres psql -d "${NEW_DB_NAME}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${NEW_DB_USER};" || true

    NEW_DB_URL="postgresql://${NEW_DB_USER}:${NEW_DB_PASS}@localhost/${NEW_DB_NAME}"
    if grep -q "DATABASE_URL" "$ENV_FILE"; then
        sed -i "s|^DATABASE_URL=.*|DATABASE_URL=${NEW_DB_URL}|" "$ENV_FILE"
    else
        echo "DATABASE_URL=${NEW_DB_URL}" >> "$ENV_FILE"
    fi
    chown "$APP_USER:$APP_USER" "$ENV_FILE"

    print_warning "Syncing instance/ folder (read-only from old server)..."
    rsync -az -e "ssh -p ${OLD_SSH_PORT}" "${OLD_SSH}:${OLD_APP_DIR}/instance/" "$APP_DIR/instance/" || true

    # Decide migration path based on old DATABASE_URL
    # - If old server used SQLite (or DATABASE_URL missing), we copy instance/servers.db then migrate into new Postgres.
    # - If old server used Postgres, we stream pg_dump over SSH and restore directly.
    OLD_DB_URL_LC="$(echo "${OLD_DB_URL}" | tr '[:upper:]' '[:lower:]')"
    if [ -z "${OLD_DB_URL}" ] || [[ "${OLD_DB_URL_LC}" == sqlite:* ]]; then
        print_warning "Old server appears to use SQLite; migrating instance/servers.db into PostgreSQL..."
        SQLITE_DB_LOCAL="${APP_DIR}/instance/servers.db"
        if [ ! -f "${SQLITE_DB_LOCAL}" ]; then
            print_error "SQLite DB not found after instance sync: ${SQLITE_DB_LOCAL}"
            print_warning "Verify old server has ${OLD_APP_DIR}/instance/servers.db"
            exit 1
        fi

        if [ ! -f "${APP_DIR}/migrate_db.py" ]; then
            print_error "migrate_db.py not found in ${APP_DIR} (update code first)."
            exit 1
        fi

        print_warning "Running SQLite → PostgreSQL migration script on new server..."
        sudo -u "$APP_USER" bash -c "set -a; source $ENV_FILE; set +a; source $APP_DIR/venv/bin/activate && cd $APP_DIR && SQLITE_DB_PATH='$SQLITE_DB_LOCAL' python3 migrate_db.py"
        print_success "SQLite data migrated into PostgreSQL"
    else
        print_warning "Dumping old PostgreSQL database over SSH (this does NOT modify old server)..."
        DUMP_FILE="/tmp/eve_manager_dump_$(date +%s).sql.gz"

        # Use remote .env to avoid quoting issues with special chars in passwords.
        # Best-effort install of pg_dump on old server (requires sudo/root on remote).
        if ! ssh -p "$OLD_SSH_PORT" "$OLD_SSH" "bash -lc 'set -e; [ -f ""$OLD_ENV_PATH"" ] && set -a && source ""$OLD_ENV_PATH"" && set +a || true; command -v pg_dump >/dev/null 2>&1 || (sudo apt-get update -qq && sudo apt-get install -y postgresql-client >/dev/null); pg_dump --no-owner --no-privileges --dbname=""${DATABASE_URL:-$OLD_DB_URL}""'" | gzip -9 > "$DUMP_FILE"; then
            print_error "pg_dump failed. Check SSH access and that old DATABASE_URL is valid."
            print_warning "Tip: On old server run: pg_dump --no-owner --no-privileges \"$OLD_DB_URL\" > /tmp/test.sql"
            exit 1
        fi
        print_success "DB dump saved to $DUMP_FILE"

        print_warning "Restoring DB on new server..."
        if ! gunzip -c "$DUMP_FILE" | psql "$NEW_DB_URL" -v ON_ERROR_STOP=1; then
            print_error "Restore failed. Check DB credentials or dump file."
            exit 1
        fi
        print_success "Database restored"
    fi

    print_warning "Verifying imported data (row counts)..."
    psql "$NEW_DB_URL" -v ON_ERROR_STOP=0 -tAc "SELECT 'admins=' || COUNT(*) FROM admins;" 2>/dev/null || true
    psql "$NEW_DB_URL" -v ON_ERROR_STOP=0 -tAc "SELECT 'servers=' || COUNT(*) FROM servers;" 2>/dev/null || true
    psql "$NEW_DB_URL" -v ON_ERROR_STOP=0 -tAc "SELECT 'packages=' || COUNT(*) FROM packages;" 2>/dev/null || true

    print_success "Remote migration complete"
    echo -e "New DB URL: ${NEW_DB_URL}"
    echo -e "Note: old server remains untouched."
}

backup_local_db_if_configured() {
    # Best-effort safety net: if DATABASE_URL is set locally, take a compressed dump.
    if [ ! -f "$ENV_FILE" ]; then
        return 0
    fi
    LOCAL_DB_URL=$(grep -E '^DATABASE_URL=' "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true)
    if [ -z "$LOCAL_DB_URL" ]; then
        return 0
    fi
    print_warning "Backing up current local DB (best-effort)..."
    BACKUP_FILE="/tmp/eve_manager_local_backup_$(date +%s).sql.gz"
    if pg_dump --no-owner --no-privileges "$LOCAL_DB_URL" | gzip -9 > "$BACKUP_FILE"; then
        print_success "Local DB backup saved to $BACKUP_FILE"
    else
        print_warning "Local DB backup failed (continuing)"
    fi
}

import_remote_db_only() {
    require_root
    detect_os
    install_dependencies

    # If the imported DB is empty (or old server used SQLite and had no admins),
    # init_db.py will create a first superadmin. Prompt so the password is known.
    reset_admin_defaults
    prompt_admin_credentials

    if [ ! -d "$APP_DIR" ]; then
        print_error "App directory not found: $APP_DIR"
        print_warning "Run full install first (menu option 1)"
        exit 1
    fi
    if [ ! -f "$ENV_FILE" ]; then
        print_error ".env not found: $ENV_FILE"
        print_warning "Run full install first (menu option 1)"
        exit 1
    fi

    backup_local_db_if_configured

    remote_db_migration

    print_warning "Running app migrations on restored DB..."
    run_migrations

    print_warning "Restarting service..."
    systemctl restart ${SERVICE_NAME} || true
    print_success "Remote DB import complete"
}

backup_letsencrypt_dirs() {
    local ts
    ts="$(date +%s)"
    if [ -d "/etc/letsencrypt" ]; then
        print_warning "Backing up /etc/letsencrypt to /etc/letsencrypt.bak.${ts}"
        cp -a /etc/letsencrypt "/etc/letsencrypt.bak.${ts}" || true
    fi
    if [ -d "/var/lib/letsencrypt" ]; then
        print_warning "Backing up /var/lib/letsencrypt to /var/lib/letsencrypt.bak.${ts}"
        cp -a /var/lib/letsencrypt "/var/lib/letsencrypt.bak.${ts}" || true
    fi
}

import_ssl_from_remote() {
    require_root
    detect_os
    install_dependencies

    print_header "Import SSL (Let's Encrypt) from Remote Server (SSH)"
    print_warning "This will copy private keys from the old server to this server."
    read -rp "Continue? (type YES): " confirm
    if [ "$confirm" != "YES" ]; then
        print_warning "Cancelled"
        return 0
    fi

    # Domain is used to validate that cert files exist and to generate nginx config.
    if [ -z "${DOMAIN}" ]; then
        ask_domain
    fi

    read -rp "Old server SSH (user@host): " OLD_SSH
    read -rp "Old server SSH port [22]: " OLD_SSH_PORT
    OLD_SSH_PORT=${OLD_SSH_PORT:-22}

    if [ -z "$OLD_SSH" ]; then
        print_error "Old SSH host is required"
        exit 1
    fi

    backup_letsencrypt_dirs

    print_warning "Streaming /etc/letsencrypt and /var/lib/letsencrypt from remote..."
    if ssh -p "$OLD_SSH_PORT" "$OLD_SSH" "sudo tar -C / -czf - etc/letsencrypt var/lib/letsencrypt" | tar -C / -xzf -; then
        print_success "SSL files imported (sudo)"
    else
        print_warning "Remote sudo tar failed; retrying without sudo (requires root SSH on remote)..."
        ssh -p "$OLD_SSH_PORT" "$OLD_SSH" "tar -C / -czf - etc/letsencrypt var/lib/letsencrypt" | tar -C / -xzf -
        print_success "SSL files imported"
    fi

    # Validate cert presence
    SSL_FULLCHAIN="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    SSL_PRIVKEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    if [ ! -f "$SSL_FULLCHAIN" ] || [ ! -f "$SSL_PRIVKEY" ]; then
        print_warning "Imported SSL files, but cert for '${DOMAIN}' was not found at expected paths."
        print_warning "Check /etc/letsencrypt/live/ and ensure DOMAIN matches the existing certificate name."
    fi

    print_warning "Rebuilding nginx config to use imported SSL (if available)..."
    setup_nginx
    nginx -t && systemctl restart nginx
    print_success "Nginx reloaded"

    echo
    print_header "Notes"
    echo "- Certificate is now installed on this server (no re-issue)."
    echo "- Renewal will still require the domain to point here when certbot runs."
}

install_with_remote_migration() {
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
    create_env_file
    ensure_server_password_key

    SKIP_DB_MIGRATIONS=true setup_python_env

    remote_db_migration
    run_migrations

    setup_systemd
    ensure_systemd_envfile_evemanager
    setup_nginx
    print_header "Installation + Migration Complete!"
    echo -e "URL:      http://${DOMAIN}"
    echo -e "Logs:     journalctl -u ${SERVICE_NAME} -f"
}

update_self() {
    print_header "Updating Script (Online)"
    if curl -o "$0" -fsSL "${REPO_URL%.git}/raw/main/setup.sh"; then
        chmod +x "$0"
        if [ -f /usr/local/bin/eve ]; then
            cp "$0" /usr/local/bin/eve
            chmod +x /usr/local/bin/eve
            print_success "eve CLI updated"
        fi
        print_success "Script updated — re-run 'eve' or 'bash setup.sh'"
    else
        print_error "Download failed. Check internet / GitHub access."
        print_warning "If GitHub is blocked, use option [3] Offline Update instead."
    fi
    exit 0
}

# ──────────────────────────────────────────────────────────────
# Status helpers for the menu banner
# ──────────────────────────────────────────────────────────────

get_app_version() {
    local ver=""
    if [ -f "$APP_DIR/app.py" ]; then
        ver=$(grep -m1 'APP_VERSION' "$APP_DIR/app.py" 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"' || true)
    fi
    [ -z "$ver" ] && ver="not installed"
    echo "$ver"
}

get_service_status() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo -e "${GREEN}● Running${NC}"
    else
        echo -e "${RED}● Stopped${NC}"
    fi
}

get_db_type() {
    if [ -f "$ENV_FILE" ]; then
        if grep -q '^DATABASE_URL=postgresql' "$ENV_FILE" 2>/dev/null; then
            echo "PostgreSQL"
        elif grep -q '^DATABASE_URL=sqlite' "$ENV_FILE" 2>/dev/null; then
            echo "SQLite"
        elif grep -q '^DATABASE_URL=' "$ENV_FILE" 2>/dev/null; then
            echo "Custom"
        else
            echo "SQLite (default)"
        fi
    else
        echo "Not installed"
    fi
}

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "   ███████╗██╗   ██╗███████╗"
    echo "   ██╔════╝██║   ██║██╔════╝"
    echo "   █████╗  ██║   ██║█████╗"
    echo "   ██╔══╝  ╚██╗ ██╔╝██╔══╝"
    echo "   ███████╗ ╚████╔╝ ███████╗"
    echo -e "   ╚══════╝  ╚═══╝  ╚══════╝  ${NC}${BOLD}X-UI Manager${NC}"
    echo -e "${NC}"
    echo -e "  ${DIM}  github.com/yoyoraya/eve-xui-manager   by yoyoraya${NC}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  %-12s : %s\n"  "Version"  "$(get_app_version)"
    printf "  %-12s : " "Status";   echo -e "$(get_service_status)"
    printf "  %-12s : %s\n"  "Port"     "${APP_PORT}"
    printf "  %-12s : %s\n"  "Database" "$(get_db_type)"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
}

# ──────────────────────────────────────────────────────────────
# Install the 'eve' CLI command to /usr/local/bin/eve
# ──────────────────────────────────────────────────────────────

install_eve_cli() {
    local TARGET="/usr/local/bin/eve"
    local SRC="$0"

    # When piped through bash (e.g. curl | bash), $0 is /dev/stdin
    if [ ! -f "$SRC" ] || [[ "$SRC" == /dev/std* ]] || [[ "$SRC" == /proc/* ]]; then
        if is_offline_mode; then
            print_warning "Offline mode: eve CLI not auto-installed (piped run detected)."
            print_warning "  Run manually: cp /path/to/setup.sh /usr/local/bin/eve && chmod +x /usr/local/bin/eve"
            return
        fi
        print_warning "Cannot copy piped script — downloading eve CLI from repo..."
        if curl -o "$TARGET" -fsSL "${REPO_URL%.git}/raw/main/setup.sh"; then
            chmod +x "$TARGET"
            print_success "eve CLI installed — type 'eve' to manage your panel"
        else
            print_warning "Could not download (GitHub blocked?). Copy setup.sh to /usr/local/bin/eve manually."
        fi
        return
    fi

    if cp "$SRC" "$TARGET" && chmod +x "$TARGET"; then
        print_success "eve CLI installed — type 'eve' to manage your panel"
    else
        print_warning "Could not install eve CLI (permission denied?)"
    fi

    # Allow the app user to reload nginx without a password (needed for SSL apply)
    local SUDOERS_FILE="/etc/sudoers.d/eve-nginx"
    cat > "$SUDOERS_FILE" <<EOF
# Allow ${APP_USER} to reload/test nginx for SSL management
${APP_USER} ALL=(root) NOPASSWD: /bin/systemctl reload nginx, /usr/sbin/nginx -t, /usr/bin/tee /etc/nginx/sites-available/${SERVICE_NAME}
EOF
    chmod 440 "$SUDOERS_FILE"
    print_success "Sudoers entry created for nginx reload"
}

# ──────────────────────────────────────────────────────────────
# Offline update — apply a ZIP file without touching GitHub
# ──────────────────────────────────────────────────────────────

offline_update() {
    require_root
    print_header "Offline Update (from ZIP)"

    echo -e "  Upload the release ZIP to the server (SCP/SFTP), then choose this option."
    echo -e "  ZIP must contain full project files (app.py, templates/, static/, ...)."
    echo -e "  Optional: include a ${CYAN}wheels/${NC} folder (.whl files) for fully offline pip install."
    echo

    # Auto-detect ZIP in common locations
    local ZIP_PATH=""
    for _f in "/root/eve-update.zip" "/root/eve.zip" "$HOME/eve-update.zip" "$HOME/eve.zip" "/tmp/eve-update.zip"; do
        if [ -f "$_f" ]; then
            ZIP_PATH="$_f"
            print_success "Auto-detected ZIP: $ZIP_PATH"
            break
        fi
    done

    if [ -z "$ZIP_PATH" ]; then
        ZIP_PATH=$(find /root /tmp -maxdepth 1 -name "eve*.zip" 2>/dev/null | sort | head -1 || true)
        [ -n "$ZIP_PATH" ] && print_success "Found ZIP: $ZIP_PATH"
    fi

    if [ -z "$ZIP_PATH" ]; then
        read -rp "  Enter full path to ZIP file: " ZIP_PATH
        ZIP_PATH="${ZIP_PATH// /}"
    fi

    if [ -z "$ZIP_PATH" ] || [ ! -f "$ZIP_PATH" ]; then
        print_error "ZIP not found: ${ZIP_PATH:-<none>}"
        echo
        echo -e "  ${DIM}How to upload:   scp eve-update.zip root@YOUR_SERVER:/root/${NC}"
        echo
        return 1
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        print_warning "unzip not installed — installing..."
        apt-get install -y -qq unzip
    fi

    local TMPDIR
    TMPDIR=$(mktemp -d /tmp/eve-update-XXXXXX)
    print_warning "Extracting $ZIP_PATH ..."
    if ! unzip -q "$ZIP_PATH" -d "$TMPDIR"; then
        print_error "Failed to extract ZIP"
        rm -rf "$TMPDIR"
        return 1
    fi

    # GitHub source ZIPs contain one sub-folder (e.g. eve-xui-manager-main/)
    local EXTRACT_ROOT="$TMPDIR"
    local _subdirs
    _subdirs=$(find "$TMPDIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
    if [ "$_subdirs" -eq 1 ]; then
        EXTRACT_ROOT=$(find "$TMPDIR" -maxdepth 1 -mindepth 1 -type d | head -1)
    fi

    if [ ! -f "$EXTRACT_ROOT/app.py" ]; then
        print_error "Invalid ZIP — app.py not found inside archive"
        rm -rf "$TMPDIR"
        return 1
    fi

    # Backup (skip .env, database, venv)
    local BAK_TS; BAK_TS="$(date +%s)"
    print_warning "Backing up current installation..."
    if rsync -a \
        --exclude='.env' --exclude='instance/' --exclude='venv/' \
        "$APP_DIR/" "${APP_DIR}.bak.${BAK_TS}/" 2>/dev/null; then
        print_success "Backup saved to ${APP_DIR}.bak.${BAK_TS}"
    else
        print_warning "Backup failed (continuing)"
    fi

    print_warning "Stopping service..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

    print_warning "Applying update files..."
    rsync -a \
        --exclude='.env' \
        --exclude='instance/' \
        --exclude='venv/' \
        "$EXTRACT_ROOT/" "$APP_DIR/"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    print_success "Files synced"

    # Python packages - with proper retry logic
    if [ -d "$EXTRACT_ROOT/wheels" ]; then
        WHEELS_COUNT=$(find "$EXTRACT_ROOT/wheels" -name '*.whl' -o -name '*.tar.gz' 2>/dev/null | wc -l)
        if [ $WHEELS_COUNT -gt 5 ]; then
            print_warning "Installing Python packages from bundled wheels ($WHEELS_COUNT files)..."
            sudo -u "$APP_USER" bash -c \
                "source $APP_DIR/venv/bin/activate && \
                 pip install --no-index --find-links='$EXTRACT_ROOT/wheels' \
                 -r '$APP_DIR/requirements.txt' --default-timeout=120 --retries 10" && {
                print_success "Python packages installed from wheels"
            } || {
                print_warning "Wheel install failed, trying online..."
            }
        else
            print_warning "wheels/ folder exists but too few packages ($WHEELS_COUNT < 5)"
        fi
    fi
    
    # Fallback: online install with extended timeout
    if [ ! -f "$APP_DIR/requirements.txt" ] || ! sudo -u "$APP_USER" bash -c \
        "source $APP_DIR/venv/bin/activate && pip list | grep -q flask"; then
        
        print_warning "Installing/updating packages from online sources..."
        
        if ! sudo -u "$APP_USER" bash -c \
            "source $APP_DIR/venv/bin/activate && \
             pip install --default-timeout=120 --retries 10 -r '$APP_DIR/requirements.txt' 2>&1 | tail -10"; then
            
            print_warning "Trying Aliyun mirror..."
            sudo -u "$APP_USER" bash -c \
                "source $APP_DIR/venv/bin/activate && \
                 pip install -i https://mirrors.aliyun.com/pypi/simple/ \
                 --default-timeout=120 --retries 10 -r '$APP_DIR/requirements.txt' 2>&1 | tail -10" ||
            print_warning "pip install failed (PyPI unreachable?). Continuing with existing packages."
        fi
        
        print_success "Python packages updated/installed"
    fi

    # DB migrations
    print_warning "Running database migrations..."
    run_migrations

    # Update eve CLI from the ZIP
    if [ -f "$EXTRACT_ROOT/setup.sh" ]; then
        print_warning "Updating eve CLI..."
        cp "$EXTRACT_ROOT/setup.sh" /usr/local/bin/eve
        chmod +x /usr/local/bin/eve
        print_success "eve CLI updated"
    fi

    print_warning "Starting service..."
    systemctl start "${SERVICE_NAME}"
    sleep 2
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_success "Service is running"
    else
        print_error "Service failed to start"
        print_warning "Logs: journalctl -u ${SERVICE_NAME} -n 50"
    fi

    rm -rf "$TMPDIR"
    echo
    print_success "Offline update complete!"
    echo -e "  ${DIM}Backup : ${APP_DIR}.bak.${BAK_TS}${NC}"
    echo -e "  ${DIM}Logs   : journalctl -u ${SERVICE_NAME} -f${NC}"
}

# ──────────────────────────────────────────────────────────────
# Full Offline Install — runs entire setup from local bundle
# ──────────────────────────────────────────────────────────────

full_offline_install() {
    require_root
    OFFLINE_MODE=true
    detect_os
    resolve_offline_root
    ask_domain
    prompt_admin_credentials
    ask_database_type
    install_dependencies        # → install_offline_apt_dependencies
    create_app_user
    prepare_directories
    clone_or_update_repo_from_local_bundle
    [ "$DB_TYPE" = "postgres" ] && setup_postgresql_for_install
    create_env_file
    ensure_server_password_key
    setup_python_env            # → offline wheels + bundled Python 3.11
    setup_systemd
    ensure_systemd_envfile_evemanager
    setup_nginx
    install_eve_cli
    print_header "Offline Installation Complete!"
    echo -e "  URL      : http://${DOMAIN}"
    echo -e "  Admin    : ${ADMIN_USERNAME}"
    echo -e "  Password : ${ADMIN_PASS}"
    [ "$DB_TYPE" = "postgres" ] && echo -e "  DB URL   : ${DATABASE_URL}"
    echo -e "  Logs     : journalctl -u ${SERVICE_NAME} -f"
    echo -e "  CLI      : type 'eve' to manage this panel"
}

# ──────────────────────────────────────────────────────────────
# Main interactive menu (loops until quit)
# ──────────────────────────────────────────────────────────────

show_menu() {
    while true; do
        show_banner
        echo -e "  ${BOLD}Installation & Update${NC}"
        echo -e "   ${GREEN}[1]${NC}  Install / Re-install (Full)"
        echo -e "   ${YELLOW}[o]${NC}  ${BOLD}Setup Full Offline${NC}  ← extract bundle → run this"
        echo -e "   ${GREEN}[2]${NC}  Update  (Online — from GitHub)"
        echo -e "   ${YELLOW}[3]${NC}  Update  (Offline — from ZIP file)"
        echo
        echo -e "  ${BOLD}SSL & Domain${NC}"
        echo -e "   ${BLUE}[4]${NC}  SSL — Let's Encrypt (Certbot)"
        echo -e "   ${BLUE}[5]${NC}  SSL — Self-Signed Certificate"
        echo
        echo -e "  ${BOLD}Database & Migration${NC}"
        echo -e "   ${CYAN}[6]${NC}  Migrate to PostgreSQL"
        echo -e "   ${CYAN}[7]${NC}  Install + Migrate from Remote Server (SSH)"
        echo -e "   ${CYAN}[8]${NC}  Import Remote DB only (SSH)"
        echo -e "   ${CYAN}[9]${NC}  Import SSL from Remote Server (SSH)"
        echo
        echo -e "  ${BOLD}System${NC}"
        echo -e "   ${DIM}[s]${NC}  Update this Script (Online — GitHub)"
        echo -e "   ${RED}[u]${NC}  Uninstall"
        echo -e "   ${DIM}[q]${NC}  Exit"
        echo
        echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -rp "  Select option: " choice
        echo

        case $choice in
            o|O)
                full_offline_install
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            1)
                require_root
                detect_os
                ask_domain
                prompt_admin_credentials
                ask_database_type
                ask_install_source
                update_system
                ensure_python_pkg
                install_dependencies
                create_app_user
                prepare_directories
                if [ "$INSTALL_SOURCE" = "zip" ]; then
                    clone_or_update_repo_from_zip
                else
                    clone_or_update_repo
                fi
                [ "$DB_TYPE" = "postgres" ] && setup_postgresql_for_install
                create_env_file
                ensure_server_password_key
                setup_python_env
                setup_systemd
                ensure_systemd_envfile_evemanager
                setup_nginx
                install_eve_cli
                print_header "Installation Complete!"
                echo -e "  URL      : http://${DOMAIN}"
                echo -e "  Admin    : ${ADMIN_USERNAME}"
                echo -e "  Password : ${ADMIN_PASS}"
                [ "$DB_TYPE" = "postgres" ] && echo -e "  DB URL   : ${DATABASE_URL}"
                echo -e "  Logs     : journalctl -u ${SERVICE_NAME} -f"
                echo -e "  CLI      : type 'eve' to manage this panel"
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            2)
                require_root
                detect_os
                install_dependencies
                clone_or_update_repo
                create_env_file
                ensure_server_password_key
                ensure_systemd_envfile_evemanager
                setup_python_env
                setup_nginx
                systemctl restart ${SERVICE_NAME}
                install_eve_cli
                print_success "Updated and service restarted"
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            3)
                offline_update
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            4)
                require_root
                setup_certbot_ssl
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            5)
                require_root
                detect_os
                setup_self_signed_ssl
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            6)
                require_root
                migrate_to_postgres
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            7)
                install_with_remote_migration
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            8)
                import_remote_db_only
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            9)
                import_ssl_from_remote
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            s|S)
                update_self
                ;;
            u|U)
                require_root
                echo -e "  ${RED}${BOLD}WARNING:${NC} This removes all Eve files, configs, and the service."
                read -rp "  Type YES to confirm: " _confirm
                if [ "$_confirm" = "YES" ]; then
                    uninstall_project
                else
                    print_warning "Uninstall cancelled"
                fi
                read -rp "  Press Enter to return to menu..." _dummy
                ;;
            q|Q|0)
                echo -e "  ${DIM}Bye!${NC}"
                echo
                exit 0
                ;;
            *)
                print_error "Invalid option: $choice"
                sleep 1
                ;;
        esac
    done
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
    rm -f /usr/local/bin/eve
    nginx -t && systemctl restart nginx
    userdel -r ${APP_USER} 2>/dev/null || true
    print_success "Eve X-UI Manager and all related files removed."
}

# ──────────────────────────────────────────────────────────────
# Entry point — non-interactive if args given, else show menu
# ──────────────────────────────────────────────────────────────

if [ $# -gt 0 ]; then
    require_root
    detect_os
    reset_admin_defaults
    ask_database_type
    ask_install_source
    update_system
    ensure_python_pkg
    install_dependencies
    create_app_user
    prepare_directories
    if [ "$INSTALL_SOURCE" = "zip" ]; then
        clone_or_update_repo_from_zip
    else
        clone_or_update_repo
    fi
    [ "$DB_TYPE" = "postgres" ] && setup_postgresql_for_install
    create_env_file
    ensure_server_password_key
    setup_python_env
    setup_systemd
    ensure_systemd_envfile_evemanager
    setup_nginx
    install_eve_cli
    print_header "Installation Complete!"
    echo -e "  URL      : http://${DOMAIN}"
    echo -e "  Admin    : ${ADMIN_USERNAME}"
    echo -e "  Password : ${ADMIN_PASS}"
    [ "$DB_TYPE" = "postgres" ] && echo -e "  DB URL   : ${DATABASE_URL}"
    echo -e "  CLI      : type 'eve' to manage this panel"
else
    show_menu
fi
