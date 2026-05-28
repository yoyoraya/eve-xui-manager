#!/bin/bash

#############################################################
# Eve X-UI Manager | Full Offline Bundle Builder
# Run on an internet-connected Linux/WSL machine.
#############################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() { echo -e "\n${CYAN}${BOLD}  -- $1 --${NC}\n"; }
print_success() { echo -e "  ${GREEN}OK${NC} $1"; }
print_error() { echo -e "  ${RED}ERR${NC} $1"; }
print_warning() { echo -e "  ${YELLOW}WARN${NC} $1"; }

PROJECT_DIR="$(cd "${1:-.}" && pwd -P)"
OFFLINE_DIR="$PROJECT_DIR/offline"
DIST_DIR="$PROJECT_DIR/dist"
PY_WHEEL_DIR="$OFFLINE_DIR/wheels/cp311-linux-x86_64"
PY_RUNTIME_DIR="$OFFLINE_DIR/python"
REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"

TARGETS="${EVE_OFFLINE_TARGETS:-focal jammy noble}"
APT_PACKAGES=(
    ca-certificates
    curl
    wget
    git
    rsync
    unzip
    nginx
    build-essential
    supervisor
    ufw
    openssl
    certbot
    python3-certbot-nginx
    postgresql
    postgresql-contrib
    postgresql-client
    libpq-dev
    libmagic1
)

usage() {
    cat <<EOF
Usage:
  bash prepare-offline-bundle.sh /path/to/eve-xui-manager

Environment:
  EVE_OFFLINE_TARGETS="focal jammy noble"   Ubuntu 20.04/22.04/24.04
  PBS_URL="https://..."                     Override Python standalone runtime URL

Output:
  offline/
    apt/focal-amd64/*.deb
    apt/jammy-amd64/*.deb
    apt/noble-amd64/*.deb
    python/python-3.11-linux-x86_64.tar.gz
    wheels/cp311-linux-x86_64/*.whl
  dist/eve-xui-manager-offline.tar.gz
EOF
}

if [ ! -f "$REQUIREMENTS_FILE" ] || [ ! -f "$PROJECT_DIR/setup.sh" ]; then
    print_error "Project files not found in $PROJECT_DIR"
    usage
    exit 1
fi

mkdir -p "$OFFLINE_DIR" "$DIST_DIR" "$PY_WHEEL_DIR" "$PY_RUNTIME_DIR"

download_python_wheels() {
    print_header "Downloading Python wheels (CPython 3.11 / Linux x86_64)"
    python3 -m pip download \
        --only-binary=:all: \
        --platform manylinux_2_28_x86_64 \
        --platform manylinux2014_x86_64 \
        --implementation cp \
        --python-version 311 \
        --abi cp311 \
        --dest "$PY_WHEEL_DIR" \
        --default-timeout=120 \
        --retries 10 \
        -r "$REQUIREMENTS_FILE"

    python3 -m pip download \
        --only-binary=:all: \
        --platform manylinux_2_28_x86_64 \
        --platform manylinux2014_x86_64 \
        --implementation cp \
        --python-version 311 \
        --abi cp311 \
        --dest "$PY_WHEEL_DIR" \
        pip setuptools wheel

    local count
    count="$(find "$PY_WHEEL_DIR" -name '*.whl' | wc -l)"
    if [ "$count" -lt 10 ]; then
        print_error "Too few wheels downloaded ($count)"
        exit 1
    fi
    print_success "Downloaded $count Python wheel files"
}

find_python_runtime_url() {
    if [ -n "${PBS_URL:-}" ]; then
        echo "$PBS_URL"
        return
    fi

    python3 - <<'PY'
import json
import re
import sys
import urllib.request

api = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
pattern = re.compile(r"cpython-3\.11\.\d+\+\d+-x86_64-unknown-linux-gnu-install_only\.tar\.gz$")
with urllib.request.urlopen(api, timeout=60) as resp:
    data = json.load(resp)
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if pattern.search(name):
        print(asset["browser_download_url"])
        sys.exit(0)
raise SystemExit("No CPython 3.11 x86_64 install_only asset found; set PBS_URL manually.")
PY
}

download_python_runtime() {
    print_header "Downloading portable Python 3.11 runtime"
    local runtime="$PY_RUNTIME_DIR/python-3.11-linux-x86_64.tar.gz"
    if [ -s "$runtime" ]; then
        print_success "Runtime already exists: $runtime"
        return
    fi

    local url
    url="$(find_python_runtime_url)"
    print_warning "Runtime URL: $url"
    curl -fL --retry 5 --retry-delay 3 -o "$runtime" "$url"
    tar -tzf "$runtime" >/dev/null
    print_success "Downloaded portable Python runtime"
}

ubuntu_image_for_codename() {
    case "$1" in
        focal) echo "ubuntu:20.04" ;;
        jammy) echo "ubuntu:22.04" ;;
        noble) echo "ubuntu:24.04" ;;
        *) print_error "Unsupported Ubuntu codename: $1"; exit 1 ;;
    esac
}

download_apt_with_docker() {
    local codename="$1"
    local image out_dir packages
    image="$(ubuntu_image_for_codename "$codename")"
    out_dir="$OFFLINE_DIR/apt/${codename}-amd64"
    mkdir -p "$out_dir"
    packages="${APT_PACKAGES[*]}"

    print_header "Downloading apt packages for $codename / amd64"
    docker run --rm --platform linux/amd64 \
        -v "$out_dir:/out" \
        "$image" \
        bash -lc "set -euo pipefail
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --download-only --no-install-recommends $packages
            cp -v /var/cache/apt/archives/*.deb /out/
            apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances $packages \
              | awk '/^[[:alnum:]][^< ]/ { print \$1 }' | sort -u > /out/package-list.txt
        "

    local count
    count="$(find "$out_dir" -name '*.deb' | wc -l)"
    if [ "$count" -lt 20 ]; then
        print_error "Too few .deb files downloaded for $codename ($count)"
        exit 1
    fi
    print_success "$codename: downloaded $count .deb files"
}

download_apt_for_current_host() {
    local codename out_dir
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    if [ -z "$codename" ]; then
        print_error "Cannot detect Ubuntu codename. Install Docker or run on Ubuntu."
        exit 1
    fi

    out_dir="$OFFLINE_DIR/apt/${codename}-amd64"
    mkdir -p "$out_dir"
    print_warning "Docker not found. Downloading only for current host: $codename"
    sudo apt-get update
    sudo apt-get install -y --download-only --reinstall --no-install-recommends "${APT_PACKAGES[@]}"
    cp -v /var/cache/apt/archives/*.deb "$out_dir/"
}

download_apt_packages() {
    if command -v docker >/dev/null 2>&1; then
        for target in $TARGETS; do
            download_apt_with_docker "$target"
        done
    else
        download_apt_for_current_host
    fi
}

write_manifest() {
    print_header "Writing offline manifest"
    {
        echo "Eve X-UI Manager offline bundle"
        echo "Generated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Targets: $TARGETS"
        echo "Architecture: amd64 (Intel/AMD x86_64)"
        echo
        echo "APT packages:"
        printf '  %s\n' "${APT_PACKAGES[@]}"
        echo
        echo "Python wheels:"
        find "$PY_WHEEL_DIR" -maxdepth 1 -type f -printf '  %f\n' | sort
    } > "$OFFLINE_DIR/MANIFEST.txt"
    print_success "Manifest: $OFFLINE_DIR/MANIFEST.txt"
}

build_archive() {
    print_header "Creating transfer archive"
    local archive="$DIST_DIR/eve-xui-manager-offline.tar.gz"
    tar -czf "$archive" \
        --exclude='.git' \
        --exclude='.venv' \
        --exclude='venv' \
        --exclude='env' \
        --exclude='instance' \
        --exclude='__pycache__' \
        --exclude='dist' \
        -C "$(dirname "$PROJECT_DIR")" "$(basename "$PROJECT_DIR")"
    print_success "Archive ready: $archive"
}

download_python_wheels
download_python_runtime
download_apt_packages
write_manifest
build_archive

print_header "Done"
echo "Transfer this archive to the restricted server:"
echo "  scp $DIST_DIR/eve-xui-manager-offline.tar.gz root@SERVER:/root/"
echo
echo "On the server:"
echo "  tar -xzf /root/eve-xui-manager-offline.tar.gz -C /root"
echo "  cd /root/eve-xui-manager"
echo "  sudo bash setup.sh"
echo "  Select: [o] Install (Fully Offline Bundle)"
