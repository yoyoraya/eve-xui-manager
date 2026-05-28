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

PROJECT_ARG="."
PROFILE_FILE="${EVE_OFFLINE_PROFILE:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --profile)
            PROFILE_FILE="${2:-}"
            if [ -z "$PROFILE_FILE" ]; then
                echo "Missing value for --profile" >&2
                exit 1
            fi
            shift 2
            ;;
        --print-collector)
            cat <<'EOF'
{
  . /etc/os-release
  echo "EVE_OFFLINE_PROFILE_VERSION=1"
  echo "OS_ID=${ID:-}"
  echo "OS_PRETTY=${PRETTY_NAME:-}"
  echo "VERSION_ID=${VERSION_ID:-}"
  echo "VERSION_CODENAME=${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  echo "ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)"
  echo "KERNEL=$(uname -r)"
  echo "LIBC=$(ldd --version 2>/dev/null | head -1 || true)"
  echo "PYTHON3=$(python3 --version 2>/dev/null || true)"
} | tee /root/eve-offline-profile.txt
cat /root/eve-offline-profile.txt
EOF
            exit 0
            ;;
        -h|--help)
            echo "Usage: bash prepare-offline-bundle.sh [--profile eve-offline-profile.txt] /path/to/eve-xui-manager"
            echo "       bash prepare-offline-bundle.sh --print-collector"
            exit 0
            ;;
        *)
            PROJECT_ARG="$1"
            shift
            ;;
    esac
done

PROJECT_DIR="$(cd "$PROJECT_ARG" && pwd -P)"
OFFLINE_DIR="$PROJECT_DIR/offline"
DIST_DIR="$PROJECT_DIR/dist"
PY_WHEEL_DIR="$OFFLINE_DIR/wheels/cp311-linux-x86_64"
PY_RUNTIME_DIR="$OFFLINE_DIR/python"
REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"

TARGETS="${EVE_OFFLINE_TARGETS:-focal jammy noble}"
TARGET_ARCH="${EVE_OFFLINE_ARCH:-amd64}"
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
  bash prepare-offline-bundle.sh --profile /path/to/eve-offline-profile.txt /path/to/eve-xui-manager
  bash prepare-offline-bundle.sh --print-collector

Environment:
  EVE_OFFLINE_TARGETS="focal jammy noble"   Ubuntu 20.04/22.04/24.04
  EVE_OFFLINE_ARCH="amd64"                  Target architecture
  EVE_DOCKER_IMAGE_PREFIX=""                Optional registry prefix, e.g. mirror.local/library/
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

load_target_profile() {
    if [ -z "${PROFILE_FILE:-}" ]; then
        return
    fi
    if [ ! -f "$PROFILE_FILE" ]; then
        print_error "Profile file not found: $PROFILE_FILE"
        exit 1
    fi

    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            VERSION_CODENAME)
                value="${value%\"}"; value="${value#\"}"
                TARGETS="$value"
                ;;
            ARCH)
                value="${value%\"}"; value="${value#\"}"
                TARGET_ARCH="$value"
                ;;
            OS_PRETTY)
                value="${value%\"}"; value="${value#\"}"
                print_success "Target profile: $value"
                ;;
        esac
    done < "$PROFILE_FILE"

    if [ -z "$TARGETS" ]; then
        print_error "Profile does not include VERSION_CODENAME"
        exit 1
    fi
    if [ "$TARGET_ARCH" = "x86_64" ]; then
        TARGET_ARCH="amd64"
    fi
    if [ "$TARGET_ARCH" != "amd64" ]; then
        print_error "Only amd64/x86_64 offline bundles are supported right now; profile arch: $TARGET_ARCH"
        exit 1
    fi
    print_success "Building offline apt bundle for: ${TARGETS}-${TARGET_ARCH}"
}

load_target_profile
mkdir -p "$OFFLINE_DIR" "$DIST_DIR" "$PY_WHEEL_DIR" "$PY_RUNTIME_DIR"

run_as_root() {
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        print_error "Need root privileges to install build prerequisites. Re-run with sudo/root."
        exit 1
    fi
}

ensure_build_prerequisites() {
    print_header "Checking build prerequisites"

    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v tar >/dev/null 2>&1 || missing+=(tar)
    if ! command -v python3 >/dev/null 2>&1; then
        missing+=(python3 python3-pip)
    elif ! python3 -m pip --version >/dev/null 2>&1; then
        missing+=(python3-pip)
    fi

    if [ "${#missing[@]}" -gt 0 ]; then
        print_warning "Installing missing build tools: ${missing[*]}"
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            run_as_root apt-get update
            run_as_root apt-get install -y --no-install-recommends "${missing[@]}"
        else
            print_error "Missing tools: ${missing[*]}"
            print_warning "Install them manually, then re-run this script."
            exit 1
        fi
    fi

    python3 -m pip install --upgrade --user pip >/dev/null 2>&1 || true
    print_success "Build prerequisites are ready"
}

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
    local prefix="${EVE_DOCKER_IMAGE_PREFIX:-}"
    case "$1" in
        focal) echo "${prefix}ubuntu:20.04" ;;
        jammy) echo "${prefix}ubuntu:22.04" ;;
        noble) echo "${prefix}ubuntu:24.04" ;;
        *) print_error "Unsupported Ubuntu codename: $1"; exit 1 ;;
    esac
}

docker_pull_with_retry() {
    local image="$1"
    local attempt
    for attempt in 1 2 3 4 5; do
        if docker image inspect "$image" >/dev/null 2>&1; then
            return 0
        fi
        print_warning "Pulling Docker image ($attempt/5): $image"
        if docker pull "$image"; then
            return 0
        fi
        sleep $((attempt * 5))
    done

    print_error "Failed to pull Docker image: $image"
    print_warning "Docker Hub may be temporarily unavailable or blocked."
    print_warning "Try again later, pre-pull the image manually, or set EVE_DOCKER_IMAGE_PREFIX to a registry mirror."
    print_warning "Example: EVE_DOCKER_IMAGE_PREFIX='docker.mirror.example/library/' bash prepare-offline-bundle.sh --profile profile.txt ."
    exit 1
}

download_apt_with_docker() {
    local codename="$1"
    local image out_dir packages
    image="$(ubuntu_image_for_codename "$codename")"
    out_dir="$OFFLINE_DIR/apt/${codename}-${TARGET_ARCH}"
    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    packages="${APT_PACKAGES[*]}"

    print_header "Downloading apt packages for $codename / $TARGET_ARCH"
    docker_pull_with_retry "$image"
    docker run --rm --platform "linux/$TARGET_ARCH" \
        -v "$out_dir:/out" \
        "$image" \
        bash -lc "set -euo pipefail
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --download-only --no-install-recommends $packages
            find /var/cache/apt/archives -maxdepth 1 -type f -name '*.deb' -exec cp -v {} /out/ \\;
            for deb in /out/*.deb; do
              dpkg-deb -f \"\$deb\" Package
            done | sort -u > /out/package-list.txt
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

    if [ "$TARGETS" != "$codename" ]; then
        print_error "Docker is required to build apt packages for '$TARGETS' from this machine."
        print_warning "This build machine is '$codename', but the target server profile is '$TARGETS'."
        print_warning "Install Docker on the online build machine, or run this builder on Ubuntu '$TARGETS'."
        print_warning "Do not use packages from '$codename' on '$TARGETS' - libc/dependency versions will not match."
        exit 1
    fi

    out_dir="$OFFLINE_DIR/apt/${codename}-${TARGET_ARCH}"
    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    mkdir -p "$out_dir/partial"
    print_warning "Docker not found. Downloading only for current host: $codename"
    sudo apt-get update
    sudo apt-get install -y --download-only --no-install-recommends \
        -o Dir::Cache::archives="$out_dir" \
        "${APT_PACKAGES[@]}"
    rm -rf "$out_dir/partial" "$out_dir/lock"
    local deb
    for deb in "$out_dir"/*.deb; do
        [ -f "$deb" ] || continue
        dpkg-deb -f "$deb" Package
    done | sort -u > "$out_dir/package-list.txt"
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
        echo "Architecture: $TARGET_ARCH"
        [ -n "${PROFILE_FILE:-}" ] && echo "Profile: $PROFILE_FILE"
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

ensure_build_prerequisites
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
