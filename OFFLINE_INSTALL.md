# Offline Installation Guide for Eve X-UI Manager

For servers in Iran or regions with restricted internet access to PyPI.

## The Problem

When installing on servers with limited or blocked access to PyPI, pip times out:

```
WARNING: Retrying... Connection to pypi.org timed out (connect timeout=15)
```

## Solutions

### Solution 1: Use PyPI Mirrors (Simplest)

If your server has some internet but PyPI is blocked:

```bash
# On server - the setup script now automatically tries mirrors
bash setup.sh

# Select [1] Install
# Answer the prompts
# Script automatically tries: Aliyun → Tsinghua → Official PyPI
```

**Available mirrors:**
- Aliyun (China): `https://mirrors.aliyun.com/pypi/simple/`
- Tsinghua (China): `https://pypi.tuna.tsinghua.edu.cn/simple`

### Solution 2: Full Offline Bundle (Recommended for zero internet)

Use this when the server cannot reach GitHub, PyPI, or Ubuntu repositories.

#### Build the bundle on an internet-connected Linux/WSL machine

Recommended exact-target flow:

On the restricted server, run:

```bash
cat > /root/eve-offline-profile.sh <<'EOF'
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
EOF
bash /root/eve-offline-profile.sh
```

Copy `/root/eve-offline-profile.txt` back to the online build machine, then run:

```bash
git clone https://github.com/yoyoraya/eve-xui-manager.git
cd eve-xui-manager
chmod +x prepare-offline-bundle.sh
bash prepare-offline-bundle.sh --profile /path/to/eve-offline-profile.txt .
```

If you previously built a bundle and saw conflicts such as `make` vs
`make-guile` or multiple nginx flavors (`nginx-core`, `nginx-light`,
`nginx-extras`), delete the old apt folder before rebuilding:

```bash
rm -rf offline/apt/jammy-amd64
bash prepare-offline-bundle.sh --profile /path/to/eve-offline-profile.txt .
```

The builder uses apt's own resolver with `--download-only`, so the bundle keeps
only the package choices that Ubuntu would actually install.

Generic all-target flow:

```bash
git clone https://github.com/yoyoraya/eve-xui-manager.git
cd eve-xui-manager
chmod +x prepare-offline-bundle.sh
bash prepare-offline-bundle.sh .
```

Docker is required when the online build machine is not the same Ubuntu release
as the restricted target server. For example, do not build `jammy` packages on a
`noble`/`resolute` machine without Docker; libc and dependency versions will not
match.

This creates:

```text
offline/apt/focal-amd64/*.deb   # Ubuntu 20.04
offline/apt/jammy-amd64/*.deb   # Ubuntu 22.04
offline/apt/noble-amd64/*.deb   # Ubuntu 24.04
offline/python/python-3.11-linux-x86_64.tar.gz
offline/wheels/cp311-linux-x86_64/*.whl
dist/eve-xui-manager-offline.tar.gz
```

`amd64` covers normal Intel and AMD x86_64 servers.

#### Transfer and install on the restricted server

```bash
scp dist/eve-xui-manager-offline.tar.gz root@SERVER_IP:/root/
ssh root@SERVER_IP
tar -xzf /root/eve-xui-manager-offline.tar.gz -C /root
cd /root/eve-xui-manager
sudo bash setup.sh
```

Select:

```text
[o] Install (Fully Offline Bundle)
```

The installer uses only local files from `offline/`:
- Ubuntu `.deb` packages for nginx, PostgreSQL, Certbot, UFW, rsync, etc.
- Portable Python 3.11 runtime.
- Python wheels for `requirements.txt`, `gunicorn`, and `psycopg2-binary`.

### Solution 3: Offline Python Wheels Only

#### Step 1: Prepare Wheels (on a machine with internet)

```bash
# On a Linux/Mac/WSL machine with internet
git clone https://github.com/yoyoraya/eve-xui-manager.git
cd eve-xui-manager

# Download all dependencies
chmod +x prepare-wheels.sh
bash prepare-wheels.sh .

# Or manually:
mkdir -p wheels
pip download -r requirements.txt -d wheels --default-timeout=120 --retries 10
pip wheel --wheel-dir wheels -r requirements.txt --no-build-isolation
```

This creates a `wheels/` folder with 20+ `.whl` files (~30-50 MB).

#### Step 2: Transfer to Server

```bash
# Create archive with wheels included
cd ..
zip -r eve-xui-manager.zip eve-xui-manager/

# Upload to server
scp eve-xui-manager.zip root@SERVER_IP:/root/
# or via SFTP
```

**Important:** Make sure the `wheels/` folder is inside the ZIP!

#### Step 3: Install on Server

```bash
# SSH into server
ssh root@SERVER_IP
cd /root

# Run installer
bash setup.sh

# Select [1] Install / Re-install
# When asked "Install from GitHub or ZIP?" → Select [2] ZIP file
# When asked for ZIP location → Press Enter (auto-detected)
```

The script automatically:
- Detects the `wheels/` folder
- Uses offline pip (`--no-index --find-links`)
- Installs all packages without internet

### Solution 4: Hybrid Approach

```bash
# Setup script tries in this order:
# 1. Offline wheels (if wheels/ folder exists)
# 2. Official PyPI with extended timeout (120s, retry 10x)
# 3. Aliyun mirror
# 4. Tsinghua mirror

# Just run the installer
bash setup.sh
```

---

## Advanced Usage

### View Installation Logs

```bash
# Watch service during installation
journalctl -u eve-manager -f -n 50

# Full log
journalctl -u eve-manager --no-pager
```

### Verify Installed Packages

```bash
cd /opt/eve-xui-manager
source venv/bin/activate
pip list

# Check if all packages installed
pip install --dry-run -r requirements.txt
```

### If Installation Fails Halfway

```bash
# Try mirror installation
cd /opt/eve-xui-manager
source venv/bin/activate

# Aliyun mirror
pip install -i https://mirrors.aliyun.com/pypi/simple/ \
  --default-timeout=120 --retries 10 -r requirements.txt

# Or Tsinghua mirror
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple \
  --default-timeout=120 --retries 10 -r requirements.txt
```

### Configure pip Permanently (Optional)

```bash
# Create ~/.pip/pip.conf
mkdir -p ~/.pip
cat > ~/.pip/pip.conf <<EOF
[global]
timeout = 120
retries = 10
index-url = https://mirrors.aliyun.com/pypi/simple/

[install]
use-deprecated = legacy-resolver
EOF
```

---

## Troubleshooting

### Connection Timeout

**Symptom:** Repeated "Connection to pypi.org timed out" messages

**Solution:**
1. Use mirrors (automatic in new setup.sh)
2. Increase timeout: `pip install --default-timeout=300 ...`
3. Use offline wheels

### Specific Package Fails

**Symptom:** One package fails but others succeed

**Solution:**
```bash
# Install remaining packages one by one
pip install package-name --default-timeout=120 --retries 10
```

### Wheels Download Stalls

**Symptom:** `prepare-wheels.sh` hangs or stops

**Solution:**
```bash
# Cancel (Ctrl+C) and try manual download
mkdir -p wheels
pip download flask==3.1.2 -d wheels --default-timeout=120
pip download flask-limiter==4.0.0 -d wheels --default-timeout=120
# ... repeat for each package
```

### Service Won't Start

**Symptom:** Service fails to start even after installation

**Solution:**
```bash
# Check what's missing
systemctl status eve-manager
journalctl -u eve-manager -n 20

# Reinstall dependencies
source /opt/eve-xui-manager/venv/bin/activate
pip install -r /opt/eve-xui-manager/requirements.txt --force-reinstall
systemctl restart eve-manager
```

---

## FAQ

**Q: How long does offline installation take?**
- Hybrid (mirrors): 5-15 minutes
- Fully offline (wheels): 2-3 minutes

**Q: How much disk space do wheels require?**
- Uncompressed: 30-50 MB
- In ZIP: 10-20 MB

**Q: Can I use wheels from one server on another?**
- Yes! Wheels are architecture-independent for pure Python packages
- Binary wheels (psycopg2, Pillow) should match OS/Python version

**Q: What if a package has no wheel?**
- Script will try to build from source
- Some packages require development headers (gcc, python-dev)
- See error message for which package and install its dev files

---

## Step-by-Step for Complete Beginners

### If you have internet:
```bash
# 1. Run setup
bash setup.sh

# 2. Follow prompts
# 3. Done!
```

### If you have NO internet:
```bash
# On another computer WITH internet:
# 1. Download project
git clone https://github.com/yoyoraya/eve-xui-manager.git

# 2. Download wheels
bash eve-xui-manager/prepare-wheels.sh eve-xui-manager

# 3. Create ZIP
zip -r eve-xui-manager.zip eve-xui-manager

# 4. Copy eve-xui-manager.zip to USB/cloud/email
# 5. Move to your offline server

# On your server (NO internet):
bash setup.sh
# Choose [1] Install
# Choose [2] ZIP file
```

---

## Resources

- [setup.sh](./setup.sh) - Main installation script
- [prepare-wheels.sh](./prepare-wheels.sh) - Wheel downloader
- [requirements.txt](./requirements.txt) - Dependencies list

## Support

For issues:
1. Check logs: `journalctl -u eve-manager -f`
2. Verify wheels: `ls -lah wheels/`
3. Test pip: `pip list`
4. Report issue with error output
