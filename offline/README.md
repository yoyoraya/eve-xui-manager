# Offline Bundle Folder

This folder is populated by:

```bash
bash prepare-offline-bundle.sh .
```

The generated bundle is intentionally not committed to git because it contains
large distro-specific `.deb` files, Python wheels, and a portable Python runtime.

Expected generated layout:

```text
offline/
  apt/focal-amd64/*.deb
  apt/jammy-amd64/*.deb
  apt/noble-amd64/*.deb
  python/python-3.11-linux-x86_64.tar.gz
  wheels/cp311-linux-x86_64/*.whl
  MANIFEST.txt
```

On a restricted server, extract the generated archive and run:

```bash
sudo bash setup.sh
```

Then choose `[o] Install (Fully Offline Bundle)`.
