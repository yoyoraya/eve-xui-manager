# Docker Deployment

This is the recommended deployment path for restricted servers. Build once on GitHub Actions or any online server, then run the same image anywhere Docker is available.

## Server Requirements

- Ubuntu 20.04, 22.04, or 24.04
- Docker Engine with Docker Compose plugin
- Ports `80` and `443` open if Caddy should issue HTTPS certificates

## Configure

Create `.env` next to `docker-compose.yml`:

```env
DOMAIN=panel.example.com
SSL_MODE=letsencrypt
LETSENCRYPT_EMAIL=admin@example.com
EVE_IMAGE=ghcr.io/yoyoraya/eve-xui-manager:latest
POSTGRES_PASSWORD=change-this-long-random-password
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=change-this-admin-password
```

`SSL_MODE` options:

- `letsencrypt`: automatic trusted HTTPS certificates (requires correct DNS + open 80/443)
- `internal`: self-signed HTTPS via Caddy's internal CA (works without DNS validation; browsers warn)
- `http`: HTTP only (no TLS; useful for IP-only or debugging)

`DOMAIN` is the domain/IP you want this server to use. For `http` mode you can use an IP or hostname.

`LETSENCRYPT_EMAIL` is optional. Caddy can issue certificates without it, but keeping it set is recommended for real domains.

You can start from `.env.docker.example`.

## Online Install

```bash
docker compose pull
docker compose up -d
docker compose logs -f app
```

Open `https://YOUR_DOMAIN`.

To build locally instead of using GHCR:

```bash
docker build -t ghcr.io/yoyoraya/eve-xui-manager:latest .
docker compose up -d
```

## Restricted / Offline Server

### Build a Complete Bundle on Hetzner

On a server that has internet access, such as Hetzner:

```bash
git clone https://github.com/yoyoraya/eve-xui-manager.git
cd eve-xui-manager
bash scripts/docker/build-offline-bundle.sh
```

This creates:

```text
eve-docker-offline-bundle.tar.gz
```

Upload that file to the restricted server, then:

```bash
mkdir -p /opt/eve-docker
tar -xzf eve-docker-offline-bundle.tar.gz -C /opt/eve-docker
cd /opt/eve-docker
sudo bash install.sh
```

The installer asks for the domain/IP, email, PostgreSQL password, and initial admin credentials, then starts Eve with Docker Compose.

The target server only needs Docker Engine and the Docker Compose plugin. The app itself does not depend on the target Ubuntu package versions, so Ubuntu 20.04, 22.04, and 24.04 on amd64 are supported.

### Manual Image Export

On an online machine:

```bash
docker pull ghcr.io/yoyoraya/eve-xui-manager:latest
docker pull postgres:16-alpine
docker pull caddy:2-alpine
docker save -o eve-docker-images.tar \
  ghcr.io/yoyoraya/eve-xui-manager:latest \
  postgres:16-alpine \
  caddy:2-alpine
```

If GHCR is private, either make the package public in GitHub Packages or run `docker login ghcr.io` on the online machine before pulling.

GitHub Actions also uploads `eve-xui-manager-image-amd64` as an artifact. You can download that tar from the workflow run, load it, and then save it together with `postgres:16-alpine` and `caddy:2-alpine`.

Copy these files to the restricted server:

- `eve-docker-images.tar`
- `docker-compose.yml`
- `docker/Caddyfile`
- `.env`

On the restricted server:

```bash
docker load -i eve-docker-images.tar
docker compose up -d
docker compose logs -f app
```

No GitHub, PyPI, or apt package download is needed after the images are loaded.

## Installing Docker on the Target Server

If the restricted server already has Docker, skip this part.

Docker itself must be installed once on the target server. If that server cannot access apt repositories, install Docker on another same-architecture Ubuntu server and transfer Docker's official `.deb` packages, or prepare the server image with Docker before moving it behind the restricted network.

After Docker is installed, Eve updates no longer need apt, PyPI, or GitHub access.

## Data

Persistent data is stored in Docker volumes:

- `eve_data`: database metadata, generated secrets, backups, temporary files
- `eve_uploads`: uploaded receipts/media
- `eve_app_files`: generated app files
- `postgres_data`: PostgreSQL data
- `caddy_data`, `caddy_config`: HTTPS certificates and Caddy state

Back up everything:

```bash
docker run --rm -v eve-xui-manager_eve_data:/data -v "$PWD:/backup" alpine tar czf /backup/eve_data.tar.gz -C /data .
docker run --rm -v eve-xui-manager_postgres_data:/data -v "$PWD:/backup" alpine tar czf /backup/postgres_data.tar.gz -C /data .
```

## Useful Commands

```bash
docker compose ps
docker compose logs -f app
docker compose restart app
docker compose pull && docker compose up -d
```
