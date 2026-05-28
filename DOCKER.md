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
LETSENCRYPT_EMAIL=admin@example.com
POSTGRES_PASSWORD=change-this-long-random-password
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=change-this-admin-password
```

`DOMAIN` is the domain or IP you want this server to use. For local HTTP-only tests, set `DOMAIN=:80`.

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
