FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    API_PORT=5000 \
    FLASK_ENV=production

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libmagic1 \
        postgresql-client \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .
COPY docker/entrypoint.sh /usr/local/bin/eve-entrypoint

RUN useradd --system --create-home --home-dir /home/eve --shell /usr/sbin/nologin eve \
    && mkdir -p /app/instance /app/static/uploads /app/static/app-files \
    && chown -R eve:eve /app /home/eve \
    && chmod +x /usr/local/bin/eve-entrypoint

USER eve

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${API_PORT}/healthz" || exit 1

ENTRYPOINT ["eve-entrypoint"]
