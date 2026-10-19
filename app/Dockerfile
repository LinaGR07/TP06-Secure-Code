# Pinned base image: a precise, slim tag instead of the floating "latest" tag
FROM python:3.12-slim

# No .pyc files, unbuffered logs, production mode by default
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DB_PATH=/app/data/shop.db

WORKDIR /app

# /ping needs the ping binary, which the slim image does not ship.
# --no-install-recommends keeps the image (and its attack surface) small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first (better layer cache), every package checked against its hash
COPY requirements.txt .
RUN pip install --require-hashes --no-cache-dir -r requirements.txt

# Application code is owned by root: the app user can run it but not modify it
COPY . .

# Unprivileged user; only the data directory is writable by it.
RUN groupadd --system app \
    && useradd --system --gid app --no-create-home app \
    && mkdir -p /app/data \
    && chown -R app:app /app/data
USER app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

# The demo database is seeded at startup with ADMIN_PASSWORD, given at run time
# (docker run --env-file .env): no password is ever baked into the image.
# 0.0.0.0 is required inside a container; no --reload
CMD ["sh", "-c", "python -c 'import app; app.init_db()' && exec uvicorn app:app --host 0.0.0.0 --port 5000"]