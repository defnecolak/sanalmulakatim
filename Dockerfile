FROM python:3.14-slim

# Conservative defaults for containers
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Minimal OS deps (curl for health/debug; tesseract for OCR fallback)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system app \
    && adduser --system --ingroup app app \
    && mkdir -p /app/backend/data \
    && chown -R app:app /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY deploy/Caddyfile /app/deploy/Caddyfile
COPY deploy/docker-compose.prod.yml /app/deploy/docker-compose.prod.yml

# Make runtime writable paths owned by the non-root user
RUN chown -R app:app /app/backend

USER app

EXPOSE 5555

# Trust proxy headers only from private ranges (Caddy runs in the same Docker network)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "5555", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
