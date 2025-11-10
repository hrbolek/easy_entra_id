###############################################################
# Base stage: Python + system deps + pip install
###############################################################
FROM python:3.13-alpine AS pythonbase

# Základní systémové závislosti pro build některých Python balíků
# (uvloop/httptools/cryptography, atd.)
RUN apk add --no-cache \
    build-base \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    # runtime knihovny (často potřeba)
    libstdc++ \
    ca-certificates

# Prostředí pro čistší instalaci
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Nejdřív jen requirements kvůli cache layerům
COPY requirements.txt /app/requirements.txt

# Instalace Python závislostí
RUN python -m pip install --no-cache-dir -r /app/requirements.txt


###############################################################
# Final stage: aplikační kód + non-root user
###############################################################
FROM python:3.13-alpine AS executepython

# Runtime knihovny (menší set než v builderu)
RUN apk add --no-cache \
    libstdc++ \
    ca-certificates

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Přeneseme nainstalované site-packages z base stage
# (kopírujeme celé /usr/local z builderu – je to standardní cesta pro pip v oficiálních Python image)
COPY --from=pythonbase /usr/local /usr/local

# Zbytek zdrojů (kód aplikace)
COPY --chown=app:app . /app

# Vytvoření non-root uživatele (Alpine varianta)
RUN addgroup -S app && adduser -S -G app app \
    && chown -R app:app /app

USER app

EXPOSE 8000

# Start přes gunicorn s Uvicorn workerem
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "-t", "60", "-k", "uvicorn.workers.UvicornWorker", "main:app"]
# Pro vývoj:
# CMD ["gunicorn", "--reload", "--reload-engine", "inotify", "--bind", "0.0.0.0:8000", "-k", "uvicorn.workers.UvicornWorker", "main:app"]
