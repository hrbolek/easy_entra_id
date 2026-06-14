###############################################################
# Base stage: Python + system deps + pip install
###############################################################
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS pythonbase

# Základní systémové závislosti pro build některých Python balíků
# Debian/Ubuntu varianta - používá apt-get, ne apk.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --no-cache-dir -r /app/requirements.txt


###############################################################
# Final stage: aplikační kód + non-root user
###############################################################
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS executepython

# Runtime knihovny pro Debian/Ubuntu variantu.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Vytvoření non-root uživatele - Debian varianta.
RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app

# Přeneseme nainstalované site-packages z builder stage.
COPY --from=pythonbase /usr/local /usr/local

# Zbytek zdrojů aplikace.
COPY --chown=app:app . /app

USER app

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "-t", "60", "-k", "uvicorn.workers.UvicornWorker", "main:app"]