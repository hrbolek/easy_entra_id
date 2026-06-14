ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/main.py
COPY index.html /app/index.html
COPY fake_users.json /app/fake_users.json

ENV TARGET_SERVER=http://frontend:8000
ENV FAKE_USERS_JSON=/app/fake_users.json
ENV FAKE_LOGIN_HTML_PATH=/app/index.html
ENV FAKE_AUTH_COOKIE=fake_easy_entra_user

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]