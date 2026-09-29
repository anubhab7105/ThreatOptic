
FROM python:3.11-slim AS builder
WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1
COPY backend/requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY backend/scripts ./scripts
COPY backend/app ./app

RUN PYTHONPATH=. /opt/venv/bin/python scripts/train_nlp.py || true

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    PATH="/opt/venv/bin:$PATH"
RUN useradd -r -m -s /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=appuser:appuser /build/app ./app
COPY --from=builder --chown=appuser:appuser /build/ml_models ./ml_models
COPY --from=builder --chown=appuser:appuser /build/scripts ./scripts

COPY --chown=appuser:appuser backend/alembic.ini ./alembic.ini
COPY --chown=appuser:appuser backend/alembic ./alembic
USER appuser
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
