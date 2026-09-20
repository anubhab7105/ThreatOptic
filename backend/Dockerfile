FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000
# Context is repo root (see docker-compose.yml and Railway). For local `docker build -f backend/Dockerfile backend/` use that folder as context instead.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/scripts ./scripts
RUN python scripts/train_nlp.py || true
EXPOSE 8000
# Railway injects $PORT at runtime. Use JSON form with shell for proper signal handling and env expansion.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
