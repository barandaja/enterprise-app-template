# Multi-stage build for production API Gateway
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/app/.local/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create directories
WORKDIR /app
RUN mkdir -p /app/logs /tmp/prometheus_multiproc && \
    chown -R appuser:appuser /app /tmp/prometheus_multiproc

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser src/ /app/src/
COPY --chown=appuser:appuser alembic/ /app/alembic/
COPY --chown=appuser:appuser alembic.ini /app/

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Run database migrations if needed\n\
if [ "$RUN_MIGRATIONS" = "true" ]; then\n\
    echo "Running database migrations..."\n\
    alembic upgrade head\n\
fi\n\
\n\
# Start the application\n\
exec uvicorn src.main:app \\\n\
    --host 0.0.0.0 \\\n\
    --port ${PORT:-8000} \\\n\
    --workers ${WORKERS:-4} \\\n\
    --loop uvloop \\\n\
    --http httptools \\\n\
    --log-config logging.yaml\n\
' > /app/start.sh && chmod +x /app/start.sh

# Create logging configuration
RUN echo 'version: 1\n\
disable_existing_loggers: false\n\
formatters:\n\
  default:\n\
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"\n\
  json:\n\
    format: "%(message)s"\n\
handlers:\n\
  default:\n\
    formatter: default\n\
    class: logging.StreamHandler\n\
    stream: ext://sys.stdout\n\
  json:\n\
    formatter: json\n\
    class: logging.StreamHandler\n\
    stream: ext://sys.stdout\n\
root:\n\
  level: INFO\n\
  handlers: [json]\n\
loggers:\n\
  uvicorn:\n\
    level: INFO\n\
    handlers: [json]\n\
    propagate: false\n\
  uvicorn.error:\n\
    level: INFO\n\
    handlers: [json]\n\
    propagate: false\n\
  uvicorn.access:\n\
    level: INFO\n\
    handlers: [json]\n\
    propagate: false\n\
' > /app/logging.yaml

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Expose ports
EXPOSE 8000 8001

# Set default command
CMD ["/app/start.sh"]

# Metadata
LABEL maintainer="Enterprise Team <team@example.com>" \
      version="1.0.0" \
      description="Enterprise API Gateway" \
      org.opencontainers.image.title="API Gateway" \
      org.opencontainers.image.description="Central API Gateway for microservices architecture" \
      org.opencontainers.image.vendor="Enterprise Corp" \
      org.opencontainers.image.version="1.0.0"