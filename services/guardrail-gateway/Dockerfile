# Build from the repository root:  docker build -f services/guardrail-gateway/Dockerfile .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY packages/guardrail-sdk /tmp/guardrail-sdk
COPY services/guardrail-gateway/requirements.txt /tmp/requirements.txt
RUN pip install /tmp/guardrail-sdk -r /tmp/requirements.txt && rm -rf /tmp/guardrail-sdk

COPY services/guardrail-gateway/ /app/

RUN useradd --uid 10001 --no-create-home app \
    && mkdir -p /bootstrap /var/cache/guardrail-gateway \
    && chown -R app /app /bootstrap /var/cache/guardrail-gateway
USER app

EXPOSE 8100

# Compose runs migrations here; on Kubernetes/k3s run `alembic upgrade head` as a Job instead.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8100 --proxy-headers"]
