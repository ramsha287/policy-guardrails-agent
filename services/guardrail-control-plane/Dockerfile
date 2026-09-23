# Build from the repository root:  docker build -f services/guardrail-control-plane/Dockerfile .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY packages/guardrail-sdk /tmp/guardrail-sdk
COPY services/guardrail-control-plane/requirements.txt /tmp/requirements.txt
RUN pip install /tmp/guardrail-sdk -r /tmp/requirements.txt && rm -rf /tmp/guardrail-sdk

COPY services/guardrail-control-plane/ /app/
# Manifests of the guardrails shipped in the gateway image, for `import-gateway` / `bootstrap-dev`.
COPY services/guardrail-gateway/app/plugins /app/gateway-plugins
COPY services/guardrail-gateway/config/snapshots /app/gateway-snapshots

RUN useradd --uid 10001 --no-create-home app && mkdir -p /bootstrap && chown -R app /app /bootstrap
USER app

EXPOSE 8200

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8200 --proxy-headers"]
