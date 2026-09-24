# Build from the repository root:  docker build -f services/guardrail-control-plane/Dockerfile .

# ---- console (apps/console): static files, so build once on the build platform for every target arch
FROM --platform=$BUILDPLATFORM node:22-alpine AS console
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    npm_config_audit=false \
    npm_config_fund=false
WORKDIR /console
COPY apps/console/package.json apps/console/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY apps/console/ ./
RUN npm run build

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
# Operator console + human review UI, served at /console (and /review)
COPY --from=console /console/dist /app/console

RUN useradd --uid 10001 --no-create-home app && mkdir -p /bootstrap && chown -R app /app /bootstrap
USER app

EXPOSE 8200

CMD ["sh", "-c", "alembic upgrade head && exec python -m app.serve"]
