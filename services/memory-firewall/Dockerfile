# Build with Compose (docker compose build memory-firewall), or directly:
#   docker build services/memory-firewall
# The Memory Firewall library is the verbatim copy in vendor/ (see vendor/VENDORED.md).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# The library's source and its pyproject (read for the version), exactly as vendored.
COPY vendor/memory-firewall /opt/memory-firewall
ENV PYTHONPATH=/opt/memory-firewall/src \
    MEMORY_FIREWALL_DATA_DIR=/var/lib/memory-firewall

COPY app /app/app

RUN useradd --uid 10001 --no-create-home app \
    && mkdir -p /var/lib/memory-firewall \
    && chown -R app /var/lib/memory-firewall
USER app

EXPOSE 8300

CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8300", "--no-access-log"]
