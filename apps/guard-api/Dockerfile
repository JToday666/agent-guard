# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /wheelhouse
COPY release-dist/aegis-agentguard-core/*.whl /wheelhouse/
COPY release-dist/aegis-agentguard-api/*.whl /wheelhouse/
RUN python -m pip download --dest /wheelhouse --only-binary=:all: \
      --find-links=/wheelhouse aegis-agentguard-api==0.1.0b1

FROM python:3.12-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTGUARD_ENV=production \
    AGENTGUARD_HOST=0.0.0.0 \
    AGENTGUARD_PORT=8088

RUN groupadd --system agentguard \
    && useradd --system --gid agentguard --create-home agentguard \
    && install -d -o agentguard -g agentguard -m 0700 /var/lib/agentguard

COPY --from=builder /wheelhouse /wheelhouse
RUN python -m pip install --no-index --find-links=/wheelhouse \
      aegis-agentguard-core==0.1.0b1 aegis-agentguard-api==0.1.0b1 \
    && rm -rf /wheelhouse

USER agentguard:agentguard
WORKDIR /home/agentguard
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/health', timeout=3).read()"]

ENTRYPOINT ["agentguard-api"]
