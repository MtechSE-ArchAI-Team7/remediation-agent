FROM node:20-bookworm-slim AS node-runtime

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node

RUN node --version | grep -E '^v2[0-9]\.' \
    && pip install --no-cache-dir \
      bandit==1.9.4 \
      mypy==2.2.0 \
      pytest==9.1.1 \
      ruff==0.15.21 \
    && useradd --system --uid 10001 --create-home sandbox
WORKDIR /workspace
USER 10001:10001

ENTRYPOINT []
CMD ["python", "--version"]
