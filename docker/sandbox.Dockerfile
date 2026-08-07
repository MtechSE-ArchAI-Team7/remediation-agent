FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir \
      bandit==1.9.4 \
      mypy==2.2.0 \
      pytest==9.1.1 \
      ruff==0.15.21 \
    && useradd --system --uid 10001 --create-home sandbox
WORKDIR /workspace
USER 10001:10001

ENTRYPOINT []
CMD ["python", "--version"]
