FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[google,oidc]'

ENV PYTHONUNBUFFERED=1
USER nobody
ENTRYPOINT ["sg-token-broker", "serve-user-tokens"]
