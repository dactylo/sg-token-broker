FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

WORKDIR /app
COPY requirements-image.txt pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements-image.txt \
    && pip install --no-cache-dir --no-deps --no-build-isolation . \
    && apt-get update && apt-get install -y --no-install-recommends nginx openssl \
    && rm -rf /var/lib/apt/lists/*
COPY docs/reverse-proxy.conf /etc/nginx/reverse-proxy.conf
COPY benchmarks ./benchmarks
RUN install -d -o www-data -g www-data /etc/nginx/tls \
    && touch /run/nginx.pid && chown www-data /run/nginx.pid \
    && chown -R www-data /var/lib/nginx /var/log/nginx \
    && printf '%s\n' '#!/bin/sh' 'set -eu' \
    'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout /etc/nginx/tls/privkey.pem -out /etc/nginx/tls/fullchain.pem 2>/dev/null' \
    'owner=www-data; group=www-data; if test -d /results; then owner=$(stat -c %u /results); group=$(stat -c %g /results); fi' \
    'chown -R "$owner:$group" /etc/nginx/tls /var/lib/nginx /var/log/nginx /run/nginx.pid' \
    'exec setpriv --reuid "$owner" --regid "$group" --clear-groups "$@"' > /usr/local/bin/farm-entry && chmod 755 /usr/local/bin/farm-entry
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/farm-entry"]
CMD ["python", "-m", "benchmarks.farm", "--help"]
