#!/bin/sh
set -e

alembic -c alembic.ini upgrade head

python3 -c "from app.services.bas_ca import ensure_ca; ensure_ca()"

BAS_CA_DIR="${BAS_CA_DIR:-/app/bas_ca}"
BAS_MTLS_PORT="${BAS_MTLS_PORT:-8443}"

uvicorn app.mtls:app --host 0.0.0.0 --port "$BAS_MTLS_PORT" \
  --ssl-certfile "$BAS_CA_DIR/server.crt" --ssl-keyfile "$BAS_CA_DIR/server.key" \
  --ssl-ca-certs "$BAS_CA_DIR/ca.crt" --ssl-cert-reqs 2 &

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
