#!/bin/sh
# Backend startup: migrations, then two uvicorn listeners on the SAME
# FastAPI app --
#   :8000 (plain HTTP)  -- unchanged, everything normal users/frontend and
#                          BAS agent enrollment (bootstrap, no cert yet) use.
#   :8443 (mTLS)        -- BAS agent traffic from enroll onward (heartbeat,
#                          future agent calls). ssl_cert_reqs=CERT_REQUIRED
#                          means a client presenting no cert, or one the BAS
#                          root CA didn't sign, never completes the TLS
#                          handshake here at all -- enforced at the
#                          transport layer, before any FastAPI route runs.
# See app/services/bas_ca.py for the CA itself.
set -e

alembic -c alembic.ini upgrade head

python3 -c "from app.services.bas_ca import ensure_ca; ensure_ca()"

BAS_CA_DIR="${BAS_CA_DIR:-/app/bas_ca}"
BAS_MTLS_PORT="${BAS_MTLS_PORT:-8443}"

uvicorn app.main:app --host 0.0.0.0 --port "$BAS_MTLS_PORT" \
  --ssl-certfile "$BAS_CA_DIR/server.crt" --ssl-keyfile "$BAS_CA_DIR/server.key" \
  --ssl-ca-certs "$BAS_CA_DIR/ca.crt" --ssl-cert-reqs 2 &

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
