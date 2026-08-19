#!/bin/sh
# Resolves bas_agent_stub's IP once at container start and writes a runtime
# proxychains config -- see the Dockerfile comment above this script's COPY
# for why a literal IP is required instead of the hostname.
set -e

BAS_STUB_IP="$(getent hosts bas_agent_stub 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [ -n "$BAS_STUB_IP" ]; then
  sed "s/bas_agent_stub/${BAS_STUB_IP}/" /app/profiles/bas_proxychains.conf > /tmp/bas_proxychains_resolved.conf
  echo "entrypoint: resolved bas_agent_stub -> ${BAS_STUB_IP} (/tmp/bas_proxychains_resolved.conf)"
else
  echo "entrypoint: bas_agent_stub not resolvable yet -- BAS-tagged jobs will fail until this container restarts after it's up"
fi

exec "$@"
