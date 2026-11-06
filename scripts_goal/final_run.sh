#!/usr/bin/env bash
# Reta final do goal LANGGRAPH_BRAIN_PLAN — executar APÓS o término do scan 42.
# Uso: bash scripts_goal/final_run.sh
set -euo pipefail

echo "== 1. Restart kali_runner + worker_scope (push, RAG attach, loop guard honesto)"
docker compose --profile dev restart kali_runner worker_scope 2>&1 | tail -2
sleep 25
curl -fsS http://localhost:8001/health >/dev/null && echo "backend OK"
curl -fsS http://localhost:8088/healthz >/dev/null && echo "runner OK"

echo "== 2. Scan de validação final: example.com (standard=agressivo, engine=langgraph)"
TOKEN=$(curl -fsS -X POST http://localhost:8001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"admin123"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
SCAN_ID=$(curl -fsS -X POST http://localhost:8001/api/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "target_query": "example.com",
    "mode": "unit",
    "scan_engine": "langgraph",
    "scope_authorization_attested": true,
    "access_group_id": 1
  }' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "scan de validação: $SCAN_ID"
echo "$SCAN_ID" > /tmp/final_scan_id.txt
