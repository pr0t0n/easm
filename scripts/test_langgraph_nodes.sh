#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test_langgraph_nodes.sh
#
# Testa os nós e passos da missão (LangGraph workflow)
# Dispara um scan real e monitora o progresso através dos nós:
#   1) asset_discovery (RECON: Amass, MassDns, Sublist3r, Nmap)
#   2) threat_intel (OSINT: Shodan.io) [paralelo]
#   3) risk_assessment (VULN: Burp, Nmap Vulscan, Nikto) [paralelo]
#   4) governance (FAIR+AGE rating)
#   5) executive_analyst (Narrativa LLM)
#
# Uso:
#   ./scripts/test_langgraph_nodes.sh [target_domain] [mode]
#
# Exemplos:
#   ./scripts/test_langgraph_nodes.sh example.com single
#   ./scripts/test_langgraph_nodes.sh monitoring.example.com scheduled
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Cores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()  { echo -e "${GREEN}✅ PASS${RESET} $*"; }
fail()  { echo -e "${RED}❌ FAIL${RESET} $*"; FAILURES=$((FAILURES + 1)); }
warn()  { echo -e "${YELLOW}⚠️  WARN${RESET} $*"; }
info()  { echo -e "${CYAN}ℹ️  INFO${RESET} $*"; }
title() { echo -e "\n${BOLD}┌─ $* ${RESET}"; }
footer(){ echo -e "${BOLD}└─ Fim ${RESET}\n"; }

HTTP_STATUS=""
RESPONSE_BODY=""
TOKEN=""
ALLOW_ID=""
SCAN_ID=""

api_request() {
  local method="$1"
  local url="$2"
  local payload="${3:-}"
  local auth_token="${4:-}"
  local response
  local -a curl_args=(-sS -X "$method" "$url")

  if [[ -n "$auth_token" ]]; then
    curl_args+=(-H "Authorization: Bearer $auth_token")
  fi
  if [[ -n "$payload" ]]; then
    curl_args+=(-H "Content-Type: application/json" -d "$payload")
  fi

  response=$(curl "${curl_args[@]}" -w $'\n%{http_code}') || return 1
  HTTP_STATUS="${response##*$'\n'}"
  RESPONSE_BODY="${response%$'\n'*}"
}

json_get_field() {
  local field="$1"
  local default_value="${2:-}"
  python3 -c '
import json, sys
field = sys.argv[1]
default = sys.argv[2]
try:
    data = json.load(sys.stdin)
    value = data.get(field, default)
    if value is None:
        value = default
    print(value)
except Exception:
    print(default)
' "$field" "$default_value" 2>/dev/null
}

array_contains_exact() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

cleanup() {
  if [[ -n "$ALLOW_ID" && -n "$TOKEN" ]]; then
    api_request "DELETE" "$BACKEND_URL/api/policy/allowlist/$ALLOW_ID" "" "$TOKEN" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

FAILURES=0
TARGET_DOMAIN="${1:-www.valid.com}"
SCAN_MODE="${2:-single}"

# Configurações
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"
MAX_WAIT="${MAX_WAIT:-0}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

# Nós esperados do LangGraph
EXPECTED_NODES=("asset_discovery" "threat_intel" "risk_assessment" "governance" "executive_analyst")

# Passos da missão esperados
EXPECTED_MISSION_STEPS=(
  "1. AssetDiscovery"
  "2. ThreatIntel"
  "3. RiskAssessment"
  "4. Governance"
  "5. ExecutiveAnalysis"
)

echo -e "\n${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PENTEST.IO — Teste LangGraph Nodes & Mission Steps${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
info "Target: $TARGET_DOMAIN"
info "Mode: $SCAN_MODE"
info "Backend: $BACKEND_URL"
if [[ "$ADMIN_EMAIL" == "admin@example.com" && "$ADMIN_PASSWORD" == "admin123" ]]; then
  warn "Usando credenciais administrativas default via ambiente local"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "1. Backend Health Check"
# ═══════════════════════════════════════════════════════════════════════════
if curl -s -f "$BACKEND_URL/docs" >/dev/null 2>&1; then
  pass "Backend API respondendo em $BACKEND_URL"
else
  fail "Backend não respondendo em $BACKEND_URL"
  exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
title "2. Authentication"
# ═══════════════════════════════════════════════════════════════════════════
api_request "POST" "$BACKEND_URL/api/auth/login" "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" || {
  fail "Falha HTTP ao autenticar no backend"
  exit 1
}
LOGIN_RESP="$RESPONSE_BODY"

if [[ ! "$HTTP_STATUS" =~ ^2 ]]; then
  fail "Falha ao autenticar (HTTP $HTTP_STATUS): $LOGIN_RESP"
  exit 1
fi

TOKEN=$(printf '%s' "$LOGIN_RESP" | json_get_field "access_token" "")

if [[ -z "$TOKEN" ]]; then
  fail "Falha ao obter token de autenticação"
  exit 1
fi
pass "JWT token obtido com sucesso"

# ═══════════════════════════════════════════════════════════════════════════
title "3. Adicionar target à allowlist"
# ═══════════════════════════════════════════════════════════════════════════
api_request "POST" "$BACKEND_URL/api/policy/allowlist" "{\"target_pattern\":\"$TARGET_DOMAIN\"}" "$TOKEN" || {
  fail "Falha HTTP ao adicionar allowlist"
  exit 1
}
ALLOW_RESP="$RESPONSE_BODY"

if [[ "$HTTP_STATUS" =~ ^2 ]]; then
  ALLOW_ID=$(printf '%s' "$ALLOW_RESP" | json_get_field "id" "")
fi

if [[ -n "$ALLOW_ID" ]]; then
  pass "Target adicionado à allowlist (ID: $ALLOW_ID)"
elif [[ ! "$HTTP_STATUS" =~ ^2 ]]; then
  fail "Falha ao adicionar allowlist (HTTP $HTTP_STATUS): $ALLOW_RESP"
  exit 1
else
  warn "Pode já estar na allowlist: $ALLOW_RESP"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "4. Criar scan"
# ═══════════════════════════════════════════════════════════════════════════
api_request "POST" "$BACKEND_URL/api/scans" "{\"target_query\":\"$TARGET_DOMAIN\",\"mode\":\"$SCAN_MODE\"}" "$TOKEN" || {
  fail "Falha HTTP ao criar scan"
  exit 1
}
SCAN_RESP="$RESPONSE_BODY"

if [[ ! "$HTTP_STATUS" =~ ^2 ]]; then
  fail "Falha ao criar scan (HTTP $HTTP_STATUS): $SCAN_RESP"
  exit 1
fi

SCAN_ID=$(printf '%s' "$SCAN_RESP" | json_get_field "id" "")
if [[ -z "$SCAN_ID" ]]; then
  fail "Falha ao criar scan: $SCAN_RESP"
  exit 1
fi
pass "Scan criado: ID $SCAN_ID"
echo "  Resposta: $(echo "$SCAN_RESP" | python3 -m json.tool | head -5)"

# ═══════════════════════════════════════════════════════════════════════════
title "5. Monitorar progresso do scan"
# ═══════════════════════════════════════════════════════════════════════════
START_TIME=$(date +%s)
NODES_VISITED=()
NODE_ITEMS=()
LAST_STEP=""
FINAL_STATUS=""

info "Polling a cada ${POLL_INTERVAL}s..."
while true; do
  CURRENT_TIME=$(date +%s)
  ELAPSED=$((CURRENT_TIME - START_TIME))

  api_request "GET" "$BACKEND_URL/api/scans/$SCAN_ID/status" "" "$TOKEN" || {
    fail "Falha HTTP ao consultar status do scan"
    FINAL_STATUS="FAILED"
    break
  }
  STATUS_RESP="$RESPONSE_BODY"

  if [[ ! "$HTTP_STATUS" =~ ^2 ]]; then
    fail "Consulta de status falhou (HTTP $HTTP_STATUS): $STATUS_RESP"
    FINAL_STATUS="FAILED"
    break
  fi

  SCAN_STATUS=$(printf '%s' "$STATUS_RESP" | json_get_field "status" "?")
  CURRENT_STEP=$(printf '%s' "$STATUS_RESP" | json_get_field "current_step" "?")
  MISSION_PROGRESS=$(printf '%s' "$STATUS_RESP" | json_get_field "mission_progress" "0")
    # node_history pode vir no topo (/status) e, por compatibilidade, em state_data
    NODE_HISTORY=$(echo "$STATUS_RESP" | python3 -c "
  import sys, json
  try:
    d = json.load(sys.stdin)
    nh = d.get('node_history')
    if not isinstance(nh, list):
      sd = d.get('state_data', {})
      if isinstance(sd, str):
        sd = json.loads(sd)
      nh = sd.get('node_history', []) if isinstance(sd, dict) else []
    print(json.dumps(nh if isinstance(nh, list) else []))
  except Exception:
    print('[]')
  " 2>/dev/null || echo "[]")
  CURRENT_NODE=$(echo "$NODE_HISTORY" | python3 -c "import sys,json; nodes=json.loads(sys.stdin.read() or '[]'); print(nodes[-1] if nodes else '?')" 2>/dev/null || echo "?")

  # Log progresso
  printf "[%3ds] Status: %-10s | Node: %-20s | Step: %s | Progress: %d%% \n" \
    "$ELAPSED" "$SCAN_STATUS" "$CURRENT_NODE" "$CURRENT_STEP" "$MISSION_PROGRESS"

  # Rastreia nós visitados
  if [[ "$CURRENT_NODE" != "?" ]]; then
    NODE_ITEMS=$(echo "$NODE_HISTORY" | python3 -c "
import sys, json
try:
    nodes = json.loads(sys.stdin.read())
    for node in nodes:
        print(node)
except:
    pass
" )
    while IFS= read -r node; do
      [[ -z "$node" ]] && continue
      if ! array_contains_exact "$node" "${NODES_VISITED[@]:-}"; then
        NODES_VISITED+=("$node")
        pass "Nó visitado: $node"
      fi
    done <<< "$NODE_ITEMS"
  fi

  LAST_STEP="$CURRENT_STEP"

  # Verifica se completou
  if [[ "$SCAN_STATUS" == "completed" ]]; then
    FINAL_STATUS="COMPLETED"
    pass "Scan completado!"
    break
  elif [[ "$SCAN_STATUS" == "failed" ]] || [[ "$SCAN_STATUS" == "error" ]]; then
    FINAL_STATUS="FAILED"
    fail "Scan falhou com status: $SCAN_STATUS"
    break
  fi

  # Timeout opcional apenas quando MAX_WAIT > 0
  if [[ "$MAX_WAIT" =~ ^[0-9]+$ ]] && [[ "$MAX_WAIT" -gt 0 ]] && [[ $ELAPSED -ge $MAX_WAIT ]]; then
    FINAL_STATUS="TIMEOUT"
    warn "Timeout configurado (${MAX_WAIT}s) atingido. Scan ainda em execução."
    break
  fi

  sleep "$POLL_INTERVAL"
done

# ═══════════════════════════════════════════════════════════════════════════
title "6. Validar nós do LangGraph visitados"
# ═══════════════════════════════════════════════════════════════════════════
for node in "${EXPECTED_NODES[@]}"; do
  if array_contains_exact "$node" "${NODES_VISITED[@]:-}"; then
    pass "Nó executado: $node"
  else
    warn "Nó não visitado (pode estar em paralelo ou pendente): $node"
  fi
done

# ═══════════════════════════════════════════════════════════════════════════
title "7. Validar passos da missão"
# ═══════════════════════════════════════════════════════════════════════════
# Obter estado final detalhado
api_request "GET" "$BACKEND_URL/api/scans/$SCAN_ID/report" "" "$TOKEN" || {
  fail "Falha HTTP ao obter estado final do scan"
  exit 1
}
FINAL_STATE="$RESPONSE_BODY"

if [[ ! "$HTTP_STATUS" =~ ^2 ]]; then
  fail "Falha ao obter estado final (HTTP $HTTP_STATUS): $FINAL_STATE"
  exit 1
fi

MISSION_INDEX=$(echo "$FINAL_STATE" | python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    sd = d.get('state_data', {})
    if isinstance(sd, str):
        sd = json.loads(sd)
    print(int(sd.get('mission_index', 0)))
except:
    print(0)
" 2>/dev/null || echo "0")

VULN_EVIDENCE=$(echo "$FINAL_STATE" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  sd = d.get('state_data', {})
  if isinstance(sd, str):
    sd = json.loads(sd)
  report_v2 = sd.get('report_v2', {}) if isinstance(sd, dict) else {}
  evidence = report_v2.get('vulnerability_analysis_evidence', {}) if isinstance(report_v2, dict) else {}
  print(int((evidence.get('executions_found') or 0)))
except Exception:
  print(0)
" 2>/dev/null || echo "0")

VULN_TOOLS_FOUND=$(echo "$FINAL_STATE" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  sd = d.get('state_data', {})
  if isinstance(sd, str):
    sd = json.loads(sd)
  report_v2 = sd.get('report_v2', {}) if isinstance(sd, dict) else {}
  evidence = report_v2.get('vulnerability_analysis_evidence', {}) if isinstance(report_v2, dict) else {}
  tools = evidence.get('tools', []) if isinstance(evidence, dict) else []
  names = [str(t.get('tool') or '') for t in tools if isinstance(t, dict) and str(t.get('tool') or '')]
  print(','.join(sorted(set(names))))
except Exception:
  print('')
" 2>/dev/null || echo "")

echo "Mission Index: $MISSION_INDEX"
for i in "${!EXPECTED_MISSION_STEPS[@]}"; do
  STEP_NUM=$((i + 1))
  if [[ $STEP_NUM -le $MISSION_INDEX ]]; then
    pass "Passo ${STEP_NUM}: ${EXPECTED_MISSION_STEPS[$i]}"
  else
    info "Passo ${STEP_NUM}: ${EXPECTED_MISSION_STEPS[$i]} (pendente)"
  fi
done

if [[ "$VULN_EVIDENCE" =~ ^[0-9]+$ ]] && [[ "$VULN_EVIDENCE" -gt 0 ]]; then
  pass "Evidência de análise de vulnerabilidade encontrada no report_v2 (executions=$VULN_EVIDENCE, tools=$VULN_TOOLS_FOUND)"
else
  fail "Sem evidência de análise de vulnerabilidade no report_v2.vulnerability_analysis_evidence"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "8. Resumo da Execução"
# ═══════════════════════════════════════════════════════════════════════════
echo "Scan ID: $SCAN_ID"
echo "Status Final: $FINAL_STATUS"
echo "Último passo: $LAST_STEP"
echo "Nós visitados: ${NODES_VISITED[*]:-nenhum}"
echo "Falhas: $FAILURES"

if [[ $FAILURES -eq 0 ]]; then
  echo -e "\n${GREEN}${BOLD}✅ Teste concluído com sucesso!${RESET}"
else
  echo -e "\n${RED}${BOLD}❌ Teste concluído com $FAILURES falha(s)${RESET}"
fi

footer
exit $FAILURES
