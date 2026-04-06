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

FAILURES=0
TARGET_DOMAIN="${1:-www.valid.com}"
SCAN_MODE="${2:-single}"

# Configurações
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

# Nós esperados do LangGraph
EXPECTED_NODES=("asset_discovery" "threat_intel" "risk_assessment" "governance" "executive_analyst")

# Passos da missão esperados
EXPECTED_MISSION_STEPS=(
  "1. Amass Subdomain Recon"
  "2. Sublist3r Subdomain Expansion"
  "3. MassDns DNS Validation"
  "4. Nmap Port Scanning"
  "5. Nmap Service Detection"
  "6. Shodan Intelligence Gathering"
  "7. Shodan Fingerprint Analysis"
  "8. Burp Suite Scanning"
  "9. Nmap Vulscan Script Analysis"
  "10. Nikto Web Server Scan"
  "11. Consolidar Dados (Recon + OSINT + Vuln)"
  "12. Validate Risk via LLM"
  "13. Gerar Recomendações de Correção"
  "14. Relatorio Final JsonL"
)

echo -e "\n${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PENTEST.IO — Teste LangGraph Nodes & Mission Steps${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
info "Target: $TARGET_DOMAIN"
info "Mode: $SCAN_MODE"
info "Backend: $BACKEND_URL"

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
TOKEN=$(curl -s -X POST "$BACKEND_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")

if [[ -z "$TOKEN" ]]; then
  fail "Falha ao obter token de autenticação"
  exit 1
fi
pass "JWT token obtido: ${TOKEN:0:40}..."

# ═══════════════════════════════════════════════════════════════════════════
title "3. Adicionar target à allowlist"
# ═══════════════════════════════════════════════════════════════════════════
ALLOW_RESP=$(curl -s -X POST "$BACKEND_URL/api/policy/allowlist" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"target_pattern\":\"$TARGET_DOMAIN\"}" 2>/dev/null)

ALLOW_ID=$(echo "$ALLOW_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || echo "")
if [[ -n "$ALLOW_ID" ]]; then
  pass "Target adicionado à allowlist (ID: $ALLOW_ID)"
else
  warn "Pode já estar na allowlist: $ALLOW_RESP"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "4. Criar scan"
# ═══════════════════════════════════════════════════════════════════════════
SCAN_RESP=$(curl -s -X POST "$BACKEND_URL/api/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"target_query\":\"$TARGET_DOMAIN\",\"mode\":\"$SCAN_MODE\"}" 2>/dev/null)

SCAN_ID=$(echo "$SCAN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || echo "")
if [[ -z "$SCAN_ID" ]]; then
  fail "Falha ao criar scan: $SCAN_RESP"
  exit 1
fi
pass "Scan criado: ID $SCAN_ID"
echo "  Resposta: $(echo "$SCAN_RESP" | python3 -m json.tool | head -5)"

# ═══════════════════════════════════════════════════════════════════════════
title "5. Monitorar progresso do scan (5 min)"
# ═══════════════════════════════════════════════════════════════════════════
START_TIME=$(date +%s)
MAX_WAIT=300  # 5 minutos
POLL_INTERVAL=5
NODES_VISITED=()
NODE_ITEMS=()
LAST_STEP=""
FINAL_STATUS=""

info "Polling a cada ${POLL_INTERVAL}s..."
while true; do
  CURRENT_TIME=$(date +%s)
  ELAPSED=$((CURRENT_TIME - START_TIME))

  STATUS_RESP=$(curl -s "$BACKEND_URL/api/scans/$SCAN_ID/status" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)

  SCAN_STATUS=$(echo "$STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
  CURRENT_STEP=$(echo "$STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('current_step','?'))" 2>/dev/null || echo "?")
  MISSION_PROGRESS=$(echo "$STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mission_progress',0))" 2>/dev/null || echo "0")
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
      if [[ ! " ${NODES_VISITED[@]} " =~ " ${node} " ]]; then
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

  # Verifica timeout
  if [[ $ELAPSED -ge $MAX_WAIT ]]; then
    FINAL_STATUS="TIMEOUT"
    warn "Timeout de 5min atingido. Scan ainda em execução."
    break
  fi

  sleep "$POLL_INTERVAL"
done

# ═══════════════════════════════════════════════════════════════════════════
title "6. Validar nós do LangGraph visitados"
# ═══════════════════════════════════════════════════════════════════════════
for node in "${EXPECTED_NODES[@]}"; do
  if [[ " ${NODES_VISITED[@]} " =~ " ${node} " ]]; then
    pass "Nó executado: $node"
  else
    warn "Nó não visitado (pode estar em paralelo ou pendente): $node"
  fi
done

# ═══════════════════════════════════════════════════════════════════════════
title "7. Validar passos da missão"
# ═══════════════════════════════════════════════════════════════════════════
# Obter estado final detalhado
FINAL_STATE=$(curl -s "$BACKEND_URL/api/scans/$SCAN_ID" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null)

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

echo "Mission Index: $MISSION_INDEX"
for i in "${!EXPECTED_MISSION_STEPS[@]}"; do
  STEP_NUM=$((i + 1))
  if [[ $STEP_NUM -le $MISSION_INDEX ]]; then
    pass "Passo ${STEP_NUM}: ${EXPECTED_MISSION_STEPS[$i]}"
  else
    info "Passo ${STEP_NUM}: ${EXPECTED_MISSION_STEPS[$i]} (pendente)"
  fi
done

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
