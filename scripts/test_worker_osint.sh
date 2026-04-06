#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test_worker_osint.sh
# Testa o Worker OSINT (threat_intel)
#   Filas monitoradas:
#     worker.unit.osint | worker.scheduled.osint
#   Ferramentas esperadas:
#     theHarvester, h8mail, whatweb, subjack, metagoofil, shodan (CLI)
#
# Uso:
#   ./scripts/test_worker_osint.sh [--docker] [--redis-url redis://host:6379/0]
#
# Flags:
#   --docker         Executa verificações de binários via 'docker exec' no
#                    container pentest_worker_unit_osint (ou prod)
#   --redis-url URL  Sobrescreve a URL do Redis (padrão: $REDIS_URL ou redis://localhost:6379/0)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Cores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()  { echo -e "${GREEN}  [PASS]${RESET} $*"; }
fail()  { echo -e "${RED}  [FAIL]${RESET} $*"; FAILURES=$((FAILURES + 1)); }
warn()  { echo -e "${YELLOW}  [WARN]${RESET} $*"; }
info()  { echo -e "${CYAN}  [INFO]${RESET} $*"; }
title() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

FAILURES=0
USE_DOCKER=0
REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
CELERY_APP="app.workers.celery_app.celery"
WORKER_ROLE="osint"
WORKER_QUEUES="worker.unit.osint,worker.scheduled.osint"
# theHarvester registrado como 'theHarvester' (CLI) — alias 'theharvester' pode variar por distro
EXPECTED_TOOLS="theHarvester h8mail whatweb subjack shodan"
# ferramentas com paths alternativos
EXPECTED_TOOLS_OPTIONAL="metagoofil chaos urlscan"

# ── Parse args ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker)    USE_DOCKER=1; shift ;;
    --redis-url) REDIS_URL="$2"; shift 2 ;;
    *) echo "Opção desconhecida: $1"; exit 1 ;;
  esac
done

REDIS_HOST=$(echo "$REDIS_URL" | sed 's|redis://||;s|/.*||;s|:.*||')
REDIS_PORT=$(echo "$REDIS_URL" | sed 's|redis://[^:]*:||;s|/.*||')
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DB=$(echo "$REDIS_URL" | grep -oE '/[0-9]+$' | tr -d '/' || echo "0")
REDIS_DB="${REDIS_DB:-0}"

_docker_container() {
  docker ps --format '{{.Names}}' 2>/dev/null \
    | grep -E "pentest_worker_unit_osint(_prod)?$" \
    | head -1 || echo ""
}

echo -e "\n${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PENTEST.IO — Teste Worker OSINT (threat_intel)${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
info "Redis: $REDIS_URL"
info "Docker mode: $USE_DOCKER"

# ═══════════════════════════════════════════════════════════════════════════
title "1. Conectividade Redis (broker)"
# ═══════════════════════════════════════════════════════════════════════════
if command -v redis-cli &>/dev/null; then
  if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" PING 2>/dev/null | grep -q "PONG"; then
    pass "redis-cli PING → PONG"
  else
    fail "Redis não respondeu em $REDIS_HOST:$REDIS_PORT"
  fi
else
  warn "redis-cli não encontrado; tentando via python…"
  if python3 -c "import redis; redis.Redis.from_url('$REDIS_URL').ping()" 2>/dev/null; then
    pass "Python redis PING OK"
  else
    fail "Falha ao conectar no Redis via Python"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
title "2. Worker vivo — celery inspect ping"
# ═══════════════════════════════════════════════════════════════════════════
if [[ "$USE_DOCKER" -eq 1 ]]; then
  CONTAINER=$(_docker_container)
  if [[ -z "$CONTAINER" ]]; then
    fail "Nenhum container osint encontrado (pentest_worker_unit_osint[_prod])"
  else
    info "Usando container: $CONTAINER"
    if docker exec "$CONTAINER" sh -c "celery -A $CELERY_APP inspect ping --timeout 5 2>&1" \
        | grep -q "pong"; then
      pass "Worker respondeu ao ping Celery"
    else
      warn "Ping sem resposta — worker pode estar inicializando ou sem tasks ativas"
    fi
  fi
else
  CELERY_BIN="celery"
  if [[ -f "$(pwd)/.venv/bin/celery" ]]; then
    CELERY_BIN="$(pwd)/.venv/bin/celery"
  fi
  CELERY_BROKER_URL="$REDIS_URL" \
    $CELERY_BIN -A $CELERY_APP inspect ping --timeout 5 2>&1 \
    | grep -q "pong" && pass "Worker respondeu ao ping Celery" \
    || warn "Ping sem resposta — verifique se o worker está em execução"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "3. Filas registradas no Redis"
# ═══════════════════════════════════════════════════════════════════════════
IFS=',' read -ra EXPECTED_QUEUES <<< "$WORKER_QUEUES"
for q in "${EXPECTED_QUEUES[@]}"; do
  if command -v redis-cli &>/dev/null; then
    LEN=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" LLEN "$q" 2>/dev/null || echo "ERR")
    if [[ "$LEN" == "ERR" ]]; then
      warn "Fila '$q': não foi possível ler comprimento"
    else
      pass "Fila '$q' existe — $LEN mensagens pendentes"
    fi
  else
    warn "redis-cli necessário para inspeção de filas"
    break
  fi
done

# ═══════════════════════════════════════════════════════════════════════════
title "4. Binários de ferramentas OSINT"
# ═══════════════════════════════════════════════════════════════════════════
if [[ "$USE_DOCKER" -eq 1 ]]; then
  CONTAINER=$(_docker_container)
  if [[ -z "$CONTAINER" ]]; then
    warn "Container não disponível; pulando verificação de binários"
  else
    # Ferramentas obrigatórias
    for tool in $EXPECTED_TOOLS; do
      if docker exec "$CONTAINER" sh -c "command -v $tool >/dev/null 2>&1"; then
        pass "Binário encontrado: $tool"
      else
        # theHarvester pode ter alias em lower-case
        ALT=$(echo "$tool" | tr '[:upper:]' '[:lower:]')
        if docker exec "$CONTAINER" sh -c "command -v $ALT >/dev/null 2>&1"; then
          pass "Binário encontrado: $ALT (alias de $tool)"
        else
          fail "Binário ausente: $tool"
        fi
      fi
    done

    # Ferramentas opcionais
    for tool in $EXPECTED_TOOLS_OPTIONAL; do
      if docker exec "$CONTAINER" sh -c "command -v $tool >/dev/null 2>&1"; then
        pass "Binário opcional encontrado: $tool"
      else
        warn "Binário opcional ausente: $tool (best-effort, não crítico)"
      fi
    done
  fi
else
  warn "Use --docker para verificar binários dentro do container"
  info "Ferramentas obrigatórias: $EXPECTED_TOOLS"
  info "Ferramentas opcionais: $EXPECTED_TOOLS_OPTIONAL"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "5. Verificação de chaves de API externas"
# ═══════════════════════════════════════════════════════════════════════════
SHODAN_KEY="${SHODAN_API_KEY:-}"
if [[ -n "$SHODAN_KEY" ]]; then
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    "https://api.shodan.io/api-info?key=${SHODAN_KEY}" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "200" ]]; then
    pass "Shodan API key válida (HTTP 200)"
  else
    warn "Shodan API key retornou HTTP $STATUS"
  fi
else
  warn "SHODAN_API_KEY não definida — theHarvester/shodan-cli poderão falhar com dados limitados"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "6. Envio de task de diagnóstico (worker.unit.osint.execute)"
# ═══════════════════════════════════════════════════════════════════════════
TASK_RESULT=$(
  CELERY_BROKER_URL="$REDIS_URL" \
  python3 - <<'PYEOF' 2>&1 || true
import os, sys

broker = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
try:
    import celery as cel
    app = cel.Celery(broker=broker)
    result = app.send_task(
        "worker.unit.osint.execute",
        kwargs={"_probe": True},
        queue="worker.unit.osint",
        countdown=0,
        expires=30,
    )
    print(f"task_id={result.id}")
    sys.exit(0)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
)
if echo "$TASK_RESULT" | grep -q "task_id="; then
  TASK_ID=$(echo "$TASK_RESULT" | grep -oE 'task_id=[^ ]+' | cut -d= -f2)
  pass "Task enviada → ID: $TASK_ID"
  info "Use 'celery -A app.workers.celery_app.celery result $TASK_ID' para inspecionar"
else
  fail "Falha ao enviar task: $TASK_RESULT"
fi

# ═══════════════════════════════════════════════════════════════════════════
title "7. Heartbeat do worker osint no banco"
# ═══════════════════════════════════════════════════════════════════════════
DB_URL="${DATABASE_URL:-postgresql://easm:easm@localhost:5432/easm}"
set +e
HB_CHECK=$(python3 - <<'PYEOF' 2>&1
import sys
try:
    import psycopg2
    conn = psycopg2.connect("$DB_URL")
    cur = conn.cursor()
    cur.execute("""
        SELECT worker_name, status, last_seen_at
        FROM worker_heartbeats
        WHERE worker_name ILIKE '%osint%'
           OR worker_name ILIKE '%threat%'
        ORDER BY last_seen_at DESC
        LIMIT 3
    """)
    rows = cur.fetchall()
    conn.close()
    if rows:
        for r in rows:
            print(f"  {r[0]} | {r[1]} | {r[2]}")
    else:
        print("NO_ROWS")
except Exception as e:
    print(f"DB_ERROR: {e}")
PYEOF
)
set -e
if echo "$HB_CHECK" | grep -q "NO_ROWS"; then
  warn "Nenhum heartbeat osint no banco — worker nunca executou um scan"
elif echo "$HB_CHECK" | grep -q "DB_ERROR"; then
  warn "Não foi possível consultar heartbeats: $HB_CHECK"
else
  pass "Heartbeats osint encontrados:"
  echo "$HB_CHECK"
fi

# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
if [[ "$FAILURES" -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}  RESULTADO: PASSOU — 0 falhas${RESET}"
else
  echo -e "${RED}${BOLD}  RESULTADO: FALHOU — $FAILURES falha(s)${RESET}"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}\n"

exit "$FAILURES"
