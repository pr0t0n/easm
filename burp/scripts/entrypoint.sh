#!/bin/sh
set -e

BURP_JAR="${BURP_JAR:-/opt/burpsuite/burpsuite_pro.jar}"
BURP_HOME="${BURP_HOME:-/root/.BurpSuite}"
BURP_API_HOST="${BURP_API_HOST:-0.0.0.0}"
BURP_API_PORT="${BURP_API_PORT:-1337}"
BURP_BROWSER_VERSION="${BURP_BROWSER_VERSION:-146.0.7680.153}"
BURP_LOG=/var/log/burp.log

# ── 1. Display virtual — permite ao Burp inicializar a UI Swing/AWT ──────────
# Limpa lock/socket stale de execuções anteriores para evitar
# "Fatal server error: Server is already active for display 99"
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99

echo "[burp] Iniciando Xvfb em :99..."
Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &
XVFB_PID=$!
sleep 2

# Valida que o Xvfb realmente subiu
if ! kill -0 "$XVFB_PID" 2>/dev/null; then
    echo "[burp] ERRO: Xvfb falhou ao iniciar. Verificando log..." >&2
    exit 1
fi
echo "[burp] Xvfb pronto (PID $XVFB_PID)."

# ── 2. Preparar diretórios ────────────────────────────────────────────────────
mkdir -p "$BURP_HOME"
mkdir -p "/opt/burpsuite/bin/burpbrowser/${BURP_BROWSER_VERSION}"

# ── 3. Aplicar configuração da REST API no UserConfigPro.json ─────────────────
python3 /opt/burp/scripts/patch_config.py

# ── 4. FIFO para aceite automático da EULA (primeiro arranque) ────────────────
#
#   O Burp, quando não encontra registo de aceite da EULA no data-dir,
#   apresenta um prompt interativo no stdin:  "Do you accept? (y/n)"
#   Usamos um FIFO para manter stdin aberto e enviar "y" após 20 s.
#   Em execuções subsequentes (volume com EULA já aceite) o "y" vai para
#   um stdin que o Burp ignora — sem efeito negativo.
#
EULA_FIFO=/tmp/burp-eula.fifo
rm -f "$EULA_FIFO"
mkfifo "$EULA_FIFO"
{
    sleep 20
    printf 'y\n'
    # Manter o lado de escrita aberto para que o Burp não receba EOF no stdin
    sleep 5
    printf '%s\n' "${BURP_LICENSE_KEY:-NOKEY}"
    sleep 10
    printf 'o\n'
    sleep infinity
} > "$EULA_FIFO" &
FIFO_PID=$!

# ── 5. Iniciar o Burp Pro ─────────────────────────────────────────────────────
echo "[burp] Iniciando Burp Suite Professional..."
java \
    -Xmx2g \
    -Djava.awt.headless=true \
    -jar "$BURP_JAR" \
    --use-defaults \
    --data-dir="$BURP_HOME" \
    --user-config-file="$BURP_HOME/UserConfigPro.json" \
    < "$EULA_FIFO" \
    >> "$BURP_LOG" 2>&1 &

BURP_PID=$!
echo "$BURP_PID" > /var/run/burp.pid
echo "[burp] Burp PID: $BURP_PID"

# ── 6. Aguardar REST API ──────────────────────────────────────────────────────
python3 /opt/burp/scripts/wait_for_api.py

echo "[burp] Container pronto. Aguardando término do processo Burp..."
wait "$BURP_PID"
