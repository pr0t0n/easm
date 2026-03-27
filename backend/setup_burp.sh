#!/bin/bash
# Setup do Burp Pro + cliente REST cihanmehmet/burp-cli

set -euo pipefail

BURP_BASE="/opt/burpsuite"
BURP_BIN_DIR="${BURP_BASE}/bin"
BURP_CLI_DIR="/opt/burp-rest-cli"

mkdir -p "${BURP_BIN_DIR}" "${BURP_CLI_DIR}"

echo "[*] Instalando cliente REST cihanmehmet/burp-cli..."
if [ ! -d "${BURP_CLI_DIR}/.git" ]; then
	rm -rf "${BURP_CLI_DIR}"
	git clone --depth 1 https://github.com/cihanmehmet/burp-cli.git "${BURP_CLI_DIR}"
else
	git -C "${BURP_CLI_DIR}" pull --ff-only || true
fi

(
	cd "${BURP_CLI_DIR}"
	go build -o /usr/local/bin/burp-api-cli .
)

chmod +x /usr/local/bin/burp-api-cli

# Opcional: se o JAR do Burp Pro vier no build context, copia para local padrao.
if [ -f "/app/burpsuite_pro.jar" ]; then
	cp /app/burpsuite_pro.jar "${BURP_BIN_DIR}/burpsuite_pro.jar"
elif [ -f "/app/burp/burpsuite_pro.jar" ]; then
	cp /app/burp/burpsuite_pro.jar "${BURP_BIN_DIR}/burpsuite_pro.jar"
fi

ln -sf /app/scripts/burp_cli_wrapper.sh /usr/local/bin/burp-cli
ln -sf /app/scripts/start_burp_rest.sh /usr/local/bin/start-burp-rest

chmod +x /app/scripts/burp_cli_wrapper.sh
chmod +x /app/scripts/start_burp_rest.sh

echo "✓ cliente cihanmehmet/burp-cli instalado e wrapper configurado"
/usr/local/bin/burp-api-cli -V || true
