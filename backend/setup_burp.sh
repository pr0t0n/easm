#!/bin/bash
# Setup script para instalar Burp CLI Mock no container
# Executar dentro do container backend: bash /app/setup_burp.sh

mkdir -p /opt/burpsuite/bin

# Copiar o mock Python do repositório
cp /app/burp_cli_mock.py /opt/burpsuite/bin/burpsuite_pro
chmod +x /opt/burpsuite/bin/burpsuite_pro

# Criar symlinks
ln -sf /opt/burpsuite/bin/burpsuite_pro /usr/local/bin/burp-cli
ln -sf /opt/burpsuite/bin/burpsuite_pro /usr/local/bin/burpsuite_pro

echo "✓ Burp CLI Mock instalado com sucesso"
burp-cli --version
