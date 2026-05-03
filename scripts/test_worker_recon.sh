#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "SCRIPTKIDD.O - Validacao RECON via Kali Runner"
echo "Grupo: reconnaissance"
echo

python3 scripts/validate_kali_toolflow.py --group reconnaissance "$@"
