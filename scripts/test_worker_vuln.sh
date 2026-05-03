#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "PENTEST.IO - Validacao VULN/Exploitation via Kali Runner"
echo "Grupo: exploitation"
echo

python3 scripts/validate_kali_toolflow.py --group exploitation "$@"
