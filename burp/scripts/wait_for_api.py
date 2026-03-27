#!/usr/bin/env python3
"""Aguarda a REST API do Burp ficar disponível (timeout 5 minutos)."""
import os
import pathlib
import sys
import time
import urllib.request

host     = "127.0.0.1"
port     = int(os.environ.get("BURP_API_PORT", "1337"))
url      = f"http://{host}:{port}/v0.1/"
log_path = pathlib.Path("/var/log/burp.log")
deadline = time.time() + 300

print(f"[burp] Aguardando REST API em {host}:{port} (timeout 5 min)...", flush=True)

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            if r.status >= 200:
                print(f"[burp] REST API pronta em {host}:{port}", flush=True)
                sys.exit(0)
    except Exception:
        pass
    time.sleep(3)

print("[burp] ERRO: REST API nao disponivel apos 5 minutos.", file=sys.stderr)
if log_path.exists():
    print(log_path.read_text(errors="replace")[-8000:], file=sys.stderr)
sys.exit(1)
