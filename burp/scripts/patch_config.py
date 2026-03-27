#!/usr/bin/env python3
"""Aplica configuração da REST API no UserConfigPro.json do Burp."""
import json
import os
import shutil

burp_home = os.environ.get("BURP_HOME", "/root/.BurpSuite")
template  = "/opt/burp/config/UserConfigPro.json"
target    = os.path.join(burp_home, "UserConfigPro.json")
api_host  = os.environ.get("BURP_API_HOST", "0.0.0.0")
api_port  = int(os.environ.get("BURP_API_PORT", "1337"))

os.makedirs(burp_home, exist_ok=True)

if not os.path.exists(target):
    shutil.copyfile(template, target)

with open(target, encoding="utf-8") as f:
    cfg = json.load(f)

api = cfg.setdefault("user_options", {}).setdefault("misc", {}).setdefault("api", {})
api.update(
    enabled=True,
    listen_mode="all_interfaces",
    address=api_host,
    port=api_port,
    insecure_mode=True,
    keys=api.get("keys", []) or [],
)

with open(target, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=4)

print(f"[burp] UserConfigPro.json configurado: REST API em {api_host}:{api_port}", flush=True)
