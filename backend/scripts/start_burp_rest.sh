#!/bin/sh
set -eu

BURP_JAR_PATH="${BURP_JAR_PATH:-/opt/burpsuite/bin/burpsuite_pro.jar}"
BURP_HOME="${BURP_HOME:-/root/.BurpSuite}"
BURP_API_HOST="${BURP_API_HOST:-127.0.0.1}"
BURP_API_PORT="${BURP_API_PORT:-1337}"
BURP_BROWSER_VERSION="${BURP_BROWSER_VERSION:-146.0.7680.153}"
BURP_LOG_FILE="${BURP_LOG_FILE:-/tmp/burp-rest.log}"
BURP_PID_FILE="${BURP_PID_FILE:-/tmp/burp-rest.pid}"
BURP_USER_CONFIG_TEMPLATE="${BURP_USER_CONFIG_TEMPLATE:-/app/burp/UserConfigPro.json}"

if [ ! -f "$BURP_JAR_PATH" ]; then
	echo "Burp Pro JAR nao encontrado em $BURP_JAR_PATH" >&2
	exit 3
fi

mkdir -p "$BURP_HOME" "/opt/burpsuite/bin/burpbrowser/${BURP_BROWSER_VERSION}"

python3 - <<'PY' "$BURP_HOME" "$BURP_USER_CONFIG_TEMPLATE" "$BURP_API_HOST" "$BURP_API_PORT"
import json
import os
import shutil
import sys

burp_home, template_path, api_host, api_port = sys.argv[1:5]
target_path = os.path.join(burp_home, "UserConfigPro.json")

if not os.path.exists(target_path):
    shutil.copyfile(template_path, target_path)

with open(target_path, encoding="utf-8") as fh:
    config = json.load(fh)

api = config.setdefault("user_options", {}).setdefault("misc", {}).setdefault("api", {})
api["enabled"] = True
api["listen_mode"] = "loopback_only"
api["address"] = api_host
api["port"] = int(api_port)
api["insecure_mode"] = True
api["keys"] = api.get("keys", []) or []

with open(target_path, "w", encoding="utf-8") as fh:
    json.dump(config, fh, ensure_ascii=False, indent=4)
PY

if python3 - <<'PY' "$BURP_API_HOST" "$BURP_API_PORT"
import sys
import urllib.request

host, port = sys.argv[1:3]
url = f"http://{host}:{port}/v0.1/"
try:
    with urllib.request.urlopen(url, timeout=2) as resp:
        if resp.status >= 200:
            print("ready")
            raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
then
	echo "Burp REST API ja esta ativa em ${BURP_API_HOST}:${BURP_API_PORT}"
	exit 0
fi

nohup java -Djava.awt.headless=true -jar "$BURP_JAR_PATH" --use-defaults --data-dir="$BURP_HOME" --user-config-file="$BURP_HOME/UserConfigPro.json" >"$BURP_LOG_FILE" 2>&1 &
echo $! >"$BURP_PID_FILE"

python3 - <<'PY' "$BURP_API_HOST" "$BURP_API_PORT" "$BURP_LOG_FILE"
import pathlib
import sys
import time
import urllib.request

host, port, log_file = sys.argv[1:4]
url = f"http://{host}:{port}/v0.1/"
deadline = time.time() + 90

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            if resp.status >= 200:
                print(f"Burp REST API pronta em {host}:{port}")
                raise SystemExit(0)
    except Exception:
        time.sleep(2)

print("Burp nao iniciou a REST API dentro do timeout.", file=sys.stderr)
path = pathlib.Path(log_file)
if path.exists():
    print(path.read_text(errors="replace")[-4000:], file=sys.stderr)
raise SystemExit(1)
PY