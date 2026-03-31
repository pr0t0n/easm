#!/bin/sh
set -eu

REAL_CLI="${BURP_REAL_CLI:-/usr/local/bin/burp-api-cli}"
START_SCRIPT="${BURP_START_SCRIPT:-/usr/local/bin/start-burp-rest}"
BURP_API_HOST="${BURP_API_HOST:-burp_rest}"
BURP_API_PORT="${BURP_API_PORT:-1337}"
BURP_API_KEY="${BURP_API_KEY:-}"
BURP_SCAN_TIMEOUT="${BURP_SCAN_TIMEOUT:-1800}"
BURP_PAUSE_MAX_RETRIES="${BURP_PAUSE_MAX_RETRIES:-10}"
BURP_PREFLIGHT_CONNECT_TIMEOUT="${BURP_PREFLIGHT_CONNECT_TIMEOUT:-6}"

api_is_alive() {
    python3 - <<'PY' "$BURP_API_HOST" "$BURP_API_PORT" "$BURP_API_KEY"
import sys
import urllib.request

host, port, api_key = sys.argv[1:4]
if api_key:
    url = f"http://{host}:{port}/{api_key}/v0.1/"
else:
    url = f"http://{host}:{port}/v0.1/"

try:
    with urllib.request.urlopen(url, timeout=3) as response:
        raise SystemExit(0 if int(response.status) >= 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

ensure_api() {
    # Tenta até 3 vezes com intervalo de 5s antes de desistir (burp_rest pode demorar a ficar healthy)
    _retries=0
    while [ "$_retries" -lt 3 ]; do
        if api_is_alive; then
            return 0
        fi
        _retries=$((_retries + 1))
        [ "$_retries" -lt 3 ] && sleep 5
    done

    case "$BURP_API_HOST" in
        127.0.0.1|localhost|0.0.0.0)
            ;;
        *)
            echo "Burp REST API indisponivel em ${BURP_API_HOST}:${BURP_API_PORT} apos 3 tentativas; host remoto configurado, nao sera iniciado Burp local." >&2
            exit 1
            ;;
    esac

    "$START_SCRIPT" >/tmp/burp-start-wrapper.log 2>&1 || {
        cat /tmp/burp-start-wrapper.log >&2 || true
        exit 1
    }
}

poll_scan_status() {
    python3 - <<'PY' "$1" "$BURP_SCAN_TIMEOUT" "$BURP_API_HOST" "$BURP_API_PORT" "$BURP_API_KEY"
import json
import sys
import time
import urllib.request

scan_id, timeout_s, host, port, api_key = sys.argv[1:6]
timeout_s = int(timeout_s)

if api_key:
    url = f"http://{host}:{port}/{api_key}/v0.1/scan/{scan_id}"
else:
    url = f"http://{host}:{port}/v0.1/scan/{scan_id}"

deadline = time.time() + timeout_s
last_status = "unknown"

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace") or "{}")
        metrics = payload.get("scan_metrics") or {}
        last_status = str(metrics.get("scan_status") or payload.get("scan_status") or "unknown").strip().lower()
        print(last_status)
        if last_status == "paused":
            raise SystemExit(2)
        if last_status in {"succeeded", "failed", "cancelled"}:
            raise SystemExit(0)
    except Exception:
        print(last_status)
    time.sleep(5)

print(last_status)
raise SystemExit(1)
PY
}

extract_scan_id() {
    python3 - <<'PY' "$1"
import re
import sys

text = sys.argv[1]
patterns = [
    r"\bID\s+(\d+)\b",
    r"/scan/(\d+)\b",
    r"\bscan id[:\s]+(\d+)\b",
]
for pattern in patterns:
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        print(match.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

run_real_cli() {
    if [ -n "$BURP_API_KEY" ]; then
        "$REAL_CLI" -t "$BURP_API_HOST" -p "$BURP_API_PORT" -k "$BURP_API_KEY" "$@"
    else
        "$REAL_CLI" -t "$BURP_API_HOST" -p "$BURP_API_PORT" "$@"
    fi
}

alternate_seed_url() {
    case "$1" in
        http://*)
            printf '%s\n' "https://${1#http://}"
            ;;
        https://*)
            printf '%s\n' "http://${1#https://}"
            ;;
        *)
            printf '%s\n' ""
            ;;
    esac
}

preflight_target_reachable() {
    python3 - <<'PY' "$1" "$BURP_PREFLIGHT_CONNECT_TIMEOUT"
import socket
import sys
from urllib.parse import urlparse

raw_url = str(sys.argv[1] or "").strip()
timeout_s = float(sys.argv[2] or 6)

if not raw_url:
    raise SystemExit(2)

if "://" not in raw_url:
    raw_url = f"http://{raw_url}"

parsed = urlparse(raw_url)
host = parsed.hostname
if not host:
    raise SystemExit(2)

if parsed.port:
    port = int(parsed.port)
else:
    port = 443 if (parsed.scheme or "").lower() == "https" else 80

try:
    with socket.create_connection((host, port), timeout=timeout_s):
        raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
}

legacy_scan() {
    url=""
    output_file=""
    config_file=""

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --url|-u)
                url="${2:-}"
                shift 2
                ;;
            --output-file|-r)
                output_file="${2:-}"
                shift 2
                ;;
            --config-file|-cf)
                config_file="${2:-}"
                shift 2
                ;;
            --format|-f|--license-key|-k)
                shift 2
                ;;
            --active|-a|--passive|-p|--no-spider)
                shift 1
                ;;
            *)
                shift 1
                ;;
        esac
    done

    if [ -z "$url" ]; then
        echo "--url e obrigatorio" >&2
        exit 2
    fi

    if ! preflight_target_reachable "$url"; then
        echo "Seed URL inacessivel no preflight (host/porta indisponiveis): $url" >&2
        exit 3
    fi

    ensure_api

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT INT TERM

    set +e
    if [ -n "$config_file" ]; then
        start_output="$(run_real_cli -s "$url" -cf "$config_file" 2>&1)"
        start_rc=$?
    else
        start_output="$(run_real_cli -s "$url" 2>&1)"
        start_rc=$?
    fi
    set -e

    printf '%s\n' "$start_output" >&2
    if [ "$start_rc" -ne 0 ]; then
        exit "$start_rc"
    fi

    scan_id="$(extract_scan_id "$start_output")" || {
        echo "Nao foi possivel identificar o scan ID retornado pelo burp-api-cli." >&2
        exit 1
    }

    attempts=0
    last_status="unknown"
    alternate_url="$(alternate_seed_url "$url")"
    while [ "$attempts" -lt "$BURP_PAUSE_MAX_RETRIES" ]; do
        attempts=$((attempts + 1))

        set +e
        poll_output="$(poll_scan_status "$scan_id" 2>&1)"
        poll_rc=$?
        set -e

        last_status="$(printf '%s\n' "$poll_output" | tail -n 1 | tr -d '\r' | tr '[:upper:]' '[:lower:]')"

        if [ "$poll_rc" -eq 0 ]; then
            break
        fi

        if [ "$poll_rc" -eq 2 ] || [ "$last_status" = "paused" ]; then
            echo "Scan Burp ${scan_id} pausado. Tentando reativar (${attempts}/${BURP_PAUSE_MAX_RETRIES})..." >&2

            retry_url="$url"
            if [ -n "$alternate_url" ]; then
                retry_url="$alternate_url"
                echo "Tentando esquema alternativo para seed URL: $retry_url" >&2
            fi

            set +e
            if [ -n "$config_file" ]; then
                restart_output="$(run_real_cli -s "$retry_url" -cf "$config_file" 2>&1)"
                restart_rc=$?
            else
                restart_output="$(run_real_cli -s "$retry_url" 2>&1)"
                restart_rc=$?
            fi
            set -e

            printf '%s\n' "$restart_output" >&2
            if [ "$restart_rc" -ne 0 ]; then
                continue
            fi

            new_scan_id="$(extract_scan_id "$restart_output")" || true
            if [ -n "$new_scan_id" ]; then
                scan_id="$new_scan_id"
                url="$retry_url"
                alternate_url="$(alternate_seed_url "$url")"
            fi
            continue
        fi

        echo "Timeout aguardando scan Burp ${scan_id}. Ultimo status: ${last_status}" >&2
        exit 1
    done

    if [ "$last_status" != "succeeded" ]; then
        echo "Scan Burp ${scan_id} terminou com status ${last_status}." >&2
        exit 1
    fi

    set +e
    run_real_cli -S "$scan_id" -e "$tmpdir" >/tmp/burp-export-wrapper.log 2>&1
    export_rc=$?
    set -e
    if [ "$export_rc" -ne 0 ]; then
        cat /tmp/burp-export-wrapper.log >&2 || true
        exit "$export_rc"
    fi

    json_file="$tmpdir/Burp_export.json"
    if [ ! -f "$json_file" ]; then
        json_file="$(find "$tmpdir" -maxdepth 1 -name '*.json' | head -n 1)"
    fi

    if [ -z "$json_file" ] || [ ! -f "$json_file" ]; then
        echo "Export do Burp finalizado, mas nenhum JSON foi encontrado em $tmpdir" >&2
        exit 1
    fi

    if [ -n "$output_file" ]; then
        cp "$json_file" "$output_file"
        echo "[+] JSON salvo em: $output_file"
    else
        cat "$json_file"
    fi
}

if [ ! -x "$REAL_CLI" ]; then
    echo "Cliente real nao encontrado em $REAL_CLI" >&2
    exit 1
fi

if [ "$#" -eq 0 ]; then
    exec "$REAL_CLI" -h
fi

case "$1" in
    --version|version|-V)
        exec "$REAL_CLI" -V
        ;;
    scan)
        shift
        legacy_scan "$@"
        ;;
    *)
        ensure_api
        exec "$REAL_CLI" "$@"
        ;;
esac
