#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import socket
import urllib.error
import urllib.request


BASE_URL_DEFAULT = os.getenv("VASM_BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_EMAIL_DEFAULT = os.getenv("VASM_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD_DEFAULT = os.getenv("VASM_ADMIN_PASSWORD", "admin123")
TARGET_DEFAULT = os.getenv("VASM_TARGET", "example.com")
TIMEOUT_SECONDS_DEFAULT = int(os.getenv("VASM_E2E_TIMEOUT", "180"))

BASE_URL = BASE_URL_DEFAULT
ADMIN_EMAIL = ADMIN_EMAIL_DEFAULT
ADMIN_PASSWORD = ADMIN_PASSWORD_DEFAULT
TARGET = TARGET_DEFAULT
TIMEOUT_SECONDS = TIMEOUT_SECONDS_DEFAULT

REQUEST_TIMEOUT_SECONDS = 20
REQUEST_MAX_RETRIES = 4
REQUEST_RETRY_BASE_SECONDS = 0.6


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Valida o fluxo E2E de autenticacao/compliance/scan/report")
    parser.add_argument("--base-url", default=BASE_URL_DEFAULT, help="URL base da API (padrao: variavel VASM_BASE_URL)")
    parser.add_argument("--admin-email", default=ADMIN_EMAIL_DEFAULT, help="Email do admin (padrao: VASM_ADMIN_EMAIL)")
    parser.add_argument("--admin-password", default=ADMIN_PASSWORD_DEFAULT, help="Senha do admin (padrao: VASM_ADMIN_PASSWORD)")
    parser.add_argument("--target", default=TARGET_DEFAULT, help="Alvo do scan/allowlist")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS_DEFAULT, help="Timeout em segundos para conclusao do scan")
    parser.add_argument(
        "--scan-mode",
        default="single",
        choices=["single", "scheduled", "unit"],
        help="Modo de scan. 'unit' e mapeado para 'single' por compatibilidade.",
    )
    return parser.parse_args()


def _request(method: str, path: str, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    last_network_error = ""
    for attempt in range(REQUEST_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            payload = {}
            if raw:
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = {"raw": raw}
            return exc.code, payload
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, socket.timeout, OSError) as exc:
            last_network_error = str(exc)
            if attempt >= REQUEST_MAX_RETRIES:
                break
            backoff = REQUEST_RETRY_BASE_SECONDS * (2 ** attempt)
            time.sleep(backoff)

    raise RuntimeError(f"Falha de rede em {method} {path}: {last_network_error}")


def _assert(cond: bool, message: str):
    if not cond:
        raise RuntimeError(message)


def main():
    global BASE_URL, ADMIN_EMAIL, ADMIN_PASSWORD, TARGET, TIMEOUT_SECONDS

    args = _parse_args()
    BASE_URL = args.base_url.rstrip("/")
    ADMIN_EMAIL = args.admin_email
    ADMIN_PASSWORD = args.admin_password
    TARGET = args.target
    TIMEOUT_SECONDS = max(1, int(args.timeout))
    requested_mode = "single" if args.scan_mode == "unit" else args.scan_mode

    print("[1/6] Login admin")
    status, payload = _request(
        "POST",
        "/api/auth/login",
        {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    _assert(status == 200, f"Falha no login: {status} {payload}")
    token = payload.get("access_token")
    _assert(bool(token), "Token nao retornado no login")

    print("[2/6] Adicionar alvo na allowlist")
    status, payload = _request(
        "POST",
        "/api/policy/allowlist",
        {
            "target_pattern": TARGET,
            "tool_group": "*",
            "is_active": True,
        },
        token,
    )
    _assert(status == 200, f"Falha ao adicionar allowlist: {status} {payload}")

    print("[3/6] Criar scan")
    status, payload = _request(
        "POST",
        "/api/scans",
        {
            "target_query": TARGET,
            "mode": requested_mode,
            "access_group_id": None,
        },
        token,
    )
    _assert(status == 200, f"Falha ao criar scan: {status} {payload}")
    scan_id = payload.get("id")
    _assert(bool(scan_id), "scan_id ausente")

    print("[4/6] Aguardar conclusao")
    started = time.time()
    final_status = None
    while time.time() - started < TIMEOUT_SECONDS:
        try:
            status, current = _request("GET", f"/api/scans/{scan_id}/status", token=token)
        except RuntimeError as exc:
            # Durante scans longos o backend pode reiniciar conexoes; tolera e segue polling.
            print(f"  - aviso: {exc}")
            time.sleep(2)
            continue

        _assert(status == 200, f"Falha ao consultar status: {status} {current}")
        final_status = current.get("status")
        print(f"  - status={final_status} progresso={current.get('mission_progress')}")
        if final_status in {"completed", "failed", "blocked"}:
            break
        time.sleep(3)

    _assert(final_status == "completed", f"Scan nao concluiu com sucesso. status={final_status}")

    print("[5/6] Ler relatorio")
    status, report = _request("GET", f"/api/scans/{scan_id}/report", token=token)
    _assert(status == 200, f"Falha ao obter relatorio: {status} {report}")
    findings = report.get("findings", [])
    _assert(isinstance(findings, list), "Formato de findings invalido")
    _assert(len(findings) > 0, "Relatorio sem findings")

    first = findings[0]
    details = first.get("details", {}) if isinstance(first.get("details"), dict) else {}
    _assert("qwen_recomendacao_pt" in details, "Recomendacao qwen nao persistida")
    _assert("cloudcode_recomendacao_pt" in details, "Recomendacao cloudcode nao persistida")

    print("[6/6] Validacao concluida")
    print(json.dumps({
        "ok": True,
        "scan_id": scan_id,
        "findings": len(findings),
        "first_finding_title": first.get("title"),
    }, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True))
        sys.exit(1)
