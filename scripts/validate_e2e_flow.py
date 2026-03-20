#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("VASM_BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_EMAIL = os.getenv("VASM_ADMIN_EMAIL", "admin@vasm.local")
ADMIN_PASSWORD = os.getenv("VASM_ADMIN_PASSWORD", "admin123")
TARGET = os.getenv("VASM_TARGET", "example.com")
TIMEOUT_SECONDS = int(os.getenv("VASM_E2E_TIMEOUT", "180"))


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

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
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


def _assert(cond: bool, message: str):
    if not cond:
        raise RuntimeError(message)


def main():
    print("[1/7] Login admin")
    status, payload = _request(
        "POST",
        "/api/auth/login",
        {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    _assert(status == 200, f"Falha no login: {status} {payload}")
    token = payload.get("access_token")
    _assert(bool(token), "Token nao retornado no login")

    print("[2/7] Solicitar autorizacao de escopo")
    status, payload = _request(
        "POST",
        "/api/compliance/authorizations/request",
        {
            "scope_ref": f"scan:{TARGET}",
            "ownership_proof": "ticket-e2e-automation",
            "notes": "validacao automatizada e2e",
        },
        token,
    )
    _assert(status == 200, f"Falha ao solicitar autorizacao: {status} {payload}")
    authorization_id = payload.get("authorization_id")
    authorization_code = payload.get("authorization_code")
    _assert(bool(authorization_id and authorization_code), "authorization_id/code ausentes")

    print("[3/7] Aprovar autorizacao")
    status, payload = _request(
        "PUT",
        f"/api/compliance/authorizations/{authorization_id}/approve",
        {"notes": "aprovado para validacao e2e"},
        token,
    )
    _assert(status == 200, f"Falha ao aprovar autorizacao: {status} {payload}")

    print("[4/7] Criar scan")
    status, payload = _request(
        "POST",
        "/api/scans",
        {
            "target_query": TARGET,
            "authorization_code": authorization_code,
            "mode": "single",
            "access_group_id": None,
        },
        token,
    )
    _assert(status == 200, f"Falha ao criar scan: {status} {payload}")
    scan_id = payload.get("id")
    _assert(bool(scan_id), "scan_id ausente")

    print("[5/7] Aguardar conclusao")
    started = time.time()
    final_status = None
    while time.time() - started < TIMEOUT_SECONDS:
        status, current = _request("GET", f"/api/scans/{scan_id}/status", token=token)
        _assert(status == 200, f"Falha ao consultar status: {status} {current}")
        final_status = current.get("status")
        print(f"  - status={final_status} progresso={current.get('mission_progress')}")
        if final_status in {"completed", "failed", "blocked"}:
            break
        time.sleep(3)

    _assert(final_status == "completed", f"Scan nao concluiu com sucesso. status={final_status}")

    print("[6/7] Ler relatorio")
    status, report = _request("GET", f"/api/scans/{scan_id}/report", token=token)
    _assert(status == 200, f"Falha ao obter relatorio: {status} {report}")
    findings = report.get("findings", [])
    _assert(isinstance(findings, list), "Formato de findings invalido")
    _assert(len(findings) > 0, "Relatorio sem findings")

    first = findings[0]
    details = first.get("details", {}) if isinstance(first.get("details"), dict) else {}
    _assert("qwen_recomendacao_pt" in details, "Recomendacao qwen nao persistida")
    _assert("cloudcode_recomendacao_pt" in details, "Recomendacao cloudcode nao persistida")

    print("[7/7] Validacao concluida")
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
