#!/usr/bin/env bash
# validate_flow_mcp_rag_llm_jev.sh — valida ponta a ponta as camadas de
# decisão/execução da plataforma: MCP, RAG, LLM (Ollama) e JEV (jev-local).
#
# Uso:  bash scripts/validate_flow_mcp_rag_llm_jev.sh
#
# Roda os checks HTTP de dentro do container do backend (rede interna do
# compose — mcp_server/kali_rag/jev_local não expõem porta no host).
# Exit code 0 = todos os checks PASS; 1 = ao menos um FAIL.
set -u

BACKEND_CONTAINER="${BACKEND_CONTAINER:-scriptkiddo_backend}"
MCP_URL="${MCP_URL:-http://mcp_server:3000}"
RAG_URL="${RAG_URL:-http://kali_rag:8099}"
OLLAMA_URL="${OLLAMA_URL:-http://ollama:11434}"
JEV_URL="${JEV_URL:-http://jev_local:8097}"

echo "═══════════════════════════════════════════════════════════════"
echo " Validação de fluxo: MCP + RAG + LLM + JEV"
echo " Backend container : ${BACKEND_CONTAINER}"
echo "═══════════════════════════════════════════════════════════════"

if ! docker ps --format '{{.Names}}' | grep -qx "$BACKEND_CONTAINER"; then
  echo "FAIL  backend container '${BACKEND_CONTAINER}' não está rodando"
  exit 1
fi

docker exec -i "$BACKEND_CONTAINER" python - "$MCP_URL" "$RAG_URL" "$OLLAMA_URL" "$JEV_URL" <<'PY'
"""Checks de validação — executado dentro do container do backend."""
from __future__ import annotations

import json
import sys
import time
import urllib.request

MCP_URL, RAG_URL, OLLAMA_URL, JEV_URL = sys.argv[1:5]

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
results: list[tuple[str, str, str]] = []  # (status, layer, message)


def _req(method: str, url: str, payload: dict | None = None, timeout: float = 60.0) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode() or "{}"
            return resp.status, {"json": json.loads(body), "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()[:300]
        return exc.code, {"json": {"raw": body}, "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001 — validação reporta, não levanta
        return 0, {"json": {"error": f"{type(exc).__name__}: {exc}"}, "latency_ms": round((time.monotonic() - started) * 1000, 1)}


def check(status: str, layer: str, message: str) -> None:
    results.append((status, layer, message))
    print(f"{status}  [{layer:<4}] {message}")


# ─────────────────────────────────────────────────────────────
# 1. JEV — motor de decisão tipada
# ─────────────────────────────────────────────────────────────

status, body = _req("GET", f"{JEV_URL}/health", timeout=10)
if status == 200:
    health = body["json"]
    backend_note = "ollama backend ok" if health.get("ollama_ok") else "ollama backend OFF (fallback rule ativo)"
    check(PASS, "JEV", f"/health status={health.get('status')} model={health.get('model')} ({backend_note}, {body['latency_ms']}ms)")
else:
    check(FAIL, "JEV", f"/health HTTP {status} {body['json']}")

jev_payload = {
    "state": {"endpoint": "/api/v1/login", "tech": ["wordpress"], "evidence": "wp-content theme detected"},
    "questions": [
        {"id": "is_api", "kind": "noul", "question": "Is this endpoint part of a programmatic API?",
         "criteria": "Answer yes only if the path looks like a machine-facing API endpoint."},
        {"id": "family", "kind": "choice", "question": "Which testing family fits this target best?",
         "options": ["vuln-injection", "recon-web-crawl", "auth-session"]},
        {"id": "priority", "kind": "score", "question": "How urgent is testing this endpoint?", "scale_max": 5},
    ],
}
status, body = _req("POST", f"{JEV_URL}/v1/systemone", payload=jev_payload, timeout=90)
if status != 200:
    check(FAIL, "JEV", f"/v1/systemone HTTP {status} {body['json']}")
else:
    answers = {a["id"]: a for a in body["json"].get("answers", [])}
    problems = []
    for qid, kind, expected_type in (("is_api", "noul", bool), ("family", "choice", str), ("priority", "score", int)):
        ans = answers.get(qid)
        if not ans:
            problems.append(f"{qid} missing")
            continue
        if ans["kind"] != kind:
            problems.append(f"{qid} kind={ans['kind']}")
        if not isinstance(ans["value"], expected_type):
            problems.append(f"{qid} value type {type(ans['value']).__name__}")
        if not (0.0 <= float(ans.get("probability", -1)) <= 1.0):
            problems.append(f"{qid} probability out of range")
        if ans.get("source") not in ("jev", "rule"):
            problems.append(f"{qid} source={ans.get('source')}")
    if answers.get("family", {}).get("value") not in ("vuln-injection", "recon-web-crawl", "auth-session"):
        problems.append("family value outside declared options")
    if problems:
        check(FAIL, "JEV", f"/v1/systemone fora do contrato: {'; '.join(problems)}")
    else:
        sources = {a['id']: a['source'] for a in answers.values()}
        check(PASS, "JEV", f"/v1/systemone noul/choice/score tipados em {body['latency_ms']}ms (sources={sources})")

# ─────────────────────────────────────────────────────────────
# 2. LLM — Ollama com sampling determinístico
# ─────────────────────────────────────────────────────────────

# Descobre o modelo disponível (não assumir nome fixo)
status, body = _req("GET", f"{OLLAMA_URL}/api/tags", timeout=10)
models = [m.get("name") for m in (body["json"].get("models") or []) if m.get("name")] if status == 200 else []
if not models:
    check(FAIL, "LLM", f"nenhum modelo no Ollama (HTTP {status}) — puxe um modelo (ex.: ollama pull llama3.2:3b)")
    models = [""]
else:
    check(PASS, "LLM", f"modelos disponíveis: {', '.join(models[:5])}")

llm_payload = {
    "model": models[0],
    "prompt": "Reply with exactly one word: the capital of France.",
    "stream": False,
    "options": {"temperature": 0, "top_p": 1, "seed": 424242, "num_predict": 16},
}
status, body = _req("POST", f"{OLLAMA_URL}/api/generate", payload=llm_payload, timeout=120)
if status != 200:
    check(FAIL, "LLM", f"/api/generate HTTP {status} {body['json']}")
else:
    text = str(body["json"].get("response") or "").strip()
    if text:
        check(PASS, "LLM", f"/api/generate respondeu '{text[:60]}' em {body['latency_ms']}ms")
    else:
        check(FAIL, "LLM", "resposta vazia")

status2, body2 = _req("POST", f"{OLLAMA_URL}/api/generate", payload=llm_payload, timeout=120)
if status == 200 and status2 == 200:
    same = body["json"].get("response") == body2["json"].get("response")
    check(PASS if same else FAIL, "LLM",
          f"determinismo (temperature 0 + seed 424242): {'respostas idênticas' if same else 'DIVERGENTES'}")

# ─────────────────────────────────────────────────────────────
# 3. RAG — kali_rag retrieve-and-operate
# ─────────────────────────────────────────────────────────────

rag_payload = {"phase_id": "P09", "tech_stack": ["wordpress", "php"], "limit": 3}
status, body = _req("POST", f"{RAG_URL}/retrieve", payload=rag_payload, timeout=15)
if status != 200:
    check(FAIL, "RAG", f"/retrieve HTTP {status} {body['json']}")
else:
    ctx = body["json"].get("operational_context") or {}
    learnings = ctx.get("learnings") or []
    skills = ctx.get("skill_docs") or []
    budget = body["json"].get("within_budget")
    note = f"{len(learnings)} learnings, {len(skills)} skill docs, {body['latency_ms']}ms"
    if budget is False:
        check(WARN, "RAG", f"/retrieve fora do budget de 100ms: {note}")
    else:
        check(PASS, "RAG", f"/retrieve ok ({note})")

# ─────────────────────────────────────────────────────────────
# 4. MCP — ponte de execução
# ─────────────────────────────────────────────────────────────

status, body = _req("GET", f"{MCP_URL}/health", timeout=10)
if status == 200:
    check(PASS, "MCP", f"/health ok ({body['latency_ms']}ms)")
else:
    check(FAIL, "MCP", f"/health HTTP {status} {body['json']}")

status, body = _req("GET", f"{MCP_URL}/mcp/tools", timeout=10)
if status == 200:
    tools = body["json"].get("tools") or []
    check(PASS, "MCP", f"/mcp/tools catálogo com {len(tools)} ferramentas")
else:
    check(FAIL, "MCP", f"/mcp/tools HTTP {status} {body['json']}")

# Execução real, porém inócua: curl_headers contra o healthz do próprio
# kali_runner (alvo interno, read-only, sem dado de cliente).
mcp_exec = {
    "phase_id": "P05",
    "skill_id": "recon-web-fingerprint",
    "tool_name": "curl_headers",
    "profile": "curl_headers",
    "target": "http://kali_runner:8088/healthz",
    "expected_evidence": ["http_headers_raw"],
    "arguments": {"authorized_scope": ["kali_runner"]},
    "timeout_seconds": 30,
}
status, body = _req("POST", f"{MCP_URL}/mcp/execute", payload=mcp_exec, timeout=90)
if status != 200:
    check(FAIL, "MCP", f"/mcp/execute HTTP {status} {body['json']}")
else:
    result = body["json"]
    exec_status = str(result.get("status") or "")
    if exec_status in ("success", "executed"):
        check(PASS, "MCP", f"/mcp/execute curl_headers executado (exit={result.get('exit_code')}, {result.get('duration_ms')}ms)")
    elif exec_status == "blocked":
        check(WARN, "MCP", f"/mcp/execute bloqueado pelo contrato: {result.get('error')} (guardrail ativo — comportamento correto)")
    else:
        check(WARN, "MCP", f"/mcp/execute status inesperado: {exec_status or str(result)[:120]}")

# ─────────────────────────────────────────────────────────────
# Resumo
# ─────────────────────────────────────────────────────────────

print("───────────────────────────────────────────────────────────────")
fails = sum(1 for s, _, _ in results if s == FAIL)
warns = sum(1 for s, _, _ in results if s == WARN)
print(f"Resumo: {len(results) - fails - warns} PASS, {warns} WARN, {fails} FAIL")
sys.exit(1 if fails else 0)
PY
