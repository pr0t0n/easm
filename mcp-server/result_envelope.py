"""Result envelope v1 — contrato padronizado de resultado de ferramenta.

Fase 2 do docs/LANGGRAPH_BRAIN_PLAN.md: o MCP deixa de ser proxy puro e vira
camada de contrato de resultado. O envelope é Puro-Python (stdlib apenas) para
ser testável em qualquer lugar e servir tanto o MCP quanto consumidores legados.

Design:
  - findings_raw: extração determinística e CONSERVADORA por família de
    ferramenta. Família sem extrator retorna [] — nunca inventa achado
    (classe de bug vista em produção: contadores de "findings" por ferramenta
    contando ruído de stdout).
  - quality_flags: sinais de qualidade do resultado (vazio, timeout, saída de
    erro, ruído alto) para o consumidor decidir peso da evidência.
  - compare_evidence: veredito de re-teste (confirmed|not_reproducible|
    inconclusive) comparando sinais esperados com stdout/parsed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

ENVELOPE_VERSION = "result-envelope/v1"

NOISE_STDOUT_BYTES = 500_000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── findings_raw por família (conservador, determinístico) ───────────────────

def _findings_nuclei(parsed: Any, stdout: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = parsed if isinstance(parsed, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        template = str(row.get("template-id") or row.get("template") or "").strip()
        if not template:
            continue
        out.append({
            "id": template,
            "severity": str(row.get("severity") or "unknown").lower(),
            "host": str(row.get("host") or ""),
            "matched": str(row.get("matched-at") or row.get("matched") or "")[:300],
            "family": "nuclei",
        })
    return out


def _findings_ffuf(parsed: Any, stdout: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = parsed if isinstance(parsed, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = int(row.get("status") or 0)
        if status in (0, 404):
            continue
        url = str(row.get("url") or "")
        if not url:
            continue
        out.append({
            "id": f"ffuf:{status}",
            "severity": "info",
            "host": url,
            "length": int(row.get("length") or 0),
            "family": "ffuf",
        })
    return out


def _findings_httpx(parsed: Any, stdout: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = parsed if isinstance(parsed, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        out.append({
            "id": f"httpx:{row.get('status_code') or 'unknown'}",
            "severity": "info",
            "host": url,
            "title": str(row.get("title") or "")[:200],
            "tech": [str(t) for t in (row.get("tech") or [])][:8] if isinstance(row.get("tech"), list) else [],
            "family": "httpx",
        })
    return out


def _findings_sqlmap(parsed: Any, stdout: str) -> list[dict[str, Any]]:
    """Só confirma injeção quando o sqlmap mesmo declara vulnerabilidade."""
    out: list[dict[str, Any]] = []
    text = stdout or ""
    if "is vulnerable" not in text and "injectable" not in text.lower():
        return out
    parameter = ""
    for line in text.splitlines():
        if line.strip().startswith("Parameter:"):
            parameter = line.split(":", 1)[1].strip()
            break
    out.append({
        "id": f"sqlmap:{parameter or 'unknown'}",
        "severity": "high",
        "host": parameter,
        "family": "sqlmap",
    })
    return out


_FAMILY_EXTRACTORS = {
    "nuclei": _findings_nuclei,
    "ffuf": _findings_ffuf,
    "ffuf-files": _findings_ffuf,
    "ffuf-params": _findings_ffuf,
    "ffuf-values": _findings_ffuf,
    "ffuf-post": _findings_ffuf,
    "httpx": _findings_httpx,
    "sqlmap": _findings_sqlmap,
}


def _quality_flags(status: str, return_code: int | None, stdout: str, allowed_return_codes: list[int] | None) -> list[str]:
    flags: list[str] = []
    if status == "timeout":
        flags.append("timeout")
    if status == "done" and not (stdout or "").strip():
        flags.append("empty_output")
    allowed = allowed_return_codes if allowed_return_codes else [0]
    if return_code is not None and return_code not in allowed:
        flags.append("error_exit")
    if len(stdout or "") > NOISE_STDOUT_BYTES:
        flags.append("high_noise")
    return flags


def build_envelope(
    *,
    tool: str,
    target: str,
    status: str,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    parsed: Any = None,
    command: str = "",
    workdir: str = "",
    duration_seconds: float | None = None,
    allowed_return_codes: list[int] | None = None,
    job_id: str = "",
) -> dict[str, Any]:
    """Monta o envelope v1 a partir do resultado cru do runner."""
    tool_key = str(tool or "").strip().lower()
    extractor = _FAMILY_EXTRACTORS.get(tool_key)
    findings_raw = extractor(parsed, stdout) if extractor else []
    return {
        "envelope_version": ENVELOPE_VERSION,
        "job_id": job_id,
        "tool": tool_key,
        "target": target,
        "status": status,
        "return_code": return_code,
        "duration_seconds": duration_seconds,
        "command": command,
        "parsed": parsed,
        "findings_raw": findings_raw,
        "findings_raw_count": len(findings_raw),
        "evidence_refs": {"workdir": workdir} if workdir else {},
        "quality_flags": _quality_flags(status, return_code, stdout, allowed_return_codes),
        "stderr_tail": (stderr or "")[-2000:],
        "normalized_at": _utc_now(),
    }


# ── Veredito de re-teste ──────────────────────────────────────────────────────

VERDICT_CONFIRMED = "confirmed"
VERDICT_NOT_REPRODUCIBLE = "not_reproducible"
VERDICT_INCONCLUSIVE = "inconclusive"


def compare_evidence(
    *,
    evidence_expected: list[str],
    status: str,
    stdout: str = "",
    parsed: Any = None,
) -> dict[str, Any]:
    """Compara sinais esperados com o resultado re-executado.

    - job não terminou 'done'            -> inconclusive
    - todos os sinais presentes          -> confirmed
    - algum presente                     -> inconclusive
    - nenhum                             -> not_reproducible
    """
    expected = [str(e).strip() for e in (evidence_expected or []) if str(e).strip()]
    if status != "done":
        return {"verdict": VERDICT_INCONCLUSIVE, "matched": [], "missing": expected,
                "reason": f"job status={status}"}
    if not expected:
        return {"verdict": VERDICT_INCONCLUSIVE, "matched": [], "missing": [],
                "reason": "sem sinais de evidência esperados"}
    haystacks = [stdout or ""]
    try:
        haystacks.append(json.dumps(parsed, ensure_ascii=False) if parsed is not None else "")
    except Exception:
        pass
    haystack = "\n".join(haystacks).lower()
    matched = [e for e in expected if e.lower() in haystack]
    missing = [e for e in expected if e.lower() not in haystack]
    if not missing:
        verdict = VERDICT_CONFIRMED
        reason = "todos os sinais presentes"
    elif matched:
        verdict = VERDICT_INCONCLUSIVE
        reason = f"sinais parciais ({len(matched)}/{len(expected)})"
    else:
        verdict = VERDICT_NOT_REPRODUCIBLE
        reason = "nenhum sinal presente"
    return {"verdict": verdict, "matched": matched, "missing": missing, "reason": reason}
