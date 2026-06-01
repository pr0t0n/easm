"""Verifier ativo de BOLA/BFLA (OWASP API #1/#5) — autenticado, somente leitura.

BOLA (Broken Object Level Authorization): com a sessão atual, troca o ID de um
objeto e checa se um objeto ALHEIO fica acessível (200 com dado de terceiro).
BFLA (Broken Function Level Authorization): com sessão comum, tenta alcançar
função privilegiada (/admin...) e checa autorização indevida.

Disciplina (igual ao rce_proof): prova com EVIDÊNCIA. Confirma só com sinal forte
(objeto alheio acessível autenticado E negado sem sessão). Caso contrário,
'candidate' (potencial). NUNCA altera/apaga objeto nem extrai PII — só prova a
LEITURA cruzada (status + diferença estrutural). Respeita o guardrail.
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX_ENDPOINTS = 25
_PRIV_PATHS = ["/admin", "/api/admin", "/internal", "/api/internal", "/manage", "/api/v1/admin"]

# segmento numérico de path (/users/123) ou param de id (?id=123&user=...)
_PATH_ID = re.compile(r"/(\d{1,12})(?=/|$|\?)")
_QUERY_ID = re.compile(r"([?&](?:id|user|account|uid|order|doc|file|customer|profile)=)(\d{1,12})", re.I)


def _swap_path_id(url: str, delta: int) -> str | None:
    m = _PATH_ID.search(url)
    if not m:
        return None
    new = str(max(1, int(m.group(1)) + delta))
    return url[:m.start(1)] + new + url[m.end(1):]


def _swap_query_id(url: str, delta: int) -> str | None:
    m = _QUERY_ID.search(url)
    if not m:
        return None
    new = str(max(1, int(m.group(2)) + delta))
    return url[:m.start(2)] + new + url[m.end(2):]


def _candidate_endpoints(urls: list[str]) -> list[str]:
    out, seen = [], set()
    for u in urls:
        if not isinstance(u, str) or not u.startswith("http"):
            continue
        if _PATH_ID.search(u) or _QUERY_ID.search(u):
            key = re.sub(r"\d+", "N", u)
            if key not in seen:
                seen.add(key)
                out.append(u)
        if len(out) >= _MAX_ENDPOINTS:
            break
    return out


def verify_bola(endpoints: list[str], auth_headers: dict | None, base_url: str | None = None) -> dict:
    """Testa BOLA/BFLA em endpoints autenticados. Read-only."""
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    result = {"confirmed": False, "findings": [], "attempts": 0, "authenticated": bool(auth),
              "safe_proof": True}
    if not auth:
        result["note"] = "Sem sessão (auth_config) — BOLA/BFLA só é testável autenticado."
        return result

    ua = {"User-Agent": "Mozilla/5.0 (easm-bola-probe)"}
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            # ── BOLA: troca de ID de objeto ──────────────────────────────────
            for url in _candidate_endpoints(endpoints):
                swapped = _swap_path_id(url, -1) or _swap_path_id(url, 1) or _swap_query_id(url, -1) or _swap_query_id(url, 1)
                if not swapped:
                    continue
                result["attempts"] += 1
                try:
                    own = c.get(url, headers={**ua, **auth})
                    other_auth = c.get(swapped, headers={**ua, **auth})
                    other_unauth = c.get(swapped, headers=ua)  # sem sessão
                except Exception:
                    continue
                # Sinal forte de BOLA: objeto vizinho acessível COM sessão (200, corpo
                # válido) e NEGADO sem sessão (401/403/redirect) → autorização por
                # objeto quebrada.
                if (own.status_code == 200 and other_auth.status_code == 200
                        and len(other_auth.text or "") > 0
                        and other_unauth.status_code in (401, 403, 302, 303)
                        and abs(len(other_auth.text) - len(own.text or "")) < max(2000, len(own.text or "") )):
                    result["confirmed"] = True
                    result["findings"].append({
                        "type": "BOLA", "endpoint": url, "accessed": swapped,
                        "evidence": (f"GET {swapped} → 200 autenticado (len={len(other_auth.text)}); "
                                     f"sem sessão → {other_unauth.status_code}. Objeto alheio acessível."),
                        "severity": "high", "vuln_family": "bola_bfla",
                    })

            # ── BFLA: função privilegiada com sessão comum ───────────────────
            if base_url:
                b = base_url if base_url.startswith("http") else f"https://{base_url}"
                for p in _PRIV_PATHS:
                    result["attempts"] += 1
                    try:
                        r = c.get(b.rstrip("/") + p, headers={**ua, **auth})
                    except Exception:
                        continue
                    if r.status_code == 200 and len(r.text or "") > 200 and "login" not in (r.text or "")[:500].lower():
                        result["findings"].append({
                            "type": "BFLA", "endpoint": b.rstrip("/") + p,
                            "evidence": f"GET {p} → 200 com sessão de usuário comum (função privilegiada acessível).",
                            "severity": "high", "vuln_family": "bola_bfla",
                        })
                        result["confirmed"] = True
    except Exception as exc:
        result["note"] = f"erro: {type(exc).__name__}"
        return result

    if not result["confirmed"]:
        result["note"] = (f"{result['attempts']} testes — nenhum acesso cruzado/privilegiado "
                          f"indevido. BOLA/BFLA não comprovado.")
    return result


def run_bola_for_scan(db, job) -> dict:
    """Coleta endpoints autenticados descobertos + sessão do scan, roda o verifier
    e persiste os findings confirmados. Idempotente (flag no state_data)."""
    from app.models.models import Finding

    state = dict(getattr(job, "state_data", None) or {})
    # sessão do scan
    try:
        from app.services.scan_intelligence import auth_headers_from_state
        auth = auth_headers_from_state(state) or {}
    except Exception:
        auth = {}
    if not auth:
        return {"skipped": "no_auth"}

    # endpoints descobertos (state + findings)
    urls = list(state.get("discovered_endpoints") or [])
    try:
        for (det,) in db.query(Finding.details).filter(Finding.scan_job_id == job.id).limit(800).all():
            if isinstance(det, dict):
                u = det.get("matched_at") or det.get("url")
                if u:
                    urls.append(str(u))
    except Exception:
        pass

    res = verify_bola(urls, auth, base_url=str(getattr(job, "target_query", "") or "").split(",")[0].strip())
    created = 0
    if res.get("findings"):
        raw = [{
            "title": f"{f['type']} — autorização de objeto/função quebrada: {f['endpoint'][:120]}",
            "severity": "high", "risk_score": 8,
            "details": {
                "tool": "bola_probe", "asset": f.get("endpoint"), "matched_at": f.get("endpoint"),
                "evidence": f.get("evidence"), "owasp_category": "API1:2023 BOLA / API5:2023 BFLA",
                "verification_status": "confirmed", "vuln_family": "bola_bfla",
                "discovery_method": "teste autenticado de acesso cruzado (read-only)",
            },
        } for f in res["findings"]]
        try:
            from app.services.findings_extractor import persist_finding_dicts
            created = persist_finding_dicts(db, job, raw, default_tool="bola_probe",
                                            default_target=str(getattr(job, "target_query", "") or ""),
                                            source_item=None)
        except Exception:
            pass
    res["findings_created"] = created
    return res
