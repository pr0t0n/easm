"""Verifier de Excessive Data Exposure (API3) e Mass Assignment (API6) — read-only.

- Excessive Data Exposure: lê respostas JSON de endpoints de API e detecta CAMPOS
  SENSÍVEIS expostos (password/hash/token/cpf/cartão...). Confirmável só lendo.
- Mass Assignment: a confirmação ativa exigiria ESCRITA (mutação = impacto) →
  NÃO executamos (guardrail). Sinalizamos a POSSIBILIDADE quando a resposta expõe
  campos privilegiados graváveis (role/isAdmin/verified/balance...).

Somente GET; nunca altera nem extrai conteúdo além de nomes de campo p/ evidência.
"""

from __future__ import annotations

import json
import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX_ENDPOINTS = 25

# Campos sensíveis (exposição excessiva).
_SENSITIVE = re.compile(
    r"^(password|passwd|pwd|pass|hash|secret|token|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key|ssn|cpf|cnpj|rg|credit[_-]?card|card[_-]?number|"
    r"cardnumber|cvv|cvc|pin|salt|session[_-]?id|auth)$", re.I)
# Campos privilegiados/graváveis (risco de mass assignment).
_PRIVILEGED = re.compile(
    r"^(role|roles|is[_-]?admin|isadmin|admin|is[_-]?staff|staff|permissions?|"
    r"is[_-]?verified|verified|account[_-]?type|plan|tier|balance|credit|"
    r"is[_-]?active|approved|owner|user[_-]?id)$", re.I)

_API_HINT = re.compile(r"(/api/|/v\d+/|/rest/|/graphql|\.json($|\?))", re.I)


def _candidate_endpoints(urls: list[str]) -> list[str]:
    out, seen = [], set()
    for u in urls:
        if not isinstance(u, str) or not u.startswith("http"):
            continue
        if not _API_HINT.search(u):
            continue
        key = re.sub(r"\d+", "N", u.split("#")[0])
        if key not in seen:
            seen.add(key)
            out.append(u)
        if len(out) >= _MAX_ENDPOINTS:
            break
    return out


def _collect_fields(obj, sens: set, priv: set, depth: int = 0):
    """Coleta nomes de campo sensíveis/privilegiados com valor não-vazio."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            if v not in (None, "", [], {}):
                if _SENSITIVE.match(ks):
                    sens.add(ks)
                elif _PRIVILEGED.match(ks):
                    priv.add(ks)
            _collect_fields(v, sens, priv, depth + 1)
    elif isinstance(obj, list):
        for it in obj[:20]:
            _collect_fields(it, sens, priv, depth + 1)


def verify_api_exposure(endpoints: list[str], auth_headers: dict | None = None) -> dict:
    """Analisa respostas JSON de API por exposição excessiva / risco de mass assignment."""
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    ua = {"User-Agent": "Mozilla/5.0 (easm-api-probe)", "Accept": "application/json", **auth}
    result = {"confirmed": False, "findings": [], "attempts": 0, "safe_proof": True}
    cands = _candidate_endpoints(endpoints)
    if not cands:
        result["note"] = "Nenhum endpoint de API/JSON para analisar."
        return result

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            for url in cands:
                result["attempts"] += 1
                try:
                    r = c.get(url, headers=ua)
                except Exception:
                    continue
                ctype = r.headers.get("content-type", "")
                body = r.text or ""
                if "json" not in ctype.lower() and not body.lstrip().startswith(("{", "[")):
                    continue
                try:
                    data = r.json()
                except Exception:
                    continue
                sens: set = set()
                priv: set = set()
                _collect_fields(data, sens, priv)
                if sens:
                    hi = any(re.match(r"^(password|passwd|pwd|hash|secret|token|private|ssn|cpf|card|cvv)", s, re.I) for s in sens)
                    result["confirmed"] = True
                    result["findings"].append({
                        "endpoint": url, "vuln_family": "excessive_data_exposure",
                        "severity": "high" if hi else "medium",
                        "evidence": f"Resposta de API expõe campos sensíveis: {', '.join(sorted(sens)[:8])}.",
                    })
                if priv:
                    result["findings"].append({
                        "endpoint": url, "vuln_family": "mass_assignment",
                        "severity": "medium",
                        "evidence": (f"Campos privilegiados/graváveis expostos: {', '.join(sorted(priv)[:8])}. "
                                     f"Mass assignment POSSÍVEL (escrita não executada — guardrail)."),
                        "possibility": True,
                    })
    except Exception as exc:
        result["note"] = f"erro: {type(exc).__name__}"
        return result

    if not result["findings"]:
        result["note"] = f"{result['attempts']} endpoints analisados — sem exposição sensível/privilegiada."
    return result


def run_api_probe_for_scan(db, job) -> dict:
    from app.models.models import Finding

    state = dict(getattr(job, "state_data", None) or {})
    try:
        from app.services.scan_intelligence import auth_headers_from_state
        auth = auth_headers_from_state(state) or {}
    except Exception:
        auth = {}
    urls = list(state.get("discovered_endpoints") or [])
    try:
        for (det,) in db.query(Finding.details).filter(Finding.scan_job_id == job.id).limit(800).all():
            if isinstance(det, dict):
                u = det.get("matched_at") or det.get("url")
                if u:
                    urls.append(str(u))
    except Exception:
        pass

    res = verify_api_exposure(urls, auth)
    created = 0
    if res.get("findings"):
        fam_title = {"excessive_data_exposure": "Exposição Excessiva de Dados (API)",
                     "mass_assignment": "Mass Assignment — campos privilegiados expostos (API)"}
        raw = [{
            "title": f"{fam_title.get(f['vuln_family'], 'API')}: {f['endpoint'][:100]}",
            "severity": f.get("severity", "medium"),
            "risk_score": 8 if f.get("severity") == "high" else 5,
            "details": {
                "tool": "api_probe", "asset": f.get("endpoint"), "matched_at": f.get("endpoint"),
                "evidence": f.get("evidence"), "owasp_category": "API3:2023 / API6:2023",
                "verification_status": "confirmed" if not f.get("possibility") else "candidate",
                "vuln_family": f["vuln_family"],
                "discovery_method": "análise read-only da resposta JSON da API",
            },
        } for f in res["findings"]]
        try:
            from app.services.findings_extractor import persist_finding_dicts
            created = persist_finding_dicts(db, job, raw, default_tool="api_probe",
                                            default_target=str(getattr(job, "target_query", "") or ""),
                                            source_item=None)
        except Exception:
            pass
    res["findings_created"] = created
    return res
