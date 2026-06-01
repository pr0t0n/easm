"""Verifier ativo de NoSQL Injection (MongoDB-style) — read-only, seguro.

Testa parâmetros com OPERADORES NoSQL inócuos ([$ne], [$gt], [$regex]) e confirma
por:
  - SINAL DE ERRO do banco (MongoError/CastError/BSON/$where...) → forte; ou
  - RESPOSTA DIFERENCIAL (o operador é interpretado como query → corpo muda
    significativamente vs baseline).

Disciplina (igual rce_proof/bola_probe): prova com evidência; nunca extrai dados,
nunca altera. Se nada diferencia, retorna refutado honestamente.
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX_ENDPOINTS = 20

# Assinaturas de erro de NoSQL/Mongo na resposta (prova forte).
_ERROR_RE = re.compile(
    r"(MongoError|Mongo\s*Server|BSONError|CastError|E11000|\$where|"
    r"unexpected token.*\$|querySelector|MongooseError|unterminated)", re.I)

# Operadores benignos (não destrutivos) para teste diferencial.
_OPERATORS = ["[$ne]", "[$gt]", "[$regex]"]
_QUERY_PARAM = re.compile(r"([?&])([A-Za-z_][\w\-]*)=([^&#]*)")


def _inject_operator(url: str, op: str) -> str | None:
    """Transforma o 1º param ?p=v em ?p[$ne]=v (injeção de operador)."""
    m = _QUERY_PARAM.search(url)
    if not m:
        return None
    sep, name, val = m.group(1), m.group(2), m.group(3)
    return url[:m.start()] + f"{sep}{name}{op}={val}" + url[m.end():]


def _candidate_endpoints(urls: list[str]) -> list[str]:
    out, seen = [], set()
    _static = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|woff2?|ico|map|webp)(?:\?|$)", re.I)
    for u in urls:
        if not isinstance(u, str) or not u.startswith("http") or "=" not in u:
            continue
        if not _QUERY_PARAM.search(u) or _static.search(u):
            continue
        key = re.sub(r"=[^&#]*", "=V", u)
        if key not in seen:
            seen.add(key)
            out.append(u)
        if len(out) >= _MAX_ENDPOINTS:
            break
    return out


def verify_nosql(endpoints: list[str], auth_headers: dict | None = None) -> dict:
    """Testa NoSQLi nos endpoints com parâmetro. Read-only."""
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    ua = {"User-Agent": "Mozilla/5.0 (easm-nosql-probe)", **auth}
    result = {"confirmed": False, "findings": [], "attempts": 0, "safe_proof": True}
    cands = _candidate_endpoints(endpoints)
    if not cands:
        result["note"] = "Nenhum endpoint com parâmetro para testar NoSQLi."
        return result

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            for url in cands:
                try:
                    base = c.get(url, headers=ua)
                except Exception:
                    continue
                base_len = len(base.text or "")
                for op in _OPERATORS:
                    inj = _inject_operator(url, op)
                    if not inj:
                        break
                    result["attempts"] += 1
                    try:
                        r = c.get(inj, headers=ua)
                    except Exception:
                        continue
                    body = r.text or ""
                    # 1) erro de banco = prova forte
                    em = _ERROR_RE.search(body)
                    if em:
                        result["confirmed"] = True
                        result["findings"].append({
                            "endpoint": url, "payload": inj,
                            "evidence": f"Operador {op} disparou erro NoSQL: …{body[max(0,em.start()-20):em.end()+40]}…",
                            "severity": "high", "vuln_family": "nosql_injection", "kind": "error-based",
                        })
                        break
                    # 2) diferencial forte (operador interpretado como query)
                    if r.status_code == 200 and base.status_code == 200 and base_len > 0:
                        if abs(len(body) - base_len) > max(800, base_len * 0.6):
                            result["findings"].append({
                                "endpoint": url, "payload": inj,
                                "evidence": (f"Operador {op}: resposta diferencial "
                                             f"(base={base_len} → inj={len(body)} bytes) — operador "
                                             f"interpretado como query NoSQL."),
                                "severity": "medium", "vuln_family": "nosql_injection",
                                "kind": "differential",
                            })
                            result["confirmed"] = True
                            break
    except Exception as exc:
        result["note"] = f"erro: {type(exc).__name__}"
        return result

    if not result["confirmed"]:
        result["note"] = f"{result['attempts']} testes — sem sinal de NoSQLi. Não comprovado."
    return result


def run_nosql_for_scan(db, job) -> dict:
    """Coleta endpoints com parâmetro descobertos + roda o probe + persiste."""
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

    res = verify_nosql(urls, auth)
    created = 0
    if res.get("findings"):
        raw = [{
            "title": f"NoSQL Injection ({f.get('kind')}): {f['endpoint'][:110]}",
            "severity": f.get("severity", "high"), "risk_score": 8 if f.get("severity") == "high" else 5,
            "details": {
                "tool": "nosql_probe", "asset": f.get("endpoint"), "matched_at": f.get("endpoint"),
                "payload": f.get("payload"), "evidence": f.get("evidence"),
                "owasp_category": "A03:2021 Injection", "verification_status": "confirmed",
                "vuln_family": "nosql_injection",
                "discovery_method": "injeção de operador NoSQL ([$ne]/[$gt]/[$regex]) read-only",
            },
        } for f in res["findings"]]
        try:
            from app.services.findings_extractor import persist_finding_dicts
            created = persist_finding_dicts(db, job, raw, default_tool="nosql_probe",
                                            default_target=str(getattr(job, "target_query", "") or ""),
                                            source_item=None)
        except Exception:
            pass
    res["findings_created"] = created
    return res
