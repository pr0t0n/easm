"""Análise estática de JavaScript (recon de aplicação) — read-only.

Baixa os arquivos .js da aplicação e extrai:
  - ENDPOINTS / rotas de API (fetch/axios/XHR/strings) → realimentam o teste;
  - PARÂMETROS e nomes de função (entender a lógica da app);
  - SINKS perigosos: eval, new Function, setTimeout(string), innerHTML,
    document.write, insertAdjacentHTML (risco de DOM XSS / eval);
  - PROTOTYPE POLLUTION sinks: __proto__, Object.assign, merge/extend recursivo;
  - SEGREDOS hardcoded (reusa os padrões do page_analyzer).

Tudo GET/leitura — nenhum impacto. Endpoints novos são reinjetados via
endpoint_discovery (fecha o loop).
"""

from __future__ import annotations

import re

import httpx

from app.services.page_analyzer import _SECRET_PATTERNS, _host_of, _root_domain

_TIMEOUT = httpx.Timeout(connect=6.0, read=15.0, write=6.0, pool=6.0)
_MAX_JS = 30
_MAX_BYTES = 1_500_000

_ENDPOINT_RES = [
    re.compile(r"""['"](/(?:api|rest|graphql|v\d+|admin|internal|service|auth|user|account)[^'"\s]{0,120})['"]"""),
    re.compile(r"""(?:fetch|axios(?:\.\w+)?)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""(?:url|endpoint|baseURL|path|uri)\s*[:=]\s*['"](/[^'"]+|https?://[^'"]+)['"]""", re.I),
]
_EVAL_SINKS = [
    ("eval()", re.compile(r"\beval\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("setTimeout(string)", re.compile(r"set(?:Timeout|Interval)\s*\(\s*['\"`]")),
    ("document.write()", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(")),
    ("jQuery .html()", re.compile(r"\.html\s*\(\s*[^)]")),
]
_PROTO_SINKS = [
    ("__proto__", re.compile(r"__proto__")),
    ("constructor.prototype", re.compile(r"constructor\s*(?:\.|\[\s*['\"])\s*prototype")),
    ("Object.assign", re.compile(r"Object\.assign\s*\(")),
    ("jQuery.extend(true)", re.compile(r"\$\.extend\s*\(\s*true")),
    ("recursive merge", re.compile(r"\b(?:deep[_]?merge|_\.merge|merge)\s*\(")),
]
_PARAM_RE = re.compile(r"""['"]([a-zA-Z_][\w\-]{1,40})['"]\s*:""")  # chaves de objeto (params/config)
_FUNC_RE = re.compile(r"\bfunction\s+([a-zA-Z_]\w{2,40})\s*\(|\b([a-zA-Z_]\w{2,40})\s*[:=]\s*(?:async\s*)?\(")


def analyze_js(js_url: str, scope_root: str | None = None) -> dict:
    """Baixa e analisa um arquivo JS. Read-only."""
    out = {"url": js_url, "ok": False, "endpoints": [], "params": [], "functions": [],
           "eval_sinks": [], "proto_sinks": [], "secrets": []}
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (easm-js-analyzer)"}) as c:
            r = c.get(js_url)
            body = (r.text or "")[:_MAX_BYTES]
    except Exception as exc:
        out["error"] = type(exc).__name__
        return out
    out["ok"] = True
    base_host = _host_of(js_url)
    root = (scope_root or _root_domain(base_host)).lower()

    eps = set()
    for pat in _ENDPOINT_RES:
        for m in pat.finditer(body):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("data:", "//", "http")) and _root_domain(_host_of(raw)) != root:
                if raw.startswith("http"):
                    continue
            if raw.startswith("/"):
                eps.add(f"https://{base_host}{raw}")
            elif raw.startswith("http") and _root_domain(_host_of(raw)) == root:
                eps.add(raw)
    out["endpoints"] = sorted(eps)[:120]

    out["params"] = sorted({m.group(1) for m in _PARAM_RE.finditer(body)})[:60]
    funcs = set()
    for m in _FUNC_RE.finditer(body):
        funcs.add(m.group(1) or m.group(2))
    out["functions"] = sorted(f for f in funcs if f)[:60]

    for name, pat in _EVAL_SINKS:
        if pat.search(body):
            out["eval_sinks"].append(name)
    for name, pat in _PROTO_SINKS:
        if pat.search(body):
            out["proto_sinks"].append(name)

    seen = set()
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(body):
            val = m.group(0)
            k = (label, val[:30])
            if k in seen:
                continue
            seen.add(k)
            out["secrets"].append({"type": label, "match": val[:80]})
            if len(out["secrets"]) >= 25:
                break
    return out


def _candidate_js(urls: list[str]) -> list[str]:
    out, seen = [], set()
    for u in urls:
        if isinstance(u, str) and u.startswith("http") and re.search(r"\.js(\?|$)", u, re.I):
            base = u.split("?")[0]
            if base not in seen:
                seen.add(base)
                out.append(u)
        if len(out) >= _MAX_JS:
            break
    return out


def run_js_analysis_for_scan(db, job) -> dict:
    from app.models.models import Finding

    state = dict(getattr(job, "state_data", None) or {})
    root = _root_domain(str(getattr(job, "target_query", "") or "").split(",")[0].strip())
    urls = list(state.get("discovered_endpoints") or [])
    try:
        for (det,) in db.query(Finding.details).filter(Finding.scan_job_id == job.id).limit(800).all():
            if isinstance(det, dict):
                for k in ("matched_at", "url"):
                    if det.get(k):
                        urls.append(str(det[k]))
                for e in (det.get("external_scripts") or []):
                    urls.append(str(e))
    except Exception:
        pass

    js_files = _candidate_js(urls)
    if not js_files:
        return {"skipped": "no_js"}

    findings: list[dict] = []
    new_endpoints: set[str] = set()
    analyzed = 0
    for ju in js_files:
        a = analyze_js(ju, scope_root=root)
        if not a.get("ok"):
            continue
        analyzed += 1
        for e in a["endpoints"]:
            new_endpoints.add(e)
        for sec in a["secrets"]:
            findings.append({
                "title": f"Segredo hardcoded em JS ({sec['type']}): {ju.split('/')[-1][:60]}",
                "severity": "high", "risk_score": 8,
                "details": {"tool": "js_analyzer", "asset": ju, "matched_at": ju,
                            "evidence": f"{sec['type']}: {sec['match']}", "vuln_family": "secrets",
                            "owasp_category": "A05:2021 Security Misconfiguration",
                            "verification_status": "confirmed",
                            "discovery_method": "análise estática de JS (regex de segredo)"},
            })
        if a["eval_sinks"]:
            findings.append({
                "title": f"Sink perigoso de JS ({', '.join(a['eval_sinks'][:3])}) — risco DOM XSS/eval",
                "severity": "medium", "risk_score": 5,
                "details": {"tool": "js_analyzer", "asset": ju, "matched_at": ju,
                            "evidence": f"Sinks detectados: {', '.join(a['eval_sinks'])}. Funções suspeitas: {', '.join(a['functions'][:6])}",
                            "vuln_family": "xss", "owasp_category": "A03:2021 Injection",
                            "verification_status": "candidate",
                            "discovery_method": "análise estática de JS (sinks de execução)"},
            })
        if a["proto_sinks"]:
            findings.append({
                "title": f"Sink de Prototype Pollution em JS ({', '.join(a['proto_sinks'][:3])})",
                "severity": "medium", "risk_score": 5,
                "details": {"tool": "js_analyzer", "asset": ju, "matched_at": ju,
                            "evidence": f"Sinks: {', '.join(a['proto_sinks'])}.",
                            "vuln_family": "prototype_pollution",
                            "owasp_category": "A08:2021 Software and Data Integrity Failures",
                            "verification_status": "candidate",
                            "discovery_method": "análise estática de JS (sinks de pollution)"},
            })

    # Realimenta os endpoints achados no JS (fecha o loop de descoberta).
    reseeded = 0
    if new_endpoints:
        st = dict(job.state_data or {})
        seen = set(st.get("discovered_endpoints") or [])
        fresh = [e for e in new_endpoints if e not in seen]
        for e in fresh:
            seen.add(e)
        st["discovered_endpoints"] = list(seen)[:5000]
        job.state_data = st
        reseeded = len(fresh)

    created = 0
    if findings:
        try:
            from app.services.findings_extractor import persist_finding_dicts
            created = persist_finding_dicts(db, job, findings, default_tool="js_analyzer",
                                            default_target=str(getattr(job, "target_query", "") or ""),
                                            source_item=None)
        except Exception:
            pass
    try:
        db.commit()
    except Exception:
        db.rollback()
    return {"analyzed": analyzed, "js_files": len(js_files), "endpoints_found": len(new_endpoints),
            "endpoints_reseeded": reseeded, "findings_created": created}
