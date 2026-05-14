"""Target code analyzer — fetches HTML+JS and extracts structured intelligence.

The user noted that the existing recon (fuzzing + header analysis) is too
shallow: "Deveriamos analisar o código do alvo para verificar as variaveis
de ambiente e endpoint e com isso realizar testes."

This module fills that gap. It runs in the BACKEND (no Kali round-trip)
and is wired in as a regular `tool_name="code-analyzer"` so the existing
workflow tracks it in executed_tool_runs / agent_trace_events.

What it extracts from the target:
  - <form> elements: action, method, named inputs (login candidates)
  - <script src=...> URLs (referenced JS bundles)
  - <a href=...> and absolute URLs inside HTML/JS
  - URL strings in JS (relative + absolute) → endpoint inventory
  - process.env.*, REACT_APP_*, NEXT_PUBLIC_*, __NEXT_DATA__ → env hints
  - High-confidence API key patterns (AWS, Google, Stripe, GitHub, JWT)
  - <meta name="generator">, <meta name="application-name"> → framework
  - HTML comments (<!-- … -->) — frequently leak dev paths / TODOs
  - Cookies set by Set-Cookie (first response only)
  - Inline JSON blobs with hostnames

The output is a dict; convert_to_findings() turns it into structured
findings that the hypothesis engine picks up (especially the param-bearing
endpoints — those generate sqli/xss/ssrf hypotheses).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

# Generous timeouts: this runs once per scan, not in a hot loop.
DEFAULT_TIMEOUT = 25
MAX_JS_PER_TARGET = 12
MAX_JS_BYTES = 1_500_000  # 1.5 MB per script — protect against tarpits
MAX_HTML_BYTES = 3_000_000

# Common API key patterns (high-confidence shapes only — fewer FP).
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,20})?(secret|sk)['\"\s:=]+[A-Za-z0-9/+=]{40}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_live",    re.compile(r"\bsk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_test",    re.compile(r"\bsk_test_[0-9a-zA-Z]{24,99}\b")),
    ("github_token",   re.compile(r"\bgh[pous]_[A-Za-z0-9]{36,40}\b")),
    ("slack_token",    re.compile(r"\bxox[abprs]-[0-9a-zA-Z\-]{10,}\b")),
    ("jwt",            re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("private_key",    re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) (PRIVATE )?KEY-----")),
    ("firebase_url",   re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
]

# Env-variable / config references frequently exposed by SPAs.
_ENV_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("process.env", re.compile(r"process\.env\.([A-Z_][A-Z0-9_]+)")),
    ("react_app",   re.compile(r"\b(REACT_APP_[A-Z0-9_]+)\b")),
    ("next_public", re.compile(r"\b(NEXT_PUBLIC_[A-Z0-9_]+)\b")),
    ("vue_app",     re.compile(r"\b(VUE_APP_[A-Z0-9_]+)\b")),
    ("vite_env",    re.compile(r"import\.meta\.env\.([A-Z_][A-Z0-9_]+)")),
    ("ng_env",      re.compile(r"\benvironment\.([a-zA-Z_][a-zA-Z0-9_]+)\b")),
    ("window_env",  re.compile(r"window\.__ENV__\.([A-Z_][A-Z0-9_]+)")),
]

# URL extraction regex — works on HTML and JS source.
_URL_LITERAL = re.compile(r'[\"\']((?:https?:)?//[^\s\"\'<>)]+|/[A-Za-z0-9_\-./?&=%:#]+)[\"\']')
_API_PATH_LITERAL = re.compile(r'[\"\'](/(?:api|graphql|v\d+|rest|services|admin|user|auth|login|logout|register|reset|account|me|data|search|query|export|import|upload|download|file|files|backup|config|settings|webhook|callback)[A-Za-z0-9_\-./?&=%:#]*)[\"\']', re.IGNORECASE)

# Tags we care about during HTML pass — keep simple, no full DOM parser.
_FORM_RE   = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE  = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*\bsrc=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_META_RE   = re.compile(r'<meta\b[^>]*\b(?:name|property)=[\"\']([^\"\']+)[\"\'][^>]*\bcontent=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ATTR_RE   = re.compile(r'\b([a-zA-Z_-]+)\s*=\s*[\"\']([^\"\']*)[\"\']')


def _http_get(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> tuple[bytes, dict[str, str], int]:
    """GET with browser-ish UA; returns (body, headers, status). Never raises."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # webapps with self-signed certs are common targets
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; ScriptKiddo-CodeAnalyzer/1.0)",
                "Accept": "text/html,application/xhtml+xml,application/xml,*/*",
            },
            stream=True,
        )
        chunks: list[bytes] = []
        size = 0
        for chunk in resp.iter_content(chunk_size=16_384):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_HTML_BYTES:
                break
        body = b"".join(chunks)
        return body, dict(resp.headers), resp.status_code
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_analyzer GET failed url=%s err=%s", url, exc)
        return b"", {}, 0


def _parse_form(attrs_blob: str, body: str) -> dict[str, Any]:
    attrs = {k.lower(): v for k, v in _ATTR_RE.findall(attrs_blob)}
    inputs: list[dict[str, str]] = []
    for input_attrs_blob in _INPUT_RE.findall(body):
        ia = {k.lower(): v for k, v in _ATTR_RE.findall(input_attrs_blob)}
        if "name" in ia:
            inputs.append({
                "name": ia.get("name", ""),
                "type": ia.get("type", "text"),
                "value": ia.get("value", "")[:200],
            })
    return {
        "action": attrs.get("action", ""),
        "method": (attrs.get("method") or "GET").upper(),
        "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
        "inputs": inputs[:30],
    }


def _absolutise(base: str, link: str) -> str:
    try:
        return urljoin(base, link)
    except Exception:  # noqa: BLE001
        return link


def _extract_urls(text: str, base: str) -> set[str]:
    found: set[str] = set()
    for m in _URL_LITERAL.finditer(text):
        link = m.group(1)
        if link.startswith("//"):
            link = "https:" + link
        absu = _absolutise(base, link)
        if absu.startswith(("http://", "https://")):
            found.add(absu)
    for m in _API_PATH_LITERAL.finditer(text):
        absu = _absolutise(base, m.group(1))
        if absu.startswith(("http://", "https://")):
            found.add(absu)
    return found


def _extract_secrets(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            sample = m.group(0)
            out.append({
                "kind": label,
                "match": sample if len(sample) <= 80 else (sample[:60] + "..."),
            })
            if len(out) >= 40:
                return out
    return out


def _extract_env_refs(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kind, pat in _ENV_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            key = (kind, name)
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": kind, "name": name})
            if len(out) >= 50:
                return out
    return out


def analyze(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Fetch target HTML + referenced JS, extract structured intel.

    Returns a dict with:
        target, http_status, headers, cookies, forms, scripts,
        endpoints, env_refs, secrets, meta, comments, ajax_endpoints,
        elapsed_ms
    Safe to call on any URL — never raises.
    """
    import time as _time
    started = _time.perf_counter()

    raw, headers, status = _http_get(url, timeout=timeout)
    body = raw.decode("utf-8", errors="replace")

    parsed_base = urlparse(url)
    base = urlunparse((parsed_base.scheme or "http", parsed_base.netloc, "/", "", "", ""))

    # ── Forms ────────────────────────────────────────────────────────────
    forms: list[dict[str, Any]] = []
    for m in _FORM_RE.finditer(body):
        form = _parse_form(m.group(1), m.group(2))
        form["resolved_action"] = _absolutise(url, form.get("action", "") or url)
        forms.append(form)

    # ── Scripts ──────────────────────────────────────────────────────────
    script_sources = [_absolutise(url, src) for src in _SCRIPT_SRC_RE.findall(body)][:MAX_JS_PER_TARGET]
    inline_scripts = _INLINE_SCRIPT_RE.findall(body)

    # ── HTML-level extractions ───────────────────────────────────────────
    meta_tags = {name: content for name, content in _META_RE.findall(body)}
    html_comments = [c.strip()[:400] for c in _COMMENT_RE.findall(body) if c.strip()]

    endpoints = _extract_urls(body, url)
    secrets = _extract_secrets(body)
    env_refs = _extract_env_refs(body)

    # ── Fetch each referenced JS, extract more endpoints/env/secrets ────
    js_scanned: list[dict[str, Any]] = []
    for src in script_sources:
        if not src.startswith(("http://", "https://")):
            continue
        jraw, _jheaders, jstatus = _http_get(src, timeout=min(15, timeout))
        if not jraw or jstatus >= 400:
            js_scanned.append({"src": src, "status": jstatus, "endpoints": 0})
            continue
        jbody = jraw[:MAX_JS_BYTES].decode("utf-8", errors="replace")
        more_eps = _extract_urls(jbody, src)
        more_secrets = _extract_secrets(jbody)
        more_envs = _extract_env_refs(jbody)
        endpoints.update(more_eps)
        secrets.extend(more_secrets)
        env_refs.extend(more_envs)
        js_scanned.append({
            "src": src,
            "status": jstatus,
            "bytes": len(jraw),
            "endpoints": len(more_eps),
            "secrets": len(more_secrets),
            "env_refs": len(more_envs),
        })

    # Also scan inline scripts.
    for inline in inline_scripts[:10]:
        endpoints.update(_extract_urls(inline, url))
        secrets.extend(_extract_secrets(inline))
        env_refs.extend(_extract_env_refs(inline))

    # ── AJAX endpoints subset — endpoints that look like APIs ───────────
    ajax_endpoints = sorted({
        ep for ep in endpoints
        if re.search(r"/(api|graphql|rest|v\d+|services|webhook|callback|auth|login|register|reset|me|user|admin|data|search|export|upload|file)\b", ep, re.IGNORECASE)
    })[:60]

    # Dedupe + cap.
    endpoints_list = sorted(endpoints)[:200]
    # Dedupe secrets (string match).
    seen_sigs: set[str] = set()
    secrets_unique: list[dict[str, str]] = []
    for s in secrets:
        sig = f"{s.get('kind')}|{s.get('match')}"
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        secrets_unique.append(s)

    # Cookies from Set-Cookie header(s).
    cookies_raw = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
    cookies: list[str] = [c.strip() for c in cookies_raw.split(",") if c.strip()] if cookies_raw else []

    elapsed_ms = int((_time.perf_counter() - started) * 1000)

    result = {
        "target": url,
        "http_status": status,
        "headers": {k: v for k, v in headers.items() if k.lower() in {
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "content-type", "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "access-control-allow-origin",
            "access-control-allow-credentials", "set-cookie", "location",
        }},
        "cookies": cookies,
        "forms": forms,
        "meta": meta_tags,
        "html_comments": html_comments[:25],
        "scripts": script_sources,
        "js_scanned": js_scanned,
        "endpoints": endpoints_list,
        "ajax_endpoints": ajax_endpoints,
        "env_refs": env_refs[:60],
        "secrets": secrets_unique[:40],
        "elapsed_ms": elapsed_ms,
    }
    return result


def convert_to_findings(analysis: dict[str, Any], scan_target: str, step_name: str) -> list[dict[str, Any]]:
    """Turn analyzer output into structured findings the hypothesis engine
    can read (especially `details.url` + `details.evidence`)."""
    findings: list[dict[str, Any]] = []
    base_details = {
        "node": "code-analyzer",
        "step": step_name,
        "asset": scan_target,
        "tool": "code-analyzer",
    }

    # 1) Server / framework headers (info)
    for k, v in (analysis.get("headers") or {}).items():
        if not v:
            continue
        if k.lower() in {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}:
            findings.append({
                "title": f"Header revela tecnologia: {k}={v}",
                "severity": "info",
                "risk_score": 2,
                "source_worker": "code_analyzer",
                "details": {**base_details, "evidence": f"{k}: {v}", "header_name": k, "header_value": v},
            })

    # 2) Forms (potential login / search vectors)
    for form in analysis.get("forms") or []:
        action = form.get("resolved_action") or form.get("action") or scan_target
        inputs = ", ".join(i.get("name", "") for i in form.get("inputs") or [])
        ev = f"<form action={action} method={form.get('method')} inputs=[{inputs}]>"
        findings.append({
            "title": f"Formulario descoberto em {action}",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": ev,
                "url": action,
                "form_method": form.get("method"),
                "form_inputs": form.get("inputs"),
            },
        })

    # 3) Endpoints (especially AJAX/API)
    for ep in (analysis.get("ajax_endpoints") or [])[:30]:
        findings.append({
            "title": f"Endpoint API descoberto: {ep}",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "code_analyzer",
            "details": {**base_details, "evidence": ep, "url": ep, "kind": "ajax_endpoint"},
        })

    # 4) Env refs (REACT_APP_*, NEXT_PUBLIC_*, etc.)
    if analysis.get("env_refs"):
        for ref in (analysis.get("env_refs") or [])[:20]:
            findings.append({
                "title": f"Referencia a env var: {ref.get('kind')} -> {ref.get('name')}",
                "severity": "low",
                "risk_score": 3,
                "source_worker": "code_analyzer",
                "details": {
                    **base_details,
                    "evidence": f"{ref.get('kind')}.{ref.get('name')}",
                    "env_kind": ref.get("kind"),
                    "env_name": ref.get("name"),
                },
            })

    # 5) Secrets — high severity
    for sec in analysis.get("secrets") or []:
        findings.append({
            "title": f"Secret pattern detectado: {sec.get('kind')}",
            "severity": "high",
            "risk_score": 8,
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": sec.get("match"),
                "secret_kind": sec.get("kind"),
                "validation_status": "hypothesis",
                "confidence": 75,
                "repro_steps": (
                    f"GET {scan_target}; baixar JS referenciado; grep para padrao {sec.get('kind')}."
                ),
            },
        })

    # 6) Cookies sem flags
    for cookie in analysis.get("cookies") or []:
        lc = cookie.lower()
        missing = []
        if "httponly" not in lc:
            missing.append("HttpOnly")
        if "secure" not in lc:
            missing.append("Secure")
        if "samesite" not in lc:
            missing.append("SameSite")
        if missing:
            findings.append({
                "title": f"Cookie sem flags ({', '.join(missing)}): {cookie.split(';',1)[0][:80]}",
                "severity": "low",
                "risk_score": 4,
                "source_worker": "code_analyzer",
                "details": {
                    **base_details,
                    "evidence": cookie[:300],
                    "missing_flags": missing,
                },
            })

    # 7) HTML comments — sometimes leak paths / TODOs
    for cmt in (analysis.get("html_comments") or [])[:5]:
        if len(cmt) < 12:
            continue
        suspicious = re.search(r"(TODO|FIXME|password|secret|api[_ ]?key|admin|debug|backup|/api/)", cmt, re.IGNORECASE)
        if not suspicious:
            continue
        findings.append({
            "title": "Comentario HTML potencialmente sensivel",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "code_analyzer",
            "details": {**base_details, "evidence": cmt[:300], "marker": suspicious.group(0)},
        })

    return findings


def run_as_tool(target: str) -> dict[str, Any]:
    """Adapter that matches the dict shape `_run_tools_and_collect` expects
    from `execute_tool_with_workers`. Used by the dispatcher special-case.
    """
    try:
        analysis = analyze(target)
        findings = convert_to_findings(analysis, scan_target=target, step_name="CodeAnalysis")
        endpoints_summary = "\n".join((analysis.get("ajax_endpoints") or [])[:20])
        forms_summary = "\n".join(
            f"{f.get('method')} {f.get('resolved_action')} inputs={[i.get('name') for i in f.get('inputs') or []]}"
            for f in analysis.get("forms") or []
        )
        env_summary = "\n".join(
            f"{r.get('kind')}.{r.get('name')}" for r in (analysis.get("env_refs") or [])[:30]
        )
        secrets_summary = "\n".join(f"{s.get('kind')}: {s.get('match')}" for s in analysis.get("secrets") or [])
        stdout_blob = json.dumps(analysis, indent=2)[:200_000]
        return {
            "tool": "code-analyzer",
            "target": target,
            "scan_mode": "unit",
            "status": "done",
            "command": f"code-analyzer GET {target} (+JS)",
            "return_code": 0,
            "stdout": stdout_blob,
            "stderr": "",
            "open_ports": [],
            "parsed": analysis,
            "findings_extracted": findings,  # consumed by tool_parsers special path
        }
    except Exception as exc:
        return {
            "tool": "code-analyzer",
            "target": target,
            "scan_mode": "unit",
            "status": "failed",
            "command": f"code-analyzer GET {target}",
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "open_ports": [],
            "dispatch_error": f"{type(exc).__name__}: {exc}",
        }
