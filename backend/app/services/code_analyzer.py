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
# <a href> / <link href> / <area href> / form action — the REAL site map.
# Used to discover navigable pages (login.aspx, Comments.aspx?id=, etc.)
_HREF_RE = re.compile(r'<(?:a|link|area)\b[^>]*\bhref=[\"\']([^\"\'#]+)[\"\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form\b[^>]*\baction=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)

# Tags we care about during HTML pass — keep simple, no full DOM parser.
_FORM_RE   = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE  = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*\bsrc=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_META_RE   = re.compile(r'<meta\b[^>]*\b(?:name|property)=[\"\']([^\"\']+)[\"\'][^>]*\bcontent=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ATTR_RE   = re.compile(r'\b([a-zA-Z_-]+)\s*=\s*[\"\']([^\"\']*)[\"\']')

# Depth-1 crawl budget — number of same-host pages to fetch beyond root.
MAX_CRAWL_PAGES = 14
# Static asset extensions that are NOT injectable endpoints — skip crawl.
_STATIC_EXT = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4",
    ".webp", ".avif",
)


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _is_garbage_url(url: str) -> bool:
    """Reject things the URL-literal regex mis-captures as endpoints:
    XML-schema namespaces, ASP.NET __VIEWSTATE base64 blobs pasted into a
    path, data: URIs, and absurdly long opaque path segments.
    """
    low = url.lower()
    if "schemas." in low or "/intellisense/" in low or "w3.org" in low:
        return True
    if low.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return True
    try:
        path = urlparse(url).path or ""
    except Exception:  # noqa: BLE001
        path = url
    # Any path SEGMENT >60 chars that is mostly base64 alphabet is almost
    # always an ASP.NET __VIEWSTATE blob mis-captured as a route. Check
    # every segment (not just the last) — VIEWSTATE blobs contain `/`.
    for seg in path.split("/"):
        seg = seg.strip()
        if len(seg) > 60 and "." not in seg:
            b64ish = sum(1 for c in seg if c.isalnum() or c in "+/=")
            if b64ish / max(1, len(seg)) > 0.92:
                return True
    return False


def _is_crawlable(url: str, root_host: str) -> bool:
    """True when url is a same-host HTML page worth fetching in the crawl."""
    if _is_garbage_url(url):
        return False
    if _host_of(url) != root_host:
        return False
    low = url.lower().split("?")[0].split("#")[0]
    if low.endswith(_STATIC_EXT):
        return False
    return url.startswith(("http://", "https://"))


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
    import html as _html
    found: set[str] = set()
    for m in _URL_LITERAL.finditer(text):
        link = _html.unescape(m.group(1))  # decode &amp; -> &
        if link.startswith("//"):
            link = "https:" + link
        absu = _absolutise(base, link)
        if absu.startswith(("http://", "https://")) and not _is_garbage_url(absu):
            found.add(absu)
    for m in _API_PATH_LITERAL.finditer(text):
        absu = _absolutise(base, _html.unescape(m.group(1)))
        if absu.startswith(("http://", "https://")) and not _is_garbage_url(absu):
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


def _parse_html_page(page_url: str, body: str) -> dict[str, Any]:
    """Parse a single HTML page — forms, hrefs, scripts, meta, comments."""
    import html as _html
    forms: list[dict[str, Any]] = []
    for m in _FORM_RE.finditer(body):
        form = _parse_form(m.group(1), m.group(2))
        # HTML-unescape the action so query separators are real `&`, not
        # `&amp;` — otherwise urlparse/parse_qs sees param "amp;NewsAd".
        raw_action = _html.unescape(form.get("action", "") or "")
        form["action"] = raw_action
        form["resolved_action"] = _absolutise(page_url, raw_action or page_url)
        form["found_on"] = page_url
        forms.append(form)

    # <a href> / <link> / <area> / form action — the navigable site map.
    import html as _html
    hrefs: set[str] = set()
    for href in _HREF_RE.findall(body):
        absu = _absolutise(page_url, _html.unescape(href.strip()))
        if absu.startswith(("http://", "https://")) and not _is_garbage_url(absu):
            hrefs.add(absu)
    for action in _FORM_ACTION_RE.findall(body):
        absu = _absolutise(page_url, _html.unescape(action.strip()))
        if absu.startswith(("http://", "https://")) and not _is_garbage_url(absu):
            hrefs.add(absu)

    script_sources = [_absolutise(page_url, src) for src in _SCRIPT_SRC_RE.findall(body)]
    inline_scripts = _INLINE_SCRIPT_RE.findall(body)
    meta_tags = {name: content for name, content in _META_RE.findall(body)}
    html_comments = [c.strip()[:400] for c in _COMMENT_RE.findall(body) if c.strip()]
    return {
        "forms": forms,
        "hrefs": hrefs,
        "scripts": script_sources,
        "inline_scripts": inline_scripts,
        "meta": meta_tags,
        "comments": html_comments,
    }


def analyze(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Fetch target HTML, crawl same-host links depth-1, fetch referenced
    JS, extract structured intel.

    The crawl is the key improvement: a single GET on the root only sees
    the landing page. Real ASP.NET/PHP apps expose login.aspx,
    Comments.aspx?id=, Signup.aspx etc. as <a href> links — we follow
    them so the hypothesis engine gets the actual injectable endpoints.

    Returns a dict with: target, http_status, headers, cookies, forms,
    scripts, endpoints (same-host only), external_links, ajax_endpoints,
    pages_crawled, env_refs, secrets, meta, comments, elapsed_ms.
    Safe to call on any URL — never raises.
    """
    import time as _time
    started = _time.perf_counter()

    raw, headers, status = _http_get(url, timeout=timeout)
    body = raw.decode("utf-8", errors="replace")
    root_host = _host_of(url)

    # ── Parse root page ──────────────────────────────────────────────────
    root = _parse_html_page(url, body)
    forms: list[dict[str, Any]] = list(root["forms"])
    all_hrefs: set[str] = set(root["hrefs"])
    script_sources: list[str] = list(root["scripts"])
    inline_scripts: list[str] = list(root["inline_scripts"])
    meta_tags: dict[str, str] = dict(root["meta"])
    html_comments: list[str] = list(root["comments"])

    endpoints: set[str] = _extract_urls(body, url)
    secrets = _extract_secrets(body)
    env_refs = _extract_env_refs(body)

    # ── Depth-1 crawl of same-host pages ────────────────────────────────
    # Pick crawlable same-host HTML pages from the root's hrefs, fetch each,
    # merge its forms/hrefs/scripts. This is what surfaces login.aspx,
    # Comments.aspx?id=, etc. that a root-only GET would miss.
    crawl_queue = sorted(
        {h for h in all_hrefs if _is_crawlable(h, root_host)},
        key=lambda u: (len(urlparse(u).query) == 0, u),  # param-bearing first
    )[:MAX_CRAWL_PAGES]
    pages_crawled: list[dict[str, Any]] = [{"url": url, "status": status}]
    for page_url in crawl_queue:
        praw, _ph, pstatus = _http_get(page_url, timeout=min(15, timeout))
        pages_crawled.append({"url": page_url, "status": pstatus})
        if not praw or pstatus >= 400:
            continue
        pbody = praw[:MAX_HTML_BYTES].decode("utf-8", errors="replace")
        parsed = _parse_html_page(page_url, pbody)
        forms.extend(parsed["forms"])
        all_hrefs.update(parsed["hrefs"])
        script_sources.extend(parsed["scripts"])
        inline_scripts.extend(parsed["inline_scripts"])
        for cmt in parsed["comments"]:
            if cmt not in html_comments:
                html_comments.append(cmt)
        endpoints.update(_extract_urls(pbody, page_url))
        secrets.extend(_extract_secrets(pbody))
        env_refs.extend(_extract_env_refs(pbody))

    # All discovered hrefs ARE endpoints (the real site map).
    endpoints.update(all_hrefs)

    # ── Fetch referenced JS, extract more endpoints/env/secrets ─────────
    script_sources = list(dict.fromkeys(script_sources))[:MAX_JS_PER_TARGET]
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
        endpoints.update(more_eps)
        secrets.extend(_extract_secrets(jbody))
        env_refs.extend(_extract_env_refs(jbody))
        js_scanned.append({
            "src": src, "status": jstatus, "bytes": len(jraw),
            "endpoints": len(more_eps),
        })

    for inline in inline_scripts[:15]:
        endpoints.update(_extract_urls(inline, url))
        secrets.extend(_extract_secrets(inline))
        env_refs.extend(_extract_env_refs(inline))

    # ── Classify endpoints: same-host (injectable) vs external links ────
    same_host: set[str] = set()
    external: set[str] = set()
    for ep in endpoints:
        if _is_garbage_url(ep):
            continue
        # Skip static assets (.css/.js/.png/...) — not injectable endpoints.
        ep_path = ep.lower().split("?")[0].split("#")[0]
        if ep_path.endswith(_STATIC_EXT):
            continue
        if _host_of(ep) == root_host:
            same_host.add(ep)
        else:
            external.add(ep)

    # Form actions are always injectable endpoints.
    for f in forms:
        ra = f.get("resolved_action")
        if ra and _host_of(ra) == root_host and not _is_garbage_url(ra):
            same_host.add(ra)

    endpoints_list = sorted(same_host)[:250]
    external_list = sorted(external)[:60]

    # ── AJAX/API-pattern endpoints (same-host only) ──────────────────────
    ajax_endpoints = sorted({
        ep for ep in same_host
        if re.search(r"/(api|graphql|rest|v\d+|services|webhook|callback|auth|login|logout|register|signup|reset|me|user|account|admin|data|search|export|import|upload|download|file|comment)s?\b", ep, re.IGNORECASE)
        or "?" in ep  # any param-bearing URL is a test target
    })[:80]

    # Dedupe secrets.
    seen_sigs: set[str] = set()
    secrets_unique: list[dict[str, str]] = []
    for s in secrets:
        sig = f"{s.get('kind')}|{s.get('match')}"
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        secrets_unique.append(s)

    cookies_raw = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
    cookies: list[str] = [c.strip() for c in cookies_raw.split(",") if c.strip()] if cookies_raw else []
    elapsed_ms = int((_time.perf_counter() - started) * 1000)

    return {
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
        "forms": forms[:40],
        "meta": meta_tags,
        "html_comments": html_comments[:25],
        "scripts": script_sources,
        "js_scanned": js_scanned,
        "endpoints": endpoints_list,
        "external_links": external_list,
        "ajax_endpoints": ajax_endpoints,
        "pages_crawled": pages_crawled,
        "env_refs": env_refs[:60],
        "secrets": secrets_unique[:40],
        "elapsed_ms": elapsed_ms,
    }


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

    # 3) Endpoints — emit a finding for EVERY same-host endpoint so the
    # hypothesis engine sees them. Param-bearing endpoints (?id=, ?q=) get
    # `kind=param_endpoint` so the injection matrix fires per parameter.
    emitted_eps: set[str] = set()
    for ep in (analysis.get("endpoints") or [])[:120]:
        if ep in emitted_eps:
            continue
        emitted_eps.add(ep)
        has_params = "?" in ep
        is_ajax = ep in set(analysis.get("ajax_endpoints") or [])
        kind = "param_endpoint" if has_params else ("ajax_endpoint" if is_ajax else "page_endpoint")
        findings.append({
            "title": f"Endpoint descoberto ({kind}): {ep}",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "code_analyzer",
            "details": {**base_details, "evidence": ep, "url": ep, "kind": kind},
        })

    # 3b) Crawl summary so the operator sees how deep the analyzer went.
    pages = analysis.get("pages_crawled") or []
    if pages:
        ok_pages = [p for p in pages if isinstance(p, dict) and int(p.get("status") or 0) < 400]
        findings.append({
            "title": f"Code-analyzer crawl: {len(ok_pages)}/{len(pages)} paginas, "
                     f"{len(analysis.get('endpoints') or [])} endpoints, "
                     f"{len(analysis.get('forms') or [])} forms",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": "; ".join(str(p.get('url')) for p in ok_pages[:15]),
                "kind": "crawl_summary",
            },
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
