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
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

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


# ─────────────────────────────────────────────────────────────────────
# DEEP RECON — well-known paths, differential probing, fingerprint→CVE,
# authenticated recon. The user explicitly wants maximum depth: runtime
# and request noise are acceptable.
# ─────────────────────────────────────────────────────────────────────

# Well-known paths probed on every scan (item 5). High value, low cost.
_WELL_KNOWN_PATHS: list[tuple[str, str]] = [
    ("/robots.txt",                  "robots"),
    ("/sitemap.xml",                 "sitemap"),
    ("/sitemap_index.xml",           "sitemap"),
    ("/.well-known/security.txt",    "security_txt"),
    ("/.git/config",                 "git_exposure"),
    ("/.git/HEAD",                   "git_exposure"),
    ("/.svn/entries",                "svn_exposure"),
    ("/.env",                        "env_exposure"),
    ("/.DS_Store",                   "dsstore_exposure"),
    ("/web.config",                  "webconfig_exposure"),
    ("/phpinfo.php",                 "phpinfo_exposure"),
    ("/server-status",               "apache_status"),
    ("/.htaccess",                   "htaccess_exposure"),
    ("/crossdomain.xml",             "crossdomain"),
    ("/clientaccesspolicy.xml",      "silverlight_policy"),
    ("/backup.zip",                  "backup_exposure"),
    ("/backup.sql",                  "backup_exposure"),
    ("/.well-known/openid-configuration", "oidc_config"),
    ("/swagger.json",                "swagger"),
    ("/swagger/v1/swagger.json",     "swagger"),
    ("/openapi.json",                "openapi"),
    ("/api/swagger.json",            "swagger"),
    ("/actuator",                    "spring_actuator"),
    ("/actuator/env",                "spring_actuator"),
    ("/trace.axd",                   "aspnet_trace"),
    ("/elmah.axd",                   "aspnet_elmah"),
]

# Differential-probe payloads (item 1). Benign, read-only — each probe is
# a single GET. The diff between baseline and probe responses is the
# evidence that turns "param exists" into "param is vulnerable to X".
_DIFF_PROBES: dict[str, list[str]] = {
    "sqli_quote":       ["'", "\"", "')", "';"],
    "sqli_bool_true":   [" AND 1=1", "' AND '1'='1", " OR 1=1"],
    "sqli_bool_false":  [" AND 1=2", "' AND '1'='2"],
    "sqli_numeric":     ["99999999", "-1", "0"],
    "xss_reflect":      ["sk0xCANARY<x>", "\"sk0xCANARY"],
    "lfi_traversal":    ["../../../../etc/passwd", "....//....//etc/passwd"],
    "ssti_math":        ["{{7*7}}", "${7*7}"],
    "path_append":      ["/", "%2e%2e%2f"],
}

# SQL error signatures — presence in a probe response = strong SQLi signal.
_SQL_ERROR_SIGNS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft SQL|ODBC SQL|"
    r"PostgreSQL.*ERROR|SQLite/JDBC|Unclosed quotation mark|"
    r"quoted string not properly terminated|System\.Data\.SqlClient|"
    r"Incorrect syntax near|Warning: mysqli|SQLSTATE\[)",
    re.IGNORECASE,
)
# Generic stack-trace / verbose-error signatures.
_STACKTRACE_SIGNS = re.compile(
    r"(Traceback \(most recent call last\)|Exception in thread|"
    r"at [a-zA-Z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)|"
    r"\.aspx\.cs:line \d+|Server Error in '/' Application|"
    r"<b>Fatal error</b>|<b>Warning</b>|on line <b>\d+)",
    re.IGNORECASE,
)

# Version → CVE-family hints (item 3). Drives targeted nuclei templates.
_VERSION_CVE_HINTS: list[tuple[re.Pattern[str], str, list[str]]] = [
    (re.compile(r"Microsoft-IIS/([6-8])\.", re.I), "iis-legacy",
     ["iis", "aspx", "tilde-enum", "shortname"]),
    (re.compile(r"Apache/2\.(2|4)\.", re.I), "apache",
     ["apache", "cve", "exposures"]),
    (re.compile(r"nginx/1\.[0-9]\.", re.I), "nginx-old",
     ["nginx", "cve"]),
    (re.compile(r"PHP/[45]\.", re.I), "php-eol",
     ["php", "cve", "exposures"]),
    (re.compile(r"X-AspNet-Version:\s*[12]\.", re.I), "aspnet-legacy",
     ["aspx", "iis", "cve"]),
    (re.compile(r"OpenSSL/(0|1\.0)\.", re.I), "openssl-eol",
     ["ssl", "cve", "heartbleed"]),
    (re.compile(r"jQuery v?[12]\.", re.I), "jquery-old",
     ["xss", "javascript", "cve"]),
    (re.compile(r"WordPress ([0-5])\.", re.I), "wordpress",
     ["wordpress", "wp-plugin", "cve"]),
]


def _http_request(
    method: str,
    url: str,
    *,
    timeout: int = 20,
    data: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[bytes, dict[str, str], int, float, dict[str, str]]:
    """Generic request (GET/POST). Returns (body, headers, status,
    elapsed_seconds, response_cookies). Never raises."""
    import time as _t
    base_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ScriptKiddo-CodeAnalyzer/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml,*/*",
    }
    if headers:
        base_headers.update(headers)
    started = _t.perf_counter()
    try:
        resp = requests.request(
            method.upper(), url,
            timeout=timeout, allow_redirects=allow_redirects, verify=False,
            headers=base_headers, data=data, cookies=cookies, stream=True,
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
        elapsed = _t.perf_counter() - started
        resp_cookies = {c.name: c.value for c in resp.cookies}
        return body, dict(resp.headers), resp.status_code, elapsed, resp_cookies
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_analyzer %s failed url=%s err=%s", method, url, exc)
        return b"", {}, 0, _t.perf_counter() - started, {}


def _probe_well_known(base: str, *, timeout: int = 15) -> dict[str, Any]:
    """Item 5 — fetch well-known paths. Returns discovered extra URLs +
    exposure findings (.git, .env, web.config, sitemap entries, etc.)."""
    import html as _html
    discovered: set[str] = set()
    exposures: list[dict[str, Any]] = []
    for path, kind in _WELL_KNOWN_PATHS:
        url = urljoin(base, path)
        body, headers, status, _elapsed, _ck = _http_request("GET", url, timeout=timeout)
        if status == 0 or status >= 400:
            continue
        text = body.decode("utf-8", errors="replace")
        ctype = str(headers.get("Content-Type", "")).lower()
        # robots.txt → extract Disallow/Allow paths
        if kind == "robots" and status == 200:
            for m in re.finditer(r"(?im)^\s*(?:Dis)?Allow:\s*(\S+)", text):
                p = m.group(1).strip()
                if p and p != "/":
                    discovered.add(urljoin(base, p))
            for m in re.finditer(r"(?im)^\s*Sitemap:\s*(\S+)", text):
                discovered.add(m.group(1).strip())
            exposures.append({"kind": "robots", "url": url, "status": status,
                              "evidence": text[:600], "severity": "info"})
        # sitemap.xml → extract <loc>
        elif kind == "sitemap" and status == 200:
            for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.IGNORECASE):
                discovered.add(_html.unescape(m.group(1).strip()))
            exposures.append({"kind": "sitemap", "url": url, "status": status,
                              "evidence": f"{text.count('<loc>')} URLs", "severity": "info"})
        # high-severity exposures
        elif kind in {"git_exposure", "svn_exposure", "env_exposure",
                      "webconfig_exposure", "backup_exposure", "aspnet_trace",
                      "aspnet_elmah", "spring_actuator", "htaccess_exposure"}:
            # Only flag when content actually looks like the sensitive file,
            # not a SPA catch-all 200.
            looks_real = (
                ("git_exposure" == kind and ("[core]" in text or text.startswith("ref:")))
                or ("env_exposure" == kind and re.search(r"(?im)^[A-Z_]+=", text))
                or ("webconfig_exposure" == kind and "<configuration" in text.lower())
                or ("svn_exposure" == kind and text.strip()[:3].isdigit())
                or ("backup_exposure" == kind and ("application/zip" in ctype or "application/sql" in ctype or "PK\x03\x04" in text[:8]))
                or ("aspnet_trace" == kind and "Request Details" in text)
                or ("aspnet_elmah" == kind and ("Error Log" in text or "elmah" in text.lower()))
                or ("spring_actuator" == kind and ("\"profiles\"" in text or "\"_links\"" in text))
                or ("htaccess_exposure" == kind and ("RewriteRule" in text or "<Files" in text))
            )
            if looks_real:
                exposures.append({
                    "kind": kind, "url": url, "status": status,
                    "evidence": text[:600], "severity": "high",
                })
        elif kind in {"swagger", "openapi"} and status == 200 and ("\"paths\"" in text or "\"swagger\"" in text or "\"openapi\"" in text):
            # API spec → extract every documented path
            for m in re.finditer(r'"(/[A-Za-z0-9_\-./{}]+)"\s*:\s*\{', text):
                discovered.add(urljoin(base, m.group(1)))
            exposures.append({"kind": "api_spec", "url": url, "status": status,
                              "evidence": text[:600], "severity": "medium"})
        elif kind in {"security_txt", "crossdomain", "silverlight_policy",
                      "oidc_config", "phpinfo_exposure", "apache_status",
                      "dsstore_exposure"} and status == 200:
            sev = "high" if kind in {"phpinfo_exposure", "apache_status"} else "info"
            exposures.append({"kind": kind, "url": url, "status": status,
                              "evidence": text[:400], "severity": sev})
    return {"discovered_urls": sorted(discovered)[:200], "exposures": exposures}


def _differential_probe(endpoint: str, *, timeout: int = 12) -> dict[str, Any]:
    """Item 1 — send benign read-only probes to each parameter of an
    endpoint and diff the responses against the baseline.

    The diff (status change, body-size delta, response-time delta, SQL
    error / stacktrace / canary reflection) is the OBSERVED evidence that
    lets the hypothesis engine raise confidence from "param name matches"
    to "param behaves vulnerably".

    Returns {param: {signals...}} where signals include:
      sql_error, stacktrace, canary_reflected, bool_diff, time_anomaly,
      traversal_passwd, ssti_math_eval.
    """
    try:
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)
    except Exception:  # noqa: BLE001
        return {}
    if not params:
        return {}

    def _build(param: str, value: str) -> str:
        new_q = {k: v[:] for k, v in params.items()}
        new_q[param] = [value]
        flat = "&".join(f"{k}={requests.utils.quote(str(vv), safe='')}"
                         for k, vals in new_q.items() for vv in vals)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", flat, ""))

    # Baseline
    b_body, _bh, b_status, b_time, _bc = _http_request("GET", endpoint, timeout=timeout)
    baseline_text = b_body.decode("utf-8", errors="replace")
    baseline_len = len(baseline_text)

    out: dict[str, Any] = {}
    for param in params.keys():
        signals: dict[str, Any] = {
            "sql_error": False, "stacktrace": False, "canary_reflected": False,
            "bool_diff": False, "time_anomaly": False, "traversal_passwd": False,
            "ssti_math_eval": False, "status_changes": [], "len_deltas": [],
        }
        # SQLi quote probe
        for payload in _DIFF_PROBES["sqli_quote"]:
            body, _h, status, _t, _c = _http_request("GET", _build(param, payload), timeout=timeout)
            text = body.decode("utf-8", errors="replace")
            if _SQL_ERROR_SIGNS.search(text):
                signals["sql_error"] = True
            if _STACKTRACE_SIGNS.search(text):
                signals["stacktrace"] = True
            if status and status != b_status:
                signals["status_changes"].append(f"quote:{b_status}->{status}")
        # Boolean differential (true vs false should differ)
        true_body, _h1, _s1, _t1, _c1 = _http_request(
            "GET", _build(param, "1" + _DIFF_PROBES["sqli_bool_true"][0]), timeout=timeout)
        false_body, _h2, _s2, _t2, _c2 = _http_request(
            "GET", _build(param, "1" + _DIFF_PROBES["sqli_bool_false"][0]), timeout=timeout)
        tlen, flen = len(true_body), len(false_body)
        if abs(tlen - flen) > max(40, int(0.05 * max(tlen, flen, 1))):
            signals["bool_diff"] = True
            signals["len_deltas"].append(f"bool:{tlen}vs{flen}")
        # Time-based probe (best-effort — no real sleep payload, just measure)
        _tb, _th, _ts, t_time, _tc = _http_request(
            "GET", _build(param, "1' AND 1=1"), timeout=timeout)
        if t_time > max(5.0, b_time * 4 + 2):
            signals["time_anomaly"] = True
        # XSS canary
        for payload in _DIFF_PROBES["xss_reflect"]:
            body, _h, _s, _t, _c = _http_request("GET", _build(param, payload), timeout=timeout)
            if "sk0xCANARY" in body.decode("utf-8", errors="replace"):
                signals["canary_reflected"] = True
                break
        # LFI traversal
        for payload in _DIFF_PROBES["lfi_traversal"]:
            body, _h, _s, _t, _c = _http_request("GET", _build(param, payload), timeout=timeout)
            text = body.decode("utf-8", errors="replace")
            if "root:x:0:0:" in text or re.search(r"\[(extensions|fonts|mci)\]", text):
                signals["traversal_passwd"] = True
                break
        # SSTI math
        for payload in _DIFF_PROBES["ssti_math"]:
            body, _h, _s, _t, _c = _http_request("GET", _build(param, payload), timeout=timeout)
            if "49" in body.decode("utf-8", errors="replace")[:baseline_len + 4000] and "{{7*7}}" not in body.decode("utf-8", errors="replace"):
                signals["ssti_math_eval"] = True
                break
        # Keep only params that produced at least one positive signal OR
        # always keep so the hypothesis engine can see "probed, clean".
        signals["any_signal"] = any(
            signals[k] for k in
            ("sql_error", "stacktrace", "canary_reflected", "bool_diff",
             "time_anomaly", "traversal_passwd", "ssti_math_eval")
        )
        out[param] = signals
    return out


def _fingerprint_deep(headers: dict[str, str], body: str) -> dict[str, Any]:
    """Item 3 — extract precise version strings and map to CVE families
    so the supervisor can run targeted nuclei templates."""
    blob_parts = [f"{k}: {v}" for k, v in (headers or {}).items()]
    blob_parts.append(body[:8000])
    blob = "\n".join(blob_parts)
    versions: list[str] = []
    cve_families: list[str] = []
    nuclei_tags: set[str] = set()
    for pat, family, tags in _VERSION_CVE_HINTS:
        m = pat.search(blob)
        if m:
            versions.append(m.group(0).strip())
            cve_families.append(family)
            nuclei_tags.update(tags)
    # generator meta
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        versions.append(f"generator:{gen.group(1).strip()}")
    return {
        "versions": list(dict.fromkeys(versions))[:20],
        "cve_families": list(dict.fromkeys(cve_families))[:12],
        "nuclei_tags": sorted(nuclei_tags)[:20],
    }


def _authenticated_recon(
    base: str,
    forms: list[dict[str, Any]],
    *,
    timeout: int = 20,
) -> dict[str, Any]:
    """Item 4 — find a signup/register form, create a throwaway account,
    log in, and report the session cookie so the caller can re-crawl
    authenticated. Best-effort: never raises, returns {} on failure.

    Heuristic form detection: a form with both a username-ish and a
    password-ish input. Signup forms often have a second password field
    or an email field.
    """
    import uuid as _uuid

    def _classify_inputs(form: dict[str, Any]) -> dict[str, str]:
        roles: dict[str, str] = {}
        for inp in form.get("inputs") or []:
            name = str(inp.get("name") or "")
            low = name.lower()
            itype = str(inp.get("type") or "text").lower()
            if itype == "password" or "pass" in low or "pwd" in low:
                roles.setdefault("password", name)
                if "password" in roles and name != roles["password"]:
                    roles.setdefault("password_confirm", name)
            elif "email" in low or "mail" in low:
                roles.setdefault("email", name)
            elif itype in {"text", ""} and ("user" in low or "login" in low or "name" in low) and not low.startswith("__"):
                roles.setdefault("username", name)
        return roles

    cred_user = f"sk_{_uuid.uuid4().hex[:10]}"
    cred_pass = f"Sk0x!{_uuid.uuid4().hex[:8]}A"
    cred_email = f"{cred_user}@example.com"

    signup_form = None
    login_form = None
    for form in forms:
        roles = _classify_inputs(form)
        action = str(form.get("resolved_action") or "").lower()
        if "password" in roles and "username" in roles:
            if "signup" in action or "register" in action or "password_confirm" in roles or "email" in roles:
                signup_form = (form, roles)
            else:
                login_form = login_form or (form, roles)

    result: dict[str, Any] = {
        "attempted": False, "registered": False, "logged_in": False,
        "session_cookies": {}, "credentials": {}, "notes": [],
    }

    # ── Register ─────────────────────────────────────────────────────────
    if signup_form:
        result["attempted"] = True
        form, roles = signup_form
        action = form.get("resolved_action") or base
        payload: dict[str, str] = {}
        for inp in form.get("inputs") or []:
            name = str(inp.get("name") or "")
            if not name:
                continue
            payload[name] = str(inp.get("value") or "")
        if roles.get("username"):
            payload[roles["username"]] = cred_user
        if roles.get("password"):
            payload[roles["password"]] = cred_pass
        if roles.get("password_confirm"):
            payload[roles["password_confirm"]] = cred_pass
        if roles.get("email"):
            payload[roles["email"]] = cred_email
        body, _h, status, _t, cookies = _http_request(
            "POST", action, timeout=timeout, data=payload)
        text = body.decode("utf-8", errors="replace").lower()
        if status in (200, 302, 303) and not re.search(r"(already exists|invalid|error)", text):
            result["registered"] = True
            result["notes"].append(f"signup POST {action} status={status}")
            if cookies:
                result["session_cookies"].update(cookies)

    # ── Login ────────────────────────────────────────────────────────────
    target_login = login_form or signup_form
    if target_login:
        result["attempted"] = True
        form, roles = target_login
        action = form.get("resolved_action") or base
        payload = {}
        for inp in form.get("inputs") or []:
            name = str(inp.get("name") or "")
            if not name:
                continue
            payload[name] = str(inp.get("value") or "")
        if roles.get("username"):
            payload[roles["username"]] = cred_user
        if roles.get("password"):
            payload[roles["password"]] = cred_pass
        body, _h, status, _t, cookies = _http_request(
            "POST", action, timeout=timeout, data=payload,
            cookies=result["session_cookies"] or None)
        text = body.decode("utf-8", errors="replace").lower()
        if cookies:
            result["session_cookies"].update(cookies)
        if status in (200, 302, 303) and result["session_cookies"] and not re.search(r"(invalid|incorrect|failed)", text):
            result["logged_in"] = True
            result["notes"].append(f"login POST {action} status={status}")

    if result["registered"] or result["logged_in"]:
        result["credentials"] = {"username": cred_user, "password": cred_pass, "email": cred_email}
    return result


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
    _pb = urlparse(url)
    base = urlunparse((_pb.scheme or "http", _pb.netloc, "/", "", "", ""))

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

    # ── Item 5: well-known paths + sitemap/robots → more endpoints ──────
    well_known = _probe_well_known(base, timeout=min(15, timeout))
    for wk_url in well_known.get("discovered_urls") or []:
        if _host_of(wk_url) == root_host and not _is_garbage_url(wk_url):
            wk_path = wk_url.lower().split("?")[0]
            if not wk_path.endswith(_STATIC_EXT):
                same_host.add(wk_url)

    # ── Item 4: authenticated recon — register/login then re-crawl ──────
    auth_recon = _authenticated_recon(base, forms, timeout=min(20, timeout))
    if auth_recon.get("session_cookies"):
        # Re-crawl a few key pages WITH the session cookie; authenticated
        # views expose endpoints anonymous crawl can't reach.
        sess = auth_recon["session_cookies"]
        auth_pages = sorted(same_host)[:8]
        auth_found: set[str] = set()
        for page_url in auth_pages:
            praw, _ph, pstatus, _pt, _pc = _http_request(
                "GET", page_url, timeout=min(15, timeout), cookies=sess)
            if not praw or pstatus >= 400:
                continue
            pbody = praw[:MAX_HTML_BYTES].decode("utf-8", errors="replace")
            parsed_pg = _parse_html_page(page_url, pbody)
            for f in parsed_pg["forms"]:
                forms.append(f)
            for h in parsed_pg["hrefs"]:
                if _host_of(h) == root_host and not _is_garbage_url(h):
                    hp = h.lower().split("?")[0]
                    if not hp.endswith(_STATIC_EXT):
                        auth_found.add(h)
        same_host.update(auth_found)
        auth_recon["authenticated_endpoints_found"] = sorted(auth_found)[:60]

    endpoints_list = sorted(same_host)[:300]
    external_list = sorted(external)[:60]

    # ── AJAX/API-pattern endpoints (same-host only) ──────────────────────
    ajax_endpoints = sorted({
        ep for ep in same_host
        if re.search(r"/(api|graphql|rest|v\d+|services|webhook|callback|auth|login|logout|register|signup|reset|me|user|account|admin|data|search|export|import|upload|download|file|comment)s?\b", ep, re.IGNORECASE)
        or "?" in ep  # any param-bearing URL is a test target
    })[:80]

    # ── Item 1: differential probing on every param-bearing endpoint ────
    # Benign read-only probes; the response diff is the evidence that
    # turns "param exists" into "param behaves vulnerably".
    probe_signals: dict[str, dict[str, Any]] = {}
    param_endpoints = [ep for ep in endpoints_list if "?" in ep][:40]
    for ep in param_endpoints:
        sigs = _differential_probe(ep, timeout=min(12, timeout))
        # Keep only params with at least one positive signal to bound size,
        # but record the endpoint even when clean so the engine knows it
        # was probed.
        if sigs:
            probe_signals[ep] = sigs

    # ── Item 3: deep fingerprint → CVE families / nuclei tags ───────────
    fingerprint = _fingerprint_deep(headers, body)

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
        "forms": forms[:60],
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
        # ── deep-recon outputs ──
        "well_known": well_known,
        "probe_signals": probe_signals,
        "fingerprint": fingerprint,
        "auth_recon": auth_recon,
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

    # 3c) Well-known path exposures (.git/.env/web.config/sitemap/robots).
    for exp in (analysis.get("well_known") or {}).get("exposures") or []:
        sev = str(exp.get("severity") or "info")
        kind = str(exp.get("kind") or "exposure")
        findings.append({
            "title": f"Well-known path: {kind} ({exp.get('url')})",
            "severity": sev,
            "risk_score": 8 if sev == "high" else (5 if sev == "medium" else 2),
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": str(exp.get("evidence") or "")[:600],
                "url": exp.get("url"),
                "kind": f"well_known:{kind}",
                "http_status": exp.get("status"),
                "validation_status": "hypothesis" if sev == "high" else "unverified",
            },
        })

    # 3d) Differential-probe signals — the OBSERVED vulnerability evidence.
    # Each positive signal becomes a finding the hypothesis engine reads to
    # raise confidence from "param name matches" to "param behaves vuln".
    for ep, params in (analysis.get("probe_signals") or {}).items():
        for param, sig in (params or {}).items():
            if not isinstance(sig, dict) or not sig.get("any_signal"):
                continue
            hits = [k for k in (
                "sql_error", "stacktrace", "canary_reflected", "bool_diff",
                "time_anomaly", "traversal_passwd", "ssti_math_eval",
            ) if sig.get(k)]
            sev = "high" if any(h in hits for h in ("sql_error", "traversal_passwd", "ssti_math_eval")) else "medium"
            findings.append({
                "title": f"Probe diferencial: {ep}?{param} -> {', '.join(hits)}",
                "severity": sev,
                "risk_score": 8 if sev == "high" else 6,
                "source_worker": "code_analyzer",
                "details": {
                    **base_details,
                    "evidence": f"endpoint={ep} param={param} signals={hits} "
                                f"status_changes={sig.get('status_changes')} "
                                f"len_deltas={sig.get('len_deltas')}",
                    "url": ep,
                    "param": param,
                    "kind": "probe_signal",
                    "probe_signals": hits,
                    "validation_status": "hypothesis",
                    "confidence": 80,
                },
            })

    # 3e) Deep fingerprint → CVE families (drives targeted nuclei templates).
    fp = analysis.get("fingerprint") or {}
    if fp.get("versions") or fp.get("cve_families"):
        findings.append({
            "title": f"Fingerprint profundo: {', '.join(fp.get('versions') or [])[:6]}",
            "severity": "info",
            "risk_score": 3,
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": (
                    f"versions={fp.get('versions')} "
                    f"cve_families={fp.get('cve_families')} "
                    f"nuclei_tags={fp.get('nuclei_tags')}"
                ),
                "kind": "fingerprint_deep",
                "cve_families": fp.get("cve_families"),
                "nuclei_tags": fp.get("nuclei_tags"),
            },
        })

    # 3f) Authenticated recon outcome.
    auth = analysis.get("auth_recon") or {}
    if auth.get("attempted"):
        findings.append({
            "title": (
                f"Recon autenticado: registered={auth.get('registered')} "
                f"logged_in={auth.get('logged_in')}"
            ),
            "severity": "info",
            "risk_score": 2,
            "source_worker": "code_analyzer",
            "details": {
                **base_details,
                "evidence": "; ".join(auth.get("notes") or []),
                "kind": "auth_recon",
                "authenticated_endpoints": auth.get("authenticated_endpoints_found") or [],
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
