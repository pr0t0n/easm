"""Tech-stack fingerprint extractor.

Reads evidence accumulated in `vulnerabilidades_encontradas` (and optionally
the target URL) and returns a normalised list of environment tags such as
``["asp.net", "iis", "mssql", "cloudflare"]``.

Used by the supervisor and skill-runtime to steer skill selection and to
prioritise accepted learning whose content matches the detected stack.

Recognised tag families:
  - Web server / runtime:  iis, apache, nginx, lighttpd, tomcat
  - App framework / lang:  asp.net, php, node.js, express, django, flask,
                           rails, java, spring, golang, dotnet
  - CMS:                   wordpress, joomla, drupal, magento, shopify,
                           ghost, sharepoint
  - Database hints:        mssql, mysql, mariadb, postgresql, oracle,
                           mongodb, redis, elasticsearch
  - WAF / CDN:             cloudflare, akamai, awswaf, sucuri, imperva,
                           f5-bigip, fastly
  - Container / cloud:     kubernetes, docker, aws, azure, gcp

The detector is conservative: a tag is added only when a regex matches an
evidence string. Duplicates are removed and the output sorted alphabetically
so the resulting signature is stable across iterations.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable


# Patterns are anchored to common evidence formats: HTTP headers, banner
# strings, whatweb output, nikto/nuclei lines, sslscan, etc.
_TECH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # ── Web server / runtime ────────────────────────────────────────────────
    ("iis", re.compile(r"\bmicrosoft[- ]iis|server:\s*iis|x-aspnet-version", re.I)),
    ("apache", re.compile(r"\bserver:\s*apache|httpd/2\.\d|mod_php|mod_ssl", re.I)),
    ("nginx", re.compile(r"\bserver:\s*nginx|nginx/\d", re.I)),
    ("lighttpd", re.compile(r"\bserver:\s*lighttpd|lighttpd/\d", re.I)),
    ("tomcat", re.compile(r"\bapache[- ]tomcat|tomcat/\d|jsessionid|coyote/\d", re.I)),
    ("openresty", re.compile(r"\bopenresty\b", re.I)),
    # ── App framework / language ────────────────────────────────────────────
    ("asp.net", re.compile(r"\basp\.net\b|x-aspnet-version|x-aspnetmvc-version|aspnet_sessionid|\.aspx?\b|\.ashx\b", re.I)),
    ("dotnet", re.compile(r"\bx-powered-by:\s*asp\.net|\.net framework|\.net core|dotnet|\.net\b(?!\s*support)", re.I)),
    ("php", re.compile(r"\bphp/\d|x-powered-by:\s*php|phpsessid|\.php\b", re.I)),
    ("node.js", re.compile(r"\bnode\.js\b|nodejs|express(?:/\d|\b)|x-powered-by:\s*express", re.I)),
    ("django", re.compile(r"\bdjango\b|csrftoken=|sessionid=.*django", re.I)),
    ("flask", re.compile(r"\bflask\b|werkzeug/\d", re.I)),
    ("rails", re.compile(r"\bruby on rails|rails/\d|_session_id=.*rails|x-powered-by:\s*phusion", re.I)),
    ("java", re.compile(r"\bjava/\d|servlet/|jsessionid", re.I)),
    ("spring", re.compile(r"\bspring framework|spring boot|x-application-context", re.I)),
    ("golang", re.compile(r"\bgolang\b|server:\s*go-?http", re.I)),
    ("python", re.compile(r"\bpython/\d|gunicorn|uvicorn|fastapi", re.I)),
    # ── CMS ────────────────────────────────────────────────────────────────
    ("wordpress", re.compile(r"\bwordpress\b|wp-content|wp-admin|wp-includes|wpscan", re.I)),
    ("joomla", re.compile(r"\bjoomla\b|joomla!|/components/com_", re.I)),
    ("drupal", re.compile(r"\bdrupal\b|drupal/\d|x-drupal-cache|drupal\.settings", re.I)),
    ("magento", re.compile(r"\bmagento\b|mage/cookies|magento_storeconfig", re.I)),
    ("shopify", re.compile(r"\bshopify\b|x-shopify-stage|shopify\.com", re.I)),
    ("ghost", re.compile(r"\bghost cms|x-ghost-cache-status|ghost/\d", re.I)),
    ("sharepoint", re.compile(r"\bsharepoint\b|microsoftsharepointteamservices", re.I)),
    # ── DB hints (from error pages, banners, MX records, nuclei output) ────
    ("mssql", re.compile(r"\bmicrosoft sql server|mssql|sqlserver|@@version.*microsoft sql|sqlexpress", re.I)),
    ("mysql", re.compile(r"\bmysql\b|mariadb client|you have an error in your sql syntax", re.I)),
    ("mariadb", re.compile(r"\bmariadb\b|mariadb-/\d", re.I)),
    ("postgresql", re.compile(r"\bpostgresql\b|postgres/\d|psql/\d", re.I)),
    ("oracle", re.compile(r"\boracle database|oracle/\d|ora-\d{4,5}", re.I)),
    ("mongodb", re.compile(r"\bmongodb\b|mongo/\d", re.I)),
    ("redis", re.compile(r"\bredis\b|redis/\d|loading dataset in memory", re.I)),
    ("elasticsearch", re.compile(r"\belasticsearch\b|elastic/\d|elastic-search", re.I)),
    # ── WAF / CDN ──────────────────────────────────────────────────────────
    ("cloudflare", re.compile(r"\bcloudflare\b|cf-ray|server:\s*cloudflare|__cfduid", re.I)),
    ("akamai", re.compile(r"\bakamaighost\b|akamai\b|x-akamai-", re.I)),
    ("awswaf", re.compile(r"\baws[- ]waf|x-amz-cf-id|x-amz-id-2", re.I)),
    ("sucuri", re.compile(r"\bsucuri\b|x-sucuri-id|x-sucuri-cache", re.I)),
    ("imperva", re.compile(r"\bimperva\b|incapsula|x-iinfo", re.I)),
    ("f5-bigip", re.compile(r"\bbig-?ip\b|f5 networks|server:\s*bigip", re.I)),
    ("fastly", re.compile(r"\bfastly\b|x-fastly-request-id", re.I)),
    # ── Cloud / container ──────────────────────────────────────────────────
    ("kubernetes", re.compile(r"\bkubernetes\b|/api/v1/namespaces", re.I)),
    ("docker", re.compile(r"\bdocker\b|server:\s*docker", re.I)),
    ("aws", re.compile(r"\bamazonaws\.com\b|x-amz-cf-pop|x-amz-request-id", re.I)),
    ("azure", re.compile(r"\bazurewebsites\.net|x-msedge-ref|x-azure-ref", re.I)),
    ("gcp", re.compile(r"\bgooglehosted\b|gserviceaccount|x-google-cloud", re.I)),
]


# Implication map: when one tag is present we can confidently add another.
# Resolved AFTER pattern matching so explicit matches always win.
_IMPLICATIONS: list[tuple[str, str]] = [
    ("asp.net", "iis"),       # ASP.NET almost always implies IIS
    ("asp.net", "dotnet"),    # .NET is the runtime
    ("aspx", "asp.net"),
    ("wordpress", "php"),     # WP is PHP
    ("joomla", "php"),
    ("drupal", "php"),
    ("magento", "php"),
    ("sharepoint", "asp.net"),
]


def _iter_evidence_blobs(findings: Iterable[dict[str, Any]]) -> Iterable[str]:
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        yield str(finding.get("title") or "")
        details = finding.get("details") or {}
        if not isinstance(details, dict):
            continue
        yield str(details.get("evidence") or "")
        yield str(details.get("stdout") or "")
        yield str(details.get("http_headers_raw") or "")
        yield str(details.get("banner") or "")
        yield str(details.get("server") or "")
        yield str(details.get("x_powered_by") or "")
        yield str(details.get("technology") or "")
        yield str(details.get("framework") or "")
        yield str(details.get("cms") or "")
        # Generic fallback — short pieces of stdout pulled into details by parsers.
        for value in details.values():
            if isinstance(value, str) and len(value) < 4000:
                yield value


def detect_tech_stack(
    findings: list[dict[str, Any]] | None,
    target: str = "",
) -> list[str]:
    """Return a sorted, deduplicated list of tech tags inferred from evidence.

    The function is pure and safe to call on every supervisor iteration; cost
    grows linearly with the evidence corpus, which is small in practice
    (capped by the orchestrator).
    """
    blobs: list[str] = []
    if target:
        blobs.append(str(target))
    blobs.extend(blob for blob in _iter_evidence_blobs(findings or []) if blob)
    if not blobs:
        return []

    haystack = "\n".join(blobs)
    detected: set[str] = set()
    for tag, pattern in _TECH_PATTERNS:
        if pattern.search(haystack):
            detected.add(tag)

    # Apply implications until stable.
    changed = True
    while changed:
        changed = False
        for trigger, implied in _IMPLICATIONS:
            if trigger in detected and implied not in detected:
                detected.add(implied)
                changed = True

    return sorted(detected)


def tech_stack_signature(stack: list[str]) -> str:
    """Stable hash of a stack list for change-detection between iterations."""
    if not stack:
        return ""
    joined = ",".join(sorted(str(item).strip().lower() for item in stack if str(item).strip()))
    if not joined:
        return ""
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]


# Keyword groups used by the supervisor to decide whether to auto-lock a
# specific skill tactic. ``trigger_tag`` ⇒ (skill_id, preferred_tool_priority).
TECH_STACK_TACTIC_LOCKS: dict[str, dict[str, Any]] = {
    "asp.net": {
        "skill_id": "vuln-injection",
        "capability": "risk_assessment",
        "allowed_tools": ["sqlmap", "wapiti", "nuclei", "dalfox"],
        "preferred_tool": "sqlmap",
        "extra_args": {
            "sqlmap": ["--dbms=mssql", "--batch", "--level=5", "--risk=3", "--random-agent"],
            "wapiti": ["-m", "sql,blindsql", "-f", "json"],
        },
        "hypothesis": "Stack ASP.NET → testar SQLi com payloads MSSQL no parametro search/id.",
    },
    "mssql": {
        "skill_id": "vuln-injection",
        "capability": "risk_assessment",
        "allowed_tools": ["sqlmap", "wapiti", "nuclei"],
        "preferred_tool": "sqlmap",
        "extra_args": {
            "sqlmap": ["--dbms=mssql", "--batch", "--level=5", "--risk=3"],
        },
        "hypothesis": "MSSQL detectado → priorizar sqlmap --dbms=mssql para confirmar injecao.",
    },
    "php": {
        "skill_id": "vuln-injection",
        "capability": "risk_assessment",
        "allowed_tools": ["sqlmap", "dalfox", "wapiti", "nuclei"],
        "preferred_tool": "sqlmap",
        "extra_args": {
            "sqlmap": ["--dbms=mysql", "--batch", "--level=5", "--risk=3"],
        },
        "hypothesis": "Stack PHP → testar SQLi com payloads MySQL/MariaDB e XSS dalfox.",
    },
    "wordpress": {
        "skill_id": "tech-cms-fingerprint",
        "capability": "risk_assessment",
        "allowed_tools": ["wpscan", "nuclei", "nikto"],
        "preferred_tool": "wpscan",
        "extra_args": {
            "wpscan": ["--enumerate", "u,vp,vt", "--random-user-agent"],
        },
        "hypothesis": "WordPress detectado → wpscan completo de usuarios + plugins + themes vulneraveis.",
    },
    "iis": {
        "skill_id": "tech-http-fingerprint",
        "capability": "asset_discovery",
        "allowed_tools": ["nikto", "nuclei", "httpx"],
        "preferred_tool": "nikto",
        "extra_args": {},
        "hypothesis": "IIS detectado → nikto + nuclei templates IIS para misconfig.",
    },
}
