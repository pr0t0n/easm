"""Frente E — abre páginas descobertas e extrai inteligência acionável.

Equivalente controlado ao 'curl/wget + grep': faz GET na página (somente
leitura — respeita o guardrail), e do corpo extrai:
  - NOVOS endpoints/links (mesmo domínio → realimentam o teste);
  - SEGREDOS hardcoded (API keys, tokens, chaves);
  - referências a SCRIPTS de domínio EXTERNO (→ possível script injection).
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX_BYTES = 600_000  # não baixa páginas gigantes


# ── Segredos hardcoded ───────────────────────────────────────────────────────
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Key", re.compile(r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API Key/Secret", re.compile(
        r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)"""
        r"""['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{12,})['"]""")),
    ("Bearer Token", re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.=]{20,}")),
]

# ── Endpoints no corpo / JS ──────────────────────────────────────────────────
_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#?\s]+)['"]""", re.I),
    re.compile(r"""(?:fetch|axios(?:\.\w+)?)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""(?:url|endpoint|path|api|baseURL)\s*[:=]\s*['"](/[^'"]+)['"]""", re.I),
    re.compile(r"""['"](/(?:api|rest|graphql|v\d|admin|internal|service)[^'"\s]*)['"]"""),
]

_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url or "")
    return (m.group(1).lower() if m else "")


def _root_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def fetch_and_extract(url: str, scope_root: str | None = None) -> dict:
    """Abre a página (GET) e extrai endpoints, segredos e scripts externos.

    scope_root: domínio registrável do alvo (p/ separar mesmo-domínio de
    cross-domain). Somente leitura; nunca envia payload.
    """
    out = {
        "url": url, "ok": False, "status": None,
        "endpoints_same_domain": [], "endpoints_cross_domain": [],
        "secrets": [], "external_scripts": [],
    }
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers={"User-Agent": "Mozilla/5.0 (pentest-discovery)"})
            out["status"] = r.status_code
            body = r.text[: _MAX_BYTES] if r.text else ""
    except Exception as exc:
        out["error"] = type(exc).__name__
        return out

    out["ok"] = True
    base_host = _host_of(url)
    root = (scope_root or _root_domain(base_host)).lower()

    # Segredos
    seen_sec = set()
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(body):
            val = m.group(0)
            key = (label, val[:40])
            if key in seen_sec:
                continue
            seen_sec.add(key)
            out["secrets"].append({"type": label, "match": val[:80]})
            if len(out["secrets"]) >= 25:
                break

    # Endpoints
    same, cross = set(), set()
    for pat in _ENDPOINT_PATTERNS:
        for m in pat.finditer(body):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("data:", "mailto:", "tel:", "javascript:")):
                continue
            if raw.startswith("//"):
                raw = "https:" + raw
            if raw.startswith("/"):
                same.add(f"https://{base_host}{raw.split('#')[0]}")
            elif raw.startswith("http"):
                h = _host_of(raw)
                (same if _root_domain(h) == root else cross).add(raw.split("#")[0])
    out["endpoints_same_domain"] = sorted(same)[:200]
    out["endpoints_cross_domain"] = sorted(cross)[:100]

    # Scripts de domínio externo (possível script injection)
    ext_scripts = set()
    for m in _SCRIPT_SRC.finditer(body):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = "https:" + src
        if src.startswith("http"):
            h = _host_of(src)
            if h and _root_domain(h) != root:
                ext_scripts.add(src.split("#")[0])
    out["external_scripts"] = sorted(ext_scripts)[:50]

    return out
