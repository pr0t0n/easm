"""Descoberta GENÉRICA de superfície — a fundação que toda skill consome.

Plataforma de pentest automatizada: NADA de rotas hardcoded. Cada skill opera
sobre o que ESTA camada DESCOBRE no alvo (qualquer ambiente: PHP form-based,
SPA REST, etc.):

  - crawl leve same-host (BFS, profundidade limitada) → páginas, links, params
  - parsing de FORMULÁRIOS (action, method, inputs, campo de senha, token CSRF)
  - endpoints extraídos do JS (para SPAs cujo login/áreas são via API, não <form>)
  - classificação: login (form OU API), forms de mudança de estado, endpoints
    com parâmetros injetáveis

Resultado alimenta SQLi, CSRF, XSS, IDOR, etc. — todas dirigidas por descoberta.
Pode ser enriquecido com os tools de fuzzing da plataforma (katana/ffuf/arjun),
mas funciona standalone para ser portável e testável.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs
import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_UA = {"User-Agent": "Mozilla/5.0 (easm-discovery)"}

_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_ATTR_RE = lambda a: re.compile(rf"{a}\s*=\s*['\"]([^'\"]*)['\"]", re.I)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
_HREF_RE = re.compile(r"""<a\b[^>]*href\s*=\s*['"]([^'"#]+)['"]""", re.I)
_JS_RE = re.compile(r"""<script\b[^>]*src\s*=\s*['"]([^'"]+\.js)['"]""", re.I)
# endpoints dentro do JS (SPAs): caminhos de API
_JS_ENDPOINT_RE = re.compile(r"""['"`](/(?:rest|api|v\d|auth|graphql|user|account|session)/[A-Za-z0-9_\-/]{1,60})['"`]""")
_LOGINish = re.compile(r"(?i)(login|signin|sign-in|auth|session|token|logon|authenticate)")
# links que DESTROEM a sessão — NUNCA seguir num crawl autenticado (auto-logout)
_LOGOUTish = re.compile(r"(?i)(logout|log-out|signout|sign-out|sair|logoff|log-off|deslogar|/exit\b)")
_PASSWORDish = re.compile(r"(?i)(pass|pwd|senha|secret)")
_USERish = re.compile(r"(?i)(user|email|login|mail|account|usuario|name)")
_CSRFish = re.compile(r"(?i)(csrf|token|nonce|authenticity|_token|xsrf)")


def _attr(tag: str, name: str) -> str:
    m = _ATTR_RE(name).search(tag)
    return m.group(1) if m else ""


def _parse_forms(html: str, page_url: str) -> list[dict]:
    forms = []
    for fm in _FORM_RE.findall(html):
        open_tag = fm[:fm.find(">") + 1]
        action = _attr(open_tag, "action")
        method = (_attr(open_tag, "method") or "get").lower()
        action_url = urljoin(page_url, action) if action else page_url
        inputs = []
        for tag in _INPUT_RE.findall(fm):
            nm = _attr(tag, "name")
            if not nm:
                continue
            typ = (_attr(tag, "type") or "text").lower()
            val = _attr(tag, "value")
            inputs.append({"name": nm, "type": typ, "value": val})
        names = [i["name"] for i in inputs]
        pw = next((i["name"] for i in inputs if i["type"] == "password" or _PASSWORDish.search(i["name"])), None)
        user = next((i["name"] for i in inputs if i["name"] != pw and (i["type"] in ("text", "email") or _USERish.search(i["name"]))), None)
        csrf = next((i["name"] for i in inputs if _CSRFish.search(i["name"])), None)
        forms.append({
            "page": page_url, "action": action_url, "method": method,
            "inputs": inputs, "input_names": names,
            "password_field": pw, "user_field": user, "csrf_field": csrf,
            "is_login": bool(pw) and bool(user),
            "is_state_change": method == "post",
        })
    return forms


def profile_target(base: str, max_pages: int = 25, max_depth: int = 2,
                   authorized: bool = False, cookies: dict | None = None,
                   seeds: list[str] | None = None) -> dict:
    if not authorized:
        return {"skipped": "alvo não autorizado"}
    base = base.rstrip("/")
    host = urlparse(base).netloc
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(base + "/", 0)] + [(s, 1) for s in (seeds or [])]
    pages, forms, param_endpoints, js_files = [], [], [], set()

    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False,
                      headers=_UA, cookies=cookies or {}) as c:
        while queue and len(pages) < max_pages:
            url, depth = queue.pop(0)
            key = url.split("#")[0]
            if key in seen:
                continue
            seen.add(key)
            try:
                r = c.get(url)
            except Exception:
                continue
            ctype = r.headers.get("content-type", "")
            if "html" not in ctype and not url.endswith((".php", "/", ".html", ".jsp", ".asp", ".aspx")):
                continue
            html = r.text or ""
            pages.append(url)
            forms.extend(_parse_forms(html, url))
            # JS bundles
            for j in _JS_RE.findall(html):
                js_files.add(urljoin(url, j))
            # links
            if depth < max_depth:
                for href in _HREF_RE.findall(html):
                    if _LOGOUTish.search(href):
                        continue  # nunca seguir logout — destruiria a sessão autenticada
                    nu = urljoin(url, href)
                    if urlparse(nu).netloc == host and nu.split("#")[0] not in seen:
                        if "?" in nu:
                            param_endpoints.append(nu)
                        queue.append((nu, depth + 1))

        # endpoints do JS (SPAs cujo login/area é via API)
        js_endpoints: set[str] = set()
        for ju in list(js_files)[:8]:
            try:
                t = c.get(ju).text
            except Exception:
                continue
            for ep in _JS_ENDPOINT_RE.findall(t):
                js_endpoints.add(base + ep)

    # classificar login: forms HTML com senha + endpoints JS "login-ish"
    login_forms = [f for f in forms if f["is_login"]]
    api_login_candidates = sorted({e for e in js_endpoints if _LOGINish.search(e)})
    # fallback de descoberta: endpoints comuns de login API (sondados, não assumidos)
    state_change_forms = [f for f in forms if f["is_state_change"]]
    # params injetáveis: dos links com ?, dos forms GET, e dos endpoints JS
    param_eps = list(dict.fromkeys(param_endpoints))

    return {
        "base": base, "host": host,
        "pages_crawled": len(pages),
        "forms": forms,
        "login_forms": login_forms,
        "api_login_candidates": api_login_candidates,
        "state_change_forms": state_change_forms,
        "param_endpoints": param_eps,
        "js_endpoints": sorted(js_endpoints),
    }
