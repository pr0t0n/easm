"""Evidence-led business-logic baseline executor for phase P13.

The live entry point accepts only a persisted execution plan produced from
observed endpoints. It records response metadata/fingerprints and never guesses
routes or object IDs, brute-forces values, authenticates with injection, or
performs generic mutations. Historical pure helpers remain for compatibility;
all legacy speculative network probes are hard-disabled.
"""

from __future__ import annotations

import os
import re
import json
import time
import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=15.0, write=8.0, pool=6.0)
# Kept only for backwards-compatible pure helpers and historical tests. Active
# execution is permanently routed through the evidence-led plan at the end of
# this module; speculative legacy probes must not be callable accidentally.
_LEGACY_SPECULATIVE_PROBES_ENABLED = False

_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "wordlists")


def _wl(filename: str, fallback: list[str]) -> list[str]:
    """Load wordlist file; return fallback if unavailable."""
    try:
        path = os.path.join(_WORDLIST_DIR, filename)
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        return lines or fallback
    except Exception:
        return fallback


# ── WORDLISTS (genéricas, extensíveis — não hardcoded por alvo) ───────────────
# Nomes de campo de VALOR de negócio (casados por substring no nome do campo).
BIZ_VALUE_FIELDS = [
    "qty", "quantity", "qtd", "quantidade", "amount", "amt", "price", "preco", "preço",
    "valor", "total", "subtotal", "cost", "value", "sum", "discount", "desconto",
    "balance", "saldo", "credit", "credito", "crédito", "points", "pontos", "fee",
    "rate", "refund", "cashback", "limit", "creditlimit", "wallet", "deposit", "withdraw",
]
# Campos PRIVILEGIADOS para mass-assignment (campo → valor adversário).
PRIV_FIELDS = {
    "role": "admin", "isAdmin": True, "is_admin": True, "admin": True, "isadmin": True,
    "status": "approved", "verified": True, "active": True, "approved": True,
    "permission": "admin", "permissions": "admin", "creditLimit": 999999, "tier": "premium",
    "deluxeToken": "x", "owner": "attacker", "is_staff": True, "superuser": True,
}
# VALORES adversários testados em cada campo de negócio (não só -1).
ADVERSARIAL_VALUES = [-1, 0, -999999, 999999999, 0.01]
# WORDLIST de nomes comuns de COLEÇÕES REST de negócio (singular/plural, casos).
# Genérica — complementa a descoberta do chromium-capture (que perde coleções
# autenticadas como cestas/pedidos que só carregam após ação do usuário).
COLLECTION_WORDLIST: list[str] = _wl("rest-collections.txt", [
    "basket", "baskets", "cart", "carts", "order", "orders", "invoice", "invoices",
    "wallet", "wallets", "payment", "payments", "coupon", "coupons", "user", "users",
    "account", "accounts", "product", "products", "transaction", "transactions",
])


def _case_variants(w: str) -> list[str]:
    # gera variações de caso comuns em APIs REST (lower, Title, e Title+s já no termo)
    return list(dict.fromkeys([w, w.lower(), w.capitalize(), w.upper(),
                               w[:-1].capitalize() + "s" if w.endswith("s") else w.capitalize() + "s"]))


def _collections_from_wordlist(c: httpx.Client, base: str, deadline: float = 0.0) -> list[str]:
    """Enumera coleções REST por wordlist (autenticado). Mantém as que devolvem
    uma lista de objetos (data:[...]). Baixo volume, dirigido por wordlist.
    `deadline` (time.monotonic) corta a varredura se o orçamento da fase estourar
    — esta wordlist pode gerar ~620 probes × 15s contra um alvo lento."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    found = []
    seen = set()
    redirect_only = 0

    def _probe(url: str) -> bool:
        nonlocal redirect_only
        if url in seen:
            return True
        seen.add(url)
        try:
            r = c.get(url)
        except Exception:
            return True
        if r.status_code in {301, 302, 303, 307, 308}:
            redirect_only += 1
            if redirect_only >= 80 and not found:
                return False
        if r.status_code == 200:
            redirect_only = 0
            try:
                data = r.json().get("data")
            except Exception:
                data = None
            if isinstance(data, list) and data and isinstance(data[0], dict):
                found.append(url)
        return True

    # 1) wordlist embutida (termos de negócio) + variações de caso
    prefixes = ["/api/", "/rest/"]
    for word in COLLECTION_WORDLIST:
        if deadline > 0 and time.monotonic() > deadline:
            break
        for variant in _case_variants(word):
            for pre in prefixes:
                if not _probe(base.rstrip("/") + pre + variant):
                    return found

    # 2) SecLists api-endpoints.txt — paths reais de APIs (sondagem direta, baixo volume)
    for entry in _load_wordlist("api-endpoints.txt", [])[:300]:
        if deadline > 0 and time.monotonic() > deadline:
            break
        if not _probe(base.rstrip("/") + "/" + entry.lstrip("/")):
            break

    return found
# Parâmetros de negócio em query string (wordlist → regex de borda).
_BIZ_PARAM = re.compile(r"(?i)\b(" + "|".join(BIZ_VALUE_FIELDS + ["coupon", "cupom", "voucher", "promo"]) + r")\b")
_VALIDATION = re.compile(r"(?i)(invalid|inv[aá]lido|must be|deve ser|not allowed|negative|negativo|"
                         r"out of range|minimum|m[ií]nimo|error|erro|reject|recusad|too low|cannot be)")
_COLLECTION_RE = re.compile(r"^/(?:api|rest|v\d)/[A-Za-z][A-Za-z0-9_]+/?$")


def _is_biz_value_field(name: str) -> bool:
    n = name.lower()
    if n == "id" or n.endswith("id"):   # FK/id — nunca é campo de valor
        return False
    return any(w in n for w in BIZ_VALUE_FIELDS)


def _finding(cls, status, sev, ep, ev, payload=None):
    return {"title": f"[{status.upper()}] business_logic/{cls}: {str(ep)[:90]}",
            "severity": sev, "risk_score": 9 if status == "confirmada" else 4,
            "details": {"tool": "bl-test", "asset": ep, "matched_at": ep, "payload": payload,
                        "evidence": ev, "vuln_family": "business_logic",
                        "verification_status": "confirmed" if status == "confirmada" else "hypothesis",
                        "discovery_method": "teste ativo de business logic (chromium-capture + REST-CRUD + read-back)"}}


# SPA business routes — loaded from wordlist so new routes can be added without
# code changes. Covers hash-mode (Angular/Vue) and history-mode (React) SPAs.
SPA_BUSINESS_ROUTES: list[str] = _wl("spa-business-routes.txt", [
    "/#/basket", "/#/order-history", "/#/wallet", "/#/account", "/#/profile",
    "/basket", "/cart", "/orders", "/account", "/profile",
])


def _capture(base: str, token: str = "", creds: dict | None = None) -> dict:
    """Chama chromium-capture (CDP) UMA vez. Preferência: LOGIN REAL via form
    (o app grava o próprio storage → finding de storage genuíno); fallback p/
    injeção de token. Navega rotas de negócio p/ disparar XHRs autenticadas
    (basket/{id}, cupom…). Retorna o dict cru (api_requests + storage)."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return {"login_status": "blocked_observed_endpoint_plan_required"}
    try:
        from urllib.parse import urljoin, urlparse

        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, verify=False) as probe:
            pre = probe.get(base)
        location = pre.headers.get("location") or ""
        if location:
            target_host = (urlparse(base).hostname or "").lower()
            redirect_host = (urlparse(urljoin(base + "/", location)).hostname or "").lower()
            if redirect_host and redirect_host != target_host:
                return {"login_status": "skipped-cross-host-redirect", "redirect_location": location}

        from app.services.kali_executor import execute_via_kali
        user = (creds or {}).get("user", "")
        pw = (creds or {}).get("pass", "")
        routes = ",".join(SPA_BUSINESS_ROUTES)
        # extra_args → argv[3..6] do cdp_capture: token, user, pass, routes
        extra = [token or "", user or "", pw or "", routes]
        res = execute_via_kali("chromium-capture", base, max_wait=110, extra_args=extra)
        return json.loads(res.get("stdout", "{}")) or {}
    except Exception:
        return {}


def _collections_from_capture(cap: dict, base: str) -> list[str]:
    """Extrai coleções REST dos endpoints reais capturados pelo chromium (SPA)."""
    cols, seen = [], set()
    from urllib.parse import urlparse
    for r in (cap.get("api_requests") or []):
        path = urlparse(r.get("url", "")).path
        if _COLLECTION_RE.match(path):
            u = base.rstrip("/") + "/" + path.strip("/")
            if u not in seen:
                seen.add(u); cols.append(u)
    return cols


# ── Dados sensíveis em storage client-side (XSS-exfiltráveis) ─────────────────
# Padrões de SEGREDO (genéricos, wordlist→regex). Observação direta = confirmada.
_SECRET_PATTERNS = [
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}")),
    ("generic_secret_hex", re.compile(r"\b[a-fA-F0-9]{32,}\b")),
    ("password", re.compile(r"(?i)\"?(pass(word)?|senha|pwd|secret|apikey|api_key|token)\"?\s*[:=]\s*\"?[^\"\s,}]{4,}")),
    ("email_pii", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]
# Chaves de storage cujo NOME já denuncia material sensível.
_SENSITIVE_KEY_RE = re.compile(r"(?i)(token|jwt|auth|secret|password|senha|apikey|api_key|"
                               r"access|refresh|session|credential|bearer|private)")


def _sensitive_storage(cap: dict, base: str, injected: str = "") -> list[dict]:
    """Detecta segredos/PII em localStorage/sessionStorage (acessível a qualquer
    JS → exfiltrável via XSS). Observação DIRETA do valor → confirmada. Genérico
    por padrões/wordlist, sem alvo hardcoded. Exclui o token que EU injetei na
    captura autenticada (senão seria FP circular) — só conta o que o APP guarda."""
    out = []
    storage = cap.get("storage") or {}
    for area in ("localStorage", "sessionStorage"):
        raw = storage.get(area)
        if not raw:
            continue
        try:
            entries = json.loads(raw) if isinstance(raw, str) else raw  # [["k","v"],...]
        except Exception:
            continue
        if not isinstance(entries, list):
            continue
        for pair in entries:
            if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
                continue
            key, val = str(pair[0]), str(pair[1])
            if injected and val == injected:
                continue   # foi EU que injetei na captura autenticada → não é do app
            hit = None
            for label, pat in _SECRET_PATTERNS:
                if pat.search(val):
                    hit = label; break
            if not hit and _SENSITIVE_KEY_RE.search(key) and len(val) >= 8:
                hit = "sensitive_key_name"
            if hit:
                out.append(_finding(
                    "exposicao_dados_sensiveis", "confirmada", "high", f"{base} [{area}.{key}]",
                    f"Dado sensível ({hit}) em {area} client-side, chave '{key}' "
                    f"(prefixo: {val[:24]}…). Acessível a qualquer JS no domínio → "
                    f"exfiltrável via XSS. Não deve residir em storage acessível por script.",
                    f"{area}.{key}"))
    return out


# ── IDOR / BOLA ativo (object-level authorization) ───────────────────────────
# Campos que indicam DONO de um objeto (wordlist genérica).
OWNERSHIP_FIELDS = ["userid", "user_id", "ownerid", "owner_id", "owner", "customerid",
                    "customer_id", "accountid", "account_id", "tenantid", "tenant_id",
                    "createdby", "created_by", "author", "uid", "user"]


def _jwt_self_id(token: str) -> object:
    """Decodifica o payload do JWT (sem validar assinatura — só p/ saber QUEM sou)
    e extrai meu identificador. Genérico: claims comuns + JuiceShop data:{id}."""
    if not token or token.count(".") < 2:
        return None
    import base64
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p.encode()))
    except Exception:
        return None
    for k in ("id", "userId", "user_id", "uid", "sub"):
        if k in payload and payload[k] not in (None, ""):
            return payload[k]
    data = payload.get("data")
    if isinstance(data, dict):
        for k in ("id", "userId", "user_id", "uid"):
            if k in data:
                return data[k]
    return None


def _bola_active(c: httpx.Client, collections: list[str], token: str) -> list[dict]:
    """Acesso indevido a objeto de OUTRO usuário (BOLA/IDOR). Lê meu id no JWT,
    enumera POUCOS ids (brute force controlado) numa coleção com campo de dono e
    confirma se um objeto de dono DIFERENTE retorna p/ mim. Somente leitura."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    out = []
    my_id = _jwt_self_id(token)
    if my_id is None:
        return out          # sem identidade própria não há como provar cross-user
    my_s = str(my_id)
    for col in collections[:10]:
        try:
            items = c.get(col).json().get("data")
        except Exception:
            continue
        if not isinstance(items, list) or not items or not isinstance(items[0], dict):
            continue
        own_field = next((k for k in items[0] if k.lower() in OWNERSHIP_FIELDS), None)
        if not own_field:
            continue
        # BASELINE/controle (disciplina anti-FP): a listagem que EU vejo precisa
        # estar ESCOPADA só a mim. Se ela já mistura donos, os objetos são públicos
        # por design (não é BOLA). Só então provo acesso a id de OUTRO dono.
        owners = {str(it.get(own_field)) for it in items if it.get(own_field) is not None}
        if my_s not in owners:
            continue                      # não apareço na listagem → sem baseline
        if owners - {my_s}:
            continue                      # listagem mistura donos → dado público, não BOLA
        my_ids = {it.get("id") for it in items if isinstance(it.get("id"), int)}
        try:
            base_id = int(my_id)
            probe = [i for i in sorted({base_id - 1, base_id + 1, 1, 2, 3}) if i not in my_ids][:6]
        except Exception:
            probe = [i for i in (1, 2, 3) if i not in my_ids]
        for oid in probe:
            try:
                rb = c.get(f"{col}/{oid}")
                obj = (rb.json().get("data") if rb.status_code == 200 else None)
            except Exception:
                continue
            if isinstance(obj, list):
                obj = obj[0] if obj else None
            if not isinstance(obj, dict):
                continue
            owner = obj.get(own_field)
            # objeto FORA da minha listagem escopada, de outro dono → BOLA real
            if owner is not None and str(owner) != my_s:
                out.append(_finding(
                    "idor_bola", "confirmada", "high", f"{col}/{oid}",
                    f"Listagem escopada só a mim (dono={my_s}), mas GET {col}/{oid} devolveu "
                    f"objeto de OUTRO dono ({own_field}={owner}). Autorização a nível de objeto "
                    f"ausente (BOLA/IDOR). Baseline: id {oid} não estava na minha listagem.",
                    f"GET {col}/{oid}"))
                break   # 1 prova por coleção basta — sem extração em massa
    return out


def _bola_single_resource(c: httpx.Client, cap: dict, base: str, token: str) -> list[dict]:
    """BOLA em recurso ÚNICO (ex.: /rest/basket/{id}) — o que a descoberta por
    coleção não pega. Pega os GET /<...>/<num> que o PRÓPRIO app fez por mim
    (esse num é MEU), confirma o campo de dono = meu id, e prova que o vizinho
    (num±1) devolve objeto de OUTRO dono. Baseline = meu próprio recurso."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    out = []
    my_id = _jwt_self_id(token)
    if my_id is None:
        return out
    my_s = str(my_id)
    from urllib.parse import urlparse
    seen_paths = set()
    for r in (cap.get("api_requests") or []):
        if str(r.get("method", "GET")).upper() != "GET":
            continue
        path = urlparse(r.get("url", "")).path
        m = re.match(r"^(/(?:rest|api|v\d)/[A-Za-z][A-Za-z0-9_/-]*?)/(\d+)$", path)
        if not m:
            continue
        coll, mine = m.group(1), int(m.group(2))
        if coll in seen_paths:
            continue
        seen_paths.add(coll)
        # 1) baseline: MEU recurso confirma o campo de dono == meu id
        try:
            mineobj = c.get(f"{base}{coll}/{mine}").json().get("data")
        except Exception:
            continue
        if isinstance(mineobj, list):
            mineobj = mineobj[0] if mineobj else None
        if not isinstance(mineobj, dict):
            continue
        own_field = next((k for k in mineobj if k.lower() in OWNERSHIP_FIELDS), None)
        if not own_field or str(mineobj.get(own_field)) != my_s:
            continue        # sem baseline confiável de propriedade → não confirma
        # 2) vizinho: outro dono acessível?
        for oid in (mine - 1, mine + 1):
            if oid <= 0 or oid == mine:
                continue
            try:
                rb = c.get(f"{base}{coll}/{oid}")
                obj = rb.json().get("data") if rb.status_code == 200 else None
            except Exception:
                continue
            if isinstance(obj, list):
                obj = obj[0] if obj else None
            if isinstance(obj, dict) and obj.get(own_field) is not None and str(obj.get(own_field)) != my_s:
                out.append(_finding(
                    "idor_bola", "confirmada", "high", f"{base}{coll}/{oid}",
                    f"Recurso único: meu {coll}/{mine} tem {own_field}={my_s}, mas {coll}/{oid} "
                    f"devolveu objeto de OUTRO dono ({own_field}={obj.get(own_field)}). "
                    f"Autorização a nível de objeto ausente (BOLA/IDOR).",
                    f"GET {coll}/{oid}"))
                break
    return out


# Endpoints de "quem sou eu" (autenticado) — wordlist genérica p/ baseline.
WHOAMI_PATHS = ["/rest/user/whoami", "/api/users/me", "/api/user/me", "/api/me", "/me",
                "/api/account", "/rest/user/me", "/api/v1/me", "/user/profile"]
LOGOUT_PATHS = ["/rest/user/logout", "/api/logout", "/api/auth/logout", "/logout",
                "/logout.php", "/api/v1/logout", "/auth/logout", "/api/users/logout"]


def _is_html(resp: httpx.Response) -> bool:
    """SPA catch-all: muitos SPAs (JuiceShop) servem index.html com HTTP 200 p/
    QUALQUER rota. Isso não é um endpoint de API. Rejeita p/ não criar baseline
    falso (disciplina anti-FP)."""
    ct = (resp.headers.get("content-type") or "").lower()
    if "html" in ct:
        return True
    body = (resp.text or "")[:200].lstrip().lower()
    return body.startswith("<!doctype") or body.startswith("<html")


def _identity(resp: httpx.Response) -> str:
    """Extrai um identificador estável da resposta autenticada (id/email/user).
    Vazio se for HTML (SPA catch-all). Procura em data/user/profile/account."""
    if _is_html(resp):
        return ""
    try:
        j = resp.json()
    except Exception:
        return ""
    cands = [j]
    if isinstance(j, dict):
        for wrap in ("data", "user", "profile", "account", "result"):
            if isinstance(j.get(wrap), dict):
                cands.append(j[wrap])
    for d in cands:
        if isinstance(d, dict):
            for k in ("id", "email", "username", "userId", "user_id"):
                if d.get(k) not in (None, ""):
                    return f"{k}={d.get(k)}"
    return ""


def _token_reuse_after_logout(base: str, token: str, cookies: dict) -> list[dict]:
    """Reuso de token: o token continua válido DEPOIS do logout? FP-guard: só
    confirma se (a) existe baseline autenticado, (b) o endpoint de logout existe
    e retorna 2xx (app reconhece o logout) e (c) o MESMO token ainda autentica a
    mesma identidade. Sem logout server-side de verdade, não afirmamos nada."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    if not token:
        return []
    out = []
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, verify=False,
                      headers=headers, cookies=dict(cookies or {})) as c:
        # (a) baseline autenticado
        whoami, ident = None, ""
        for p in WHOAMI_PATHS:
            try:
                r = c.get(base + p)
            except Exception:
                continue
            if r.status_code == 200 and _identity(r):
                whoami, ident = p, _identity(r); break
        if not whoami:
            return out          # sem baseline autenticado → não há o que provar
        # (b) logout reconhecido pelo servidor
        logout_ok = False
        for p in LOGOUT_PATHS:
            for meth in ("POST", "GET"):
                try:
                    lr = c.request(meth, base + p)
                except Exception:
                    continue
                # 2xx real (não o HTML do SPA catch-all)
                if lr.status_code < 300 and not _is_html(lr):
                    logout_ok = True; break
            if logout_ok:
                break
        if not logout_ok:
            return out          # app não tem logout server-side → não é "reuso pós-logout"
        # (c) MESMO token ainda autentica a MESMA identidade?
        try:
            r2 = c.get(base + whoami)
        except Exception:
            return out
        if r2.status_code == 200 and _identity(r2) == ident:
            out.append(_finding(
                "reuso_token", "confirmada", "medium", base + whoami,
                f"Token continua VÁLIDO após logout 2xx: {whoami} devolveu a mesma "
                f"identidade ({ident}) com o mesmo token. Sessão não invalidada server-side.",
                "GET após logout"))
    return out


def _coupon_brute(c: httpx.Client, cap: dict, base: str) -> list[dict]:
    """Brute force CONTROLADO de cupom: acha endpoint/param de cupom (captura ou
    wordlist), manda 1 código claramente inválido (baseline) e uma wordlist curta
    de códigos comuns. Confirma só se um código difere do baseline inválido."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    from urllib.parse import urlparse
    COMMON = ["WELCOME", "WELCOME10", "DISCOUNT", "DISCOUNT10", "SAVE10", "PROMO",
              "FREE", "TEST", "OFF10", "NEWUSER", "SUMMER", "BLACKFRIDAY"]
    BOGUS = "ZZINVALIDZZ999"
    out = []
    # localizar um endpoint de cupom nos requests capturados (path/template)
    cand = None
    for r in (cap.get("api_requests") or []):
        path = urlparse(r.get("url", "")).path
        if re.search(r"(?i)coupon|cupom|voucher|promo|discount", path):
            cand = re.sub(r"/[^/]*$", "/{CODE}", path) if not path.endswith("/") else path + "{CODE}"
            break
    if not cand:
        return out
    def _apply(code):
        url = base + cand.replace("{CODE}", code)
        for meth in ("PUT", "POST", "GET"):
            try:
                rr = c.request(meth, url)
            except Exception:
                continue
            if rr.status_code != 405:
                return rr
        return None
    rb = _apply(BOGUS)
    if rb is None:
        return out
    base_sig = (rb.status_code, len(rb.text or ""))
    for code in COMMON:
        rr = _apply(code)
        if rr is None:
            continue
        sig = (rr.status_code, len(rr.text or ""))
        # aceitação = 2xx E resposta diferente do código inválido (baseline)
        if rr.status_code < 300 and sig != base_sig and not _VALIDATION.search((rr.text or "")[:1500]):
            out.append(_finding(
                "brute_force_cupom", "confirmada", "medium", base + cand.replace("{CODE}", code),
                f"Cupom '{code}' aceito (HTTP {rr.status_code}, resposta difere do código inválido). "
                f"Endpoint de cupom enumerável sem rate-limit/validação adequada.",
                f"coupon={code}"))
            break   # 1 prova basta — controlado, sem flood
    return out


def _rest_crud_negative(c: httpx.Client, collections: list[str]) -> list[dict]:
    """Muta campo de negócio numérico de um objeto p/ -1 e lê de volta. Reverte."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    out = []
    for col in collections[:15]:
        try:
            r = c.get(col)
            items = r.json().get("data") if r.status_code == 200 else None
        except Exception:
            continue
        if not isinstance(items, list) or not items:
            continue
        item = items[0]
        iid = item.get("id")
        if iid is None:
            continue
        for field, val in item.items():
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                continue
            if not _is_biz_value_field(field):   # wordlist: só campo de VALOR de negócio
                continue
            confirmed = False
            tested = False
            for adv in ADVERSARIAL_VALUES:       # wordlist de valores adversários
                if adv == val:
                    continue
                for method in ("PUT", "PATCH"):
                    try:
                        rr = c.request(method, f"{col}/{iid}", json={field: adv})
                    except Exception:
                        continue
                    tested = True
                    if rr.status_code >= 400 or _VALIDATION.search((rr.text or "")[:2000]):
                        continue
                    try:
                        rb = c.get(f"{col}/{iid}")
                        stored = (rb.json().get("data", {}) or {}).get(field)
                    except Exception:
                        stored = None
                    if stored == adv:
                        out.append(_finding("manipulacao_valor", "confirmada", "high", f"{col}/{iid}",
                                            f"Campo de negócio '{field}' ACEITOU valor adversário {adv} via {method}; "
                                            f"leitura-de-volta confirmou ({field}={stored}). Sem validação server-side.",
                                            f"{field}={adv}"))
                        confirmed = True
                        try:  # REVERTE (guardrail)
                            c.request(method, f"{col}/{iid}", json={field: val})
                        except Exception:
                            pass
                        break
                if confirmed:
                    break
            if tested and not confirmed:
                out.append(_finding("manipulacao_valor", "hipotese", "medium", f"{col}/{iid}",
                                    f"Campo de negócio '{field}' mutável; valores adversários rejeitados/validados.",
                                    f"{field}=<adv>"))
    return out


_load_wordlist = _wl  # alias — callers below use _load_wordlist name


def _collections_from_swagger(c: httpx.Client, base: str) -> list[str]:
    """Acha a spec OpenAPI/Swagger (wordlist SecLists Swagger.txt) e extrai os
    endpoints REAIS — fonte definitiva (sem adivinhar). Genérico."""
    if not _LEGACY_SPECULATIVE_PROBES_ENABLED:
        return []
    cols, seen = [], set()
    paths = _load_wordlist("swagger.txt", ["api-docs/swagger.json", "swagger.json", "openapi.json", "v2/api-docs"])
    spec = None
    for p in paths[:63]:
        try:
            r = c.get(base.rstrip("/") + "/" + p.lstrip("/"))
            if r.status_code == 200 and ('"paths"' in r.text[:2000] or '"swagger"' in r.text[:500] or '"openapi"' in r.text[:500]):
                spec = r.json(); break
        except Exception:
            continue
    if not spec:
        return cols
    for path in (spec.get("paths") or {}).keys():
        # coleção REST = path sem parâmetro de template, 1-2 segmentos
        if "{" in path:
            continue
        if _COLLECTION_RE.match(path):
            u = base.rstrip("/") + path.rstrip("/")
            if u not in seen:
                seen.add(u); cols.append(u)
    return cols


def run_as_tool(
    target: str,
    extra_urls: list[str] | None = None,
    max_seconds: int = 1200,
    *,
    execution_plan: dict | None = None,
    auth_headers: dict | None = None,
    auth_cookies: dict | None = None,
) -> dict:
    """Execute only read-only baselines from an observed-endpoint contract.

    Legacy helpers remain available to dedicated validators, but this phase no
    longer guesses routes/IDs, brute-forces coupons, performs SQLi authentication,
    navigates hardcoded SPA routes, or mutates arbitrary objects.
    """
    from urllib.parse import urlparse

    base = (target if str(target).startswith("http") else f"http://{target}").rstrip("/")
    plan = dict(execution_plan or {})
    actions = [dict(row) for row in plan.get("actions") or [] if isinstance(row, dict)]
    blocked = [dict(row) for row in plan.get("blocked") or [] if isinstance(row, dict)]
    common = {
        "tool": "bl-test",
        "target": base,
        "scan_mode": "unit",
        "command": f"bl-test observed-evidence-only {base}",
        "open_ports": [],
        "findings_extracted": [],
        "execution_policy": plan.get("policy") or "observed-evidence-only",
        "guardrails": plan.get("guardrails") or {
            "guess_routes": False,
            "guess_object_ids": False,
            "brute_force": False,
            "try_sqli_auth": False,
        },
    }
    if not actions:
        return {
            **common,
            "status": "blocked_precondition",
            "return_code": 0,
            "stdout": "business_logic: 0 ações; pré-condições/contratos pendentes",
            "stderr": "",
            "parsed": {"summary": {"observed": 0, "failed": 0, "blocked": len(blocked)}, "observations": [], "blocked": blocked},
        }

    base_parsed = urlparse(base)
    deadline = time.monotonic() + max(1, min(120, int(max_seconds or 0)))
    observations: list[dict] = []
    failures = 0
    headers = {str(key): str(value) for key, value in dict(auth_headers or {}).items() if value}
    cookies = {str(key): str(value) for key, value in dict(auth_cookies or {}).items() if value}
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, verify=False, headers=headers, cookies=cookies) as client:
            for action in actions[:50]:
                if time.monotonic() > deadline:
                    blocked.append({"endpoint": action.get("endpoint"), "reasons": ["execution_budget_exhausted"]})
                    continue
                endpoint = str(action.get("endpoint") or "")
                parsed = urlparse(endpoint)
                if not endpoint or parsed.scheme not in {"http", "https"} or parsed.hostname != base_parsed.hostname:
                    blocked.append({"endpoint": endpoint, "reasons": ["outside_target_scope"]})
                    continue
                if str(action.get("method") or "GET").upper() not in {"GET", "HEAD", "OPTIONS"}:
                    blocked.append({"endpoint": endpoint, "reasons": ["state_change_not_allowed_in_baseline_executor"]})
                    continue
                try:
                    response = client.request(str(action.get("method") or "GET").upper(), endpoint)
                    body = response.content or b""
                    observations.append({
                        "endpoint": endpoint,
                        "method": str(action.get("method") or "GET").upper(),
                        "status_code": response.status_code,
                        "content_type": str(response.headers.get("content-type") or "")[:160],
                        "content_length": len(body),
                        "body_fingerprint": __import__("hashlib").sha256(body).hexdigest()[:16],
                        "redirect_location": str(response.headers.get("location") or "")[:500],
                        "flows": action.get("flows") or [],
                        "invariants": action.get("invariants") or [],
                        "evidence_status": "baseline_observed",
                    })
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    observations.append({"endpoint": endpoint, "method": action.get("method"), "evidence_status": "request_failed", "error": type(exc).__name__})
    except Exception as exc:  # noqa: BLE001
        return {**common, "status": "failed", "stdout": "", "stderr": f"{type(exc).__name__}: {exc}", "dispatch_error": type(exc).__name__}

    return {
        **common,
        "status": "done" if observations and failures == 0 else ("partial" if observations else "blocked_precondition"),
        "return_code": 0,
        "stdout": f"business_logic: {len(observations)} baselines observados; {len(blocked)} bloqueados; {failures} falhas",
        "stderr": "",
        "parsed": {
            "summary": {"observed": len([row for row in observations if row.get("evidence_status") == "baseline_observed"]), "failed": failures, "blocked": len(blocked)},
            "observations": observations,
            "blocked": blocked,
            "mutation_authorized": bool(plan.get("mutation_authorized")),
            "mutation_executed": False,
        },
    }
