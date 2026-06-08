"""Teste ATIVO de Business Logic — tool de backend (como code-analyzer).

Dirigido por DESCOBERTA (chromium-capture → endpoints reais do SPA) + AUTENTICAÇÃO
genérica (generic_auth). SEM rotas hardcoded. Técnica aprendida (JuiceShop/DVWA),
genérica e com guardrail (read-back + REVERTE, sem dump em massa, sem destruição):

  - Manipulação de valor (REST-CRUD): muta campo de NEGÓCIO numérico (quantity/
    price/amount/discount/balance…) de um objeto para valor adversário (-1) e
    LÊ DE VOLTA; distingue campo de negócio de FK/id. CONFIRMA se o servidor
    armazenou o valor inválido. Reverte ao valor original.
  - Manipulação de valor (GET param) p/ apps onde a BL está em query string.
  - Mass assignment: campo privilegiado (role/isAdmin/status) aceito do cliente.

Despachado via worker_dispatcher (tool 'bl-test'), fase P13.
"""

from __future__ import annotations

import os
import re
import json
import random
import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=15.0, write=8.0, pool=6.0)

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
COLLECTION_WORDLIST = [
    "basket", "baskets", "basketitem", "basketitems", "cart", "carts", "cartitem", "cartitems",
    "order", "orders", "invoice", "invoices", "wallet", "wallets", "payment", "payments",
    "coupon", "coupons", "voucher", "vouchers", "address", "addresses", "card", "cards",
    "product", "products", "quantity", "quantitys", "quantities", "user", "users",
    "account", "accounts", "subscription", "subscriptions", "transaction", "transactions",
    "delivery", "deliverys", "deliveries", "feedback", "feedbacks", "complaint", "complaints",
    "review", "reviews", "credit", "credits", "balance", "deposit", "withdraw", "membership",
    # formas PascalCase/compostas comuns em APIs REST (Sequelize/Rails-like)
    "BasketItems", "CartItems", "OrderItems", "Orders", "Users", "Cards", "Products",
    "Addresses", "Invoices", "Payments", "Coupons", "Wallets", "Subscriptions",
    "Transactions", "Quantitys", "Deliveries", "Feedbacks", "LineItems",
]


def _case_variants(w: str) -> list[str]:
    # gera variações de caso comuns em APIs REST (lower, Title, e Title+s já no termo)
    return list(dict.fromkeys([w, w.lower(), w.capitalize(), w.upper(),
                               w[:-1].capitalize() + "s" if w.endswith("s") else w.capitalize() + "s"]))


def _collections_from_wordlist(c: httpx.Client, base: str) -> list[str]:
    """Enumera coleções REST por wordlist (autenticado). Mantém as que devolvem
    uma lista de objetos (data:[...]). Baixo volume, dirigido por wordlist."""
    found = []
    seen = set()

    def _probe(url: str) -> None:
        if url in seen:
            return
        seen.add(url)
        try:
            r = c.get(url)
        except Exception:
            return
        if r.status_code == 200:
            try:
                data = r.json().get("data")
            except Exception:
                data = None
            if isinstance(data, list) and data and isinstance(data[0], dict):
                found.append(url)

    # 1) wordlist embutida (termos de negócio) + variações de caso
    prefixes = ["/api/", "/rest/"]
    for word in COLLECTION_WORDLIST:
        for variant in _case_variants(word):
            for pre in prefixes:
                _probe(base.rstrip("/") + pre + variant)

    # 2) SecLists api-endpoints.txt — paths reais de APIs (sondagem direta, baixo volume)
    for entry in _load_wordlist("api-endpoints.txt", [])[:300]:
        _probe(base.rstrip("/") + "/" + entry.lstrip("/"))

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


def _collections_from_capture(base: str) -> list[str]:
    """Descobre coleções REST via chromium-capture (endpoints reais do SPA)."""
    cols = []
    try:
        from app.services.kali_executor import execute_via_kali
        res = execute_via_kali("chromium-capture", base, max_wait=80)
        data = json.loads(res.get("stdout", "{}"))
        from urllib.parse import urlparse
        seen = set()
        for r in data.get("api_requests", []):
            path = urlparse(r.get("url", "")).path
            if _COLLECTION_RE.match(path):
                u = base.rstrip("/") + "/" + path.strip("/")
                if u not in seen:
                    seen.add(u); cols.append(u)
    except Exception:
        pass
    return cols


def _rest_crud_negative(c: httpx.Client, collections: list[str]) -> list[dict]:
    """Muta campo de negócio numérico de um objeto p/ -1 e lê de volta. Reverte."""
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


_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "wordlists")


def _load_wordlist(filename: str, fallback: list[str]) -> list[str]:
    """Carrega wordlist do SecLists (copiada p/ o repo). Fallback embutido."""
    try:
        with open(os.path.join(_WORDLIST_DIR, filename), encoding="utf-8", errors="ignore") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        return lines or fallback
    except Exception:
        return fallback


def _collections_from_swagger(c: httpx.Client, base: str) -> list[str]:
    """Acha a spec OpenAPI/Swagger (wordlist SecLists Swagger.txt) e extrai os
    endpoints REAIS — fonte definitiva (sem adivinhar). Genérico."""
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


def run_as_tool(target: str) -> dict:
    from app.services.target_discovery import profile_target
    from app.services.generic_auth import authenticate
    base = (target if str(target).startswith("http") else f"http://{target}").rstrip("/")
    findings = []
    try:
        prof = profile_target(base, authorized=True)
        auth = authenticate(base, prof, try_sqli=True)
        cookies = auth.get("session_cookies") or {}
        token = auth.get("token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        # coleções: chromium-capture (endpoints reais) + estático
        collections = _collections_from_capture(base)

        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False,
                          cookies=cookies, headers=headers) as c:
            # coleções: chromium-capture (reais) + SWAGGER/OpenAPI (spec real,
            # SecLists Swagger.txt) + WORDLIST (autenticado, SecLists api-endpoints
            # + termos de negócio). Swagger é a fonte definitiva quando existe.
            merged = collections + _collections_from_swagger(c, base) + _collections_from_wordlist(c, base)
            # dedupe case-insensitive: roteadores case-insensitive (ex.: JuiceShop)
            # resolvem /api/Products == /api/products → MESMO recurso. Mantém 1 só
            # para não gerar findings duplicados. API case-sensitive não é afetada
            # (só o caso correto devolve data:[...]).
            collections, _low = [], set()
            for u in merged:
                k = u.lower()
                if k not in _low:
                    _low.add(k); collections.append(u)
            # 1) manipulação de valor via REST-CRUD (corpo) — a técnica principal
            findings += _rest_crud_negative(c, collections)

            # 2) manipulação de valor via GET param (apps onde BL está na query)
            from urllib.parse import urlparse, parse_qs, urlunparse
            for u in (prof.get("param_endpoints") or [])[:20]:
                pr = urlparse(u); q = parse_qs(pr.query)
                for pn in q:
                    if not _BIZ_PARAM.search(pn):
                        continue
                    bu = urlunparse(pr._replace(query="")); pp = {k: v[0] for k, v in q.items()}
                    try:
                        good = c.get(bu, params=pp); bad = c.get(bu, params={**pp, pn: "-1"})
                    except Exception:
                        continue
                    if bad.status_code < 400 and not _VALIDATION.search((bad.text or "")[:3000]) and bad.text != good.text:
                        findings.append(_finding("manipulacao_valor_query", "confirmada", "high", bu,
                                                 f"Param de negócio '{pn}' aceitou -1 (HTTP {bad.status_code}).", f"{pn}=-1"))

            # 3) mass assignment em forms de criação/perfil
            for f in (prof.get("forms") or []):
                if f.get("method") != "post" or not re.search(r"(?i)user|account|profile|register|cadastr", f.get("action", "")):
                    continue
                data = {i["name"]: (i.get("value") or f"x{random.randint(100,999)}") for i in f.get("inputs", []) if i.get("name")}
                data.update(PRIV_FIELDS)
                try:
                    r = c.post(f["action"], data=data)
                    if r.status_code in (200, 201) and ('"role":"admin"' in r.text.replace(" ", "") or '"isAdmin":true' in r.text.replace(" ", "")):
                        findings.append(_finding("mass_assignment", "confirmada", "critical", f["action"],
                                                 "Campo privilegiado (role=admin/isAdmin) aceito do cliente.", "role=admin"))
                except Exception:
                    pass

        summary = {"confirmada": sum(1 for x in findings if "[CONFIRMADA]" in x["title"]),
                   "hipotese": sum(1 for x in findings if "[HIPOTESE]" in x["title"])}
        return {"tool": "bl-test", "target": base, "scan_mode": "unit", "status": "done",
                "command": f"bl-test (chromium-capture+auth+REST-CRUD) {base}", "return_code": 0,
                "stdout": f"business_logic: {summary} | auth={auth.get('where')} | coleções={len(collections)}",
                "stderr": "", "open_ports": [], "parsed": {"summary": summary, "collections": collections},
                "findings_extracted": findings}
    except Exception as exc:
        return {"tool": "bl-test", "target": base, "scan_mode": "unit", "status": "failed",
                "command": f"bl-test {base}", "stdout": "", "stderr": f"{type(exc).__name__}: {exc}",
                "open_ports": [], "dispatch_error": f"{type(exc).__name__}: {exc}"}
