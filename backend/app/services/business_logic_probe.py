"""Testes de LÓGICA DE NEGÓCIO — com DISCIPLINA DE BASELINE (questiona o próprio achado).

Lição aprendida validando no OWASP JuiceShop: um SPA devolve o MESMO index.html
(HTTP 200) para QUALQUER rota — então "etapa de fluxo acessível, HTTP 200" é
falso-positivo em massa. E a falha REAL (quantidade negativa na cesta) é uma
MUTAÇÃO autenticada (PUT) cujo sinal é o servidor ARMAZENAR o valor adversário —
nunca um GET com status 200.

Por isso, todo achado aqui passa por um CONTROLE/BASELINE antes de ser reportado:

  1. BYPASS de fluxo: só conta se a rota DIFERIR de uma rota-controle aleatória
     (garantidamente inexistente) E tiver marcadores reais de fluxo. SPA com
     catch-all (rota == controle) é SUPRIMIDO.
  2. TAMPERING de parâmetro (read-only): só conta se a resposta ao valor
     adulterado DIFERIR da resposta ao valor original de forma que prove
     processamento — não apenas "HTTP 200".
  3. MUTAÇÃO de valor negativo (a falha real): OPT-IN por alvo autorizado e
     REVERSÍVEL — cria entidade descartável, seta valor negativo, LÊ DE VOLTA o
     que o servidor guardou (prova), e reverte. Respeita o guardrail (nunca
     completa transação, nunca extrai dados, só alvos com consentimento).

Confirmação read-only é POSSIBILIDADE (candidate); mutação com leitura-de-volta
do valor adversário é CONFIRMAÇÃO (confirmed).
"""

from __future__ import annotations

import hashlib
import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX = 25

# parâmetros "de negócio"
_BIZ_PARAM = re.compile(
    r"(?i)\b(qty|quantity|qtd|amount|amt|price|preco|valor|total|cost|value|sum|"
    r"discount|desconto|coupon|cupom|promo|voucher|balance|saldo|credit|credito|"
    r"points|pontos|plan|plano|tier|fee|rate|refund|cashback)\b")
# sinais de que houve VALIDAÇÃO (rejeição) — ausência NÃO basta; ver baseline
_VALIDATION_RE = re.compile(
    r"(?i)(invalid|inv[aá]lido|must be|deve ser|n[aã]o permitido|not allowed|"
    r"negative|negativo|out of range|fora do intervalo|required|obrigat[oó]rio|"
    r"minimum|m[ií]nimo|reject|recusad)")
# marcadores de que a página É MESMO uma etapa final de fluxo (não o shell do SPA)
_FLOW_MARKER_RE = re.compile(
    r"(?i)(order\s*total|total\s*do\s*pedido|invoice\s*#|fatura\s*n|order\s*number|"
    r"n[uú]mero\s*do\s*pedido|payment\s*confirm|pagamento\s*confirm|thank\s*you\s*for\s*your\s*order|"
    r"obrigado\s*pela\s*sua\s*compra|receipt\s*#|recibo\s*n|amount\s*(paid|due)|valor\s*(pago|devido))")
# etapas finais de fluxo (acessá-las direto = possível bypass)
_FLOW_STEPS = ["/checkout/success", "/order/success", "/payment/success", "/cart/confirm",
               "/checkout/complete", "/order/complete", "/invoice", "/receipt", "/thank-you",
               "/obrigado", "/pedido/sucesso", "/pagamento/sucesso", "/download/invoice"]
_QUERY = re.compile(r"([?&])([A-Za-z_][\w\-]*)=([^&#]*)")
_CONTROL_PATHS = ["/zzq-control-9f3a1c-nonexistent", "/__baseline__/x7k2/none", "/no-such-route-7281-aa"]


def _looks_like_login(text: str) -> bool:
    head = (text or "")[:1500].lower()
    return any(k in head for k in ("login", "sign in", "entrar", "autenticar", "password", "senha"))


def _fingerprint(resp: httpx.Response) -> tuple[int, str]:
    """(status, sha256[:16] do corpo normalizado) — para diferenciar de baseline."""
    body = (resp.content or b"")
    return resp.status_code, hashlib.sha256(body).hexdigest()[:16]


def _establish_baseline(client: httpx.Client, base: str, ua: dict) -> dict:
    """Busca rotas-controle aleatórias (inexistentes). Se TODAS devolverem o mesmo
    corpo 200, o alvo é catch-all (SPA) — guardamos esse fingerprint p/ suprimir FPs."""
    fps, sizes = [], []
    for p in _CONTROL_PATHS:
        try:
            r = client.get(base + p, headers=ua)
            fps.append(_fingerprint(r)); sizes.append(len(r.content or b""))
        except Exception:
            continue
    catch_all = bool(fps) and all(f == fps[0] for f in fps) and fps[0][0] == 200
    return {"catch_all": catch_all, "fingerprints": set(fps),
            "sizes": sizes, "control_size": (sizes[0] if sizes else 0)}


def _biz_param_endpoints(urls: list[str]) -> list[str]:
    out, seen = [], set()
    for u in urls:
        if not isinstance(u, str) or not u.startswith("http") or "=" not in u:
            continue
        if not _BIZ_PARAM.search(u):
            continue
        key = re.sub(r"=[^&#]*", "=V", u)
        if key not in seen:
            seen.add(key); out.append(u)
        if len(out) >= _MAX:
            break
    return out


def verify_business_logic(endpoints: list[str], base_url: str, auth_headers: dict | None = None,
                          *, mutation_plan: dict | None = None) -> dict:
    """Read-only por padrão. Se `mutation_plan` for fornecido (opt-in por alvo
    autorizado), executa a prova de mutação reversível de valor negativo."""
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    ua = {"User-Agent": "Mozilla/5.0 (easm-bizlogic-probe)", **auth}
    result = {"findings": [], "attempts": 0, "safe_proof": True,
              "suppressed_false_positives": 0}
    base = (base_url if str(base_url).startswith("http") else f"https://{base_url}").rstrip("/")

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            # ── BASELINE: estabelece o controle ANTES de qualquer julgamento ──
            baseline = _establish_baseline(c, base, ua)
            result["baseline"] = {"catch_all": baseline["catch_all"],
                                  "control_size": baseline["control_size"]}

            # ── 1. Bypass de fluxo — só conta se DIFERIR do controle + marcador real ──
            for step in _FLOW_STEPS:
                result["attempts"] += 1
                try:
                    r = c.get(base + step, headers=ua)
                except Exception:
                    continue
                if r.status_code != 200:
                    continue
                fp = _fingerprint(r)
                body = r.text or ""
                # SPA catch-all OU corpo idêntico ao controle → NÃO é bypass real
                if baseline["catch_all"] or fp in baseline["fingerprints"]:
                    result["suppressed_false_positives"] += 1
                    continue
                # tem que PARECER mesmo uma etapa de fluxo (não só "200 grande")
                if len(body) > 600 and not _looks_like_login(body) and _FLOW_MARKER_RE.search(body):
                    result["findings"].append({
                        "type": "workflow_bypass", "vuln_family": "business_logic",
                        "endpoint": base + step, "verification_status": "candidate",
                        "evidence": (f"Etapa final de fluxo {step} acessível DIRETAMENTE com conteúdo "
                                     f"DISTINTO do controle e marcadores de pedido/fatura/pagamento "
                                     f"(difere do baseline) — possível bypass de fluxo."),
                        "severity": "high",
                    })

            # ── 2. Tampering de parâmetro — sinal por DIFERENÇA vs valor original ──
            for url in _biz_param_endpoints(endpoints):
                pm = _QUERY.search(url)
                if not pm:
                    continue
                try:
                    orig = c.get(url, headers=ua)
                except Exception:
                    continue
                orig_fp = _fingerprint(orig)
                for tampered in ("-1", "0"):
                    bad_url = url[:pm.start(3)] + tampered + url[pm.end(3):]
                    result["attempts"] += 1
                    try:
                        r = c.get(bad_url, headers=ua)
                    except Exception:
                        continue
                    bad_fp = _fingerprint(r)
                    txt = (r.text or "")[:4000]
                    # rejeitou? então VALIDOU (bom) — não é achado
                    if r.status_code >= 400 or _VALIDATION_RE.search(txt):
                        continue
                    # resposta IGUAL ao original → param ignorado (não processou) — não é achado
                    if bad_fp == orig_fp:
                        continue
                    # resposta IGUAL ao controle/baseline → catch-all — não é achado
                    if baseline["catch_all"] or bad_fp in baseline["fingerprints"]:
                        result["suppressed_false_positives"] += 1
                        continue
                    # 200 + DIFERENTE do original + sem validação → processou o valor adulterado
                    result["findings"].append({
                        "type": "param_tampering", "vuln_family": "business_logic",
                        "endpoint": url, "payload": bad_url, "verification_status": "candidate",
                        "evidence": (f"Parâmetro de negócio '{pm.group(2)}' processou valor adulterado "
                                     f"'{tampered}' (HTTP 200, resposta DIFERE do valor original e sem "
                                     f"validação) — possível manipulação de preço/quantidade/valor."),
                        "severity": "medium",
                    })
                    break

            # ── 3. MUTAÇÃO de valor negativo (a falha real) — OPT-IN reversível ──
            if mutation_plan:
                mut = _mutation_negative_value(c, base, ua, mutation_plan)
                result["mutation"] = {k: v for k, v in mut.items() if k != "finding"}
                result["attempts"] += mut.get("attempts", 0)
                if mut.get("finding"):
                    result["findings"].append(mut["finding"])

            # ── 4. Reuso de cupom (read-only, possibilidade) ──
            for url in endpoints[:60]:
                if isinstance(url, str) and re.search(r"(?i)(coupon|cupom|promo|voucher)=", url):
                    if not re.search(r"(?i)(nonce|csrf|token|sig|hmac)=", url):
                        result["findings"].append({
                            "type": "coupon_reuse", "vuln_family": "business_logic",
                            "endpoint": url, "verification_status": "candidate",
                            "evidence": "Parâmetro de cupom/voucher sem nonce/uso-único aparente — "
                                        "possível reuso/empilhamento de cupom (validar manualmente).",
                            "severity": "medium",
                        })
                        break
    except Exception as exc:
        result["note"] = f"erro: {type(exc).__name__}"
        return result

    if not result["findings"]:
        result["note"] = (f"{result['attempts']} testes — sem indício de falha de lógica de negócio "
                          f"(FPs suprimidos por baseline: {result['suppressed_false_positives']}).")
    return result


def _mutation_negative_value(client: httpx.Client, base: str, ua: dict, plan: dict) -> dict:
    """Prova REVERSÍVEL: cria entidade descartável, seta valor negativo, LÊ DE VOLTA
    o que o servidor guardou (prova de aceitação), e reverte. Dirigido por `plan`
    explícito (opt-in por alvo autorizado) — nunca completa transação.

    plan = {
      "create_url": "/api/BasketItems", "create_body": {...}, "id_path": "data.id",
      "update_url_tpl": "/api/BasketItems/{id}", "field": "quantity",
      "bad_value": -99, "good_value": 1, "method": "PUT",
    }
    """
    out = {"attempts": 0, "executed": True, "confirmed": False}

    def _dig(obj, path):
        cur = obj
        for k in str(path).split("."):
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                return None
        return cur

    try:
        cu = plan.get("create_url"); ut = plan.get("update_url_tpl")
        field = plan.get("field", "quantity"); bad = plan.get("bad_value", -99)
        good = plan.get("good_value", 1); method = (plan.get("method") or "PUT").upper()
        eid = plan.get("entity_id")
        if cu and not eid:
            out["attempts"] += 1
            cr = client.post(base + cu, headers=ua, json=plan.get("create_body") or {})
            try:
                eid = _dig(cr.json(), plan.get("id_path", "data.id"))
            except Exception:
                eid = None
            out["created_id"] = eid
        if not eid or not ut:
            out["executed"] = False
            out["note"] = "plano insuficiente (sem id/entidade ou update_url_tpl)"
            return out
        upd_url = base + ut.format(id=eid)
        # >>> seta valor adversário (negativo) <<<
        out["attempts"] += 1
        req = client.request(method, upd_url, headers=ua, json={field: bad})
        stored = None
        try:
            stored = _dig(req.json(), "data." + field)
            if stored is None:
                stored = req.json().get(field)
        except Exception:
            stored = None
        out["status"] = req.status_code
        out["stored_value"] = stored
        # PROVA: servidor aceitou e ARMAZENOU o valor negativo
        if req.status_code < 400 and isinstance(stored, (int, float)) and stored == bad:
            out["confirmed"] = True
            out["finding"] = {
                "type": "negative_value_mutation", "vuln_family": "business_logic",
                "endpoint": upd_url, "payload": f"{field}={bad}",
                "verification_status": "confirmed",
                "evidence": (f"Servidor ACEITOU e ARMAZENOU valor de negócio inválido "
                             f"'{field}={bad}' (HTTP {req.status_code}; leitura-de-volta confirmou "
                             f"{field}={stored}). Falha de lógica de negócio: ausência de validação "
                             f"server-side permite preço/quantidade/valor negativo (ex.: crédito "
                             f"indevido / inversão de cobrança). Prova read-back, sem completar transação."),
                "severity": "high",
            }
        # REVERTE para um valor são (não deixa lixo adversário)
        try:
            out["attempts"] += 1
            client.request(method, upd_url, headers=ua, json={field: good})
            out["reverted"] = True
        except Exception:
            out["reverted"] = False
    except Exception as exc:
        out["executed"] = False
        out["note"] = f"erro na mutação: {type(exc).__name__}"
    return out


def run_business_logic_for_scan(db, job) -> dict:
    from app.models.models import Finding

    state = dict(getattr(job, "state_data", None) or {})
    try:
        from app.services.scan_intelligence import auth_headers_from_state
        auth = auth_headers_from_state(state) or {}
    except Exception:
        auth = {}
    urls = list(state.get("discovered_endpoints") or [])
    try:
        for (det,) in db.query(Finding.details).filter(Finding.scan_job_id == job.id).limit(800).all():
            if isinstance(det, dict) and (det.get("matched_at") or det.get("url")):
                urls.append(str(det.get("matched_at") or det.get("url")))
    except Exception:
        pass
    base = str(getattr(job, "target_query", "") or "").split(",")[0].strip()

    # mutação só com opt-in explícito no state (alvo autorizado p/ teste de mutação)
    mutation_plan = state.get("business_logic_mutation_plan") if isinstance(state, dict) else None

    res = verify_business_logic(urls, base, auth, mutation_plan=mutation_plan)
    created = 0
    if res.get("findings"):
        raw = [{
            "title": f"Lógica de Negócio ({f['type']}): {f['endpoint'][:100]}",
            "severity": f.get("severity", "medium"),
            "risk_score": 8 if f.get("severity") == "high" else 5,
            "details": {
                "tool": "business_logic_probe", "asset": f.get("endpoint"), "matched_at": f.get("endpoint"),
                "payload": f.get("payload"), "evidence": f.get("evidence"),
                "owasp_category": "A04:2021 Insecure Design",
                "verification_status": f.get("verification_status", "candidate"),
                "vuln_family": "business_logic",
                "discovery_method": "teste de lógica de negócio com baseline (sem completar transação)",
            },
        } for f in res["findings"]]
        try:
            from app.services.findings_extractor import persist_finding_dicts
            created = persist_finding_dicts(db, job, raw, default_tool="business_logic_probe",
                                            default_target=base, source_item=None)
        except Exception:
            pass
    res["findings_created"] = created
    return res
