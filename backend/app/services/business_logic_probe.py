"""Legacy business-logic verification helpers behind evidence-led contracts.

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

The current scan entry point delegates to the canonical observed-endpoint
executor. Direct verification is blocked without an explicit execution plan;
workflow, parameter and mutation checks never run from guessed inputs.
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
                          *, mutation_plan: dict | None = None,
                          execution_plan: dict | None = None) -> dict:
    """Read-only por padrão. Se `mutation_plan` for fornecido (opt-in por alvo
    autorizado), executa a prova de mutação reversível de valor negativo."""
    plan = dict(execution_plan or {})
    if not plan:
        return {
            "findings": [], "attempts": 0, "safe_proof": True,
            "status": "blocked_precondition", "blocked": ["business_logic_execution_plan_required"],
            "suppressed_false_positives": 0,
        }
    allowed_urls = {str(row.get("endpoint") or "") for row in plan.get("actions") or [] if isinstance(row, dict)}
    endpoints = [url for url in endpoints if str(url) in allowed_urls]
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    ua = {"User-Agent": "Mozilla/5.0 (easm-bizlogic-probe)", **auth}
    result = {"findings": [], "attempts": 0, "safe_proof": True,
              "suppressed_false_positives": 0}
    base = (base_url if str(base_url).startswith("http") else f"https://{base_url}").rstrip("/")

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            # No route controls are guessed here. The canonical executor records
            # baselines only for endpoints already present in the execution plan.
            baseline = {"catch_all": False, "fingerprints": set(), "control_size": 0}
            result["baseline"] = {"status": "observed_endpoints_only", "control_size": 0}

            # A discovered final-looking route is not proof of workflow bypass.
            # A dedicated validator must supply an observed valid flow and an
            # observed negative control before it may compare transition states.
            observed_flow_steps = [
                url for url in endpoints
                if re.search(r"(?i)/(checkout|order|payment|invoice|receipt|thank-you|obrigado)(?:/|$)", url)
            ]
            result["workflow_candidates_blocked"] = len(observed_flow_steps)

            # ── 2. Tampering de parâmetro — sinal por DIFERENÇA vs valor original ──
            parameter_differential_allowed = bool(plan.get("allow_parameter_differential"))
            for url in (_biz_param_endpoints(endpoints) if parameter_differential_allowed else []):
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
            if mutation_plan and bool(plan.get("mutation_authorized")):
                mut = _mutation_negative_value(c, base, ua, mutation_plan)
                result["mutation"] = {k: v for k, v in mut.items() if k != "finding"}
                result["attempts"] += mut.get("attempts", 0)
                if mut.get("finding"):
                    result["findings"].append(mut["finding"])

            # Cupom sem nonce aparente is not proof. Replay/brute force remains
            # blocked until a dedicated disposable coupon fixture is supplied.
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
    out = {
        "attempts": 0,
        "executed": False,
        "confirmed": False,
        "reverted": None,
        "cleanup_status": "not_required",
    }

    def _dig(obj, path):
        cur = obj
        for k in str(path).split("."):
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                return None
        return cur

    cu = str(plan.get("create_url") or "")
    ut = str(plan.get("update_url_tpl") or "")
    read_tpl = str(plan.get("read_url_tpl") or "")
    delete_tpl = str(plan.get("delete_url_tpl") or "")
    field = str(plan.get("field") or "quantity")
    bad = plan.get("bad_value", -99)
    method = str(plan.get("method") or "PUT").upper()
    eid = plan.get("entity_id")
    created = False
    baseline_value: Any = None
    upd_url = ""
    if not ut or not read_tpl or (not eid and (not cu or not delete_tpl)):
        out["note"] = "mutation contract requires update/read and either an existing fixture or create/delete pair"
        return out
    try:
        if cu and not eid:
            out["attempts"] += 1
            cr = client.post(base + cu, headers=ua, json=plan.get("create_body") or {})
            eid = _dig(cr.json(), plan.get("id_path", "data.id")) if cr.status_code < 400 else None
            created = bool(eid)
            out["created_id"] = eid
        if not eid:
            out["note"] = "disposable fixture could not be resolved"
            return out
        upd_url = base + ut.format(id=eid)
        read_url = base + read_tpl.format(id=eid)
        out["attempts"] += 1
        before = client.get(read_url, headers=ua)
        before_json = before.json() if before.status_code < 400 else None
        baseline_value = _dig(before_json, str(plan.get("read_value_path") or f"data.{field}"))
        if baseline_value is None and isinstance(before_json, dict):
            baseline_value = before_json.get(field)
        out["baseline_value"] = baseline_value
        if not created and baseline_value is None:
            out["note"] = "pre-mutation snapshot unavailable"
            return out

        out["executed"] = True
        out["cleanup_status"] = "required"
        out["attempts"] += 1
        req = client.request(method, upd_url, headers=ua, json={field: bad})
        out["status"] = req.status_code
        # A mutation response is not a read-back. Verify with an independent GET.
        out["attempts"] += 1
        readback = client.get(read_url, headers=ua)
        readback_json = readback.json() if readback.status_code < 400 else None
        stored = _dig(readback_json, str(plan.get("read_value_path") or f"data.{field}"))
        if stored is None and isinstance(readback_json, dict):
            stored = readback_json.get(field)
        out["stored_value"] = stored
        if req.status_code < 400 and readback.status_code < 400 and stored == bad:
            out["confirmed"] = True
            out["finding"] = {
                "type": "negative_value_mutation", "vuln_family": "business_logic",
                "endpoint": upd_url, "payload": f"{field}=<invalid-negative>",
                "verification_status": "confirmed",
                "evidence": (
                    f"Fixture descartável aceitou {field} negativo e GET independente confirmou o estado. "
                    "O valor concreto foi minimizado; rollback e igualdade final são registrados separadamente."
                ),
                "false_positive_controls_passed": True,
                "validation_contract_satisfied": True,
                "severity": "high",
            }
    except Exception as exc:
        out["note"] = f"mutation execution error: {type(exc).__name__}"
    finally:
        if eid and out["cleanup_status"] == "required":
            try:
                out["attempts"] += 1
                if created:
                    cleanup = client.delete(base + delete_tpl.format(id=eid), headers=ua)
                    verify = client.get(base + read_tpl.format(id=eid), headers=ua)
                    restored = cleanup.status_code < 400 and verify.status_code in {404, 410}
                else:
                    cleanup = client.request(method, upd_url, headers=ua, json={field: baseline_value})
                    verify = client.get(base + read_tpl.format(id=eid), headers=ua)
                    verify_json = verify.json() if verify.status_code < 400 else None
                    final_value = _dig(verify_json, str(plan.get("read_value_path") or f"data.{field}"))
                    if final_value is None and isinstance(verify_json, dict):
                        final_value = verify_json.get(field)
                    out["final_value"] = final_value
                    restored = cleanup.status_code < 400 and final_value == baseline_value
                out["reverted"] = restored
                out["cleanup_status"] = "restored" if restored else "cleanup_failed"
            except Exception as exc:
                out["reverted"] = False
                out["cleanup_status"] = "cleanup_failed"
                out["cleanup_error"] = type(exc).__name__
        if out.get("finding") and out.get("cleanup_status") != "restored":
            out["finding"]["verification_status"] = "candidate"
            out["finding"]["validation_contract_satisfied"] = False
    return out


def run_business_logic_for_scan(db, job, *, execution_context: str = "external") -> dict:
    state = dict(getattr(job, "state_data", None) or {})
    base = str(getattr(job, "target_query", "") or "").split(",")[0].strip()
    from app.models.models import OffensiveEndpoint, ScanAuthSession
    from app.services.business_logic_intelligence import build_business_logic_execution_plan
    from app.services.business_logic_test import run_as_tool

    from app.services.execution_context_service import inventory_auth_context, normalize_execution_context

    execution_context = normalize_execution_context(execution_context)
    endpoints = db.query(OffensiveEndpoint).filter(
        OffensiveEndpoint.scan_job_id == job.id,
        OffensiveEndpoint.auth_context == inventory_auth_context(execution_context),
    ).all()
    analyses = [
        dict((dict(row.endpoint_metadata or {}).get("analysis") or {}))
        for row in endpoints
        if (dict(row.endpoint_metadata or {}).get("analysis") or {}).get("business_logic")
    ]
    valid_sessions = db.query(ScanAuthSession).filter(
        ScanAuthSession.scan_job_id == job.id,
        ScanAuthSession.status.in_(["valid", "static"]),
    ).limit(1).all()
    identities = ["user_a"] if valid_sessions and execution_context == "internal" else []
    plan = build_business_logic_execution_plan(
        analyses,
        available_identities=identities,
        mutation_plan=state.get("business_logic_mutation_plan"),
    )
    primary_session = valid_sessions[0] if valid_sessions else None
    res = run_as_tool(
        base,
        execution_plan=plan,
        auth_headers=dict(primary_session.headers or {}) if primary_session else {},
        auth_cookies=dict(primary_session.cookies or {}) if primary_session else {},
    )
    res["findings_created"] = 0
    res["execution_context"] = execution_context
    return res
