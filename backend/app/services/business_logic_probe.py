"""Testes de LÓGICA DE NEGÓCIO (os que faltavam) — read-only, possibilidade.

Lógica de negócio é o ponto mais difícil p/ automação: exige entender o fluxo
da app. Aqui cobrimos os padrões DETECTÁVEIS com segurança (sem completar
transação — respeita o guardrail), reportados como POSSIBILIDADE (candidate):

  1. TAMPERING de parâmetro de negócio (preço/qtd/valor/desconto): envia valor
     negativo/zero via GET e vê se é ACEITO sem validação.
  2. BYPASS de fluxo (workflow/step-skip): acessa direto etapas finais
     (checkout/success/invoice) sem passar pelas anteriores.
  3. REUSO de cupom/voucher: detecta parâmetro de cupom sem nonce/uso-único.

Confirmação REAL (ex.: comprar com preço alterado) exige fluxo autenticado
multi-etapa + raciocínio — fora do escopo seguro automatizável; aqui sinalizamos
a possibilidade para o analista validar.
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)
_MAX = 25

# parâmetros "de negócio"
_BIZ_PARAM = re.compile(
    r"(?i)\b(qty|quantity|qtd|amount|amt|price|preco|valor|total|cost|value|sum|"
    r"discount|desconto|coupon|cupom|promo|voucher|balance|saldo|credit|credito|"
    r"points|pontos|plan|plano|tier|fee|rate|refund|cashback)\b")
# sinais de que houve VALIDAÇÃO (rejeição) — ausência = aceitou o valor adulterado
_VALIDATION_RE = re.compile(
    r"(?i)(invalid|inv[aá]lido|must be|deve ser|n[aã]o permitido|not allowed|"
    r"negative|negativo|out of range|fora do intervalo|required|obrigat[oó]rio|"
    r"minimum|m[ií]nimo|error|erro|reject)")
# etapas finais de fluxo (acessá-las direto = possível bypass)
_FLOW_STEPS = ["/checkout/success", "/order/success", "/payment/success", "/cart/confirm",
               "/checkout/complete", "/order/complete", "/invoice", "/receipt", "/thank-you",
               "/obrigado", "/pedido/sucesso", "/pagamento/sucesso", "/download/invoice"]
_QUERY = re.compile(r"([?&])([A-Za-z_][\w\-]*)=([^&#]*)")


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


def _looks_like_login(text: str) -> bool:
    head = (text or "")[:1500].lower()
    return any(k in head for k in ("login", "sign in", "entrar", "autenticar", "password", "senha"))


def verify_business_logic(endpoints: list[str], base_url: str, auth_headers: dict | None = None) -> dict:
    auth = {k: v for k, v in (auth_headers or {}).items() if v}
    ua = {"User-Agent": "Mozilla/5.0 (easm-bizlogic-probe)", **auth}
    result = {"findings": [], "attempts": 0, "safe_proof": True}
    base = (base_url if str(base_url).startswith("http") else f"https://{base_url}").rstrip("/")

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False) as c:
            # ── 1. Tampering de parâmetro de negócio (GET, read-only) ─────────
            for url in _biz_param_endpoints(endpoints):
                m = _BIZ_PARAM.search(url)
                pm = _QUERY.search(url)
                if not pm:
                    continue
                for tampered in ("-1", "0"):
                    bad_url = url[:pm.start(3)] + tampered + url[pm.end(3):]
                    result["attempts"] += 1
                    try:
                        r = c.get(bad_url, headers=ua)
                    except Exception:
                        continue
                    # aceitou se 200 e SEM sinal de validação/rejeição
                    if r.status_code == 200 and not _VALIDATION_RE.search((r.text or "")[:4000]):
                        result["findings"].append({
                            "type": "param_tampering", "vuln_family": "business_logic",
                            "endpoint": url, "payload": bad_url,
                            "evidence": (f"Parâmetro de negócio '{pm.group(2)}' aceitou valor adulterado "
                                         f"'{tampered}' (HTTP 200, sem validação visível) — possível "
                                         f"manipulação de preço/quantidade/valor."),
                            "severity": "medium",
                        })
                        break

            # ── 2. Bypass de fluxo (acesso direto a etapa final) ──────────────
            for step in _FLOW_STEPS:
                result["attempts"] += 1
                try:
                    r = c.get(base + step, headers=ua)
                except Exception:
                    continue
                body = r.text or ""
                if r.status_code == 200 and len(body) > 600 and not _looks_like_login(body):
                    result["findings"].append({
                        "type": "workflow_bypass", "vuln_family": "business_logic",
                        "endpoint": base + step,
                        "evidence": (f"Etapa final de fluxo {step} acessível DIRETAMENTE (HTTP 200, "
                                     f"sem login/redirecionamento) — possível bypass de fluxo "
                                     f"(ex.: pular pagamento)."),
                        "severity": "high",
                    })

            # ── 3. Reuso de cupom/voucher (sem nonce aparente) ────────────────
            for url in endpoints[:60]:
                if isinstance(url, str) and re.search(r"(?i)(coupon|cupom|promo|voucher)=", url):
                    if not re.search(r"(?i)(nonce|csrf|token|sig|hmac)=", url):
                        result["findings"].append({
                            "type": "coupon_reuse", "vuln_family": "business_logic",
                            "endpoint": url,
                            "evidence": "Parâmetro de cupom/voucher sem nonce/uso-único aparente — "
                                        "possível reuso/empilhamento de cupom.",
                            "severity": "medium",
                        })
                        break
    except Exception as exc:
        result["note"] = f"erro: {type(exc).__name__}"
        return result

    if not result["findings"]:
        result["note"] = f"{result['attempts']} testes — sem indício de falha de lógica de negócio."
    return result


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

    res = verify_business_logic(urls, base, auth)
    created = 0
    if res.get("findings"):
        raw = [{
            "title": f"Lógica de Negócio ({f['type']}): {f['endpoint'][:100]}",
            "severity": f.get("severity", "medium"),
            "risk_score": 8 if f.get("severity") == "high" else 5,
            "details": {
                "tool": "business_logic_probe", "asset": f.get("endpoint"), "matched_at": f.get("endpoint"),
                "payload": f.get("payload"), "evidence": f.get("evidence"),
                "owasp_category": "A04:2021 Insecure Design", "verification_status": "candidate",
                "vuln_family": "business_logic",
                "discovery_method": "teste de lógica de negócio read-only (sem completar transação)",
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
