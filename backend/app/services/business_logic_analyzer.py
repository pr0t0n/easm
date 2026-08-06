"""
business_logic_analyzer.py — Análise de lógica de negócio por contexto de serviço.

Diferente de scanners genéricos, aqui o sistema entende O QUE o serviço faz
e gera testes/findings específicos ao tipo de negócio:

  Serviço financeiro → testar: transferências duplicadas, saldo negativo,
                               bypass de autenticação, IDOR em contas, BOLA
  Docker/Portainer   → testar: API sem auth, env vars expostas, container escape
  API REST genérica  → testar: IDs sequenciais, métodos HTTP não esperados,
                               campos extras aceitos silenciosamente, mass assignment
  Auth service       → testar: JWT sem verificação, token reutilizável,
                               password reset abuse, 2FA bypass
  Dev environment    → testar: debug endpoints, stack traces, SQL em queries,
                               credenciais hardcoded em respostas
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
from datetime import datetime
from typing import Any

import requests

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (EASM-SecurityScanner/2.0; +https://scriptkidd.o)",
    "Accept": "application/json, text/html, */*",
}

# Set once per analyze_business_logic() call (see its `finally` reset) so every
# test_* function's _safe_get/_safe_post automatically carries the real
# captured session — previously every test in this module only ever made
# anonymous requests, which silently defeated auth-gated checks (rate limit,
# IDOR, mass assignment) even when a valid session existed for the scan.
_auth_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "_business_logic_auth_context", default={}
)

# ─────────────────────────────────────────────────────────────────────────────
# Service type classification
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_PROFILES: dict[str, dict] = {
    "financial_api": {
        "keywords": ["bank", "payment", "invoice", "billing", "pix", "boleto",
                     "finance", "wallet", "transfer", "account", "transaction"],
        "risk": "critical",
        "tests": ["idor_accounts", "negative_balance", "duplicate_transfer",
                  "unauthenticated_read", "bola_check", "mass_assignment",
                  "race_condition_financial", "verbose_errors"],
    },
    "container_management": {
        "keywords": ["portainer", "docker", "kubernetes", "rancher", "k8s",
                     "container", "swarm"],
        "risk": "critical",
        "tests": ["docker_api_unauth", "env_vars_leak", "container_list",
                  "exec_unauth", "registry_access"],
    },
    "auth_service": {
        "keywords": ["auth", "sso", "login", "oauth", "identity", "token",
                     "keycloak", "passport", "jwt", "session"],
        "risk": "high",
        "tests": ["jwt_none_alg", "password_reset_poisoning", "enum_users",
                  "token_reuse", "brute_force_lockout", "2fa_bypass",
                  "mass_assignment"],
    },
    "admin_panel": {
        "keywords": ["admin", "administrator", "manager", "console", "management",
                     "wp-admin", "cpanel", "plesk"],
        "risk": "high",
        "tests": ["default_creds", "unauthenticated_access", "info_disclosure_admin",
                  "cache_deception"],
    },
    "api_gateway": {
        "keywords": ["api", "gateway", "graphql", "rest", "v1", "v2", "v3",
                     "endpoint", "service", "microservice"],
        "risk": "high",
        "tests": ["idor_sequential", "http_method_abuse", "mass_assignment",
                  "verbose_errors", "rate_limit_absent", "bola_check",
                  "graphql_exposure", "cache_deception", "open_cors"],
    },
    "node_js_app": {
        "keywords": ["node", "nodejs", "express", "nestjs", "next", "nuxt",
                     "gatsby", "vercel", "netlify", "heroku"],
        "risk": "high",
        "tests": ["js_pollution", "mass_assignment", "verbose_errors",
                  "rate_limit_absent", "open_cors", "debug_mode"],
    },
    "data_storage": {
        "keywords": ["storage", "s3", "blob", "bucket", "file", "upload",
                     "media", "assets", "cdn"],
        "risk": "high",
        "tests": ["bucket_listing", "unauthenticated_download", "path_traversal_upload",
                  "cache_deception"],
    },
    "monitoring": {
        "keywords": ["grafana", "kibana", "prometheus", "zabbix", "nagios",
                     "datadog", "monitor", "metrics", "alerting"],
        "risk": "medium",
        "tests": ["unauthenticated_access", "info_disclosure_env", "api_exposure",
                  "graphql_exposure"],
    },
    "development": {
        "keywords": ["dev-", "-dev.", "staging", "homolog", "hml", "test-", "-test.",
                     "sandbox", "debug", "uat"],
        "risk": "high",
        "tests": ["debug_mode", "stack_trace", "verbose_errors",
                  "hardcoded_secrets", "open_cors", "js_pollution",
                  "graphql_exposure"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Specific business logic tests
# ─────────────────────────────────────────────────────────────────────────────

class BusinessLogicFinding:
    def __init__(
        self,
        title: str,
        severity: str,
        test_type: str,
        domain: str,
        evidence: str,
        description: str,
        reproduction_steps: list[str],
        business_impact: str,
        cvss_estimate: float = 0.0,
    ):
        self.title = title
        self.severity = severity
        self.test_type = test_type
        self.domain = domain
        self.evidence = evidence
        self.description = description
        self.reproduction_steps = reproduction_steps
        self.business_impact = business_impact
        self.cvss_estimate = cvss_estimate


def _merged_request_kwargs(explicit_headers: dict[str, str] | None, explicit_cookies: Any) -> tuple[dict, Any]:
    auth = _auth_context.get()
    merged_headers = {**_HEADERS, **(auth.get("headers") or {}), **(explicit_headers or {})}
    cookies = explicit_cookies if explicit_cookies is not None else (auth.get("cookies") or None)
    return merged_headers, cookies


def _safe_get(url: str, *, headers: dict[str, str] | None = None, cookies: Any = None, **kwargs) -> requests.Response | None:
    # `headers`/`cookies` are named explicitly (not left in **kwargs) so callers
    # can override/extend without colliding with the headers=_HEADERS this
    # function used to hardcode — passing headers={...} used to raise
    # "got multiple values for keyword argument 'headers'", silently swallowed
    # by the except below, which meant every test_open_cors call with a custom
    # Origin header always failed and returned None.
    merged_headers, merged_cookies = _merged_request_kwargs(headers, cookies)
    try:
        r = requests.get(url, timeout=_DEFAULT_TIMEOUT, headers=merged_headers,
                         cookies=merged_cookies, verify=False, allow_redirects=True, **kwargs)
        return r
    except Exception as e:
        logger.debug("GET %s failed: %s", url, e)
        return None


def _safe_post(
    url: str, data: Any = None, json_data: Any = None, *,
    headers: dict[str, str] | None = None, cookies: Any = None, **kwargs,
) -> requests.Response | None:
    merged_headers, merged_cookies = _merged_request_kwargs(headers, cookies)
    try:
        r = requests.post(url, timeout=_DEFAULT_TIMEOUT, headers=merged_headers,
                          cookies=merged_cookies, verify=False, allow_redirects=False,
                          data=data, json=json_data, **kwargs)
        return r
    except Exception as e:
        logger.debug("POST %s failed: %s", url, e)
        return None


# ── Docker / Container Management Tests ──────────────────────────────────────

def test_docker_api_unauth(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    findings = []
    docker_paths = [
        "/api/containers/json",     # Portainer list containers
        "/v1.41/containers/json",   # Docker API
        "/api/endpoints",           # Portainer endpoints
        "/api/stacks",              # Portainer stacks
        "/api/users",               # Portainer users
        "/api/status",              # Portainer status
        "/api/settings",            # Portainer settings
        "/api/registries",          # Docker registries (CRITICAL: may have push creds)
    ]

    for path in docker_paths:
        url = base_url.rstrip("/") + path
        r = _safe_get(url)
        if not r:
            continue

        if r.status_code == 200:
            try:
                data = r.json()
                count = len(data) if isinstance(data, list) else "object"
                findings.append(BusinessLogicFinding(
                    title=f"Docker/Portainer API Não Autenticada: {path}",
                    severity="critical",
                    test_type="docker_api_unauth",
                    domain=domain,
                    evidence=f"HTTP 200 em {url} sem autenticação. Retornou {count} items.",
                    description=(
                        f"O endpoint {path} está acessível sem autenticação. "
                        f"Um atacante pode listar, criar e executar comandos em containers."
                    ),
                    reproduction_steps=[
                        f"curl -s '{url}' | python3 -m json.tool",
                        "# Se retornar lista de containers ou settings: API exposta",
                        "# Para executar comandos: POST /api/containers/CONTAINER_ID/exec",
                    ],
                    business_impact=(
                        "Comprometimento total da infraestrutura de containers. "
                        "Possível acesso ao host, roubo de secrets em variáveis de ambiente, "
                        "e deployment de containers maliciosos."
                    ),
                    cvss_estimate=10.0,
                ))
            except Exception:
                pass

    return findings


def test_env_vars_leak(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    findings = []
    # Try to get env vars from container inspect or actuator
    env_paths = [
        ("/api/endpoints/1/docker/containers/json", "portainer_containers"),
        ("/actuator/env", "spring_actuator"),
        ("/v1.41/info", "docker_info"),
    ]
    for path, test_name in env_paths:
        url = base_url.rstrip("/") + path
        r = _safe_get(url)
        if not r or r.status_code != 200:
            continue
        text = r.text.lower()
        sensitive_patterns = ["password", "secret", "api_key", "token", "database_url",
                               "aws_access", "private_key", "db_pass"]
        found = [p for p in sensitive_patterns if p in text]
        if found:
            findings.append(BusinessLogicFinding(
                title=f"Variáveis de Ambiente Sensíveis Expostas via {test_name}",
                severity="critical",
                test_type="env_vars_leak",
                domain=domain,
                evidence=f"Padrões sensíveis encontrados em {url}: {', '.join(found)}",
                description=(
                    f"O endpoint {path} expõe variáveis de ambiente sem autenticação. "
                    f"Padrões como '{', '.join(found)}' sugerem credenciais expostas."
                ),
                reproduction_steps=[
                    f"curl -s '{url}' | python3 -m json.tool | grep -i 'password\\|secret\\|key\\|token'",
                ],
                business_impact="Exposição de credenciais de banco de dados, APIs e serviços internos.",
                cvss_estimate=9.1,
            ))
    return findings


# ── Financial API Tests ───────────────────────────────────────────────────────

def test_idor_accounts(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Testa se IDs de contas são sequenciais e acessíveis sem auth."""
    findings = []
    account_paths = [
        "/api/v1/accounts/{id}",
        "/api/accounts/{id}",
        "/api/users/{id}",
        "/api/customers/{id}",
        "/api/v1/transactions/{id}",
    ]

    for path_template in account_paths:
        # Test IDs 1, 2, 3 to see if they return different data
        responses = []
        for id_val in [1, 2, 3, 100]:
            url = base_url.rstrip("/") + path_template.format(id=id_val)
            r = _safe_get(url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    responses.append((id_val, r.status_code, data))
                except Exception:
                    responses.append((id_val, r.status_code, {}))

        if len(responses) >= 2:
            # Check if different IDs return different data (IDOR confirmed)
            data_set = set(json.dumps(resp[2], sort_keys=True) for resp in responses)
            if len(data_set) > 1:
                findings.append(BusinessLogicFinding(
                    title=f"IDOR/BOLA — IDs Sequenciais Acessíveis: {path_template}",
                    severity="high",
                    test_type="idor_accounts",
                    domain=domain,
                    evidence=(
                        f"IDs 1, 2, 3 retornam dados DIFERENTES sem autenticação em {path_template}. "
                        f"Acesso a recursos de outros usuários confirmado."
                    ),
                    description=(
                        "Broken Object Level Authorization (BOLA/IDOR): a API retorna dados "
                        "de outros usuários apenas trocando o ID na URL. Sem autenticação necessária."
                    ),
                    reproduction_steps=[
                        f"curl -s '{base_url}{path_template.format(id=1)}'",
                        f"curl -s '{base_url}{path_template.format(id=2)}'",
                        "# Compare os resultados — se diferentes: IDOR confirmado",
                        "# Para enumerar: for i in $(seq 1 1000); do curl {url/$i}; done",
                    ],
                    business_impact=(
                        "Acesso não autorizado a dados financeiros de outros clientes: "
                        "saldo, histórico de transações, dados pessoais. Violação LGPD + PCI DSS."
                    ),
                    cvss_estimate=8.1,
                ))
    return findings


def test_verbose_errors(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Detecta stack traces, SQL errors, paths internos em respostas de erro."""
    findings = []
    test_urls = [
        base_url + "/api/v1/accounts/999999999",
        base_url + "/api/users/../../etc/passwd",
        base_url + "/api/search?q=' OR 1=1--",
        base_url + "/api/v1/???INVALID???",
    ]
    sensitive_patterns = [
        (r"at \w+\.\w+\([\w.]+:\d+\)", "Java stack trace"),
        (r"Traceback \(most recent call last\)", "Python stack trace"),
        (r"SELECT.*FROM.*WHERE", "SQL query exposed"),
        (r"/home/\w+/", "Internal filesystem path"),
        (r"mysql_connect|mysqli_connect|pg_connect", "DB connection string"),
        (r"ORA-\d{5}", "Oracle DB error"),
        (r"Warning: .* on line \d+", "PHP warning"),
        (r"System\.Data\.SqlClient", ".NET SQL error"),
    ]

    for url in test_urls:
        r = _safe_get(url)
        if not r:
            continue
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                findings.append(BusinessLogicFinding(
                    title=f"Erro Verboso Expõe Informação Interna: {desc}",
                    severity="medium",
                    test_type="verbose_errors",
                    domain=domain,
                    evidence=f"Padrão '{desc}' encontrado em resposta de {url}",
                    description=(
                        f"A aplicação retorna informações internas em erros: {desc}. "
                        f"Isso revela tecnologias, caminhos e lógica interna ao atacante."
                    ),
                    reproduction_steps=[
                        f"curl -s '{url}'",
                        "# Verificar stack trace, SQL queries ou paths internos na resposta",
                    ],
                    business_impact="Facilita ataques direcionados ao revelar tecnologias e estrutura interna.",
                    cvss_estimate=5.3,
                ))
                break  # one finding per URL
    return findings


def test_open_cors(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Testa CORS misconfiguration — wildcard ou origem reflexiva."""
    findings = []
    r = _safe_get(
        base_url,
        headers={"Origin": "https://evil-attacker.com"},
    )
    if not r:
        return findings

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append(BusinessLogicFinding(
            title="CORS Crítico: Wildcard + Allow-Credentials",
            severity="high",
            test_type="open_cors",
            domain=domain,
            evidence=f"ACAO: {acao} | ACAC: {acac}",
            description=(
                "CORS configurado com wildcard (*) E Allow-Credentials=true. "
                "Qualquer site pode fazer requisições autenticadas a esta API. "
                "Browsers modernos bloqueiam isso, mas ambientes corporativos com "
                "proxies podem ser vulneráveis."
            ),
            reproduction_steps=[
                f"curl -H 'Origin: https://evil.com' -I '{base_url}'",
                "# Verificar: Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
            ],
            business_impact="Cross-Origin request com cookies de sessão de usuários autenticados.",
            cvss_estimate=7.5,
        ))
    elif acao == "https://evil-attacker.com":
        # Reflected origin — full CORS bypass
        findings.append(BusinessLogicFinding(
            title="CORS Crítico: Origem Refletida (Any-Origin Bypass)",
            severity="critical",
            test_type="open_cors",
            domain=domain,
            evidence=f"Origin 'evil-attacker.com' foi refletida no ACAO header: {acao}",
            description=(
                "A API reflete a origem da request no header CORS sem validação. "
                "Qualquer origem pode fazer requests cross-origin — incluindo roubo de dados "
                "de usuários autenticados via JavaScript malicioso."
            ),
            reproduction_steps=[
                f"curl -H 'Origin: https://evil.com' -H 'Cookie: session=victim' '{base_url}/api/profile'",
                "# Se ACAO retornar evil.com: CORS bypass total confirmado",
            ],
            business_impact="Exfiltração de dados de qualquer usuário autenticado via site malicioso.",
            cvss_estimate=9.1,
        ))

    # A completely different (and common) bug class from the two checks above:
    # an allowlist regex without ^...$ anchors matches on substring, so an
    # origin that merely CONTAINS the real domain as a prefix — with an
    # attacker-controlled suffix — passes validation even though neither a
    # wildcard nor an exact reflection of a throwaway origin would reveal it.
    # Confirmed live against a real target during this session: nuclei's
    # generic cors-misconfig template caught something here but only at
    # "info" severity with no reflected-origin proof — this test constructs
    # the actual bypass and checks whether IT specifically gets reflected.
    suffix_origin = f"https://{domain}.attacker.com"
    r_suffix = _safe_get(base_url, headers={"Origin": suffix_origin})
    if r_suffix:
        acao_suffix = r_suffix.headers.get("Access-Control-Allow-Origin", "")
        acac_suffix = r_suffix.headers.get("Access-Control-Allow-Credentials", "")
        if acao_suffix == suffix_origin:
            findings.append(BusinessLogicFinding(
                title="CORS Crítico: Regex de Origem Sem Âncora (Domain-Suffix Bypass)",
                severity="high" if acac_suffix.lower() == "true" else "medium",
                test_type="open_cors",
                domain=domain,
                evidence=(
                    f"Origin '{suffix_origin}' (domínio real + sufixo controlado pelo atacante) "
                    f"foi refletida no ACAO header: {acao_suffix} | ACAC: {acac_suffix}"
                ),
                description=(
                    "A política de CORS valida a origem por substring/prefixo (regex sem "
                    f"âncoras ^...$) em vez de allowlist exata — um domínio atacante que apenas "
                    f"começa com '{domain}' (ex.: {domain}.attacker.com) passa na validação."
                ),
                reproduction_steps=[
                    f"curl -sk -I '{base_url}' -H 'Origin: {suffix_origin}'",
                    "# Se Access-Control-Allow-Origin refletir esse Origin: bypass confirmado",
                ],
                business_impact=(
                    "Qualquer domínio registrável pelo atacante com esse prefixo realiza requests "
                    "cross-origin autenticadas caso Allow-Credentials também seja true."
                ),
                cvss_estimate=8.1 if acac_suffix.lower() == "true" else 6.5,
            ))
    return findings


def test_rate_limit_absent(base_url: str, domain: str, extra_paths: list[str] | None = None) -> list[BusinessLogicFinding]:
    """Verifica ausência de rate limiting em endpoints de auth.

    Real auth paths are rarely one of a handful of common guesses (e.g. the
    Valid Platform ID API uses /api/clients/auth/authorize-user) — testing
    only hardcoded common paths gets 404s and silently finds nothing on any
    target that doesn't happen to use one of them. `extra_paths` lets the
    caller pass paths the recon phase actually discovered for this scan
    (auth-like URLs from the offensive endpoint inventory), tried first.
    """
    findings = []
    default_paths = ["/api/auth/login", "/api/login", "/login", "/api/v1/auth",
                      "/api/users/login", "/auth/token"]
    auth_paths = list(dict.fromkeys((extra_paths or []) + default_paths))

    for path in auth_paths:
        url = base_url.rstrip("/") + path
        responses = []
        for _ in range(10):
            r = _safe_post(url, json_data={"username": "test@test.com", "password": "wrong"})
            if r:
                responses.append(r.status_code)

        if len(responses) >= 5 and all(s != 429 and s != 423 for s in responses):
            # No rate limiting detected
            if any(s in [400, 401, 403] for s in responses):
                findings.append(BusinessLogicFinding(
                    title=f"Ausência de Rate Limiting em {path}",
                    severity="medium",
                    test_type="rate_limit_absent",
                    domain=domain,
                    evidence=(
                        f"10 requests para {url} sem receber 429. "
                        f"Códigos recebidos: {set(responses)}"
                    ),
                    description=(
                        f"O endpoint {path} não implementa rate limiting. "
                        f"Permite brute force de credenciais sem bloqueio."
                    ),
                    reproduction_steps=[
                        f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {domain} http-post-form '{path}:username=^USER^&password=^PASS^:Invalid'",
                        "# Ou: ffuf -w wordlist.txt -X POST -d 'password=FUZZ' -u {url}",
                    ],
                    business_impact="Permite ataques de força bruta contra contas de usuários.",
                    cvss_estimate=5.3,
                ))
                break
    return findings


def test_graphql_exposure(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Testa GraphQL: introspection ativa, batching ilimitado, injeção de campo."""
    findings = []
    gql_paths = ["/graphql", "/api/graphql", "/gql", "/v1/graphql", "/query"]

    introspection_query = {"query": "{ __schema { queryType { name } types { name kind } } }"}
    batch_query = [{"query": "{ __typename }"} for _ in range(50)]

    for path in gql_paths:
        url = base_url.rstrip("/") + path
        r = _safe_post(url, json_data=introspection_query)
        if not r or r.status_code not in (200, 201):
            continue

        try:
            data = r.json()
        except Exception:
            continue

        if "data" in data and "__schema" in str(data.get("data") or ""):
            # Conta tipos para estimar exposição
            schema_data = data.get("data", {}).get("__schema") or {}
            types_count = len(schema_data.get("types") or [])
            mutations = [t for t in (schema_data.get("types") or [])
                         if str(t.get("kind") or "").upper() == "OBJECT"
                         and "mutation" in str(t.get("name") or "").lower()]

            findings.append(BusinessLogicFinding(
                title=f"GraphQL Introspection Ativa — Schema Completo Exposto ({path})",
                severity="high",
                test_type="graphql_introspection",
                domain=domain,
                evidence=(
                    f"Introspection retornou {types_count} tipos em {url}. "
                    f"Mutations visíveis: {len(mutations)}."
                ),
                description=(
                    "GraphQL introspection ativa em produção expõe o schema completo: "
                    "todos os tipos, queries, mutations e campos — incluindo os não documentados. "
                    "Permite ao atacante mapear toda a API e descobrir endpoints admin ocultos."
                ),
                reproduction_steps=[
                    f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    "  -d '{\"query\": \"{ __schema { types { name kind fields { name } } } }\"}'",
                    "# Procurar mutations com 'admin', 'delete', 'update', 'role', 'privilege'",
                    "# Ferramenta: graphql-voyager, InQL Burp extension",
                ],
                business_impact=(
                    "Schema exposto facilita IDOR/BOLA em mutations, privilege escalation via "
                    "campos ocultos, e exfiltração massiva. LGPD Art. 46: dado de projeto "
                    "que facilita acesso a dados pessoais."
                ),
                cvss_estimate=7.5,
            ))

        # Teste de batching — DoS potencial
        r_batch = _safe_post(url, json_data=batch_query)
        if r_batch and r_batch.status_code == 200:
            try:
                batch_data = r_batch.json()
                if isinstance(batch_data, list) and len(batch_data) >= 10:
                    findings.append(BusinessLogicFinding(
                        title=f"GraphQL Batching Ilimitado — DoS/Amplificação ({path})",
                        severity="medium",
                        test_type="graphql_batching",
                        domain=domain,
                        evidence=f"50 queries batched retornaram {len(batch_data)} respostas em {url}",
                        description=(
                            "GraphQL sem limite de batch permite enviar N queries em um único request. "
                            "Usado para brute force de tokens (batching de mutations de login), "
                            "DoS por amplificação, e bypass de rate limiting."
                        ),
                        reproduction_steps=[
                            f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                            "  -d '[{\"query\":\"{ __typename }\"},{\"query\":\"{ __typename }\"},...×100]'",
                            "# Usar para brute force: [{\"query\":\"mutation { login(password: \\\"pass1\\\") }\"},...×1000]",
                        ],
                        business_impact=(
                            "Permite brute force de senhas bypassando rate limit via batching. "
                            "1 request HTTP = N tentativas de login."
                        ),
                        cvss_estimate=5.9,
                    ))
            except Exception:
                pass

    return findings


def test_mass_assignment(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Detecta Mass Assignment — API aceita campos extras não documentados."""
    findings = []
    register_paths = [
        "/api/users", "/api/v1/users", "/api/register",
        "/api/auth/register", "/api/v1/auth/register", "/api/signup",
    ]

    for path in register_paths:
        url = base_url.rstrip("/") + path

        # Request com campos legítimos + campos de escalação
        import uuid as _uuid
        test_user = f"test_{_uuid.uuid4().hex[:6]}@scanner.local"
        payload = {
            "email": test_user,
            "password": "Scanner1234!",
            "name": "Test Scanner",
            # ── Campos de escalação que não deveriam ser aceitos ──
            "role": "admin",
            "isAdmin": True,
            "admin": True,
            "is_superuser": True,
            "privilege": "admin",
            "verified": True,
            "emailVerified": True,
            "active": True,
        }

        r = _safe_post(url, json_data=payload)
        if not r or r.status_code not in (200, 201):
            continue

        try:
            data = r.json()
        except Exception:
            data = {}

        # Verifica se campos de escalação foram refletidos/aceitos
        response_str = str(data).lower()
        escalation_fields = ["admin", "role", "superuser", "privilege", "verified"]
        accepted = [f for f in escalation_fields if f in response_str]

        if accepted:
            findings.append(BusinessLogicFinding(
                title="Mass Assignment — Campos de Escalação Aceitos no Registro",
                severity="critical",
                test_type="mass_assignment",
                domain=domain,
                evidence=(
                    f"POST {url} com campos extras [{', '.join(accepted)}] → "
                    f"campos aparecem na resposta: status={r.status_code}"
                ),
                description=(
                    "A API aceita campos adicionais não documentados durante criação/atualização. "
                    "Um atacante pode incluir 'role': 'admin' no registro e obter conta privilegiada. "
                    "Vulnerabilidade clássica em Rails (attr_accessible), Django, Express sem whitelist."
                ),
                reproduction_steps=[
                    f"curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    "  -d '{\"email\":\"attacker@evil.com\",\"password\":\"pass\",\"role\":\"admin\",\"isAdmin\":true}'",
                    "# Se resposta contiver role:admin → Mass Assignment confirmado",
                    "# Também testar PUT/PATCH /api/users/{id} com mesmos campos",
                ],
                business_impact=(
                    "Qualquer usuário pode criar conta admin. Comprometimento total do controle de acesso. "
                    "LGPD Art. 47: acesso indevido a dados pessoais por escalação de privilégio."
                ),
                cvss_estimate=9.1,
            ))

    return findings


def test_race_condition_financial(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """
    Detecta race conditions em operações financeiras/de limite.
    Envia múltiplos requests simultâneos para operações que deveriam ser atômicas.
    Não executa transações reais — apenas detecta ausência de idempotency/locks.
    """
    import concurrent.futures
    findings = []

    # Endpoints que tipicamente têm race conditions
    race_targets = [
        ("/api/v1/withdraw", {"amount": 1, "account": "test"}),
        ("/api/v1/transfer", {"amount": 1, "to": "test"}),
        ("/api/v1/redeem", {"code": "PROMO10"}),
        ("/api/v1/coupon/apply", {"coupon": "TESTCOUPON"}),
        ("/api/v1/voucher/use", {"voucher": "TEST"}),
        ("/api/vote", {"item_id": 1}),
        ("/api/like", {"post_id": 1}),
    ]

    def _fire(url: str, data: dict) -> int:
        r = _safe_post(url, json_data=data)
        return r.status_code if r else 0

    for path, data in race_targets:
        url = base_url.rstrip("/") + path

        # Primeiro teste: endpoint existe?
        probe = _safe_post(url, json_data=data)
        if not probe or probe.status_code in (404, 405):
            continue

        # Enviar 10 requests simultâneos
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(_fire, url, data) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Se mais de 2 retornaram 200 (em vez de 1): possível race condition
        success_count = results.count(200)
        if success_count >= 3:
            findings.append(BusinessLogicFinding(
                title=f"Possível Race Condition em Operação Financeira/Limite: {path}",
                severity="high",
                test_type="race_condition",
                domain=domain,
                evidence=(
                    f"10 requests simultâneos para {url}: {success_count} retornaram HTTP 200. "
                    f"Operação atômica esperada, mas múltiplas execuções aceitas simultaneamente."
                ),
                description=(
                    f"Ausência de controle de concorrência em {path}. "
                    "Envio de N requests paralelos causa execução múltipla de operação única. "
                    "Comum em sistemas de cupom, withdraw, like/vote, reserva de inventário."
                ),
                reproduction_steps=[
                    "# Usar Turbo Intruder no Burp Suite (single-packet attack)",
                    f"# Ou: for i in {{1..20}}; do curl -s -X POST '{url}' -H 'Content-Type: application/json' \\",
                    f"  -d '{data}' & done; wait",
                    "# Se múltiplos retornam 200: race condition confirmada",
                    "# Para transações: verificar saldo após 20 withdraws simultâneos de valor máximo",
                ],
                business_impact=(
                    "Permite dobrar benefícios (cupons, cashback), sacar mais do saldo disponível, "
                    "ou votar múltiplas vezes. Impacto financeiro direto. "
                    "BACEN RES 4893/2021 — controle de integridade de transações."
                ),
                cvss_estimate=7.5,
            ))

    return findings


def test_cache_deception(
    base_url: str,
    domain: str,
    *,
    observed_private_paths: list[str] | None = None,
    authenticated_baseline: bool = False,
) -> list[BusinessLogicFinding]:
    """
    Detecta Web Cache Deception: endpoints autenticados cacheados por extensão de arquivo.
    Sem autenticação, apenas detecta se headers de cache são permissivos em rotas privadas.
    """
    findings = []
    # Never invent "private" routes. A 200 from a guessed /api/me path may be
    # only an SPA fallback, and Cache MISS is not cache-deception evidence.
    # The validator requires an endpoint observed under an authenticated
    # session before probing cache-key behavior.
    private_paths = [
        str(path) for path in observed_private_paths or []
        if str(path).startswith("/")
    ]
    if not authenticated_baseline or not private_paths:
        return []
    # Extensões que CDNs costumam cachear
    cache_extensions = [".css", ".js", ".png", ".jpg", ".gif", ".woff"]

    for path in private_paths:
        for ext in cache_extensions[:2]:  # testa apenas 2 por path para evitar lentidão
            url = base_url.rstrip("/") + path + f"/test{ext}"
            r = _safe_get(url)
            if not r or r.status_code not in (200, 304):
                continue

            # Verifica ausência de cache-control restritivo
            cc = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()
            has_no_store = "no-store" in cc or "private" in cc
            cached_header = r.headers.get("X-Cache", "") or r.headers.get("CF-Cache-Status", "")

            cache_state = str(cached_header or "").strip().upper()
            if not has_no_store and cache_state in {"HIT", "CACHED", "TCP_HIT"}:
                findings.append(BusinessLogicFinding(
                    title=f"Web Cache Deception — Endpoint Privado Sem Cache-Control: {path}",
                    severity="high",
                    test_type="cache_deception",
                    domain=domain,
                    evidence=(
                        f"{url} retornou HTTP {r.status_code} sem 'Cache-Control: no-store/private'. "
                        f"Cache-Control: '{cc}' | X-Cache: '{cached_header}'"
                    ),
                    description=(
                        f"O endpoint {path} (tipicamente privado/autenticado) não define Cache-Control: no-store. "
                        f"Ao acessar {path}/test.css, CDNs como Cloudflare/Fastly podem cachear a resposta. "
                        "Um atacante envia o link para a vítima; após o acesso, busca a resposta cacheada — "
                        "obtendo dados pessoais da sessão autenticada da vítima."
                    ),
                    reproduction_steps=[
                        f"# 1. Atacante cria link: https://{domain}{path}/malicious.css",
                        "# 2. Vítima (autenticada) clica no link",
                        "# 3. CDN cacheia a resposta com dados da vítima",
                        f"# 4. Atacante busca: curl -s 'https://{domain}{path}/malicious.css'",
                        "# 5. Recebe resposta com dados pessoais da vítima",
                        "# Verificar: response headers no Burp/curl -I",
                    ],
                    business_impact=(
                        "Exfiltração de dados pessoais de usuários autenticados via CDN. "
                        "LGPD Art. 46: falha técnica que permite acesso não autorizado a dados pessoais."
                    ),
                    cvss_estimate=7.5,
                ))
                break  # um finding por path

    return findings


def test_debug_mode(base_url: str, domain: str) -> list[BusinessLogicFinding]:
    """Detecta endpoints de debug ativos."""
    findings = []
    debug_paths = [
        "/debug", "/debug/info", "/_debug", "/console",
        "/debug/pprof", "/debug/vars",  # Go
        "/__debug", "/dev/debug",
        "/api/debug", "/api/system/info",
        "/info", "/env", "/config",
        "/.git/config", "/.git/HEAD",  # Git exposure
        "/wp-json/wp/v2/users",  # WordPress user enum
        "/phpinfo.php", "/info.php",  # PHP info
    ]

    for path in debug_paths:
        url = base_url.rstrip("/") + path
        r = _safe_get(url)
        if not r or r.status_code not in [200, 206]:
            continue

        sensitive_indicators = [
            "database", "password", "secret", "token", "key",
            "phpinfo", "php_version", "memory_limit",
            "git", "author", "commit",
            "stack", "traceback",
        ]
        text_lower = r.text.lower()
        found = [s for s in sensitive_indicators if s in text_lower]
        if found:
            findings.append(BusinessLogicFinding(
                title=f"Endpoint de Debug Ativo: {path}",
                severity="high",
                test_type="debug_mode",
                domain=domain,
                evidence=(
                    f"HTTP 200 em {url}. "
                    f"Indicadores sensíveis encontrados: {', '.join(found[:3])}"
                ),
                description=(
                    f"Endpoint de debug/desenvolvimento acessível em {path}. "
                    f"Retornou informações sobre: {', '.join(found)}."
                ),
                reproduction_steps=[
                    f"curl -s '{url}' | head -100",
                ],
                business_impact=(
                    "Exposição de configurações internas, estrutura do código, "
                    "variáveis de ambiente e possíveis credenciais."
                ),
                cvss_estimate=6.5,
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main analyzer
# ─────────────────────────────────────────────────────────────────────────────

def classify_service(domain: str, existing_findings: list[Any] | None = None) -> str:
    """Classifica o tipo de serviço baseado no domínio e findings existentes."""
    d = domain.lower()
    for service_type, profile in SERVICE_PROFILES.items():
        if any(kw in d for kw in profile["keywords"]):
            return service_type
    # Try from existing findings titles
    if existing_findings:
        all_text = " ".join(str(f.title or "") for f in existing_findings).lower()
        for service_type, profile in SERVICE_PROFILES.items():
            if any(kw in all_text for kw in profile["keywords"]):
                return service_type
    return "api_gateway"  # default


def analyze_business_logic(
    domain: str,
    base_url: str | None = None,
    existing_findings: list[Any] | None = None,
    discovered_auth_paths: list[str] | None = None,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
) -> list[dict]:
    """
    Executa testes de business logic para um domínio.
    Retorna lista de findings no formato plataforma.

    auth_headers/auth_cookies (from a captured ScanAuthSession, if any) are
    installed into `_auth_context` for the duration of this call so every
    test_* function's _safe_get/_safe_post carries the real session —
    previously every test here only ever made anonymous requests.
    """
    if not base_url:
        base_url = f"https://{domain}" if not domain.startswith("http") else domain

    service_type = classify_service(domain, existing_findings)
    profile = SERVICE_PROFILES.get(service_type, SERVICE_PROFILES["api_gateway"])

    logger.info("BizLogic analysis: %s → service_type=%s", domain, service_type)

    raw_findings: list[BusinessLogicFinding] = []

    tests_to_run = profile.get("tests", [])

    _token = _auth_context.set({"headers": auth_headers or {}, "cookies": auth_cookies or {}})
    try:
        # Run applicable tests
        if "docker_api_unauth" in tests_to_run:
            raw_findings.extend(test_docker_api_unauth(base_url, domain))
        if "env_vars_leak" in tests_to_run:
            raw_findings.extend(test_env_vars_leak(base_url, domain))
        if "idor_accounts" in tests_to_run or "bola_check" in tests_to_run:
            raw_findings.extend(test_idor_accounts(base_url, domain))
        if "verbose_errors" in tests_to_run:
            raw_findings.extend(test_verbose_errors(base_url, domain))
        if "open_cors" in tests_to_run:
            raw_findings.extend(test_open_cors(base_url, domain))
        if "rate_limit_absent" in tests_to_run:
            raw_findings.extend(test_rate_limit_absent(base_url, domain, extra_paths=discovered_auth_paths))
        if "debug_mode" in tests_to_run:
            raw_findings.extend(test_debug_mode(base_url, domain))
        # New real-world attack tests
        if "graphql_exposure" in tests_to_run:
            raw_findings.extend(test_graphql_exposure(base_url, domain))
        if "mass_assignment" in tests_to_run:
            raw_findings.extend(test_mass_assignment(base_url, domain))
        if "race_condition_financial" in tests_to_run:
            raw_findings.extend(test_race_condition_financial(base_url, domain))
        if "cache_deception" in tests_to_run:
            raw_findings.extend(test_cache_deception(base_url, domain))
    finally:
        _auth_context.reset(_token)

    # Convert to platform format
    return [
        {
            "title": f.title,
            "severity": f.severity,
            "domain": f.domain,
            "source_tool": "business_logic_analyzer",
            "evidence": f.evidence,
            "description": f.description,
            "validation_status": "confirmed",
            "details": {
                "source": "business_logic",
                "test_type": f.test_type,
                "service_type": service_type,
                "reproduction_steps": f.reproduction_steps,
                "business_impact": f.business_impact,
                "cvss_estimate": f.cvss_estimate,
                "payload": f.reproduction_steps[0] if f.reproduction_steps else "",
            },
        }
        for f in raw_findings
    ]


_AUTH_PATH_KEYWORDS = ("login", "auth", "token", "signin", "sign-in", "session", "authorize", "sso")


def _discovered_auth_paths(db: Any, scan_id: int, domain: str) -> list[str]:
    """Pull auth-like paths the recon phase actually found for this scan's
    domain, so test_rate_limit_absent (and future tests) try real endpoints
    instead of only a handful of hardcoded common guesses."""
    from urllib.parse import urlparse

    from app.models.models import OffensiveEndpoint

    try:
        rows = (
            db.query(OffensiveEndpoint.url, OffensiveEndpoint.method)
            .filter(
                OffensiveEndpoint.scan_job_id == scan_id,
                OffensiveEndpoint.method.in_(["POST", "PUT"]),
            )
            .limit(500)
            .all()
        )
    except Exception:
        return []

    paths: list[str] = []
    for url, _method in rows:
        try:
            parsed = urlparse(str(url or ""))
        except Exception:
            continue
        if domain not in (parsed.hostname or ""):
            continue
        path = parsed.path or ""
        if path and any(kw in path.lower() for kw in _AUTH_PATH_KEYWORDS):
            paths.append(path)
    return list(dict.fromkeys(paths))[:15]


def run_business_logic_scan(
    db: Any,
    scan_id: int,
    target_domains: list[str] | None = None,
    max_domains: int = 20,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Executa análise de business logic para todos os domínios de um scan
    (ou lista específica) e persiste os findings.

    Persistence goes through findings_extractor.persist_finding_dicts — the
    single gated path (evidence grounding, scope-guard, dedup, confidence
    scoring) — instead of writing Finding rows directly. Previously this
    function bypassed that pipeline entirely, which also meant a discovered
    out-of-scope host referenced in a finding's details could slip through
    unchecked.
    """
    from app.models.models import Finding, ScanJob
    from app.services.findings_extractor import persist_finding_dicts

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return {"error": "Scan not found"}

    # Get unique domains from existing findings
    if not target_domains:
        existing = (
            db.query(Finding.domain)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.severity.in_(["critical", "high"]),
            )
            .distinct()
            .order_by(Finding.domain.asc())
            .limit(max_domains)
            .all()
        )
        target_domains = [r[0] for r in existing if r[0]]

    total_findings = 0
    results_by_domain: dict[str, int] = {}

    for domain in target_domains:
        base_url = f"https://{domain}" if not domain.startswith("http") else domain
        existing_findings = (
            db.query(Finding)
            .filter(Finding.scan_job_id == scan_id, Finding.domain == domain)
            .all()
        )
        discovered_auth_paths = _discovered_auth_paths(db, scan_id, domain)

        biz_findings = analyze_business_logic(
            domain, base_url, existing_findings, discovered_auth_paths,
            auth_headers=auth_headers, auth_cookies=auth_cookies,
        )

        raw_findings = []
        for bf in biz_findings:
            details_payload = dict(bf.get("details") or {})
            details_payload["evidence"] = bf.get("evidence", "")[:2000]
            details_payload["validation_status"] = bf.get("validation_status", "hypothesis")
            if bf.get("description") and not details_payload.get("description"):
                details_payload["description"] = bf.get("description", "")[:2000]
            raw_findings.append({
                "title": bf["title"][:500],
                "severity": bf["severity"],
                "risk_score": int(details_payload.get("cvss_estimate") or 5),
                "details": details_payload,
            })

        created = persist_finding_dicts(
            db, job, raw_findings,
            default_tool="business_logic_analyzer",
            default_target=domain,
            source_item=None,
        )
        total_findings += created
        results_by_domain[domain] = created

    return {
        "domains_analyzed": len(target_domains),
        "findings_created": total_findings,
        "by_domain": results_by_domain,
    }
