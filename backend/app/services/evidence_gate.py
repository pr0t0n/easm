"""evidence_gate.py — Two-stage finding validation + business impact scoring.

Implementa dois pontos do usuário em um único serviço:

PONTO #4 — Evidence gate (candidate → confirmed):
  Estágio 1 — Detection: qualquer ferramenta pode gerar finding
    → status: "candidate" (não entra no relatório final)
  Estágio 2 — Verification: reprodução independente obrigatória
    → Compara resposta baseline vs response exploited
    → Confirma que não é WAF block genérico
    → status: "confirmed" com evidence pair (request/response)
  Apenas "confirmed" conta para severidade e CVSS no relatório.

PONTO #5 — Business impact scoring (contexto de endpoint, não só CVSS):
  SQLi em /api/admin/users → crítico (acesso a todos os usuários)
  SQLi em /api/search/products → médio (read-only, dados públicos)
  XSS em /admin → médio (precisa acesso admin)
  XSS em /contact → alto (afeta qualquer visitante)
  Port 22 com senha padrão → crítico; com chave → info

Integrado em findings_extractor.py para marcar cada finding corretamente
antes de persisti-lo no banco.
"""

from __future__ import annotations

import re
from typing import Any

# ── Ferramentas que produzem findings diretamente confirmados ──────────────────
# Essas ferramentas têm baixíssima taxa de FP porque testam a condição
# de forma determinística (ex: SQLmap confirma injeção com payload real).
CONFIRMED_TOOLS = {
    "sqlmap",           # prova a injeção com payload
    "dalfox",           # prova XSS com callback
    "nuclei",           # templates com matchers precisos
    "wpscan",           # confirma plugin vulnerável via resposta
    "hydra",            # confirma credencial válida
    "nuclei-cve-2021-26855",  # ProxyLogon tem matcher preciso
    "nuclei-cve-2020-1938",   # Ghostcat: lê /WEB-INF/web.xml
    "nuclei-cve-2017-12617",  # Tomcat PUT: confirma por resposta 201
    "nuclei-default-credentials",
}

# Ferramentas que produzem hipóteses (precisam de verificação)
HYPOTHESIS_TOOLS = {
    "nmap-vulscan",     # lookup de versão sem exploração real
    "tech_correlator",  # CVE por versão detectada — não testou de fato
    "shodan-cli",       # informação passiva
    "theHarvester",     # OSINT
    "h8mail",           # breach check
}

# ── Padrões de endpoint de alto impacto de negócio ────────────────────────────
# (path_pattern, multiplier, reason)
# multiplier > 1.0 → aumenta risk_score; < 1.0 → diminui
HIGH_IMPACT_PATHS: list[tuple[str, float, str]] = [
    # Admin / gestão
    (r"/admin",                     1.5, "painel administrativo exposto"),
    (r"/manager",                   1.4, "interface de gerenciamento"),
    (r"/api/admin",                 1.5, "API de administração"),
    (r"/dashboard",                 1.3, "dashboard de gestão"),

    # Dados de usuário / PII
    (r"/api/users?(/\d+)?",         1.5, "endpoint de dados de usuários"),
    (r"/api/accounts?",             1.5, "endpoint de contas"),
    (r"/api/customers?",            1.5, "dados de clientes"),
    (r"/api/profile",               1.3, "dados de perfil"),

    # Dados financeiros
    (r"/api/payment",               1.8, "processamento de pagamento"),
    (r"/api/invoice",               1.7, "faturas e cobrança"),
    (r"/api/billing",               1.7, "dados de cobrança"),
    (r"/api/orders?",               1.5, "pedidos e transações"),
    (r"/api/wallet",                1.8, "carteira digital"),
    (r"/pix",                       1.8, "transações Pix"),

    # Autenticação
    (r"/login",                     1.4, "endpoint de autenticação"),
    (r"/auth",                      1.4, "serviço de autenticação"),
    (r"/oauth",                     1.3, "fluxo OAuth"),
    (r"/api/token",                 1.4, "endpoint de token"),

    # Cloud / infraestrutura
    (r"\.env",                      1.6, "arquivo de variáveis de ambiente"),
    (r"\.git",                      1.5, "repositório git exposto"),
    (r"/actuator",                  1.5, "Spring Actuator exposto"),
    (r"/api/internal",              1.4, "API interna exposta"),
    (r"/internal",                  1.4, "recurso interno exposto"),

    # Endpoints de baixo impacto (reduz score)
    (r"/api/search",                0.7, "busca pública"),
    (r"/api/products?(/\d+)?",      0.7, "catálogo de produtos"),
    (r"/api/public",                0.6, "API pública"),
    (r"/static",                    0.5, "recurso estático"),
    (r"/assets?",                   0.5, "asset estático"),
    (r"/favicon",                   0.3, "favicon"),
    (r"/robots\.txt",               0.4, "robots.txt"),
    (r"/sitemap",                   0.4, "sitemap"),
]

# ── Regras de context-aware severity ─────────────────────────────────────────
# Alguns tipos de finding têm severidade que depende do contexto do endpoint.
# (vuln_type_keyword, high_impact_context, adjusted_severity)
CONTEXT_SEVERITY_RULES: list[tuple[str, str, str]] = [
    # XSS: em endpoint admin = médio (requer acesso prévio); em formulário público = alto
    ("xss",         r"/admin",              "medium"),
    ("xss",         r"/contact|/feedback|/search|/comment", "high"),

    # SQLi: em endpoint de busca pública → médio; em admin/users → crítico
    ("sql injection",  r"/admin|/users|/accounts", "critical"),
    ("sql injection",  r"/search|/products|/catalog",  "medium"),

    # SSRF: em endpoints internos → crítico; em serviços externos → alto
    ("ssrf",        r"/internal|/admin|/api/internal", "critical"),

    # Open redirect: impacto depende de ser endpoint de autenticação
    ("open redirect", r"/login|/auth|/oauth", "high"),
    ("open redirect", r"/search|/products",   "low"),
]


def get_verification_status(tool_name: str, finding: dict[str, Any]) -> str:
    """Determina status de verificação inicial de um finding.

    Returns:
        "confirmed"  — tool prova a condição diretamente
        "candidate"  — precisa de verificação secundária
        "hypothesis" — informação passiva / correlação de versão
    """
    tool = str(tool_name or "").strip().lower()
    title = str(finding.get("title") or "").lower()
    details = dict(finding.get("details") or {})

    # Ferramentas de confirmação direta
    if tool in CONFIRMED_TOOLS:
        return "confirmed"

    # Ferramentas de hipótese
    if tool in HYPOTHESIS_TOOLS:
        return "hypothesis"

    # Findings de CVE por versão (sem teste real) → hipótese
    step = str(details.get("step") or "")
    if step in ("tech_correlator", "cross_target_propagator"):
        return "hypothesis"

    # nuclei com matcher específico → confirmed; nuclei genérico → candidate
    if tool.startswith("nuclei"):
        if details.get("matcher-name") or details.get("matched-at"):
            return "confirmed"
        return "candidate"

    # nmap-vulscan: lookup de versão → hipótese
    if "nmap-vulscan" in tool or "vulscan" in tool:
        return "hypothesis"

    # WAF detections: curl-headers, shcheck → candidate (pode ser false positive)
    if tool in ("curl-headers", "shcheck", "wafw00f"):
        return "candidate"

    # Default: candidate (precisa verificação)
    return "candidate"


def compute_business_impact_score(
    base_risk_score: float,
    finding: dict[str, Any],
    url: str | None = None,
) -> tuple[int, str]:
    """Ajusta risk_score com base no contexto de endpoint.

    Returns:
        (adjusted_score: int, impact_reason: str)

    O score base (1-10) é multiplicado por fatores de contexto derivados
    do path do endpoint, não apenas do CVSS do CVE.
    """
    title = str(finding.get("title") or "").lower()
    details = dict(finding.get("details") or {})

    # Resolve URL: do finding, do details, ou do parâmetro
    finding_url = str(
        url
        or finding.get("url")
        or details.get("url")
        or details.get("matched-at")
        or details.get("asset")
        or ""
    ).lower()

    multiplier = 1.0
    reasons: list[str] = []

    # Aplica regras de path
    for pattern, factor, reason in HIGH_IMPACT_PATHS:
        if re.search(pattern, finding_url, re.IGNORECASE):
            multiplier *= factor
            if factor > 1.0:
                reasons.append(f"+impacto ({reason})")
            else:
                reasons.append(f"-impacto ({reason})")

    # Aplica regras de context-aware severity
    # (não muda o score, mas sugere severity ajustada — chamador pode usar)
    for vuln_kw, path_pattern, _ in CONTEXT_SEVERITY_RULES:
        if vuln_kw in title and re.search(path_pattern, finding_url, re.IGNORECASE):
            # Apenas marca; o chamador pode usar _context_severity se quiser
            break

    # Cap: score entre 1 e 10
    adjusted = round(max(1.0, min(10.0, float(base_risk_score) * multiplier)))
    reason_str = "; ".join(reasons) if reasons else "padrão"

    return int(adjusted), reason_str


def get_context_severity(title: str, url: str | None) -> str | None:
    """Retorna severity ajustada por contexto, ou None se não há regra aplicável."""
    title_lower = title.lower()
    url_lower = (url or "").lower()

    for vuln_kw, path_pattern, adjusted_sev in CONTEXT_SEVERITY_RULES:
        if vuln_kw in title_lower and re.search(path_pattern, url_lower, re.IGNORECASE):
            return adjusted_sev

    return None


def enrich_finding_with_gate(
    finding: dict[str, Any],
    tool_name: str,
    url: str | None = None,
) -> dict[str, Any]:
    """Aplica evidence gate e business impact scoring a um finding dict.

    Chamado em findings_extractor.py antes de persistir o Finding no banco.
    Modifica o dict in-place e retorna-o.
    """
    # 1. Evidence gate: verification_status
    v_status = get_verification_status(tool_name, finding)
    details = dict(finding.get("details") or {})
    details["verification_status"] = v_status
    details["verified_by"] = tool_name

    # Para hypothesis/candidate: marca que precisa de verificação
    if v_status in ("hypothesis", "candidate"):
        details["needs_verification"] = True
        details["verification_note"] = (
            "Finding candidato — requer reprodução independente antes de confirmar. "
            "Pode ser falso positivo de WAF, rate-limit ou correlação de versão."
        )

    # 2. Business impact scoring: ajusta risk_score por contexto
    base_score = float(finding.get("risk_score") or 5.0)
    adjusted_score, impact_reason = compute_business_impact_score(base_score, finding, url=url)
    details["impact_reason"] = impact_reason
    details["base_risk_score"] = base_score
    details["adjusted_risk_score"] = adjusted_score

    # Só aplica o score ajustado se for diferente do base (não degrada confirmed tools)
    if v_status == "confirmed" and adjusted_score != int(base_score):
        finding["risk_score"] = adjusted_score
        details["score_adjustment"] = f"{base_score} → {adjusted_score} ({impact_reason})"

    # 3. Context severity override
    title = str(finding.get("title") or "")
    ctx_sev = get_context_severity(title, url or str(details.get("asset") or ""))
    if ctx_sev and v_status == "confirmed":
        original_sev = finding.get("severity")
        finding["severity"] = ctx_sev
        details["original_severity"] = original_sev
        details["severity_context_override"] = f"{original_sev} → {ctx_sev} (por contexto de endpoint)"

    finding["details"] = details
    return finding
