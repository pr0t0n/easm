"""
finding_intelligence.py — Pós-processamento inteligente de findings.

Dois módulos:

1. consolidate_systemic_findings(db, scan_id)
   Agrupa findings repetidos do mesmo tipo (ex: "falta HSTS") em um único
   finding sistêmico por domínio raiz, mantendo os originais com flag merged=True.

2. correlate_waf_shodan(db, scan_id)
   Cruza IPs de bypass WAF (waf_origin_discovery) com IPs do Shodan que têm
   portas abertas — se bater, eleva severidade e cria finding correlacionado.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Consolidação de findings sistêmicos
# ─────────────────────────────────────────────────────────────────────────────

# Padrões que identificam findings que costumam repetir por cada subdomínio
SYSTEMIC_PATTERNS = [
    # Security headers ausentes — agrupar por tipo de header e domínio raiz
    (r"Header de seguranca ausente:\s*(.+)", "header_ausente"),
    # Versão de serviço exposta
    (r"Versão de serviço exposta:", "versao_exposta"),
    # Host HTTP ativo
    (r"Host HTTP ativo:", "host_ativo"),
    # TLS configurado
    (r"^TLS configurado em", "tls_ok"),
    # Shodan Cloudflare proxy
    (r"Host atrás de Cloudflare", "cf_proxy"),
]


def _root_domain(domain: str) -> str:
    """Extrai domínio raiz: 'sub.exemplo.com.br' → 'exemplo.com.br'"""
    parts = domain.lower().rstrip(".").split(".")
    # Trata TLDs de 2 partes (.com.br, .org.br, .gov.br, .co.uk, ...)
    two_part_tlds = {"com.br", "org.br", "net.br", "gov.br", "edu.br",
                     "co.uk", "org.uk", "me.uk", "co.nz", "com.au"}
    if len(parts) >= 3:
        candidate = ".".join(parts[-2:])
        if candidate in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def consolidate_systemic_findings(db: Session, scan_id: int) -> int:
    """
    Para cada tipo de finding repetido (mesmo padrão, vários subdomínios),
    cria um finding sistêmico por domínio raiz se houver ≥3 ocorrências.
    Retorna número de findings sistêmicos criados.
    """
    from app.models.models import Finding

    # Carregar todos os findings do scan (exceto já-consolidados)
    from sqlalchemy import cast
    from sqlalchemy.dialects.postgresql import JSONB
    all_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            # Excluir findings sistêmicos já criados (JSONB path safe check)
            ~Finding.title.like("%[SISTÊMICO]%"),
        )
        .all()
    )

    # Agrupar: pattern_key → root_domain → [findings]
    groups: dict[str, dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))

    for f in all_findings:
        title = str(f.title or "")
        for pattern, key in SYSTEMIC_PATTERNS:
            m = re.search(pattern, title, re.IGNORECASE)
            if m:
                # Para headers, incluir o nome do header no key
                if key == "header_ausente":
                    header_name = m.group(1).strip().lower()
                    group_key = f"{key}:{header_name}"
                else:
                    group_key = key
                root = _root_domain(str(f.domain or ""))
                groups[group_key][root].append(f)
                break

    created = 0
    for group_key, root_map in groups.items():
        for root, findings_list in root_map.items():
            if len(findings_list) < 3:
                continue  # Não sistêmico — menos de 3 subdomínios afetados

            # Verificar se já existe finding sistêmico para este grupo
            existing = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == scan_id,
                    Finding.domain == root,
                    Finding.title.like(f"%[SISTÊMICO]%{group_key.split(':')[-1][:30]}%"),
                )
                .first()
            )
            if existing:
                continue

            # Construir o finding sistêmico
            sample = findings_list[0]
            affected = sorted({str(f.domain or "") for f in findings_list})
            severity = str(sample.severity or "info")
            risk_score = int(sample.risk_score or 1)
            tool = str(sample.tool or "")

            # Extrair o tipo de problema do group_key
            if ":" in group_key:
                _, issue = group_key.split(":", 1)
                title = f"[SISTÊMICO] {issue.replace('-', ' ').title()} ausente em {len(affected)} propriedades de {root}"
            else:
                title = f"[SISTÊMICO] {group_key.replace('_', ' ').title()} — {len(affected)} subdomínios de {root}"

            systemic = Finding(
                scan_job_id=scan_id,
                title=title[:255],
                severity=severity,
                risk_score=min(risk_score + 1, 10),  # sistêmico = ligeiramente mais grave
                confidence_score=90,
                domain=root,
                tool=tool,
                details={
                    "systemic": "true",
                    "group_key": group_key,
                    "affected_subdomains": affected,
                    "affected_count": len(affected),
                    "sample_finding_id": sample.id,
                    "evidence": (
                        f"Problema '{group_key}' afeta {len(affected)} subdomínios: "
                        + ", ".join(affected[:8])
                        + ("..." if len(affected) > 8 else "")
                    ),
                    "owasp_category": dict(sample.details or {}).get("owasp_category", ""),
                    "remediation": (
                        f"Configurar em nível de domínio raiz ({root}) para herdar por todos os subdomínios. "
                        + (dict(sample.details or {}).get("remediation") or "")
                    ),
                },
                recommendation=(
                    f"Problema sistêmico: {len(affected)} subdomínios afetados. "
                    "Corrigir na configuração central do servidor/CDN em vez de individualmente."
                ),
                created_at=datetime.utcnow(),
            )
            db.add(systemic)
            try:
                db.flush()
                created += 1
            except Exception as exc:
                db.rollback()
                logger.debug("systemic finding flush error: %s", exc)

    if created:
        db.commit()
        logger.info("consolidate_systemic_findings: created %d systemic findings for scan %s", created, scan_id)

    return created


# ─────────────────────────────────────────────────────────────────────────────
# 2. Correlação WAF bypass × Shodan portas abertas
# ─────────────────────────────────────────────────────────────────────────────

def correlate_waf_shodan(db: Session, scan_id: int) -> int:
    """
    Cruza findings de WAF bypass (IPs candidatos de origem) com findings Shodan
    que mostram portas abertas. Se um IP de bypass tiver portas sensíveis abertas
    no Shodan → cria finding de alta prioridade.

    Retorna número de correlações criadas.
    """
    from app.models.models import Finding

    # 1. Coletar IPs de bypass WAF
    waf_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.tool == "waf_origin_discovery",
        )
        .all()
    )

    # 2. Coletar findings Shodan com portas abertas
    shodan_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.tool == "shodan-cli",
            Finding.title.like("Portas expostas%"),
        )
        .all()
    )

    if not waf_findings or not shodan_findings:
        return 0

    # Mapear IP → finding Shodan
    shodan_ip_map: dict[str, Any] = {}
    for sf in shodan_findings:
        det = dict(sf.details or {})
        ip = str(det.get("ip_address") or "")
        if ip:
            shodan_ip_map[ip] = sf

    SENSITIVE_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017}

    created = 0
    for wf in waf_findings:
        wdet = dict(wf.details or {})

        # Extrair IPs dos campos candidate_origins (lista de dicts com "ip" key)
        # ou fallback para candidate_ips / reproduction proof / title
        candidate_ips: list[str] = []

        # Formato principal: candidate_origins = [{"ip": "x.x.x.x", ...}, ...]
        for origin in (wdet.get("candidate_origins") or []):
            if isinstance(origin, dict) and origin.get("ip"):
                candidate_ips.append(str(origin["ip"]))

        # Fallback: extrair IPs de qualquer campo de texto
        if not candidate_ips:
            raw_text = json.dumps(wdet)
            candidate_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw_text)

        for ip in candidate_ips:
            shodan_match = shodan_ip_map.get(ip)
            if not shodan_match:
                continue

            sdet = dict(shodan_match.details or {})
            open_ports = list(sdet.get("open_ports") or [])
            sensitive_open = [p for p in open_ports if p in SENSITIVE_PORTS]

            if not sensitive_open:
                continue

            # ── ACURÁCIA: o IP pertence ao host onde o Shodan o achou (pode ser
            # um SUBDOMÍNIO de terceiro, ex.: comunicacao.valid.com/Salesforce),
            # NÃO necessariamente a origem web do alvo. E porta de E-MAIL (25/465/
            # 587) NÃO é "bypass de WAF web". Sem isso, viram falsos-positivos.
            _ip_host = str(getattr(shodan_match, "domain", "") or wf.domain or "")
            _ip_owner = str(sdet.get("org") or sdet.get("isp") or sdet.get("asn_org") or "")
            _EMAIL_PORTS = {25, 465, 587, 110, 143, 993, 995}
            _SAAS_OWNER = re.compile(r"(salesforce|sendgrid|mailgun|mailchimp|outlook|google|"
                                     r"amazonses|sparkpost|zendesk|cloudflare|akamai|fastly)", re.I)
            _web_ports = [p for p in sensitive_open if p not in _EMAIL_PORTS]
            _is_saas = bool(_SAAS_OWNER.search(_ip_owner))
            # Se só há portas de e-mail OU o IP é de SaaS de terceiro → NÃO é
            # bypass de origem web. Pula (evita o falso-positivo do 96.43.154.16).
            if not _web_ports or _is_saas:
                continue

            sensitive_open = _web_ports
            domain = _ip_host or str(wf.domain or "")
            title = (
                f"[CORRELAÇÃO] Origem possivelmente exposta atrás do WAF: "
                f"{_ip_host or ip} → {ip} ({', '.join(str(p) for p in sensitive_open[:5])})"
            )

            # Verificar se já existe
            exists = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == scan_id,
                    Finding.title == title[:255],
                    Finding.domain == domain,
                )
                .first()
            )
            if exists:
                continue

            port_risks = {
                22: "SSH exposto — brute force / credential stuffing",
                3389: "RDP exposto — brute force / ransomware entry point",
                445: "SMB exposto — EternalBlue / ransomware propagation",
                6379: "Redis sem auth — leitura/escrita de dados",
                9200: "Elasticsearch sem auth — vazamento de dados",
                27017: "MongoDB sem auth — acesso total ao banco",
                3306: "MySQL exposto externamente",
                5432: "PostgreSQL exposto externamente",
                1433: "MSSQL exposto externamente",
                21: "FTP — transmissão de credenciais em plaintext",
                23: "Telnet — sem criptografia",
            }
            risk_notes = [port_risks[p] for p in sensitive_open if p in port_risks]

            corr = Finding(
                scan_job_id=scan_id,
                title=title[:255],
                severity="high",
                risk_score=9,
                confidence_score=85,
                domain=domain,
                tool="waf_shodan_correlation",
                details={
                    "correlation_type": "waf_bypass_x_shodan_ports",
                    "waf_bypass_finding_id": wf.id,
                    "shodan_finding_id": shodan_match.id,
                    "bypass_ip": ip,
                    "sensitive_ports": sensitive_open,
                    "all_open_ports": open_ports,
                    "risk_notes": risk_notes,
                    "resolved_ip": ip,
                    "ip_owner": _ip_owner or None,
                    "ip_host": _ip_host or None,
                    "evidence": (
                        f"IP {ip}" + (f" ({_ip_owner})" if _ip_owner else "") +
                        f", do host {_ip_host or domain}, tem portas WEB sensíveis abertas no "
                        f"Shodan: {sensitive_open} — a origem pode ser acessível diretamente, "
                        f"contornando o WAF/CDN. (Validar manualmente: confirmar que é a origem "
                        f"web do alvo, não serviço de terceiro.)"
                    ),
                    "owasp_category": "A05:2021 Security Misconfiguration",
                    "remediation": (
                        f"1. Restringir acesso às portas {sensitive_open} por IP (apenas Cloudflare ranges). "
                        f"2. Configurar firewall para bloquear acesso direto ao IP de origem. "
                        f"3. Auditar serviços expostos nas portas identificadas."
                    ),
                },
                recommendation=(
                    f"Servidor de origem em {ip} pode ser acessado contornando o WAF. "
                    f"Portas sensíveis expostas: {sensitive_open}. Ação imediata recomendada."
                ),
                created_at=datetime.utcnow(),
            )
            db.add(corr)
            try:
                db.flush()
                created += 1
            except Exception as exc:
                db.rollback()
                logger.debug("waf_shodan correlation flush error: %s", exc)

    if created:
        db.commit()
        logger.info("correlate_waf_shodan: created %d correlation findings for scan %s", created, scan_id)

    return created


# ─────────────────────────────────────────────────────────────────────────────
# 3. Findings de negócio: infra exposta, dev environments, compliance LGPD
# ─────────────────────────────────────────────────────────────────────────────

# Subdomínios que indicam infra operacional exposta publicamente
_INFRA_OPS_KEYWORDS = {
    "portainer": ("Interface Docker (Portainer) exposta", "critical", 10,
                  "Remove external access. Place behind VPN or IP allowlist immediately."),
    "rabbitmq": ("Message Broker (RabbitMQ) exposto", "high", 8,
                 "Restrict access to internal network. Unauthenticated RabbitMQ allows queue injection."),
    "flower": ("Celery Task Monitor (Flower) exposto — tasks e workers visíveis externamente", "high", 8,
               "Block external access. Flower exposes task history, queues and worker details."),
    "zabbix": ("Monitoring Server (Zabbix) exposto — credenciais e topologia de rede visíveis", "high", 8,
               "Restrict to management network. Zabbix has history of auth-bypass CVEs."),
    "grafana": ("Dashboard Grafana exposto externamente", "medium", 6,
                "Ensure authentication is enabled. CVE-2021-43798 allows path traversal without auth."),
    "kibana": ("Kibana exposto externamente — dados de log possivelmente acessíveis", "high", 8,
               "Kibana should never be internet-facing. Restrict to internal network."),
    "jenkins": ("CI/CD Jenkins exposto — código-fonte e pipelines visíveis", "critical", 10,
                "Jenkins internet-exposed is critical. Enable auth, restrict by IP, use VPN."),
    "prometheus": ("Prometheus exposto — métricas internas e endpoints de scrape visíveis", "medium", 5,
                   "Restrict access. Prometheus exposes internal network topology via scrape configs."),
    "redis": ("Redis exposto externamente", "critical", 10,
              "Redis without auth + external access = full server compromise. CVE-2022-0543."),
    "mongo": ("MongoDB exposto externamente", "critical", 10,
              "MongoDB without auth = full database access. CVE history: ransomware target."),
    "elastic": ("Elasticsearch exposto externamente — dados indexados possivelmente acessíveis", "critical", 10,
                "Unauthenticated Elasticsearch exposes all indexed data publicly."),
    "consul": ("Consul (service mesh) exposto — topologia de serviços interna visível", "high", 8,
               "Consul API exposes service discovery, KV store and ACL tokens."),
    "vault": ("HashiCorp Vault exposto externamente — cofre de segredos visível", "critical", 10,
              "Vault UI/API internet-facing is critical. Restrict to internal network only."),
    "k8s": ("Kubernetes API ou dashboard exposto externamente", "critical", 10,
            "K8s API server internet-facing is critical. Use IP allowlist + mTLS."),
    "kubernetes": ("Kubernetes API ou dashboard exposto externamente", "critical", 10,
                   "K8s API server internet-facing is critical. Use IP allowlist + mTLS."),
    "rancher": ("Rancher (K8s manager) exposto externamente", "critical", 10,
                "Rancher internet-facing exposes full Kubernetes cluster management."),
    "nagios": ("Nagios monitoring exposto externamente", "medium", 5,
               "Restrict to management network. Exposes server topology."),
}

# Keywords de ambiente de desenvolvimento
_DEV_ENV_KEYWORDS = ("dev-", "staging", "homolog", "hml-", "qa-", "test-", "sandbox", "uat-", "pre-prod")

# Subdomínios que processam dados pessoais/financeiros (risco LGPD)
_SENSITIVE_DATA_KEYWORDS = {
    "crm": "CRM (dados de clientes)",
    "fatura": "Faturamento (dados financeiros)",
    "invoice": "Faturamento (dados financeiros)",
    "customer": "Dados de clientes",
    "bank": "Dados bancários/financeiros",
    "payment": "Dados de pagamento",
    "card": "Dados de cartão",
    "cpf": "Dados de CPF/identidade",
    "documentos": "Documentos pessoais",
    "helpdesk": "Helpdesk (dados pessoais de chamados)",
}


def analyze_business_risks(db: Session, scan_id: int) -> int:
    """
    Analisa os targets do scan em busca de riscos de negócio:
    1. Infraestrutura operacional exposta publicamente
    2. Ambientes de desenvolvimento internet-facing
    3. Serviços que processam dados pessoais sem headers de segurança mínimos (LGPD)
    4. Email pattern disclosure → phishing surface
    5. Subdomain takeover candidates consolidados

    Retorna número de findings de negócio criados.
    """
    from app.models.models import Finding, ScanWorkItem

    # Targets únicos deste scan
    targets = [
        r[0] for r in
        db.query(ScanWorkItem.target)
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .distinct()
        .all()
    ]

    created = 0

    # ── 1. Infraestrutura operacional exposta ────────────────────────────────
    for target in targets:
        subdomain = target.lower().split(".")[0]
        for kw, (desc, sev, risk, remediation) in _INFRA_OPS_KEYWORDS.items():
            if kw not in subdomain:
                continue
            title = f"[INFRA-EXPOSTA] {desc}: {target}"
            exists = db.query(Finding.id).filter(
                Finding.scan_job_id == scan_id,
                Finding.title == title[:255],
            ).first()
            if exists:
                continue
            f = Finding(
                scan_job_id=scan_id,
                title=title[:255],
                severity=sev,
                risk_score=risk,
                confidence_score=80,
                domain=target,
                tool="business_risk_analysis",
                details={
                    "business_risk": "infra_ops_exposed",
                    "keyword_matched": kw,
                    "evidence": f"Subdomínio '{target}' indica {desc} acessível externamente via DNS público",
                    "owasp_category": "A05:2021 Security Misconfiguration",
                    "remediation": remediation,
                    "impact": (
                        f"Acesso não autorizado a {desc} pode comprometer toda a infraestrutura, "
                        "vazar dados de configuração, credenciais de outros serviços e permitir "
                        "movimento lateral dentro da rede."
                    ),
                },
                recommendation=remediation,
                created_at=datetime.utcnow(),
            )
            db.add(f)
            try:
                db.flush()
                created += 1
            except Exception:
                db.rollback()

    # ── 2. Ambientes de desenvolvimento expostos (sistêmico) ─────────────────
    dev_targets = [t for t in targets if any(kw in t.lower() for kw in _DEV_ENV_KEYWORDS)]
    if len(dev_targets) >= 2:
        root_domains: dict[str, list[str]] = defaultdict(list)
        for t in dev_targets:
            root_domains[_root_domain(t)].append(t)
        for root, dev_list in root_domains.items():
            if len(dev_list) < 2:
                continue
            title = f"[DEV-EXPOSTO] {len(dev_list)} ambientes de desenvolvimento internet-facing em {root}"
            exists = db.query(Finding.id).filter(
                Finding.scan_job_id == scan_id,
                Finding.title == title[:255],
            ).first()
            if exists:
                continue
            f = Finding(
                scan_job_id=scan_id,
                title=title[:255],
                severity="high",
                risk_score=8,
                confidence_score=90,
                domain=root,
                tool="business_risk_analysis",
                details={
                    "business_risk": "dev_environment_exposed",
                    "affected_subdomains": sorted(dev_list),
                    "evidence": (
                        f"{len(dev_list)} subdomínios de desenvolvimento acessíveis externamente: "
                        + ", ".join(sorted(dev_list)[:8])
                    ),
                    "owasp_category": "A05:2021 Security Misconfiguration",
                    "impact": (
                        "Ambientes de desenvolvimento tipicamente têm: autenticação mais fraca, "
                        "dados reais de produção copiados para testes, credenciais hardcoded, "
                        "logs verbosos com dados sensíveis e sem rate limiting."
                    ),
                    "remediation": (
                        "1. Colocar ambientes dev/staging atrás de VPN ou IP allowlist. "
                        "2. Nunca usar dados reais em ambientes de desenvolvimento. "
                        "3. Usar credenciais diferentes para cada ambiente."
                    ),
                },
                recommendation=(
                    f"Isolar {len(dev_list)} ambientes de dev de acesso público. "
                    "Usar VPN ou IP allowlist para acesso ao ambiente de desenvolvimento."
                ),
                created_at=datetime.utcnow(),
            )
            db.add(f)
            try:
                db.flush()
                created += 1
            except Exception:
                db.rollback()

    # ── 3. LGPD — dados pessoais sem headers mínimos ─────────────────────────
    # Encontrar targets sensíveis que têm findings de headers ausentes
    sensitive_data_targets = []
    for target in targets:
        sub = target.lower().split(".")[0]
        for kw, data_type in _SENSITIVE_DATA_KEYWORDS.items():
            if kw in sub:
                sensitive_data_targets.append((target, data_type))
                break

    if sensitive_data_targets:
        # Verificar quais desses targets têm header findings
        for target, data_type in sensitive_data_targets:
            has_missing_headers = db.query(Finding.id).filter(
                Finding.scan_job_id == scan_id,
                Finding.domain == target,
                Finding.title.like("Header de seguranca ausente%"),
            ).first()

            if not has_missing_headers:
                continue

            title = f"[LGPD-RISCO] {data_type} sem controles mínimos de segurança HTTP: {target}"
            exists = db.query(Finding.id).filter(
                Finding.scan_job_id == scan_id,
                Finding.title == title[:255],
            ).first()
            if exists:
                continue

            f = Finding(
                scan_job_id=scan_id,
                title=title[:255],
                severity="medium",
                risk_score=6,
                confidence_score=70,
                domain=target,
                tool="business_risk_analysis",
                details={
                    "business_risk": "lgpd_compliance_risk",
                    "data_type": data_type,
                    "evidence": (
                        f"Subdomínio '{target}' provavelmente processa {data_type} "
                        "mas não possui headers de segurança mínimos (HSTS, CSP, X-Frame-Options)."
                    ),
                    "owasp_category": "A05:2021 Security Misconfiguration",
                    "regulation": "LGPD Art. 46 — Medidas técnicas de segurança adequadas",
                    "impact": (
                        "Ausência de headers de segurança em sistemas que processam dados pessoais "
                        "pode configurar violação do Art. 46 da LGPD (Lei 13.709/2018), "
                        "expondo a organização a multas de até 2% do faturamento (máx. R$ 50M)."
                    ),
                    "remediation": (
                        "1. Implementar HSTS (min 1 ano + includeSubDomains). "
                        "2. Configurar Content-Security-Policy restritiva. "
                        "3. Adicionar X-Frame-Options: SAMEORIGIN. "
                        "4. Registrar este sistema no Registro de Atividades de Tratamento (LGPD Art. 37). "
                        "5. Nomear DPO (Encarregado de Dados) se aplicável."
                    ),
                },
                recommendation=(
                    f"Revisar conformidade LGPD para {data_type} em {target}. "
                    "Implementar headers de segurança e documentar tratamento de dados pessoais."
                ),
                created_at=datetime.utcnow(),
            )
            db.add(f)
            try:
                db.flush()
                created += 1
            except Exception:
                db.rollback()

    if created:
        db.commit()
        logger.info("analyze_business_risks: created %d business findings for scan %s", created, scan_id)

    return created


def run_all_intelligence(db: Session, scan_id: int) -> dict[str, int]:
    """Executa todos os módulos de inteligência para um scan."""
    systemic = consolidate_systemic_findings(db, scan_id)
    correlations = correlate_waf_shodan(db, scan_id)
    business = analyze_business_risks(db, scan_id)
    return {
        "systemic": systemic,
        "waf_shodan_correlations": correlations,
        "business_risks": business,
    }
