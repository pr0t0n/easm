"""Skill Library Service.

Gerencia a biblioteca de skills e o mapeamento de ferramentas por skill com score.
O agente consulta esta biblioteca para saber qual skill usar para uma atividade
e quais ferramentas usar (ranqueadas por score) para cada skill.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Catálogo canônico de skills e ferramentas com scores
# ──────────────────────────────────────────────────────────────────────────────

SKILL_CATALOG_SEED: list[dict[str, Any]] = [
    # ── RECONHECIMENTO ────────────────────────────────────────────────────────
    {
        "skill_name": "subdomain_enumeration",
        "skill_category": "asset_discovery",
        "activity_types": ["enumerate_subdomains", "dns_discovery", "subdomain_mapping"],
        "kill_chain_phases": ["P01"],
        "objective": "Mapear todos os subdomínios do alvo para expandir a superfície de ataque.",
        "quality_criteria": (
            "Mínimo de 1 subdomínio encontrado; ferramenta retornou saída estruturada; "
            "nenhum erro de execução."
        ),
        "tools": [
            {"tool_name": "subfinder", "score": 9.5, "evidence_type": "subdomain",
             "usage_guide": "Executa enumeração passiva de subdomínios via APIs públicas. "
                            "Não realiza brute-force. Usar sem flags especiais para alvo base."},
            {"tool_name": "amass", "score": 9.0, "evidence_type": "subdomain",
             "usage_guide": "Enumeração ativa e passiva de subdomínios. Suporta múltiplas fontes. "
                            "Usar flag -passive para escaneamento não intrusivo."},
            {"tool_name": "dnsx", "score": 8.0, "evidence_type": "dns_record",
             "usage_guide": "Resolução DNS em massa. Usar após subfinder para validar subdomínios."},
            {"tool_name": "shuffledns", "score": 7.5, "evidence_type": "subdomain",
             "usage_guide": "Brute-force de subdomínios com wordlist. Usar apenas quando escopo permite."},
            {"tool_name": "alterx", "score": 6.5, "evidence_type": "subdomain",
             "usage_guide": "Gera permutações de subdomínios. Usar como complemento ao subfinder."},
        ],
    },
    {
        "skill_name": "port_scanning",
        "skill_category": "asset_discovery",
        "activity_types": ["port_scan", "service_detection", "network_mapping"],
        "kill_chain_phases": ["P02"],
        "objective": "Identificar portas abertas e serviços em execução no alvo.",
        "quality_criteria": (
            "Lista de portas abertas com serviços identificados; scan completou sem timeout; "
            "resultado inclui versão do serviço quando possível."
        ),
        "tools": [
            {"tool_name": "naabu", "score": 9.5, "evidence_type": "port",
             "usage_guide": "Scanner de portas rápido. Usar com -top-ports 1000 para cobertura ampla."},
            {"tool_name": "nmap", "score": 9.0, "evidence_type": "port_service",
             "usage_guide": "Scanner com detecção de versão e scripts NSE. "
                            "Usar -sV -sC para fingerprint completo."},
            {"tool_name": "masscan", "score": 7.5, "evidence_type": "port",
             "usage_guide": "Scanner de alta velocidade para redes grandes. "
                            "Cuidado com rate limits; usar --rate conservador."},
        ],
    },
    {
        "skill_name": "web_fingerprinting",
        "skill_category": "asset_discovery",
        "activity_types": ["tech_detection", "header_analysis", "web_profiling"],
        "kill_chain_phases": ["P03"],
        "objective": "Identificar tecnologias web, frameworks e cabeçalhos de segurança.",
        "quality_criteria": (
            "Tecnologias identificadas com versão quando possível; "
            "cabeçalhos de segurança listados; WAF detectado."
        ),
        "tools": [
            {"tool_name": "httpx", "score": 9.5, "evidence_type": "http_metadata",
             "usage_guide": "Probe HTTP/HTTPS rápido com fingerprint. "
                            "Usar -tech-detect -status-code -title para output rico."},
            {"tool_name": "whatweb", "score": 8.5, "evidence_type": "technology",
             "usage_guide": "Identifica CMS, frameworks, bibliotecas JS. Usar com aggression level 3."},
            {"tool_name": "wafw00f", "score": 8.0, "evidence_type": "waf_detection",
             "usage_guide": "Detecta presença e tipo de WAF. Executar antes de testes de injeção."},
        ],
    },
    {
        "skill_name": "ssl_tls_audit",
        "skill_category": "asset_discovery",
        "activity_types": ["ssl_tls_check", "cert_analysis", "cipher_audit"],
        "kill_chain_phases": ["P05"],
        "objective": "Auditar configuração SSL/TLS, certificados e cifras criptográficas.",
        "quality_criteria": (
            "Versão TLS identificada; certificado analisado (validade, SANs, emissor); "
            "cifras fracas listadas quando presentes."
        ),
        "tools": [
            {"tool_name": "testssl", "score": 9.5, "evidence_type": "ssl_vulnerability",
             "usage_guide": "Auditoria SSL/TLS completa. Detecta BEAST, POODLE, Heartbleed. "
                            "Usar com --fast para resultado rápido."},
            {"tool_name": "sslscan", "score": 8.5, "evidence_type": "ssl_info",
             "usage_guide": "Lista cifras suportadas e protocolo TLS. Complementa testssl."},
        ],
    },
    {
        "skill_name": "web_crawling",
        "skill_category": "asset_discovery",
        "activity_types": ["crawl_endpoints", "discover_urls", "link_extraction"],
        "kill_chain_phases": ["P04"],
        "objective": "Descobrir endpoints, URLs e parâmetros expostos na aplicação web.",
        "quality_criteria": (
            "URLs únicas descobertas; endpoints de API identificados; "
            "formulários e parâmetros listados."
        ),
        "tools": [
            {"tool_name": "katana", "score": 9.5, "evidence_type": "url",
             "usage_guide": "Crawler moderno com suporte a JavaScript. "
                            "Usar -d 3 para profundidade razoável."},
            {"tool_name": "hakrawler", "score": 8.5, "evidence_type": "url",
             "usage_guide": "Crawling rápido de links e formulários. Boa cobertura de APIs."},
            {"tool_name": "gospider", "score": 8.0, "evidence_type": "url",
             "usage_guide": "Spider web com extração de JS. Usar -d 2 -c 10 para controle."},
            {"tool_name": "gau", "score": 7.5, "evidence_type": "url",
             "usage_guide": "Busca URLs históricas no Wayback Machine e outros. Passivo."},
            {"tool_name": "waybackurls", "score": 7.0, "evidence_type": "url",
             "usage_guide": "Extrai URLs do Wayback Machine. Útil para endpoints esquecidos."},
        ],
    },
    {
        "skill_name": "parameter_discovery",
        "skill_category": "asset_discovery",
        "activity_types": ["find_parameters", "param_mining", "param_discovery"],
        "kill_chain_phases": ["P06"],
        "objective": "Descobrir parâmetros GET/POST não documentados na aplicação.",
        "quality_criteria": (
            "Parâmetros únicos listados; diferenciados por método HTTP; "
            "parâmetros sensíveis sinalizados."
        ),
        "tools": [
            {"tool_name": "arjun", "score": 9.5, "evidence_type": "parameter",
             "usage_guide": "Descoberta inteligente de parâmetros HTTP. "
                            "Usar com -m GET,POST -t 10 para cobertura."},
            {"tool_name": "paramspider", "score": 8.0, "evidence_type": "parameter",
             "usage_guide": "Mining de parâmetros do Wayback Machine. Complementa arjun."},
        ],
    },
    {
        "skill_name": "subdomain_takeover",
        "skill_category": "asset_discovery",
        "activity_types": ["check_takeover", "dangling_cname", "orphan_subdomain"],
        "kill_chain_phases": ["P18"],
        "objective": "Identificar subdomínios com CNAME apontando para serviços não provisionados.",
        "quality_criteria": (
            "Subdomínios vulneráveis a takeover identificados; "
            "provedor de serviço identificado; risco de takeover confirmado."
        ),
        "tools": [
            {"tool_name": "subjack", "score": 9.5, "evidence_type": "takeover_vulnerability",
             "usage_guide": "Detecta subdomínio takeover verificando fingerprints de provedores. "
                            "Usar -w subdomains.txt -c providers.json."},
        ],
    },
    # ── WEAPONIZAÇÃO ──────────────────────────────────────────────────────────
    {
        "skill_name": "cve_correlation",
        "skill_category": "threat_intel",
        "activity_types": ["cve_lookup", "vulnerability_matching", "template_scan"],
        "kill_chain_phases": ["P07", "P08"],
        "objective": "Correlacionar serviços identificados com CVEs e templates de vulnerabilidade.",
        "quality_criteria": (
            "CVEs com CVSS ≥ 7.0 identificados; template nuclei confirmou finding; "
            "serviço e versão correspondendo ao CVE."
        ),
        "tools": [
            {"tool_name": "nuclei", "score": 9.5, "evidence_type": "cve",
             "usage_guide": "Scanner de templates para CVEs e vulnerabilidades conhecidas. "
                            "Usar -severity critical,high -t cves/ para foco."},
            {"tool_name": "nmap-vulscan", "score": 8.0, "evidence_type": "cve",
             "usage_guide": "Scripts NSE para correlação de CVE por versão de serviço."},
            {"tool_name": "nikto", "score": 7.5, "evidence_type": "web_vulnerability",
             "usage_guide": "Scanner de vulnerabilidades web clássico. "
                            "Coberto por WAFs — usar com cuidado."},
        ],
    },
    {
        "skill_name": "secret_detection",
        "skill_category": "threat_intel",
        "activity_types": ["secret_scan", "credential_leak", "key_exposure"],
        "kill_chain_phases": ["P09", "P21"],
        "objective": "Encontrar segredos, tokens e credenciais expostos em repositórios e respostas.",
        "quality_criteria": (
            "Segredos com entropia alta identificados; tipo de segredo classificado; "
            "localização exata (arquivo, linha, URL) registrada."
        ),
        "tools": [
            {"tool_name": "trufflehog", "score": 9.5, "evidence_type": "secret",
             "usage_guide": "Detecta segredos de alta entropia em git repos e filesystems. "
                            "Usar --only-verified para reduzir falsos positivos."},
            {"tool_name": "gitleaks", "score": 9.0, "evidence_type": "secret",
             "usage_guide": "Scanner de segredos em histórico git. "
                            "Usar com regras customizadas via .gitleaks.toml."},
        ],
    },
    {
        "skill_name": "osint_gathering",
        "skill_category": "threat_intel",
        "activity_types": ["email_harvest", "breach_check", "social_footprint"],
        "kill_chain_phases": ["P10"],
        "objective": "Coletar inteligência de fontes abertas sobre o alvo (emails, breaches, exposições).",
        "quality_criteria": (
            "Emails corporativos listados; breaches conhecidos identificados; "
            "informações de infraestrutura coletadas via Shodan."
        ),
        "tools": [
            {"tool_name": "shodan-cli", "score": 9.5, "evidence_type": "infrastructure",
             "usage_guide": "Busca ativa de ativos expostos na internet via Shodan API. "
                            "Requer SHODAN_API_KEY. Usar domain:{target} para busca focada."},
            {"tool_name": "theHarvester", "score": 9.0, "evidence_type": "email",
             "usage_guide": "Coleta emails, hosts e URLs de fontes OSINT. "
                            "Usar -b all para cobertura completa."},
            {"tool_name": "h8mail", "score": 8.0, "evidence_type": "breach",
             "usage_guide": "Verifica emails em breaches conhecidos. Requer API keys para fontes pagas."},
        ],
    },
    # ── ENTREGA / DELIVERY ────────────────────────────────────────────────────
    {
        "skill_name": "directory_fuzzing",
        "skill_category": "risk_assessment",
        "activity_types": ["fuzz_directories", "path_discovery", "dir_brute"],
        "kill_chain_phases": ["P15"],
        "objective": "Descobrir diretórios e arquivos ocultos ou não indexados na aplicação.",
        "quality_criteria": (
            "Caminhos com status 200/301/302 listados; admin panels e backups identificados; "
            "falsos positivos filtrados por tamanho de resposta."
        ),
        "tools": [
            {"tool_name": "ffuf", "score": 9.5, "evidence_type": "path",
             "usage_guide": "Fuzzer HTTP de alta performance. "
                            "Usar -w /wordlists/common.txt -mc 200,301,302 -fs 0."},
            {"tool_name": "gobuster", "score": 9.0, "evidence_type": "path",
             "usage_guide": "Brute-force de diretórios e DNS. "
                            "Usar mode dir -w wordlist -x php,html,js."},
            {"tool_name": "feroxbuster", "score": 8.5, "evidence_type": "path",
             "usage_guide": "Fuzzer recursivo em Rust. Ótimo para APIs REST. "
                            "Usar --depth 3 --filter-size 0."},
            {"tool_name": "dirsearch", "score": 8.0, "evidence_type": "path",
             "usage_guide": "Scanner de diretórios com wordlists built-in. "
                            "Usar com -e php,js,html para extensões comuns."},
        ],
    },
    {
        "skill_name": "parameter_fuzzing",
        "skill_category": "risk_assessment",
        "activity_types": ["fuzz_parameters", "param_testing", "input_validation"],
        "kill_chain_phases": ["P16"],
        "objective": "Testar parâmetros da aplicação com payloads para identificar vulnerabilidades.",
        "quality_criteria": (
            "Parâmetros com comportamento anômalo identificados; "
            "diferença de resposta registrada (tamanho, status, tempo)."
        ),
        "tools": [
            {"tool_name": "ffuf-params", "score": 9.5, "evidence_type": "parameter_vuln",
             "usage_guide": "FFUF configurado para fuzzing de parâmetros. "
                            "Usar -w params.txt:PARAM -w values.txt:VALUE."},
            {"tool_name": "wfuzz", "score": 8.0, "evidence_type": "parameter_vuln",
             "usage_guide": "Fuzzer versátil para parâmetros e payloads. "
                            "Usar --hc 404 para filtrar not-found."},
        ],
    },
    # ── EXPLORAÇÃO ────────────────────────────────────────────────────────────
    {
        "skill_name": "injection_testing",
        "skill_category": "risk_assessment",
        "activity_types": ["sql_injection", "xss_testing", "code_injection"],
        "kill_chain_phases": ["P11", "P12"],
        "objective": "Validar vulnerabilidades de injeção (SQLi, XSS, SSTI) com reprodução.",
        "quality_criteria": (
            "Payload que confirma injeção documentado; request/response completos; "
            "impacto avaliado (leitura de dados, execução de código)."
        ),
        "tools": [
            {"tool_name": "sqlmap", "score": 9.5, "evidence_type": "sql_injection",
             "usage_guide": "Detecção e exploração automática de SQL Injection. "
                            "Usar --level=3 --risk=2 --batch para escaneamento sem interação."},
            {"tool_name": "dalfox", "score": 9.0, "evidence_type": "xss",
             "usage_guide": "Scanner de XSS focado em precisão. "
                            "Usar --deep-domxss para cobertura de DOM XSS."},
            {"tool_name": "wapiti", "score": 8.0, "evidence_type": "injection",
             "usage_guide": "Scanner de vulnerabilidades web multi-módulo. "
                            "Usar -m sql,xss,ssrf para módulos específicos."},
        ],
    },
    {
        "skill_name": "cms_vulnerability_scan",
        "skill_category": "risk_assessment",
        "activity_types": ["cms_scan", "plugin_vuln_check", "cms_fingerprint"],
        "kill_chain_phases": ["P14"],
        "objective": "Identificar vulnerabilidades em CMS (WordPress, Joomla, etc.) e plugins.",
        "quality_criteria": (
            "CMS e versão identificados; plugins vulneráveis listados com CVE; "
            "configurações inseguras documentadas."
        ),
        "tools": [
            {"tool_name": "wpscan", "score": 9.5, "evidence_type": "cms_vulnerability",
             "usage_guide": "Scanner especializado em WordPress. "
                            "Usar --enumerate vp,vt,u para plugins, temas e usuários."},
            {"tool_name": "nikto", "score": 8.0, "evidence_type": "web_vulnerability",
             "usage_guide": "Scanner genérico que também cobre CMSs. "
                            "Usar como complemento ao wpscan."},
        ],
    },
    # ── INSTALAÇÃO / PERSISTÊNCIA ─────────────────────────────────────────────
    {
        "skill_name": "auth_brute_force",
        "skill_category": "risk_assessment",
        "activity_types": ["brute_force_auth", "credential_test", "password_spray"],
        "kill_chain_phases": ["P14", "P19"],
        "objective": "Testar autenticação com credenciais fracas ou vazadas.",
        "quality_criteria": (
            "Credenciais testadas documentadas; credenciais válidas identificadas se encontradas; "
            "rate limiting detectado se presente."
        ),
        "tools": [
            {"tool_name": "hydra", "score": 9.5, "evidence_type": "credential",
             "usage_guide": "Brute-force de autenticação multi-protocolo. "
                            "Usar -L users.txt -P pass.txt -t 4 para evitar bloqueio."},
            {"tool_name": "medusa", "score": 9.0, "evidence_type": "credential",
             "usage_guide": "Alternativa ao hydra. Usar -M http -m DIR:/admin."},
            {"tool_name": "crackmapexec", "score": 8.5, "evidence_type": "credential",
             "usage_guide": "Post-exploitation e credential testing para SMB/LDAP. "
                            "Usar smb {target} -u users.txt -p passwords.txt."},
        ],
    },
    {
        "skill_name": "jwt_analysis",
        "skill_category": "risk_assessment",
        "activity_types": ["jwt_audit", "token_analysis", "auth_bypass"],
        "kill_chain_phases": ["P19"],
        "objective": "Auditar tokens JWT para algoritmos inseguros, assinatura fraca e bypass.",
        "quality_criteria": (
            "Algoritmo JWT identificado; vulnerabilidades (alg:none, weak secret) testadas; "
            "claims sensíveis listados."
        ),
        "tools": [
            {"tool_name": "jwt_tool", "score": 9.5, "evidence_type": "auth_vulnerability",
             "usage_guide": "Toolkit completo para análise e ataque de JWT. "
                            "Usar -t {token} -M at para all-tests mode."},
        ],
    },
    # ── AÇÕES NOS OBJETIVOS ───────────────────────────────────────────────────
    {
        "skill_name": "sast_analysis",
        "skill_category": "risk_assessment",
        "activity_types": ["code_scan", "sast_check", "source_analysis"],
        "kill_chain_phases": ["P22"],
        "objective": "Analisar código-fonte em busca de vulnerabilidades estáticas.",
        "quality_criteria": (
            "Findings com severidade high/critical identificados; "
            "arquivo e linha do código vulnerável documentados; "
            "regra de detecção registrada."
        ),
        "tools": [
            {"tool_name": "semgrep", "score": 9.5, "evidence_type": "code_vulnerability",
             "usage_guide": "SAST multi-linguagem com regras da comunidade. "
                            "Usar --config=auto para cobertura automática."},
            {"tool_name": "bandit", "score": 9.0, "evidence_type": "code_vulnerability",
             "usage_guide": "SAST especializado em Python. "
                            "Usar -r {dir} -ll para low severity e acima."},
        ],
    },
    {
        "skill_name": "dependency_audit",
        "skill_category": "risk_assessment",
        "activity_types": ["dep_check", "supply_chain", "sca_scan"],
        "kill_chain_phases": ["P21"],
        "objective": "Auditar dependências de terceiros em busca de CVEs e versões vulneráveis.",
        "quality_criteria": (
            "Dependências vulneráveis listadas com CVE e CVSS; "
            "versão atual vs versão corrigida documentadas."
        ),
        "tools": [
            {"tool_name": "trivy", "score": 9.5, "evidence_type": "dependency_vulnerability",
             "usage_guide": "Scanner de SCA para containers, filesystems e repositórios. "
                            "Usar fs {path} --severity HIGH,CRITICAL."},
            {"tool_name": "retire", "score": 8.5, "evidence_type": "dependency_vulnerability",
             "usage_guide": "Detecta bibliotecas JavaScript com vulnerabilidades conhecidas."},
            {"tool_name": "gitleaks", "score": 8.0, "evidence_type": "secret",
             "usage_guide": "Detecta segredos em repositórios git. "
                            "Usar detect --source={path}."},
        ],
    },
]

# Mapeamento de capability node → activity_types preferidos
CAPABILITY_ACTIVITY_MAP: dict[str, list[str]] = {
    "asset_discovery": [
        "enumerate_subdomains",
        "port_scan",
        "tech_detection",
        "crawl_endpoints",
        "ssl_tls_check",
        "find_parameters",
        "check_takeover",
    ],
    "threat_intel": [
        "cve_lookup",
        "secret_scan",
        "email_harvest",
    ],
    "risk_assessment": [
        "fuzz_directories",
        "sql_injection",
        "brute_force_auth",
        "dep_check",
        "cms_scan",
        "jwt_audit",
        "code_scan",
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
# Funções de query e seed
# ──────────────────────────────────────────────────────────────────────────────


def seed_skill_library(db) -> None:
    """Semeia a skill_library e skill_tool_mappings se estiverem vazias."""
    from app.models.models import SkillLibrary, SkillToolMapping

    try:
        count = db.query(SkillLibrary).count()
        if count > 0:
            return

        for seed_entry in SKILL_CATALOG_SEED:
            entry = dict(seed_entry)
            tools = list(entry.pop("tools", []))
            skill = SkillLibrary(**entry)
            db.add(skill)
            db.flush()
            for tool_data in tools:
                mapping = SkillToolMapping(skill_id=skill.id, **tool_data)
                db.add(mapping)

        db.commit()
        logger.info("Skill library seeded: %d skills", len(SKILL_CATALOG_SEED))
    except Exception as exc:
        db.rollback()
        logger.warning("Skill library seed failed (may already exist): %s", exc)


def sync_markdown_skill_library(db) -> dict[str, Any]:
    """Materializa skills markdown no banco usado pela UI/Agent Flow."""
    from app.models.models import SkillLibrary, SkillToolMapping
    from app.services.skill_runtime import load_all_md_skills

    skills = load_all_md_skills()
    created = 0
    updated = 0
    mappings = 0
    for skill_id, skill_data in skills.items():
        skill = db.query(SkillLibrary).filter(SkillLibrary.skill_name == skill_id).first()
        if skill is None:
            skill = SkillLibrary(skill_name=skill_id)
            db.add(skill)
            db.flush()
            created += 1
        else:
            updated += 1
        skill.skill_category = str(skill_data.get("category") or "custom")
        skill.activity_types = list(skill_data.get("triggers") or [])
        skill.kill_chain_phases = list(skill_data.get("phase_ids") or skill_data.get("phases") or [])
        skill.objective = str(skill_data.get("description") or skill_data.get("name") or skill_id)
        skill.quality_criteria = str(skill_data.get("exit_criteria") or "")
        skill.is_active = True

        db.query(SkillToolMapping).filter(SkillToolMapping.skill_id == skill.id).delete()
        ordered_tools = []
        ordered_tools.extend((tool, 10.0, "required") for tool in list(skill_data.get("required_tools") or []))
        ordered_tools.extend((tool, 7.0, "optional") for tool in list(skill_data.get("optional_tools") or []))
        ordered_tools.extend((tool, 5.0, "fallback") for tool in list(skill_data.get("fallback_tools") or []))
        seen: set[str] = set()
        for tool_name, score, evidence_type in ordered_tools:
            tool_name = str(tool_name or "").strip()
            if not tool_name or tool_name in seen:
                continue
            seen.add(tool_name)
            db.add(
                SkillToolMapping(
                    skill_id=skill.id,
                    tool_name=tool_name,
                    score=score,
                    usage_guide=f"{evidence_type} tool from markdown skill {skill_id}",
                    evidence_type=evidence_type,
                    parameters={"source": skill_data.get("source_file")},
                    is_active=True,
                )
            )
            mappings += 1
    db.flush()
    return {
        "skills_seen": len(skills),
        "created": created,
        "updated": updated,
        "tool_mappings": mappings,
    }


def get_skill_for_activity(db, activity_type: str, capability: str = "") -> dict[str, Any] | None:
    """Retorna a melhor skill para o activity_type dado.

    Busca primeiro por activity_type exato na lista; se não encontrar,
    cai para category == capability.
    """
    from app.models.models import SkillLibrary, SkillToolMapping

    try:
        skills = db.query(SkillLibrary).filter(SkillLibrary.is_active.is_(True)).all()
        for skill in skills:
            if activity_type in (skill.activity_types or []):
                tool_rows = (
                    db.query(SkillToolMapping)
                    .filter(
                        SkillToolMapping.skill_id == skill.id,
                        SkillToolMapping.is_active.is_(True),
                    )
                    .order_by(SkillToolMapping.score.desc())
                    .all()
                )
                return _skill_to_dict(skill, tool_rows)

        # Fallback: capability match
        if capability:
            skill = (
                db.query(SkillLibrary)
                .filter(
                    SkillLibrary.skill_category == capability,
                    SkillLibrary.is_active.is_(True),
                )
                .first()
            )
            if skill:
                tool_rows = (
                    db.query(SkillToolMapping)
                    .filter(
                        SkillToolMapping.skill_id == skill.id,
                        SkillToolMapping.is_active.is_(True),
                    )
                    .order_by(SkillToolMapping.score.desc())
                    .all()
                )
                return _skill_to_dict(skill, tool_rows)
    except Exception as exc:
        logger.warning("get_skill_for_activity failed: %s", exc)
    return None


def get_tools_for_skill(db, skill_name: str) -> list[dict[str, Any]]:
    """Retorna ferramentas ordenadas por score para uma skill específica."""
    from app.models.models import SkillLibrary, SkillToolMapping

    try:
        skill = db.query(SkillLibrary).filter(SkillLibrary.skill_name == skill_name).first()
        if not skill:
            return []
        rows = (
            db.query(SkillToolMapping)
            .filter(
                SkillToolMapping.skill_id == skill.id,
                SkillToolMapping.is_active.is_(True),
            )
            .order_by(SkillToolMapping.score.desc())
            .all()
        )
        return [
            {
                "tool_name": r.tool_name,
                "score": float(r.score or 5.0),
                "usage_guide": r.usage_guide or "",
                "evidence_type": r.evidence_type or "",
                "parameters": dict(r.parameters or {}),
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning("get_tools_for_skill failed: %s", exc)
    return []


def get_activity_demand_for_capability(
    capability: str,
    iteration: int,
    target: str,
    already_done: list[str],
) -> dict[str, Any]:
    """Gera a demanda de atividade que o supervisor envia ao agente.

    Seleciona o activity_type preferido para a capability que ainda
    não foi executado nesta sessão.
    """
    import uuid

    preferred = CAPABILITY_ACTIVITY_MAP.get(capability, [capability])
    activity_type = next(
        (a for a in preferred if a not in already_done),
        preferred[0] if preferred else capability,
    )

    skill_entry = next(
        (
            s for s in SKILL_CATALOG_SEED
            if activity_type in s.get("activity_types", [])
        ),
        None,
    )

    objective = (
        skill_entry["objective"]
        if skill_entry
        else f"Execute {activity_type} on {target}"
    )
    quality_criteria = (
        skill_entry["quality_criteria"]
        if skill_entry
        else "Ferramenta executou sem erros e retornou dados."
    )
    kill_chain_phases = (
        skill_entry["kill_chain_phases"]
        if skill_entry
        else []
    )

    return {
        "activity_id": f"act-{uuid.uuid4().hex[:12]}",
        "activity_type": activity_type,
        "skill_category": capability,
        "kill_chain_phases": kill_chain_phases,
        "objective": objective,
        "quality_criteria": quality_criteria,
        "target": target,
        "demanded_at": datetime.now().isoformat(),
        "iteration": iteration,
    }


def _skill_to_dict(skill, tool_rows: list) -> dict[str, Any]:
    return {
        "skill_id": skill.id,
        "skill_name": skill.skill_name,
        "skill_category": skill.skill_category,
        "activity_types": list(skill.activity_types or []),
        "kill_chain_phases": list(skill.kill_chain_phases or []),
        "objective": skill.objective or "",
        "quality_criteria": skill.quality_criteria or "",
        "tools": [
            {
                "tool_name": r.tool_name,
                "score": float(r.score or 5.0),
                "usage_guide": r.usage_guide or "",
                "evidence_type": r.evidence_type or "",
                "parameters": dict(r.parameters or {}),
            }
            for r in tool_rows
        ],
    }


def create_agent_activity_log(
    db,
    scan_job_id: int,
    iteration: int,
    activity_demand: dict[str, Any],
) -> int | None:
    """Cria um registro AgentActivityLog e retorna o id."""
    from app.models.models import AgentActivityLog

    try:
        entry = AgentActivityLog(
            scan_job_id=scan_job_id,
            iteration=iteration,
            activity_demand=activity_demand,
            status="pending",
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id
    except Exception as exc:
        db.rollback()
        logger.warning("create_agent_activity_log failed: %s", exc)
    return None


def update_agent_activity_log(
    db,
    log_id: int,
    **fields: Any,
) -> None:
    """Atualiza campos de um AgentActivityLog existente."""
    from app.models.models import AgentActivityLog

    try:
        entry = db.query(AgentActivityLog).filter(AgentActivityLog.id == log_id).first()
        if not entry:
            return
        for key, val in fields.items():
            setattr(entry, key, val)
        entry.updated_at = datetime.now()
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("update_agent_activity_log failed: %s", exc)
