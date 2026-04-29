from __future__ import annotations

from typing import Any


MISSION_ITEMS = [
    "01. Recon - Subdomains, ports, directories",
    "02. Vuln Scan - Nuclei, nmap scripts",
    "03. Content - Fuzzing, backups, admin panels",
    "04. SSL/TLS - Cipher suites, certificates, headers",
    "05. Auth - SQLi login, brute-force, OAuth",
    "06. Injection - XSS, SQLi, Command, XXE, SSTI",
    "07. SSRF - Param fuzzing, cloud metadata",
    "08. IDOR - Access control, privilege escalation",
    "09. API - GraphQL, REST, rate limiting",
    "10. Upload - Extension bypass, webshells",
    "11. RCE - Deserialization, Log4j",
    "12. Race - TOCTOU, business logic",
    "13. Takeover - Subdomain, CNAME",
    "14. Email - SPF, DKIM, DMARC",
    "15. Cloud - S3, Azure, GCP, K8s",
    "16. WebSocket - Origin, injection",
    "17. CMS - WordPress, Joomla, Drupal",
    "18. Links - Broken link hijacking",
    "19. Supply Chain - JS libs, dependencies",
    "20. Report - JSON + PDF generation",
]


SKILL_CATALOG: list[dict[str, Any]] = [
    # 1. Supervisor Loop & Guardrails
    {
        "id": "supervisor-guardrails",
        "category": "orchestration",
        "description": "Supervisão autônoma, controle de iteração, adaptação e guardrails.",
        "triggers": ["supervisor", "loop", "autonomous", "guardrail", "iteration"],
        "playbook": [],
    },
    # 2. Planejamento Estratégico
    {
        "id": "strategic-planning",
        "category": "planning",
        "description": "Planejamento tático, definição de fases e contratos de execução.",
        "triggers": ["plan", "strategy", "contract", "delegation"],
        "playbook": [],
    },
    # 3. Descoberta de Ativos
    {
        "id": "asset-discovery",
        "category": "reconnaissance",
        "description": "Enumeração de ativos, subdomínios e mapeamento de superfície.",
        "triggers": ["domain", "subdomain", "dns", "asset", "surface", "recon"],
        "playbook": ["subfinder", "findomain", "assetfinder", "amass", "massdns", "shuffledns", "chaos", "dnsx", "hakrawler", "gau", "waybackurls", "paramspider"],
    },
    # 4. OSINT & Exposição
    {
        "id": "osint-exposure",
        "category": "osint",
        "description": "Coleta OSINT, leaks, exposição e inteligência externa.",
        "triggers": ["osint", "shodan", "leak", "exposure", "internet", "theharvester"],
        "playbook": ["shodan-cli", "theHarvester", "h8mail", "metagoofil"],
    },
    # 5. Enumeração de Serviços
    {
        "id": "service-enum",
        "category": "services",
        "description": "Enumeração de serviços, fingerprint, banners e portas.",
        "triggers": ["service", "port", "banner", "fingerprint", "nmap", "naabu", "masscan"],
        "playbook": ["nmap", "naabu", "masscan", "httpx", "whatweb", "sslscan"],
    },
    # 6. Enumeração Web/HTTP
    {
        "id": "web-enum",
        "category": "web",
        "description": "Enumeração de diretórios, arquivos, endpoints e crawling.",
        "triggers": ["web", "http", "dir", "endpoint", "crawl", "ffuf", "gobuster", "feroxbuster", "dirsearch"],
        "playbook": ["ffuf", "gobuster", "feroxbuster", "dirsearch", "katana", "gau", "hakrawler", "waymore"],
    },
    # 7. Fingerprint HTTP/TLS
    {
        "id": "http-fingerprint",
        "category": "technologies",
        "description": "Fingerprint de serviços HTTP/TLS, headers e tecnologias.",
        "triggers": ["http", "https", "header", "tls", "ssl", "tech", "whatweb", "nikto"],
        "playbook": ["curl-headers", "httpx", "whatweb", "nikto"],
    },
    # 8. SAST/Secrets/Deps
    {
        "id": "sast-secrets-deps",
        "category": "code",
        "description": "SAST, secrets, dependências e análise de código.",
        "triggers": ["sast", "secret", "dep", "semgrep", "bandit", "gitleaks", "trufflehog"],
        "playbook": ["semgrep", "bandit", "gitleaks", "trufflehog", "retire", "eslint", "jshint"],
    },
    # 9. Validação de WAF/Proxy
    {
        "id": "waf-aware-validation",
        "category": "protocols",
        "description": "Validação aware de WAF/proxy para reduzir falsos positivos.",
        "triggers": ["waf", "cloudflare", "proxy", "modsecurity", "akamai"],
        "playbook": ["wafw00f", "curl-headers", "nmap-vulscan"],
    },
    # 10. Testes de Vulnerabilidade Web
    {
        "id": "vuln-web-injection",
        "category": "vulnerabilities",
        "description": "Validação progressiva de injeção e falhas web com evidência reproduzível.",
        "triggers": ["sqli", "xss", "ssrf", "injection", "burp", "wapiti", "dalfox"],
        "playbook": ["burp-cli", "nikto", "nmap-vulscan", "dalfox", "wapiti", "nuclei"],
    },
    # 11. Exploração de Serviços
    {
        "id": "exploit-services",
        "category": "exploitation",
        "description": "Exploração de serviços, brute force, pós-exploração.",
        "triggers": ["exploit", "brute", "hydra", "john", "hashcat", "cme", "responder"],
        "playbook": ["hydra", "john", "hashcat", "CrackMapExec", "Responder"],
    },
    # 12. Pós-Exploitation/OSINT Avançado
    {
        "id": "post-exploitation",
        "category": "post-exploitation",
        "description": "Pós-exploração, enumeração interna, OSINT avançado.",
        "triggers": ["post", "internal", "osint", "loot", "pivot"],
        "playbook": ["impacket", "theHarvester", "shodan-cli", "h8mail"],
    },
    # 13. Evidência e Prova
    {
        "id": "evidence-proof-pack",
        "category": "coordination",
        "description": "Gate de evidência: só promove severidade alta com prova mínima reproduzível.",
        "triggers": ["critical", "high", "proof", "repro", "validation"],
        "playbook": ["burp-cli", "nikto", "nmap-vulscan"],
    },
    # 14. Governança & Rating
    {
        "id": "governance-rating",
        "category": "governance",
        "description": "Governança, rating FAIR, classificação de risco.",
        "triggers": ["governance", "rating", "fair", "risk", "score"],
        "playbook": [],
    },
    # 15. Narrativa Executiva
    {
        "id": "executive-narrative",
        "category": "executive",
        "description": "Sumarização executiva, narrativa e priorização.",
        "triggers": ["executive", "narrative", "summary", "priorities"],
        "playbook": [],
    },
]


def build_autonomous_mission_contract(max_iterations: int) -> dict[str, Any]:
    return {
        "mode": "autonomous-supervisor",
        "max_iterations": int(max_iterations),
        "loop": ["think", "delegate", "test", "observe", "adapt", "validate"],
        "execution_control": {
            "approaching_limit_ratio": 0.85,
            "force_finalize_remaining": 2,
            "pause_on_stagnation": True,
            "stagnation_threshold": 3,
        },
        "evidence_gate": {
            "critical_high_require_verified": True,
            "required_proof_fields": ["validation_status", "repro_steps", "technical_evidence"],
            "default_status_without_proof": "hypothesis",
        },
    }


def _text_blob(target: str, findings: list[dict[str, Any]], target_type: str, discovered_ports: list[int]) -> str:
    chunks = [str(target or ""), str(target_type or "")]
    if discovered_ports:
        chunks.append("ports:" + ",".join(str(p) for p in discovered_ports[:12]))
    for finding in findings[:40]:
        details = finding.get("details") or {}
        chunks.extend(
            [
                str(finding.get("title") or ""),
                str(finding.get("severity") or ""),
                str(details.get("tool") or ""),
                str(details.get("evidence") or ""),
            ]
        )
    return " ".join(chunks).lower()


def select_mission_skills(
    target: str,
    findings: list[dict[str, Any]] | None = None,
    target_type: str = "dominio",
    discovered_ports: list[int] | None = None,
    max_skills: int = 5,
) -> list[dict[str, Any]]:
    findings = list(findings or [])
    discovered_ports = list(discovered_ports or [])
    blob = _text_blob(target, findings, target_type, discovered_ports)

    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in SKILL_CATALOG:
        score = 0
        for trigger in skill.get("triggers") or []:
            if str(trigger).lower() in blob:
                score += 1
        if score > 0:
            scored.append((score, skill))

    # Garante diversidade mínima de base para cenários sem sinais fortes.
    if not scored:
        defaults = [
            "recon-subdomain-enum",
            "service-fingerprint-http",
            "osint-exposure-correlation",
            "vuln-web-injection",
            "evidence-proof-pack",
        ]
        by_id = {item["id"]: item for item in SKILL_CATALOG}
        return [by_id[item_id] for item_id in defaults[:max_skills] if item_id in by_id]

    scored.sort(key=lambda pair: pair[0], reverse=True)
    unique: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for _, skill in scored:
        skill_id = str(skill.get("id") or "")
        if not skill_id or skill_id in seen_ids:
            continue
        seen_ids.add(skill_id)
        unique.append(skill)
        if len(unique) >= max(1, int(max_skills)):
            break
    return unique
