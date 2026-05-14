from __future__ import annotations

from typing import Any


# Pipeline phases exposed to the frontend for progress tracking
MISSION_ITEMS = [
    "1. Autonomous Supervisor Loop & Guardrails",
    "2. Strategic Planning & Delegation Contract",
    "3. Asset Discovery & Exposure Mapping",
    "4. Threat Intelligence Correlation",
    "5. Adversarial Hypothesis & Thinking Checkpoint",
    "6. Risk Assessment & Exploit Validation",
    "7. Evidence Adjudication & Reproduction Gate",
    "8. Governance & Rating (FAIR + AGE)",
    "9. Executive Narrative & Priorities",
]

# Detailed vulnerability analysis phases executed within nodes (xalgorix-inspired 22-phase pipeline)
PENTEST_PHASES = [
    # Phase 1 – Recon
    {"id": "P01", "title": "Subdomain Enumeration", "node": "asset_discovery",
     "tools": ["subfinder", "amass", "massdns", "dnsx", "shuffledns", "assetfinder", "alterx"]},
    {"id": "P02", "title": "Port & Service Scan", "node": "asset_discovery",
     "tools": ["naabu", "nmap", "masscan", "httpx"]},
    {"id": "P03", "title": "Web Crawling & JS Extraction", "node": "asset_discovery",
     "tools": ["katana", "hakrawler", "gau", "waybackurls", "gospider", "js-snooper", "jsniper"]},
    {"id": "P04", "title": "Parameter Discovery", "node": "asset_discovery",
     "tools": ["arjun", "paramspider", "ffuf-params", "ffuf-values", "wfuzz"]},
    # Phase 2 – Tech Fingerprint
    {"id": "P05", "title": "HTTP Security Headers & OWASP Top 10 Fingerprint", "node": "asset_discovery",
     "tools": ["httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"]},
    {"id": "P06", "title": "WAF Detection & Evasion Profile", "node": "asset_discovery",
     "tools": ["wafw00f", "curl-headers"]},
    # Phase 3 – OSINT
    {"id": "P07", "title": "OSINT & Leak Intelligence", "node": "threat_intel",
     "tools": ["shodan-cli", "theHarvester", "h8mail", "trufflehog", "gitleaks", "metagoofil"]},
    {"id": "P08", "title": "Email Security Posture (SPF/DKIM/DMARC)", "node": "threat_intel",
     "tools": ["theHarvester"]},
    {"id": "P09", "title": "Subdomain Takeover", "node": "threat_intel",
     "tools": ["subjack", "nuclei"]},
    {"id": "P10", "title": "Cloud Asset Exposure (S3/GCP/Azure)", "node": "threat_intel",
     "tools": ["nuclei", "shodan-cli", "trufflehog"]},
    # Phase 4 – Vulnerability Assessment
    {"id": "P11", "title": "Nuclei CVE & Misconfiguration Scan", "node": "risk_assessment",
     "tools": ["nuclei", "nmap-vulscan"]},
    {"id": "P12", "title": "Web Injection (SQLi/XSS/SSTI/XXE)", "node": "risk_assessment",
     "tools": ["sqlmap", "dalfox", "wapiti", "nikto"]},
    {"id": "P13", "title": "SSRF & Open Redirect", "node": "risk_assessment",
     "tools": ["nuclei", "interactsh-client"]},
    {"id": "P14", "title": "Authentication Bypass & Brute Force", "node": "risk_assessment",
     "tools": ["hydra", "medusa", "jwt_tool", "nuclei", "crackmapexec", "impacket", "evilwinrm"]},
    {"id": "P15", "title": "Directory & File Enumeration", "node": "risk_assessment",
     "tools": ["ffuf", "ffuf-files", "ffuf-params", "gobuster", "feroxbuster", "dirsearch", "wfuzz"]},
    {"id": "P16", "title": "API Security (REST/GraphQL/Rate Limit)", "node": "risk_assessment",
     "tools": ["nuclei", "arjun", "wapiti", "ffuf-params", "ffuf-post"]},
    {"id": "P17", "title": "Upload & WebShell Bypass", "node": "risk_assessment",
     "tools": ["nuclei"]},
    {"id": "P18", "title": "SSL/TLS Certificate, Protocol & Cipher Audit", "node": "risk_assessment",
     "tools": ["sslscan", "testssl", "nmap", "curl-headers"]},
    {"id": "P19", "title": "IDOR & Access Control Flaws", "node": "risk_assessment",
     "tools": ["nuclei", "katana", "arjun", "curl-headers"]},
    {"id": "P20", "title": "CMS-Specific Scan (WP/Joomla/Drupal)", "node": "risk_assessment",
     "tools": ["wpscan", "nuclei", "nikto"]},
    # Phase 5 – Code/Supply Chain
    {"id": "P21", "title": "Secret & Credential Exposure", "node": "threat_intel",
     "tools": ["trufflehog", "gitleaks", "semgrep", "bandit"]},
    {"id": "P22", "title": "Dependency & Supply Chain Risk", "node": "risk_assessment",
     "tools": ["retire", "trivy", "semgrep", "bandit", "gitleaks", "eslint", "jshint", "ast-grep"]},
]


# Strix-inspired modular skill catalog (8 categories, community-extendable)
SKILL_CATALOG: list[dict[str, Any]] = [
    # ── CATEGORY 1: RECONNAISSANCE ───────────────────────────────────────────
    {
        "id": "recon-subdomain-enum",
        "category": "reconnaissance",
        "description": "Enumeração de subdomínios via passive (subfinder/amass/sublist3r/findomain/assetfinder), active brute (amass-brute/shuffledns), DNS recon (dnsrecon/dnsenum), e validação DNS.",
        "triggers": ["domain", "subdomain", "dns", "surface", "recon", "amass", "subfinder",
                     "dnsx", "sublist3r", "findomain", "dnsrecon", "dnsenum", "axfr", "zone transfer"],
        # Article ordering: passive first (fast, no noise) → DNS-level recon
        # → active brute (heavier) → DNS records (dnsx). Multi-source dedupe
        # happens downstream when findings are normalised into lista_ativos.
        "playbook": [
            "subfinder", "amass", "sublist3r", "findomain", "assetfinder",
            "dnsrecon-brt", "dnsrecon-zt", "dnsenum",
            "amass-brute", "amass-intel", "shuffledns", "alterx",
            "dnsx",
        ],
        "phases": ["P01"],
    },
    {
        "id": "recon-port-service",
        "category": "reconnaissance",
        "description": "Enumeração de portas + fingerprint de serviços. Pipeline article §8-§10: masscan/naabu (descoberta rápida) → nmap -sV -sC (versionamento) → httpx (alive check + tech detect).",
        "triggers": ["port", "service", "banner", "naabu", "nmap", "masscan", "rustscan"],
        # Pipeline order: fast port discovery → service version detect → HTTP probe
        "playbook": ["naabu", "masscan", "nmap", "httpx"],
        "phases": ["P02"],
    },
    {
        "id": "recon-web-crawl",
        "category": "reconnaissance",
        "description": "Crawling web, extração de JavaScript, endpoints e parâmetros. Inclui code-analyzer que faz GET no alvo, baixa JS referenciado e extrai forms/endpoints/env vars/secrets.",
        "triggers": ["crawl", "js", "endpoint", "param", "fuzz", "katana", "gau", "wayback", "code-analyzer"],
        # `code-analyzer` runs first by convention: it produces structured
        # endpoints + forms that downstream tools (katana, arjun) can
        # consume, and forms hypotheses for the EXPLOITATION stage.
        "playbook": ["code-analyzer", "katana", "hakrawler", "gau", "waybackurls", "gospider", "arjun", "paramspider", "ffuf-params", "wfuzz"],
        "phases": ["P03", "P04"],
    },
    # ── CATEGORY 2: TECHNOLOGIES ─────────────────────────────────────────────
    {
        "id": "tech-http-fingerprint",
        "category": "technologies",
        "description": "Fingerprint HTTP/TLS, headers de segurança, OWASP Top 10 security misconfiguration e detecção de WAF.",
        "triggers": [
            "http", "https", "header", "headers", "owasp", "tls", "ssl", "whatweb", "nikto", "waf",
            "cloudflare", "akamai", "imperva", "sucuri",
            # tech-stack tags from detected_tech_stack
            "asp.net", "iis", "apache", "nginx", "tomcat", "openresty", "lighttpd",
            "x-aspnet-version", "x-powered-by", "server:",
        ],
        "playbook": ["code-analyzer", "httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"],
        "phases": ["P05", "P06"],
    },
    {
        "id": "tech-owasp-header-analysis",
        "category": "technologies",
        "description": "Analise de cabecalhos HTTP alinhada ao OWASP Top 10: HSTS, CSP, anti-clickjacking, MIME sniffing, referrer e permissions policy.",
        "triggers": ["security header", "owasp top 10", "hsts", "csp", "x-frame-options", "content-security-policy", "permissions-policy", "referrer-policy"],
        "playbook": ["curl-headers", "nikto", "httpx", "whatweb", "nuclei"],
        "phases": ["P05", "P06", "P12"],
    },
    {
        "id": "tech-cms-fingerprint",
        "category": "technologies",
        "description": "Detecção e scan de CMS (WordPress, Joomla, Drupal, Magento, Shopify, Sharepoint).",
        "triggers": [
            "cms", "wordpress", "wp", "joomla", "drupal", "wpscan",
            "magento", "shopify", "ghost", "sharepoint",
            "wp-content", "wp-admin", "wp-includes",
        ],
        "playbook": ["whatweb", "wpscan", "nuclei"],
        "phases": ["P20"],
    },
    # ── CATEGORY 3: VULNERABILITIES ──────────────────────────────────────────
    {
        "id": "vuln-injection",
        "category": "vulnerabilities",
        "description": "Validação de injeções: SQLi, XSS, SSTI, XXE com evidência reproduzível, sensível ao stack detectado (ASP/MSSQL, PHP/MySQL, Node, etc).",
        "triggers": [
            "sqli", "xss", "ssti", "xxe", "injection", "sqlmap", "dalfox", "wapiti",
            # back-end DB hints — quando aparecem na evidência, SQLi é a skill alvo
            "mssql", "mysql", "mariadb", "postgresql", "postgres", "oracle", "mongodb",
            # framework/lang que tipicamente concatena SQL/HTML cru
            "asp.net", "asp", "aspx", "iis", "php", "node.js", "express", "rails", "django", "flask",
            # parâmetros vulneráveis comuns que aparecem em evidência
            "search=", "?id=", "?q=", "?query=", "?keyword=", "?category=", "?name=",
        ],
        "playbook": ["sqlmap", "dalfox", "wapiti", "nikto", "nuclei"],
        "phases": ["P12"],
    },
    {
        "id": "vuln-ssrf-redirect",
        "category": "vulnerabilities",
        "description": "Detecção de SSRF, open redirect e server-side interaction.",
        "triggers": ["ssrf", "redirect", "interaction", "interactsh", "oob"],
        "playbook": ["nuclei", "interactsh-client"],
        "phases": ["P13"],
    },
    {
        "id": "vuln-auth-bypass",
        "category": "vulnerabilities",
        "description": "Bypass de autenticação, brute-force/fuzzing de credenciais, JWT/OAuth e MFA abuse.",
        "triggers": [
            "auth", "bypass", "brute", "fuzz credentials", "jwt", "oauth", "token",
            "hydra", "medusa", "login", "signin", "session", "aspnet_sessionid", "phpsessid",
            "jsessionid", "csrf",
        ],
        "playbook": ["hydra", "medusa", "jwt_tool", "nuclei", "crackmapexec"],
        "phases": ["P14"],
    },
    {
        "id": "vuln-directory-enum",
        "category": "vulnerabilities",
        "description": "Fuzzing de diretórios, arquivos ocultos, parâmetros, valores e painéis admin.",
        "triggers": ["dir", "path", "admin", "backup", "fuzz", "ffuf", "wfuzz", "gobuster", "dirsearch", "feroxbuster"],
        "playbook": ["ffuf", "ffuf-files", "ffuf-params", "ffuf-values", "ffuf-post", "wfuzz", "gobuster", "feroxbuster", "dirsearch"],
        "phases": ["P04", "P15", "P16"],
    },
    {
        "id": "vuln-idor-access-control",
        "category": "vulnerabilities",
        "description": "Validação de IDOR/BOLA e falhas de controle de acesso com duas identidades autorizadas.",
        "triggers": ["idor", "bola", "access control", "authorization", "tenant", "role", "object id"],
        "playbook": ["katana", "arjun", "nuclei", "curl-headers"],
        "phases": ["P14", "P16", "P19"],
    },
    {
        "id": "vuln-api-graphql",
        "category": "vulnerabilities",
        "description": "Testes de API REST/GraphQL, fuzzing de parametros/corpos, rate limiting e endpoints expostos.",
        "triggers": ["api", "rest", "graphql", "rate", "endpoint", "json", "post", "form", "fuzz"],
        "playbook": ["nuclei", "arjun", "wapiti", "ffuf-params", "ffuf-post"],
        "phases": ["P16"],
    },
    {
        "id": "vuln-nuclei-cve",
        "category": "vulnerabilities",
        "description": "Scan de CVEs e misconfigurations: nuclei (templates YAML) + bateria NMAP NSE (vuln, http-enum, smb-vuln, ssh-audit, ssl-vuln, dns-vuln). nmap aqui não faz port scan — usa scripts NSE de vulnerabilidade.",
        "triggers": ["cve", "nuclei", "misconfiguration", "exploit", "known",
                     "ms17-010", "eternalblue", "heartbleed", "shellshock",
                     "smb", "ssh weak", "ssl weak", "http-enum"],
        # nmap dual-role: also belongs here as `nmap-vulscan` (NSE vuln category)
        # plus targeted NSE batteries (http/smb/ssh/ssl/dns).
        "playbook": [
            "nuclei", "nikto",
            "nmap-vulscan", "nmap-http-enum", "nmap-smb-vuln",
            "nmap-dns-vuln", "nmap-ssh-audit", "nmap-ssl-vuln",
        ],
        "phases": ["P11"],
    },
    {
        "id": "vuln-ssl-tls",
        "category": "protocols",
        "description": "Auditoria de SSL/TLS, certificados, cadeia, validade, protocolos legados e cipher suites fracos.",
        "triggers": ["ssl", "tls", "cipher", "cert", "certificate", "chain", "expired", "self signed", "sslscan", "testssl"],
        "playbook": ["sslscan", "testssl", "nmap", "curl-headers"],
        "phases": ["P05", "P18"],
    },
    # ── CATEGORY 4: OSINT ────────────────────────────────────────────────────
    {
        "id": "osint-exposure-intel",
        "category": "osint",
        "description": "Inteligência de exposição: Shodan, theHarvester, leaks.",
        "triggers": ["shodan", "leak", "osint", "exposure", "internet", "theharvester"],
        "playbook": ["shodan-cli", "theHarvester", "h8mail"],
        "phases": ["P07"],
    },
    {
        "id": "osint-email-infra",
        "category": "osint",
        "description": "Postura de segurança de e-mail: SPF, DKIM, DMARC.",
        "triggers": ["email", "spf", "dkim", "dmarc", "mx", "mail"],
        "playbook": ["theHarvester"],
        "phases": ["P08"],
    },
    {
        "id": "osint-subdomain-takeover",
        "category": "osint",
        "description": "Detecção de takeover de subdomínios via CNAME dangling.",
        "triggers": ["takeover", "cname", "subjack", "dangling"],
        "playbook": ["subjack", "nuclei"],
        "phases": ["P09"],
    },
    {
        "id": "osint-cloud-exposure",
        "category": "osint",
        "description": "Exposição de assets em cloud: S3, GCP buckets, Azure blobs.",
        "triggers": ["cloud", "s3", "bucket", "azure", "gcp", "aws", "k8s", "kubernetes"],
        "playbook": ["nuclei", "shodan-cli", "trufflehog"],
        "phases": ["P10"],
    },
    # ── CATEGORY 5: CODE ANALYSIS ────────────────────────────────────────────
    {
        "id": "code-secrets-sast",
        "category": "code",
        "description": "Análise estática, SAST e detecção de secrets/credenciais expostas.",
        "triggers": ["sast", "secret", "credential", "key", "token", "semgrep", "bandit", "trufflehog", "gitleaks"],
        "playbook": ["semgrep", "bandit", "trufflehog", "gitleaks"],
        "phases": ["P21"],
    },
    {
        "id": "code-supply-chain-deps",
        "category": "code",
        "description": "Análise de dependências e risco de supply chain.",
        "triggers": ["dep", "supply", "chain", "npm", "retire", "trivy", "semgrep"],
        "playbook": ["retire", "trivy", "semgrep", "bandit", "gitleaks"],
        "phases": ["P22"],
    },
    # ── New skills absorbed from juice-shop walkthrough ──────────────────────
    {
        "id": "weak-cryptography",
        "category": "vulnerabilities",
        "description": "Identificação de hashing fraco (MD5/SHA1), encoding como criptografia (Base64/ROT13/z85), e cifras quebradas em cookies/JWT/cupons.",
        "triggers": ["md5", "rainbow", "base64 cookie", "rot13", "z85", "broken hash", "weak cipher", "encoding misuse", "jwt none"],
        "playbook": ["jwt_tool", "burp-cli", "trufflehog", "hashcat"],
        "phases": ["P11", "P14", "P22"],
    },
    {
        "id": "vuln-information-disclosure",
        "category": "vulnerabilities",
        "description": "Exposição não autorizada de paths, comentários HTML, mensagens de erro verbosas, JS bundles, robots.txt e sitemap.",
        "triggers": ["info exposure", "html comment", "stack trace", "verbose error", "leaked path", "easter egg", "score board", "robots.txt"],
        "playbook": ["katana", "hakrawler", "gau", "curl-headers", "trufflehog", "nuclei"],
        "phases": ["P03", "P05", "P22"],
    },
    # ── CATEGORY 6: PROTOCOLS ────────────────────────────────────────────────
    {
        "id": "waf-aware-validation",
        "category": "protocols",
        "description": "Validação aware de WAF/proxy para reduzir falsos positivos.",
        "triggers": ["waf", "cloudflare", "proxy", "modsecurity", "akamai", "imperva"],
        "playbook": ["wafw00f", "curl-headers", "nuclei"],
        "phases": ["P06"],
    },
    # ── CATEGORY 7: TOOLING ──────────────────────────────────────────────────
    {
        "id": "evidence-proof-pack",
        "category": "tooling",
        "description": "Gate de evidência: só promove severidade alta com prova reproduzível.",
        "triggers": ["critical", "high", "proof", "repro", "validation", "evidence"],
        "playbook": ["nuclei", "interactsh-client"],
        "phases": [],
    },
    # ── CATEGORY 8: ORCHESTRATION ────────────────────────────────────────────
    {
        "id": "supervisor-guardrails",
        "category": "orchestration",
        "description": "Supervisão autônoma, circuit breaker, WAF-aware e guardrails.",
        "triggers": ["supervisor", "loop", "autonomous", "guardrail", "iteration", "circuit"],
        "playbook": [],
        "phases": [],
    },
]


def build_autonomous_mission_contract(max_iterations: int) -> dict[str, Any]:
    return {
        "mode": "autonomous-supervisor",
        "max_iterations": int(max_iterations),
        "loop": ["know", "think", "test", "validate", "adapt"],
        "phases": PENTEST_PHASES,
        "execution_control": {
            "approaching_limit_ratio": 0.85,
            "force_finalize_remaining": 2,
            "pause_on_stagnation": True,
            "stagnation_threshold": 3,
        },
        # xalgorix-inspired circuit breaker
        "circuit_breaker": {
            "tool_failure_threshold": 5,
            "cooldown_seconds": 60,
            "consecutive_llm_failure_limit": 25,
            "llm_rate_limit_backoff_minutes": 30,
        },
        # strix-inspired scope boundary
        "scope_policy": {
            "enforce_authorized_targets": True,
            "out_of_scope_action": "skip_and_log",
        },
        # xalgorix-inspired finish gate
        "finish_gate": {
            "minimum_phases_before_finish": [
                "skill_selector",
                "skill_planner",
                "tool_selector",
                "tool_executor",
                "evidence_gate",
                "governance",
                "executive_analyst",
            ],
            "require_executive_summary": True,
        },
        "coverage_policy": {
            "target_installed_tool_coverage": 0.70,
            "attempt_all_installed_tools_before_finish": True,
            "retry_failed_tools_max_attempts": 2,
        },
        "evidence_gate": {
            "critical_high_require_verified": True,
            "required_proof_fields": ["validation_status", "repro_steps", "technical_evidence"],
            "default_status_without_proof": "hypothesis",
        },
    }


def _text_blob(
    target: str,
    findings: list[dict[str, Any]],
    target_type: str,
    discovered_ports: list[int],
    detected_tech_stack: list[str] | None = None,
) -> str:
    chunks = [str(target or ""), str(target_type or "")]
    if discovered_ports:
        chunks.append("ports:" + ",".join(str(p) for p in discovered_ports[:12]))
    # Tech-stack tags weigh in via duplication so they outweigh isolated noise.
    # Repeating the stack tag 3x acts as a soft +3 score boost on any skill
    # whose triggers include the tag.
    for tag in (detected_tech_stack or []):
        tag_str = str(tag or "").strip()
        if tag_str:
            chunks.extend([tag_str, tag_str, tag_str])
    for finding in findings[:40]:
        details = finding.get("details") or {}
        chunks.extend([
            str(finding.get("title") or ""),
            str(finding.get("severity") or ""),
            str(details.get("tool") or ""),
            str(details.get("evidence") or ""),
        ])
    return " ".join(chunks).lower()


def select_mission_skills(
    target: str,
    findings: list[dict[str, Any]] | None = None,
    target_type: str = "dominio",
    discovered_ports: list[int] | None = None,
    max_skills: int = 5,
    detected_tech_stack: list[str] | None = None,
) -> list[dict[str, Any]]:
    findings = list(findings or [])
    discovered_ports = list(discovered_ports or [])
    detected_tech_stack = list(detected_tech_stack or [])
    blob = _text_blob(target, findings, target_type, discovered_ports, detected_tech_stack)

    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in SKILL_CATALOG:
        score = sum(1 for trigger in (skill.get("triggers") or []) if str(trigger).lower() in blob)
        if score > 0:
            scored.append((score, skill))

    # Guaranteed baseline when no signals yet. Keep this web-pentest oriented:
    # early scans often have no findings yet, but the supervisor still needs
    # exploit-relevant skills available so accepted learning can steer the
    # first tool choices instead of falling back to a generic vuln scan.
    if not scored:
        defaults = [
            "recon-subdomain-enum",
            "recon-web-crawl",
            "vuln-directory-enum",
            "vuln-injection",
            "vuln-api-graphql",
            "vuln-ssrf-redirect",
            "vuln-auth-bypass",
            "tech-http-fingerprint",
            "osint-exposure-intel",
        ]
        by_id = {item["id"]: item for item in SKILL_CATALOG}
        return [by_id[sid] for sid in defaults[:max_skills] if sid in by_id]

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
