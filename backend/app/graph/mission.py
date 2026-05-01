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

# Detailed pentesting phases executed within nodes (xalgorix-inspired 22-phase pipeline)
PENTEST_PHASES = [
    # Phase 1 – Recon
    {"id": "P01", "title": "Subdomain Enumeration", "node": "asset_discovery",
     "tools": ["subfinder", "amass", "massdns", "dnsx", "shuffledns", "assetfinder", "alterx"]},
    {"id": "P02", "title": "Port & Service Scan", "node": "asset_discovery",
     "tools": ["naabu", "nmap", "masscan", "httpx"]},
    {"id": "P03", "title": "Web Crawling & JS Extraction", "node": "asset_discovery",
     "tools": ["katana", "hakrawler", "gau", "waybackurls", "gospider", "js-snooper", "jsniper"]},
    {"id": "P04", "title": "Parameter Discovery", "node": "asset_discovery",
     "tools": ["arjun", "paramspider", "ffuf"]},
    # Phase 2 – Tech Fingerprint
    {"id": "P05", "title": "HTTP/TLS Fingerprint", "node": "asset_discovery",
     "tools": ["httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"]},
    {"id": "P06", "title": "WAF Detection & Evasion Profile", "node": "asset_discovery",
     "tools": ["wafw00f", "curl-headers"]},
    # Phase 3 – OSINT
    {"id": "P07", "title": "OSINT & Leak Intelligence", "node": "threat_intel",
     "tools": ["shodan-cli", "theHarvester", "h8mail", "metagoofil", "trufflehog", "gitleaks"]},
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
     "tools": ["sqlmap", "dalfox", "wapiti", "wfuzz", "burp-cli", "nikto"]},
    {"id": "P13", "title": "SSRF & Open Redirect", "node": "risk_assessment",
     "tools": ["nuclei", "burp-cli", "interactsh-client"]},
    {"id": "P14", "title": "Authentication Bypass & Brute Force", "node": "risk_assessment",
     "tools": ["hydra", "medusa", "jwt_tool", "nuclei", "burp-cli", "impacket", "evilwinrm"]},
    {"id": "P15", "title": "Directory & File Enumeration", "node": "risk_assessment",
     "tools": ["ffuf", "gobuster", "feroxbuster", "dirsearch"]},
    {"id": "P16", "title": "API Security (REST/GraphQL/Rate Limit)", "node": "risk_assessment",
     "tools": ["nuclei", "burp-cli", "arjun", "wapiti"]},
    {"id": "P17", "title": "Upload & WebShell Bypass", "node": "risk_assessment",
     "tools": ["nuclei", "burp-cli"]},
    {"id": "P18", "title": "SSL/TLS Weakness & Cipher Audit", "node": "risk_assessment",
     "tools": ["sslscan", "nmap", "testssl"]},
    {"id": "P19", "title": "IDOR & Access Control Flaws", "node": "risk_assessment",
     "tools": ["burp-cli", "nuclei"]},
    {"id": "P20", "title": "CMS-Specific Scan (WP/Joomla/Drupal)", "node": "risk_assessment",
     "tools": ["wpscan", "nuclei", "nikto"]},
    # Phase 5 – Code/Supply Chain
    {"id": "P21", "title": "Secret & Credential Exposure", "node": "threat_intel",
     "tools": ["trufflehog", "gitleaks", "semgrep", "bandit"]},
    {"id": "P22", "title": "Dependency & Supply Chain Risk", "node": "risk_assessment",
     "tools": ["retire", "trivy", "eslint", "jshint", "ast-grep", "semgrep"]},
]


# Strix-inspired modular skill catalog (8 categories, community-extendable)
SKILL_CATALOG: list[dict[str, Any]] = [
    # ── CATEGORY 1: RECONNAISSANCE ───────────────────────────────────────────
    {
        "id": "recon-subdomain-enum",
        "category": "reconnaissance",
        "description": "Enumeração de subdomínios, validação DNS e expansão de superfície.",
        "triggers": ["domain", "subdomain", "dns", "surface", "recon", "amass", "subfinder", "dnsx"],
        "playbook": ["subfinder", "amass", "massdns", "dnsx", "shuffledns", "assetfinder", "alterx"],
        "phases": ["P01"],
    },
    {
        "id": "recon-port-service",
        "category": "reconnaissance",
        "description": "Enumeração de portas e fingerprint de serviços expostos.",
        "triggers": ["port", "service", "banner", "naabu", "nmap", "masscan"],
        "playbook": ["naabu", "nmap", "masscan", "httpx"],
        "phases": ["P02"],
    },
    {
        "id": "recon-web-crawl",
        "category": "reconnaissance",
        "description": "Crawling web, extração de JavaScript, endpoints e parâmetros.",
        "triggers": ["crawl", "js", "endpoint", "param", "katana", "gau", "wayback"],
        "playbook": ["katana", "hakrawler", "gau", "waybackurls", "gospider", "arjun", "paramspider"],
        "phases": ["P03", "P04"],
    },
    # ── CATEGORY 2: TECHNOLOGIES ─────────────────────────────────────────────
    {
        "id": "tech-http-fingerprint",
        "category": "technologies",
        "description": "Fingerprint HTTP/TLS, headers de segurança e detecção de WAF.",
        "triggers": ["http", "https", "header", "tls", "ssl", "whatweb", "nikto", "waf", "cloudflare"],
        "playbook": ["httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"],
        "phases": ["P05", "P06"],
    },
    {
        "id": "tech-cms-fingerprint",
        "category": "technologies",
        "description": "Detecção e scan de CMS (WordPress, Joomla, Drupal).",
        "triggers": ["cms", "wordpress", "wp", "joomla", "drupal", "wpscan"],
        "playbook": ["whatweb", "wpscan", "nuclei"],
        "phases": ["P20"],
    },
    # ── CATEGORY 3: VULNERABILITIES ──────────────────────────────────────────
    {
        "id": "vuln-injection",
        "category": "vulnerabilities",
        "description": "Validação de injeções: SQLi, XSS, SSTI, XXE com evidência reproduzível.",
        "triggers": ["sqli", "xss", "ssti", "xxe", "injection", "sqlmap", "dalfox", "burp"],
        "playbook": ["sqlmap", "dalfox", "wapiti", "burp-cli", "nikto"],
        "phases": ["P12"],
    },
    {
        "id": "vuln-ssrf-redirect",
        "category": "vulnerabilities",
        "description": "Detecção de SSRF, open redirect e server-side interaction.",
        "triggers": ["ssrf", "redirect", "interaction", "interactsh", "oob"],
        "playbook": ["nuclei", "burp-cli", "interactsh-client"],
        "phases": ["P13"],
    },
    {
        "id": "vuln-auth-bypass",
        "category": "vulnerabilities",
        "description": "Bypass de autenticação, brute-force, JWT/OAuth e MFA abuse.",
        "triggers": ["auth", "bypass", "brute", "jwt", "oauth", "token", "hydra"],
        "playbook": ["hydra", "jwt_tool", "nuclei", "burp-cli"],
        "phases": ["P14"],
    },
    {
        "id": "vuln-directory-enum",
        "category": "vulnerabilities",
        "description": "Enumeração de diretórios, arquivos ocultos e painéis admin.",
        "triggers": ["dir", "path", "admin", "backup", "ffuf", "gobuster", "dirsearch", "feroxbuster"],
        "playbook": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
        "phases": ["P15"],
    },
    {
        "id": "vuln-api-graphql",
        "category": "vulnerabilities",
        "description": "Testes de API REST/GraphQL, rate limiting e endpoints expostos.",
        "triggers": ["api", "rest", "graphql", "rate", "endpoint", "json"],
        "playbook": ["nuclei", "burp-cli", "arjun", "wapiti"],
        "phases": ["P16"],
    },
    {
        "id": "vuln-nuclei-cve",
        "category": "vulnerabilities",
        "description": "Scan de CVEs e misconfigurations com Nuclei.",
        "triggers": ["cve", "nuclei", "misconfiguration", "exploit", "known"],
        "playbook": ["nuclei", "nmap-vulscan"],
        "phases": ["P11"],
    },
    {
        "id": "vuln-ssl-tls",
        "category": "protocols",
        "description": "Auditoria de SSL/TLS, cipher suites fracos e certificados.",
        "triggers": ["ssl", "tls", "cipher", "cert", "sslscan", "testssl"],
        "playbook": ["sslscan", "nmap", "testssl"],
        "phases": ["P18"],
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
        "triggers": ["dep", "supply", "chain", "npm", "retire", "trivy", "eslint"],
        "playbook": ["retire", "trivy", "eslint", "semgrep"],
        "phases": ["P22"],
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
        "playbook": ["burp-cli", "nuclei", "interactsh-client"],
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
                "strategic_planning",
                "asset_discovery",
                "threat_intel",
                "adversarial_hypothesis",
                "risk_assessment",
                "evidence_adjudication",
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
) -> str:
    chunks = [str(target or ""), str(target_type or "")]
    if discovered_ports:
        chunks.append("ports:" + ",".join(str(p) for p in discovered_ports[:12]))
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
) -> list[dict[str, Any]]:
    findings = list(findings or [])
    discovered_ports = list(discovered_ports or [])
    blob = _text_blob(target, findings, target_type, discovered_ports)

    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in SKILL_CATALOG:
        score = sum(1 for trigger in (skill.get("triggers") or []) if str(trigger).lower() in blob)
        if score > 0:
            scored.append((score, skill))

    # Guaranteed baseline when no signals yet
    if not scored:
        defaults = [
            "recon-subdomain-enum",
            "recon-port-service",
            "tech-http-fingerprint",
            "vuln-nuclei-cve",
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
