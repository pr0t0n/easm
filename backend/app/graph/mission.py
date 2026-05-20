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
        "description": "Enumeração de subdomínios, validação DNS e expansão de superfície.",
        "triggers": ["domain", "subdomain", "dns", "surface", "recon", "amass", "subfinder", "dnsx"],
        "playbook": ["subfinder", "amass", "dnsx", "shuffledns", "assetfinder", "alterx"],
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
        "triggers": ["crawl", "js", "endpoint", "param", "fuzz", "katana", "gau", "wayback"],
        "playbook": ["katana", "hakrawler", "gau", "waybackurls", "gospider", "arjun", "paramspider", "ffuf-params", "wfuzz"],
        "phases": ["P03", "P04"],
    },
    # ── CATEGORY 2: TECHNOLOGIES ─────────────────────────────────────────────
    {
        "id": "tech-http-fingerprint",
        "category": "technologies",
        "description": "Fingerprint HTTP/TLS, headers de segurança, OWASP Top 10 security misconfiguration e detecção de WAF.",
        "triggers": ["http", "https", "header", "headers", "owasp", "tls", "ssl", "whatweb", "nikto", "waf", "cloudflare"],
        "playbook": ["httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"],
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
        "triggers": ["sqli", "xss", "ssti", "xxe", "injection", "sqlmap", "dalfox"],
        "playbook": ["sqlmap", "dalfox", "wapiti", "nikto"],
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
        "triggers": ["auth", "bypass", "brute", "fuzz credentials", "jwt", "oauth", "token", "hydra", "medusa"],
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
        "description": "Scan de CVEs e misconfigurations com Nuclei.",
        "triggers": ["cve", "nuclei", "misconfiguration", "exploit", "known"],
        "playbook": ["nuclei", "nmap-vulscan"],
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


# ─────────────────────────────────────────────────────────────────────────────
# PHASE CONTRACTS — operational contract per pentest phase P01–P22
#
# Each contract defines:
#   required_skills   — skill IDs from SKILL_CATALOG that MUST feed this phase
#   required_tools    — tools where at least 1 must succeed for phase to complete
#   optional_tools    — best-effort tools that improve coverage
#   minimum_evidence  — what constitutes accepted evidence output
#   exit_criteria     — conditions the Phase Validator checks before advancing
#   retry_policy      — max retries, fallback behaviour, skip conditions
#
# A phase is COMPLETED only when all exit_criteria are satisfied.
# A phase is PARTIAL when tools were attempted but exit criteria not fully met.
# A phase is SKIPPED only when skip_condition is true AND reason is recorded.
# The supervisor MUST NOT advance to the next phase if the current one is
# neither completed nor skipped with a valid reason.
# ─────────────────────────────────────────────────────────────────────────────

PHASE_CONTRACTS: dict[str, dict[str, Any]] = {
    "P01": {
        "phase_id": "P01",
        "name": "Subdomain Enumeration",
        "required_skills": ["recon-subdomain-enum"],
        "required_tools": ["subfinder"],
        "optional_tools": ["amass", "massdns", "dnsx", "shuffledns", "assetfinder", "alterx"],
        "minimum_evidence": {
            "type": "subdomain_list",
            "description": "At least one subdomain resolved or root domain confirmed live",
            "fields_required": ["subdomain", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_tools_available_in_kali",
            "skip_requires_reason": True,
        },
    },
    "P02": {
        "phase_id": "P02",
        "name": "Port & Service Scan",
        "required_skills": ["recon-port-service"],
        "required_tools": ["naabu"],
        "optional_tools": ["nmap", "masscan", "httpx"],
        "minimum_evidence": {
            "type": "port_list",
            "description": "At least one open port discovered or confirmed that target has no open ports",
            "fields_required": ["port", "protocol", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_tools_available_in_kali",
            "skip_requires_reason": True,
        },
    },
    "P03": {
        "phase_id": "P03",
        "name": "Web Crawling & JS Extraction",
        "required_skills": ["recon-web-crawl"],
        "required_tools": ["katana"],
        "optional_tools": ["hakrawler", "gau", "waybackurls", "gospider"],
        "minimum_evidence": {
            "type": "url_list",
            "description": "At least one URL, JS file, or endpoint discovered",
            "fields_required": ["url", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_web_targets_found",
            "skip_requires_reason": True,
        },
    },
    "P04": {
        "phase_id": "P04",
        "name": "Parameter Discovery",
        "required_skills": ["recon-web-crawl"],
        "required_tools": ["arjun"],
        "optional_tools": ["paramspider", "ffuf-params", "ffuf-values", "wfuzz"],
        "minimum_evidence": {
            "type": "parameter_list",
            "description": "At least one parameter or form field discovered",
            "fields_required": ["parameter", "endpoint", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_web_targets_found",
            "skip_requires_reason": True,
        },
    },
    "P05": {
        "phase_id": "P05",
        "name": "HTTP Security Headers & OWASP Top 10 Fingerprint",
        "required_skills": ["tech-http-fingerprint"],
        "required_tools": ["httpx"],
        "optional_tools": ["whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"],
        "minimum_evidence": {
            "type": "http_fingerprint",
            "description": "HTTP status, server headers, TLS version, and security headers recorded",
            "fields_required": ["status_code", "server", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_http_service",
            "skip_requires_reason": True,
        },
    },
    "P06": {
        "phase_id": "P06",
        "name": "WAF Detection & Evasion Profile",
        "required_skills": ["waf-aware-validation"],
        "required_tools": ["wafw00f"],
        "optional_tools": ["curl-headers"],
        "minimum_evidence": {
            "type": "waf_status",
            "description": "WAF presence confirmed or denied; vendor recorded if present",
            "fields_required": ["waf_detected", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "mark_waf_unknown",
            "skip_condition": "no_http_service",
            "skip_requires_reason": True,
        },
    },
    "P07": {
        "phase_id": "P07",
        "name": "OSINT & Leak Intelligence",
        "required_skills": ["osint-exposure-intel"],
        "required_tools": ["theHarvester"],
        "optional_tools": ["shodan-cli", "h8mail", "trufflehog", "gitleaks", "metagoofil"],
        "minimum_evidence": {
            "type": "osint_findings",
            "description": "At least one OSINT data point (email, IP, credential leak) collected",
            "fields_required": ["source_type", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "api_keys_unavailable",
            "skip_requires_reason": True,
        },
    },
    "P08": {
        "phase_id": "P08",
        "name": "Email Security Posture (SPF/DKIM/DMARC)",
        "required_skills": ["osint-email-infra"],
        "required_tools": ["theHarvester"],
        "optional_tools": [],
        "minimum_evidence": {
            "type": "email_security",
            "description": "SPF, DKIM, DMARC records queried and status recorded",
            "fields_required": ["spf_status", "dmarc_status", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "mark_dns_lookup_failed",
            "skip_condition": "not_domain_target",
            "skip_requires_reason": True,
        },
    },
    "P09": {
        "phase_id": "P09",
        "name": "Subdomain Takeover",
        "required_skills": ["osint-subdomain-takeover"],
        "required_tools": ["subjack"],
        "optional_tools": ["nuclei"],
        "minimum_evidence": {
            "type": "takeover_check",
            "description": "Each discovered subdomain checked for dangling CNAME; result recorded",
            "fields_required": ["subdomain", "takeover_status", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_subdomains_discovered",
            "skip_requires_reason": True,
        },
    },
    "P10": {
        "phase_id": "P10",
        "name": "Cloud Asset Exposure (S3/GCP/Azure)",
        "required_skills": ["osint-cloud-exposure"],
        "required_tools": ["nuclei"],
        "optional_tools": ["shodan-cli", "trufflehog"],
        "minimum_evidence": {
            "type": "cloud_exposure",
            "description": "Cloud-related templates executed; open bucket or misconfigured resource recorded",
            "fields_required": ["cloud_provider", "exposure_status", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_cloud_indicators",
            "skip_requires_reason": True,
        },
    },
    "P11": {
        "phase_id": "P11",
        "name": "Nuclei CVE & Misconfiguration Scan",
        "required_skills": ["vuln-nuclei-cve"],
        "required_tools": ["nuclei"],
        "optional_tools": ["nmap-vulscan"],
        "minimum_evidence": {
            "type": "cve_scan_result",
            "description": "Nuclei scan completed against all discovered endpoints; matched templates recorded",
            "fields_required": ["template_id", "severity", "matched_at", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_web_targets",
            "skip_requires_reason": True,
        },
    },
    "P12": {
        "phase_id": "P12",
        "name": "Web Injection (SQLi/XSS/SSTI/XXE)",
        "required_skills": ["vuln-injection"],
        "required_tools": ["dalfox"],
        "optional_tools": ["sqlmap", "wapiti", "nikto"],
        "minimum_evidence": {
            "type": "injection_scan_result",
            "description": "At least one injection vector tested against parameterized endpoint; result recorded",
            "fields_required": ["injection_type", "endpoint", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_parameterized_targets",
            "skip_requires_reason": True,
        },
    },
    "P13": {
        "phase_id": "P13",
        "name": "SSRF & Open Redirect",
        "required_skills": ["vuln-ssrf-redirect"],
        "required_tools": ["nuclei"],
        "optional_tools": ["interactsh-client"],
        "minimum_evidence": {
            "type": "ssrf_scan_result",
            "description": "SSRF and open redirect templates executed; interactions captured if any",
            "fields_required": ["template_type", "endpoint", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_parameterized_targets",
            "skip_requires_reason": True,
        },
    },
    "P14": {
        "phase_id": "P14",
        "name": "Authentication Bypass & Brute Force",
        "required_skills": ["vuln-auth-bypass"],
        "required_tools": ["nuclei"],
        "optional_tools": ["hydra", "medusa", "jwt_tool", "crackmapexec"],
        "minimum_evidence": {
            "type": "auth_test_result",
            "description": "Authentication endpoints probed for bypass; credential test results recorded",
            "fields_required": ["endpoint", "auth_method", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_auth_endpoints",
            "skip_requires_reason": True,
        },
    },
    "P15": {
        "phase_id": "P15",
        "name": "Directory & File Enumeration",
        "required_skills": ["vuln-directory-enum"],
        "required_tools": ["ffuf"],
        "optional_tools": ["ffuf-files", "ffuf-params", "gobuster", "feroxbuster", "dirsearch", "wfuzz"],
        "minimum_evidence": {
            "type": "directory_enum_result",
            "description": "Directory/file fuzzing completed; discovered paths and status codes recorded",
            "fields_required": ["path", "status_code", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_web_targets",
            "skip_requires_reason": True,
        },
    },
    "P16": {
        "phase_id": "P16",
        "name": "API Security (REST/GraphQL/Rate Limit)",
        "required_skills": ["vuln-api-graphql"],
        "required_tools": ["nuclei"],
        "optional_tools": ["arjun", "wapiti", "ffuf-params", "ffuf-post"],
        "minimum_evidence": {
            "type": "api_scan_result",
            "description": "API endpoints tested for auth bypass, rate limiting, and injection; results recorded",
            "fields_required": ["endpoint", "api_type", "test_result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_api_endpoints",
            "skip_requires_reason": True,
        },
    },
    "P17": {
        "phase_id": "P17",
        "name": "Upload & WebShell Bypass",
        "required_skills": ["vuln-nuclei-cve"],
        "required_tools": ["nuclei"],
        "optional_tools": [],
        "minimum_evidence": {
            "type": "upload_test_result",
            "description": "Upload endpoints probed; file upload bypass templates executed",
            "fields_required": ["endpoint", "test_type", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "mark_no_upload_found",
            "skip_condition": "no_upload_endpoints",
            "skip_requires_reason": True,
        },
    },
    "P18": {
        "phase_id": "P18",
        "name": "SSL/TLS Certificate, Protocol & Cipher Audit",
        "required_skills": ["vuln-ssl-tls"],
        "required_tools": ["sslscan"],
        "optional_tools": ["testssl", "nmap", "curl-headers"],
        "minimum_evidence": {
            "type": "ssl_audit_result",
            "description": "SSL/TLS protocol version, cipher suite, and certificate validity recorded",
            "fields_required": ["protocol_version", "cipher_suite", "cert_valid", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 2,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_https_service",
            "skip_requires_reason": True,
        },
    },
    "P19": {
        "phase_id": "P19",
        "name": "IDOR & Access Control Flaws",
        "required_skills": ["vuln-idor-access-control"],
        "required_tools": ["nuclei"],
        "optional_tools": ["katana", "arjun", "curl-headers"],
        "minimum_evidence": {
            "type": "idor_test_result",
            "description": "Object reference endpoints probed for unauthorized access; results recorded",
            "fields_required": ["endpoint", "object_id_type", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_object_endpoints",
            "skip_requires_reason": True,
        },
    },
    "P20": {
        "phase_id": "P20",
        "name": "CMS-Specific Scan (WP/Joomla/Drupal)",
        "required_skills": ["tech-cms-fingerprint"],
        "required_tools": ["nuclei"],
        "optional_tools": ["wpscan", "nikto"],
        "minimum_evidence": {
            "type": "cms_scan_result",
            "description": "CMS detection attempted; version and plugin scan completed if CMS found",
            "fields_required": ["cms_detected", "cms_type", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_cms_detected",
            "skip_requires_reason": True,
        },
    },
    "P21": {
        "phase_id": "P21",
        "name": "Secret & Credential Exposure",
        "required_skills": ["code-secrets-sast"],
        "required_tools": ["trufflehog"],
        "optional_tools": ["gitleaks", "semgrep", "bandit"],
        "minimum_evidence": {
            "type": "secrets_scan_result",
            "description": "Public repositories and exposed JS/config files scanned for secrets",
            "fields_required": ["secret_type", "location", "result", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_code_repository_access",
            "skip_requires_reason": True,
        },
    },
    "P22": {
        "phase_id": "P22",
        "name": "Dependency & Supply Chain Risk",
        "required_skills": ["code-supply-chain-deps"],
        "required_tools": ["trivy"],
        "optional_tools": ["retire", "semgrep", "bandit", "gitleaks"],
        "minimum_evidence": {
            "type": "dependency_scan_result",
            "description": "Dependencies scanned for known CVEs and supply chain risks; results recorded",
            "fields_required": ["dependency", "cve", "risk_level", "source_tool"],
        },
        "exit_criteria": {
            "min_required_tools_attempted": 1,
            "min_required_tools_succeeded": 1,
            "evidence_persisted": True,
            "parser_result_registered": True,
        },
        "retry_policy": {
            "max_retries": 1,
            "on_failure": "try_optional_tools",
            "skip_condition": "no_code_repository_access",
            "skip_requires_reason": True,
        },
    },
}


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
