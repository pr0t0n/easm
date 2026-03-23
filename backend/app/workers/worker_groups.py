from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]

# ──────────────────────────────────────────────────────────────────────────────
# Workers UNITÁRIOS — execucao manual/pontual via POST /api/scans
#   Fila principal : scan.unit
#   Filas de tools : worker.unit.<grupo>
#   Perfil         : alta prioridade, concurrency=1, turnaround rapido, escopo critico
#
#   Pipeline (inspirado em EasyEASM fast + xingrin Stage-1/2):
#     recon → crawler → fuzzing → vuln → code_js → api
#
#   Ferramentas referencia:
#     EasyEASM (g0ldencybersec) — subfinder, amass, dnsx, alterx, httpx
#     xingrin   (yyhuni)        — subfinder, assetfinder, naabu, httpx,
#                                  katana, uro, nuclei, dalfox
# ──────────────────────────────────────────────────────────────────────────────
UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    # ── Etapa 1: Reconhecimento ────────────────────────────────────────────────
    # Enumeracao passiva paralela (subfinder + amass + assetfinder) +
    # bruteforce DNS rapido (dnsx) + varredura de portas criticas (naabu).
    # Baseado no modo "fast" do EasyEASM e Stage-1 do xingrin.
    "recon": {
        "queue": "worker.unit.recon",
        "description": "[UNITARIO] Descoberta inicial de subdomínios e portas",
        "tools": [
            "subfinder",    # ProjectDiscovery — melhor fonte passiva (EasyEASM + xingrin)
            "amass",        # OWASP Amass — passive enum c/ oam_subs (EasyEASM)
            "assetfinder",  # Tomnomnom — certificados e bases OSINT (xingrin)
            "dnsx",         # ProjectDiscovery — bruteforce DNS com wordlist (EasyEASM)
            "naabu",        # ProjectDiscovery — port scanner rapido (xingrin)
        ],
        "priority": 9,
    },
    # ── Etapa 2: Crawling e Probe HTTP ────────────────────────────────────────
    # Probe de hosts vivos com httpx, rastreamento de endpoints (katana) e
    # deduplicacao de URLs (uro). Equivalente ao RunHttpx() do EasyEASM e
    # ao Site Scan do xingrin.
    "crawler": {
        "queue": "worker.unit.crawler",
        "description": "[UNITARIO] Probe HTTP, deteccao de hosts vivos e crawling basico",
        "tools": [
            "httpx",        # ProjectDiscovery — probe vivo + tech detect + TLS (EasyEASM + xingrin)
            "katana",       # ProjectDiscovery — crawler JS-aware rapido (xingrin)
            "uro",          # Dee3011 — deduplicacao inteligente de URLs (xingrin)
        ],
        "priority": 8,
    },
    # ── Etapa 3: Fuzzing de Superficie ────────────────────────────────────────
    "fuzzing": {
        "queue": "worker.unit.fuzzing",
        "description": "[UNITARIO] Fuzzing rapido de diretórios e parâmetros",
        "tools": [
            "ffuf",         # Jfrog — directory/parameter fuzzer (xingrin)
            "feroxbuster",  # Epi052 — recursive content discovery
            "arjun",        # S0md3v — HTTP parameter discovery
            "gobuster",     # OJ — directory, vhost e fuzz mode
            "wfuzz",        # Xmendez — fuzzing de params, headers e body
        ],
        "priority": 8,
    },
    # ── Etapa 4: Vulnerabilidades Prioritárias ────────────────────────────────
    "vuln": {
        "queue": "worker.unit.vuln",
        "description": "[UNITARIO] Validacao de CVEs criticos e XSS",
        "tools": [
            "nessus",       # Tenable — discovery + scanner de vulnerabilidade autenticado
            "nuclei",       # ProjectDiscovery — template-based scanner (xingrin + EasyEASM/CONTRIBUTING)
            "dalfox",       # Hahwul — XSS scanner automatizado (xingrin)
            "wapiti",       # Wapiti — scanner web multi-classe para SSRF, XXE, file/include e headers
            "sqlmap",       # Sqlmap — validacao automatizada de SQL injection
            "commix",       # Commix — command injection e blind command execution
            "tplmap",       # Tplmap — validacao de SSTI em Jinja2, Mako e similares
            "wafw00f",      # Fingerprinting de WAF para orientar evasao/confirmacao
            "nikto",        # Sullo — web server scanner classico
            "nmap-vulscan", # Nmap + Vulscan NSE — network mapping + vuln assessment
        ],
        "priority": 9,
    },
    # ── Etapa 5: Análise de JavaScript e Segredos ─────────────────────────────
    "code_js": {
        "queue": "worker.unit.code_js",
        "description": "[UNITARIO] Analise expressa de JS e vazamento de segredos",
        "tools": [
            "secretfinder", # m4ll0k — regex-based endpoint/secret extractor em JS
            "trufflehog",   # Truffle Security — credenciais em codigo/historico
        ],
        "priority": 7,
    },
    # ── Etapa 6: APIs Expostas ────────────────────────────────────────────────
    "api": {
        "queue": "worker.unit.api",
        "description": "[UNITARIO] Mapeamento rapido de APIs expostas",
        "tools": [
            "kiterunner",   # Assetnote — routes bruteforce via OpenAPI wordlists
        ],
        "priority": 8,
    },
    # ── Etapa 7: OSINT e Inteligência Exposta ─────────────────────────────────
    # Coleta rapida de emails, subdomínios e exposicoes via fontes abertas.
    # Inspirado no modo OSINT do Sn1per (--osint flag): theHarvester + urlscan.io.
    "osint": {
        "queue": "worker.unit.osint",
        "description": "[UNITARIO] Coleta rapida de emails, dominios e exposicao publica",
        "tools": [
            "theharvester", # Laramies — emails, subdomínios, IPs via search engines (Sn1per osint.sh)
            "shodan-cli",   # Shodan.io CLI — lookup rapido de exposicao por host/ASN
            "whatweb",      # Urbanadventurer — fingerprint de tecnologias web (OSINT_AI_Agent)
            "urlscan-cli",  # Urlscan.io CLI — visibilidade de requisicoes e tecnologias (Sn1per)
            "subjack",      # Haccer — subdomain takeover c/ padroes de 50+ servicos (Sn1per recon.sh)
        ],
        "priority": 6,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# Workers AGENDADOS — execucao periodica/batch via ScheduledScan
#   Fila principal : scan.scheduled
#   Filas de tools : worker.scheduled.<grupo>
#   Perfil         : prioridade normal, concurrency=2, cobertura total, analise profunda
#
#   Pipeline (inspirado em EasyEASM complete + xingrin Stage-1-4):
#     recon → crawler → fingerprint → fuzzing → vuln → code_js → api
#
#   Ferramentas referencia:
#     EasyEASM (g0ldencybersec) — subfinder, amass, dnsx, alterx, httpx
#     xingrin   (yyhuni)        — subfinder, assetfinder, findomain, chaos,
#                                  puredns, dnsgen, naabu, httpx, katana,
#                                  waymore, uro, gowitness, dalfox, nuclei
# ──────────────────────────────────────────────────────────────────────────────
SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    # ── Etapa 1: Reconhecimento Completo ──────────────────────────────────────
    # Multiplas fontes passivas paralelas (Stage-1 do xingrin) +
    # bruteforce DNS com puredns/dnsx (Stage-2) +
    # permutacao de subdomínios com dnsgen/alterx (Stage-3) +
    # varredura de portas completa (naabu).
    "recon": {
        "queue": "worker.scheduled.recon",
        "description": "[AGENDADO] Enumeracao completa de subdomínios, DNS e portas",
        "tools": [
            # Passivo — fontes OSINT/Certificate Transparency
            "subfinder",    # ProjectDiscovery — principal fonte passiva (EasyEASM + xingrin)
            "amass",        # OWASP Amass — passive enum c/ oam_subs (EasyEASM)
            "assetfinder",  # Tomnomnom — certs + bases OSINT (xingrin)
            "findomain",    # Edu4rdSHL — Certificate Transparency logs (xingrin)
            "sublist3r",    # Aboul3la — motores de busca + DNS (xingrin legado)
            "chaos",        # ProjectDiscovery — dataset publico de subdomínios (xingrin)
            "cloudenum",    # Cloudlist — enumeracao de ativos em nuvem
            # Ativo — bruteforce e resolucao DNS
            "dnsx",         # ProjectDiscovery — bruteforce DNS com wordlist (EasyEASM)
            "puredns",      # D3moniumtom — bruteforce + resolve massivo (xingrin)
            "massdns",      # Blechschmidt — resolucao DNS em massa (xingrin)
            "dnsenum",      # Toolset legado — zone transfer + DNS enumeration
            # Mutacao/Permutacao
            "alterx",       # ProjectDiscovery — permutacao inteligente (EasyEASM)
            "dnsgen",       # AlephNullSK — permutacao por wordlist de partes (xingrin)
            # Portas
            "naabu",        # ProjectDiscovery — port scanner ativo + passivo (xingrin)
            "nessus",       # Tenable — host discovery complementar e baseline de superficie
            # Takeover
            "subjack",      # Haccer — subdomain takeover (50+ servicos: Sn1per recon.sh)
        ],
        "priority": 5,
    },
    # ── Etapa 2: Crawling Completo e Screenshots ──────────────────────────────
    # Probe HTTP profundo (httpx), rastreamento JS-aware (katana), coleta de
    # URLs historicas (waymore), deduplicacao (uro) e capturas de tela (gowitness).
    # Corresponde ao Site Scan + Screenshot do xingrin.
    "crawler": {
        "queue": "worker.scheduled.crawler",
        "description": "[AGENDADO] Probe HTTP, crawling aprofundado e capturas de tela",
        "tools": [
            "httpx",        # ProjectDiscovery — probe vivo, tech detect, TLS, body hash (xingrin + EasyEASM)
            "katana",       # ProjectDiscovery — crawler JS-aware + form discovery (xingrin)
            "waymore",      # Xnl Ninja — URLs historicas via Wayback/AlienVault/etc (xingrin)
            "uro",          # Dee3011 — deduplicacao e normalizacao de URLs (xingrin)
            "gowitness",    # Sensepost — screenshots de hosts via chromium headless (xingrin/playwright equiv)
        ],
        "priority": 4,
    },
    # ── Etapa 3: Fingerprinting de Tecnologias ────────────────────────────────
    # Identificacao de stack tecnologico (CMS, frameworks, servidores).
    # cmsmap detecta WordPress/Drupal/Joomla c/ CVEs especificos (Sn1per webporthttps.sh).
    "fingerprint": {
        "queue": "worker.scheduled.fingerprint",
        "description": "[AGENDADO] Fingerprinting de tecnologias, CMS e exposicao de versoes",
        "tools": [
            "wappalyzer",   # Wappalyzer CLI — identificacao de stack (equiv xingfinger)
            "whatweb",      # Urbanadventurer — banner + tech fingerprint
            "webanalyze",   # Rverton — Wappalyzer-based CLI para batch scanning
            "cmsmap",       # Dionach — CMS detection c/ plugin/theme enum (Sn1per webporthttps.sh)
        ],
        "priority": 3,
    },
    # ── Etapa 4: Fuzzing Extensivo ────────────────────────────────────────────
    "fuzzing": {
        "queue": "worker.scheduled.fuzzing",
        "description": "[AGENDADO] Fuzzing extensivo de diretórios e parâmetros",
        "tools": [
            "ffuf",         # Jfrog — directory/parameter fuzzer (xingrin)
            "feroxbuster",  # Epi052 — recursive content discovery
            "arjun",        # S0md3v — HTTP parameter discovery
            "dirb",         # Legado — wordlist-based directory scanner
            "gobuster",     # OJ — directory, vhost e fuzz mode
            "wfuzz",        # Xmendez — fuzzing flexivel de URL, header e corpo
        ],
        "priority": 4,
    },
    # ── Etapa 5: Analise Completa de Vulnerabilidades ─────────────────────────
    # Sn1per vulnscan.sh: nessus → openvas → sc0pe-passive-webscan → sc0pe-active-webscan
    # → nuclei templates → wpscan. Severidade P1-P5 mapeada para critical/high/medium/low/info.
    "vuln": {
        "queue": "worker.scheduled.vuln",
        "description": "[AGENDADO] Analise completa de CVEs, XSS e misconfiguracoes (P1-P5)",
        "tools": [
            "nuclei",       # ProjectDiscovery — template-based scanner (xingrin + Sn1per)
            "dalfox",       # Hahwul — XSS scanner automatizado (xingrin)
            "wapiti",       # Wapiti — SQLi, XSS, SSRF, XXE, file/include, CRLF e headers
            "sqlmap",       # Sqlmap — SQL injection detection/exploitation assistida
            "commix",       # Commix — command injection
            "tplmap",       # Tplmap — SSTI
            "wafw00f",      # Fingerprinting de WAF antes de evasao e DAST pesado
            "nikto",        # Sullo — web server scanner (Sn1per normal_webporthttp.sh)
            "wpscan",       # WPScan Team — scanner WordPress (Sn1per webporthttps.sh)
            "zap",          # OWASP ZAP — DAST completo
            "nessus",       # Tenable — vulnerability assessment enterprise (Sn1per vulnscan.sh)
            "openvas",      # Greenbone — VA opensource integrado ao Sn1per vulnscan.sh
            "semgrep",      # Semgrep Inc — SAST para codigo fonte e IaC
            "nmap-vulscan", # Nmap + Vulscan NSE — network mapping + vuln assessment
        ],
        "priority": 5,
    },
    # ── Etapa 6: Analise Aprofundada de JS e Segredos ─────────────────────────
    "code_js": {
        "queue": "worker.scheduled.code_js",
        "description": "[AGENDADO] Analise de JS, endpoints e vazamento de credenciais",
        "tools": [
            "linkfinder",   # GerbenJavado — endpoint extractor em arquivos JS
            "secretfinder", # m4ll0k — regex-based endpoint/secret extractor em JS
            "trufflehog",   # Truffle Security — credenciais em codigo/historico git
        ],
        "priority": 3,
    },
    # ── Etapa 7: APIs e Servicos Expostos ────────────────────────────────────
    "api": {
        "queue": "worker.scheduled.api",
        "description": "[AGENDADO] Mapeamento e validacao extensiva de APIs",
        "tools": [
            "kiterunner",      # Assetnote — routes bruteforce via OpenAPI wordlists
            "postman-to-k6",   # Grafana — conversao de colecoes Postman para carga/fuzz
        ],
        "priority": 4,
    },
    # ── Etapa 8: OSINT e Inteligência Exposta ─────────────────────────────────
    # Sn1per osint.sh: theHarvester (emails/dominios/IPs), h8mail (credenciais
    # comprometidas), metagoofil (metadata de docs publicos), urlscan.io API,
    # hunter.io API, GitHub secrets. Essencial para mapeamento de exposicao humana.
    "osint": {
        "queue": "worker.scheduled.osint",
        "description": "[AGENDADO] OSINT completo: emails, credenciais, docs e exposicao publica",
        "tools": [
            "theharvester", # Laramies — emails, subdomínios, IPs via search engines (Sn1per osint.sh)
            "h8mail",       # Khast3x — credential leaks em brechas publicas (Sn1per osint.sh)
            "metagoofil",   # laramies — metadata de docs PDF/DOCX/XLS publicos (Sn1per osint.sh)
            "urlscan-cli",  # Urlscan.io CLI — visibilidade host/req/tecnologias (Sn1per osint.sh)
            "subjack",      # Haccer — subdomain takeover detection (Sn1per recon.sh)
            "shodan-cli",   # Shodan.io CLI — exposicao de servicos via API Shodan (Sn1per recon.sh)
        ],
        "priority": 3,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# Mantido para compatibilidade retroativa — aponta para os grupos unitarios por padrao
# ──────────────────────────────────────────────────────────────────────────────
WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    """Retorna o mapa de grupos de workers para o modo informado."""
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    normalized = tool_name.strip().lower()
    groups = get_worker_groups(mode)
    for group_name, group in groups.items():
        if normalized in group["tools"]:
            return group_name
    return "recon"


def group_queue(group_name: str, mode: ScanMode = "unit") -> str:
    groups = get_worker_groups(mode)
    group = groups.get(group_name, groups["recon"])
    return str(group["queue"])


def all_queues(mode: ScanMode) -> list[str]:
    """Retorna todas as filas de ferramentas para um modo."""
    return [g["queue"] for g in get_worker_groups(mode).values()]


# Filas principais de orquestracao
SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
