from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(mode: ScanMode, queue_suffix: str, description: str, tools: list[str], priority: int) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


# ──────────────────────────────────────────────────────────────────────────────
# EASM 5-Agent Architecture
# ──────────────────────────────────────────────────────────────────────────────
#
# Agente 1 — AssetDiscovery  : subfinder → amass → dnsx → naabu → httpx → gowitness
# Agente 2 — RiskAssessment  : wafw00f → nuclei → nikto → wapiti → [sqlmap/commix]
# Agente 3 — ThreatIntel     : theharvester → shodan-cli → h8mail → subjack
# Agente 4 — Governance      : cálculo FAIR+AGE (Python puro, sem ferramentas externas)
# Agente 5 — ExecutiveAnalyst: narrativa via LLM Ollama (Python puro)
#
# Os grupos legados (reconhecimento / analise_vulnerabilidade / osint) são mantidos
# como aliases para que os agendamentos existentes continuem funcionando.
# ──────────────────────────────────────────────────────────────────────────────

# ── Unit mode ─────────────────────────────────────────────────────────────────
UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    # EASM Agent 1: Asset Discovery
    "asset_discovery": _group_config(
        "unit",
        "reconhecimento",   # mantém a fila legada para compatibilidade
        "[UNITÁRIO] EASM Agent 1 — Descoberta de ativos e mapeamento de superfície",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "dnsx",
            "naabu",
            "httpx",
            "katana",
            "uro",
            "waymore",
            "nmap",
            "gowitness",
        ],
        9,
    ),
    # EASM Agent 2: Risk Assessment
    "risk_assessment": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITÁRIO] EASM Agent 2 — Avaliação de risco e análise de vulnerabilidades",
        [
            "wafw00f",           # 1º: detecta WAF antes de escanear
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "nessus",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "nikto",
            "ffuf",
            "feroxbuster",
            "arjun",
            "gobuster",
            "wfuzz",
            "dalfox",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        9,
    ),
    # EASM Agent 3: Threat Intel (OSINT)
    "threat_intel": _group_config(
        "unit",
        "osint",
        "[UNITÁRIO] EASM Agent 3 — Inteligência de ameaças e OSINT externo",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "shodan-cli",
            "whatweb",
            "subjack",
            "cloudenum",
            "chaos",
        ],
        7,
    ),
    # EASM Agent 4: Governance (interno — sem ferramentas externas)
    "governance": _group_config(
        "unit",
        "governance",
        "[UNITÁRIO] EASM Agent 4 — Cálculo FAIR+AGE e rating contínuo (interno)",
        [],   # Pure Python, no external tools
        6,
    ),
    # EASM Agent 5: Executive Analyst (interno — LLM Ollama)
    "executive_analyst": _group_config(
        "unit",
        "executive_analyst",
        "[UNITÁRIO] EASM Agent 5 — Narrativa executiva via LLM Ollama (interno)",
        [],   # Ollama via httpx, not tool_adapters
        5,
    ),
    # ── Aliases legados para backward compat ───────────────────────────────────
    "reconhecimento": _group_config(
        "unit",
        "reconhecimento",
        "[UNITÁRIO] Reconhecimento e descoberta de ativos externos (alias → asset_discovery)",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "dnsx",
            "naabu",
            "httpx",
            "katana",
            "uro",
            "waymore",
            "nmap",
        ],
        9,
    ),
    "analise_vulnerabilidade": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITÁRIO] Análise técnica de vulnerabilidades (alias → risk_assessment)",
        [
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "nessus",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "wafw00f",
            "nikto",
            "ffuf",
            "feroxbuster",
            "arjun",
            "gobuster",
            "wfuzz",
            "dalfox",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        9,
    ),
    "osint": _group_config(
        "unit",
        "osint",
        "[UNITÁRIO] OSINT de exposição externa (alias → threat_intel)",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "shodan-cli",
            "whatweb",
            "subjack",
            "cloudenum",
            "chaos",
        ],
        7,
    ),
}

# ── Scheduled mode ─────────────────────────────────────────────────────────────
SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    # EASM Agent 1: Asset Discovery (scheduled — full tool set)
    "asset_discovery": _group_config(
        "scheduled",
        "reconhecimento",   # mantém fila legada
        "[AGENDADO] EASM Agent 1 — Reconhecimento completo de ativos e superfície",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "sublist3r",
            "chaos",
            "cloudenum",
            "dnsx",
            "puredns",
            "massdns",
            "dnsenum",
            "alterx",
            "dnsgen",
            "naabu",
            "httpx",
            "katana",
            "waymore",
            "uro",
            "gowitness",
            "nmap",
        ],
        6,
    ),
    # EASM Agent 2: Risk Assessment (scheduled — full tool set)
    "risk_assessment": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] EASM Agent 2 — Análise profunda de vulnerabilidades por ativo",
        [
            "wafw00f",           # 1º: fingerprint de WAF
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "dalfox",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "nikto",
            "wpscan",
            "zap",
            "nessus",
            "openvas",
            "semgrep",
            "ffuf",
            "feroxbuster",
            "arjun",
            "dirb",
            "gobuster",
            "wfuzz",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        6,
    ),
    # EASM Agent 3: Threat Intel (scheduled — full tool set)
    "threat_intel": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] EASM Agent 3 — OSINT completo para todos os ativos descobertos",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "subjack",
            "shodan-cli",
            "whatweb",
            "chaos",
            "cloudenum",
        ],
        5,
    ),
    # EASM Agent 4: Governance (interno)
    "governance": _group_config(
        "scheduled",
        "governance",
        "[AGENDADO] EASM Agent 4 — Rating FAIR+AGE contínuo (interno)",
        [],
        4,
    ),
    # EASM Agent 5: Executive Analyst (interno)
    "executive_analyst": _group_config(
        "scheduled",
        "executive_analyst",
        "[AGENDADO] EASM Agent 5 — Narrativa executiva via LLM (interno)",
        [],
        3,
    ),
    # ── Aliases legados ────────────────────────────────────────────────────────
    "reconhecimento": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] Reconhecimento completo de ativos e superficie (alias → asset_discovery)",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "sublist3r",
            "chaos",
            "cloudenum",
            "dnsx",
            "puredns",
            "massdns",
            "dnsenum",
            "alterx",
            "dnsgen",
            "naabu",
            "httpx",
            "katana",
            "waymore",
            "uro",
            "gowitness",
            "nmap",
        ],
        6,
    ),
    "analise_vulnerabilidade": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] Analise profunda de vulnerabilidades por ativo (alias → risk_assessment)",
        [
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "dalfox",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "wafw00f",
            "nikto",
            "wpscan",
            "zap",
            "nessus",
            "openvas",
            "semgrep",
            "ffuf",
            "feroxbuster",
            "arjun",
            "dirb",
            "gobuster",
            "wfuzz",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        6,
    ),
    "osint": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] OSINT completo para todos os ativos descobertos (alias → threat_intel)",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "subjack",
            "shodan-cli",
            "whatweb",
            "chaos",
            "cloudenum",
        ],
        5,
    ),
}

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def get_easm_agent_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    """Retorna apenas os grupos EASM (sem aliases legados)."""
    agent_keys = {"asset_discovery", "risk_assessment", "threat_intel", "governance", "executive_analyst"}
    return {k: v for k, v in get_worker_groups(mode).items() if k in agent_keys}


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    normalized = tool_name.strip().lower()
    # Busca primeiro nos grupos EASM, depois nos aliases
    for group_name in ["asset_discovery", "risk_assessment", "threat_intel", "reconhecimento", "analise_vulnerabilidade", "osint"]:
        group = get_worker_groups(mode).get(group_name, {})
        if normalized in group.get("tools", []):
            return group_name
    return "asset_discovery"


def group_queue(group_name: str, mode: ScanMode = "unit") -> str:
    groups = get_worker_groups(mode)
    group = groups.get(group_name) or groups.get("asset_discovery") or next(iter(groups.values()))
    return str(group["queue"])


def all_queues(mode: ScanMode) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for g in get_worker_groups(mode).values():
        q = g["queue"]
        if q not in seen:
            seen.add(q)
            result.append(q)
    return result


SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "reconhecimento": _group_config(
        "unit",
        "reconhecimento",
        "[UNITARIO] Reconhecimento e descoberta de ativos externos",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "dnsx",
            "naabu",
            "httpx",
            "katana",
            "uro",
            "waymore",
            "nmap",
        ],
        9,
    ),
    "analise_vulnerabilidade": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITARIO] Analise tecnica de vulnerabilidades em ativos descobertos",
        [
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "nessus",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "wafw00f",
            "nikto",
            "ffuf",
            "feroxbuster",
            "arjun",
            "gobuster",
            "wfuzz",
            "dalfox",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        9,
    ),
    "osint": _group_config(
        "unit",
        "osint",
        "[UNITARIO] OSINT de exposicao externa por alvo descoberto",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "shodan-cli",
            "whatweb",
            "subjack",
            "cloudenum",
            "chaos",
        ],
        7,
    ),
}

SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "reconhecimento": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] Reconhecimento completo de ativos e superficie",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "sublist3r",
            "chaos",
            "cloudenum",
            "dnsx",
            "puredns",
            "massdns",
            "dnsenum",
            "alterx",
            "dnsgen",
            "naabu",
            "httpx",
            "katana",
            "waymore",
            "uro",
            "gowitness",
            "nmap",
        ],
        6,
    ),
    "analise_vulnerabilidade": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] Analise profunda de vulnerabilidades por ativo",
        [
            "nmap-vulscan",
            "burp-cli",
            "nuclei",
            "dalfox",
            "wapiti",
            "sqlmap",
            "commix",
            "tplmap",
            "wafw00f",
            "nikto",
            "wpscan",
            "zap",
            "nessus",
            "openvas",
            "semgrep",
            "ffuf",
            "feroxbuster",
            "arjun",
            "dirb",
            "gobuster",
            "wfuzz",
            "secretfinder",
            "linkfinder",
            "trufflehog",
            "kiterunner",
            "postman-to-k6",
            "sslscan",
            "shcheck",
            "curl-headers",
        ],
        6,
    ),
    "osint": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] OSINT completo para todos os ativos descobertos",
        [
            "theharvester",
            "h8mail",
            "metagoofil",
            "urlscan-cli",
            "subjack",
            "shodan-cli",
            "whatweb",
            "chaos",
            "cloudenum",
        ],
        5,
    ),
}

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    normalized = tool_name.strip().lower()
    groups = get_worker_groups(mode)
    for group_name, group in groups.items():
        if normalized in group["tools"]:
            return group_name
    return "reconhecimento"


def group_queue(group_name: str, mode: ScanMode = "unit") -> str:
    groups = get_worker_groups(mode)
    group = groups.get(group_name, groups["reconhecimento"])
    return str(group["queue"])


def all_queues(mode: ScanMode) -> list[str]:
    return [g["queue"] for g in get_worker_groups(mode).values()]


SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
