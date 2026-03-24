from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(mode: ScanMode, queue_suffix: str, description: str, tools: list[str], priority: int) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


# Grupos consolidados para os dois modos:
# 1) reconhecimento            -> descobre ativos (dominio/subdominio/servicos) e gera baseline
# 2) analise_vulnerabilidade   -> testa vulnerabilidades nos ativos descobertos
# 3) osint                     -> executa inteligencia externa nos mesmos ativos descobertos
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
