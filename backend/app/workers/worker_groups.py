from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(mode: ScanMode, queue_suffix: str, description: str, tools: list[str], priority: int) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


# EASM pipeline:
# 1) AssetDiscovery -> 2) ThreatIntel -> 3) RiskAssessment -> 4) Governance -> 5) ExecutiveAnalyst
# Observacao: Wapiti permanece instalado, porem desativado no fluxo.

UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "asset_discovery": _group_config(
        "unit",
        "reconhecimento",
        "[UNITARIO] EASM Agent 1 — Descoberta de ativos e superficie",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "dnsx",
            "massdns",
            "dnsenum",
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
    "threat_intel": _group_config(
        "unit",
        "osint",
        "[UNITARIO] EASM Agent 2 — Threat Intel e OSINT",
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
        8,
    ),
    "risk_assessment": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITARIO] EASM Agent 3 — Analise de vulnerabilidade",
        [
            "burp-cli",
            "nmap-vulscan",
            "nikto",
            "nuclei",
            "wpscan",
            "wfuzz",
            "wafw00f",
        ],
        9,
    ),
    "governance": _group_config(
        "unit",
        "governance",
        "[UNITARIO] EASM Agent 4 — FAIR+AGE rating (interno)",
        [],
        6,
    ),
    "executive_analyst": _group_config(
        "unit",
        "executive_analyst",
        "[UNITARIO] EASM Agent 5 — Narrativa executiva (interno)",
        [],
        5,
    ),
    # Aliases legados
    "reconhecimento": _group_config(
        "unit",
        "reconhecimento",
        "[UNITARIO] Alias -> asset_discovery",
        [
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "dnsx",
            "massdns",
            "dnsenum",
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
    "osint": _group_config(
        "unit",
        "osint",
        "[UNITARIO] Alias -> threat_intel",
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
        8,
    ),
    "analise_vulnerabilidade": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITARIO] Alias -> risk_assessment",
        [
            "burp-cli",
            "nmap-vulscan",
            "nikto",
            "nuclei",
            "wpscan",
            "wfuzz",
            "wafw00f",
        ],
        9,
    ),
}

SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "asset_discovery": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] EASM Agent 1 — Descoberta de ativos e superficie",
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
    "threat_intel": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] EASM Agent 2 — Threat Intel e OSINT",
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
    "risk_assessment": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] EASM Agent 3 — Analise de vulnerabilidade",
        [
            "burp-cli",
            "nmap-vulscan",
            "nikto",
            "nuclei",
            "wpscan",
            "wfuzz",
            "wafw00f",
        ],
        6,
    ),
    "governance": _group_config(
        "scheduled",
        "governance",
        "[AGENDADO] EASM Agent 4 — FAIR+AGE rating (interno)",
        [],
        4,
    ),
    "executive_analyst": _group_config(
        "scheduled",
        "executive_analyst",
        "[AGENDADO] EASM Agent 5 — Narrativa executiva (interno)",
        [],
        3,
    ),
    # Aliases legados
    "reconhecimento": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] Alias -> asset_discovery",
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
    "osint": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] Alias -> threat_intel",
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
    "analise_vulnerabilidade": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] Alias -> risk_assessment",
        [
            "burp-cli",
            "nmap-vulscan",
            "nikto",
            "nuclei",
            "wpscan",
            "wfuzz",
            "wafw00f",
        ],
        6,
    ),
}

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def get_easm_agent_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    keys = {"asset_discovery", "threat_intel", "risk_assessment", "governance", "executive_analyst"}
    return {k: v for k, v in get_worker_groups(mode).items() if k in keys}


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    normalized = tool_name.strip().lower()
    ordered_groups = [
        "asset_discovery",
        "threat_intel",
        "risk_assessment",
        "reconhecimento",
        "osint",
        "analise_vulnerabilidade",
    ]
    groups = get_worker_groups(mode)
    for group_name in ordered_groups:
        group = groups.get(group_name, {})
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
    for group in get_worker_groups(mode).values():
        queue_name = str(group["queue"])
        if queue_name not in seen:
            seen.add(queue_name)
            result.append(queue_name)
    return result


SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
