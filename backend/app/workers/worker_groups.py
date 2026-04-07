from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(mode: ScanMode, queue_suffix: str, description: str, tools: list[str], priority: int) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


# Pentest.io pipeline (refatorado — 3 workers):
# 1) RECON (Amass, MassDns, Sublist3r, Nmap, Curl-Headers, WAFw00f) 
#    → 2a) OSINT (Shodan.io) + 2b) VULN (Burp, Nmap Vulscan, Nikto) [paralelo]
#    → 3) LLM (junta dados + valida risco + recomm)

UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "recon": _group_config(
        "unit",
        "reconhecimento",
        "[UNITARIO] Worker RECON — Descoberta de ativos (Amass, MassDns, Sublist3r, Nmap, Curl-Headers, WAFw00f)",
        ["amass", "massdns", "sublist3r", "nmap", "curl-headers", "wafw00f"],
        9,
    ),
    "osint": _group_config(
        "unit",
        "osint",
        "[UNITARIO] Worker OSINT — Inteligência de ameaças (Shodan.io)",
        ["shodan-cli"],
        8,
    ),
    "vuln": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITARIO] Worker VULN — Análise de vulnerabilidades (Burp, Nmap Vulscan, Nikto)",
        ["burp-cli", "nmap-vulscan", "nikto"],
        9,
    ),
    # Aliases para compatibilidade com rotas/CLI
    "reconhecimento": _group_config(
        "unit",
        "reconhecimento",
        "[UNITARIO] Alias -> recon",
        ["amass", "massdns", "sublist3r", "nmap", "curl-headers", "wafw00f"],
        9,
    ),
    "analise_vulnerabilidade": _group_config(
        "unit",
        "analise_vulnerabilidade",
        "[UNITARIO] Alias -> vuln",
        ["burp-cli", "nmap-vulscan", "nikto"],
        9,
    ),
}

SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "recon": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] Worker RECON — Descoberta de ativos (Amass, MassDns, Sublist3r, Nmap, Curl-Headers, WAFw00f)",
        ["amass", "massdns", "sublist3r", "nmap", "curl-headers", "wafw00f"],
        6,
    ),
    "osint": _group_config(
        "scheduled",
        "osint",
        "[AGENDADO] Worker OSINT — Inteligência de ameaças (Shodan.io)",
        ["shodan-cli"],
        5,
    ),
    "vuln": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] Worker VULN — Análise de vulnerabilidades (Burp, Nmap Vulscan, Nikto)",
        ["burp-cli", "nmap-vulscan", "nikto"],
        6,
    ),
    # Aliases para compatibilidade
    "reconhecimento": _group_config(
        "scheduled",
        "reconhecimento",
        "[AGENDADO] Alias -> recon",
        ["amass", "massdns", "sublist3r", "nmap", "curl-headers", "wafw00f"],
        6,
    ),
    "analise_vulnerabilidade": _group_config(
        "scheduled",
        "analise_vulnerabilidade",
        "[AGENDADO] Alias -> vuln",
        ["burp-cli", "nmap-vulscan", "nikto"],
        6,
    ),
}

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    """Return worker groups config for the given mode."""
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    """Find which worker group contains the given tool."""
    normalized = tool_name.strip().lower()
    groups = get_worker_groups(mode)
    for group_name in ["recon", "osint", "vuln", "reconhecimento", "analise_vulnerabilidade"]:
        group = groups.get(group_name, {})
        if normalized in group.get("tools", []):
            return group_name
    return "recon"


def group_queue(group_name: str, mode: ScanMode = "unit") -> str:
    """Get queue name for a worker group."""
    groups = get_worker_groups(mode)
    group = groups.get(group_name) or groups.get("recon") or next(iter(groups.values()))
    return str(group["queue"])


def all_queues(mode: ScanMode) -> list[str]:
    """Get all unique queue names for the given mode."""
    seen: set[str] = set()
    result: list[str] = []
    for group in get_worker_groups(mode).values():
        queue_name = str(group["queue"])
        if queue_name not in seen:
            seen.add(queue_name)
            result.append(queue_name)
    return result


# Queue names para roteamento de scans
SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
