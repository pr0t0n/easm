from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(mode: ScanMode, queue_suffix: str, description: str, tools: list[str], priority: int) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


CANONICAL_GROUP_TOOLS: dict[str, list[str]] = {
    "recon": ["amass", "massdns", "sublist3r", "nmap", "curl-headers", "wafw00f"],
    "osint": ["shodan-cli"],
    "vuln": ["burp-cli", "nmap-vulscan", "nikto"],
}


CYBER_AUTOAGENT_TOOL_CATALOG: dict[str, list[str]] = {
    "core_orchestration": ["supervisor", "strategic_planning", "evidence_adjudication"],
    "native_execution": ["shell", "http_request"],
    "memory_and_reflection": ["store_plan", "get_plan", "store_finding", "checkpoint_review"],
    "meta_tooling": ["editor", "load_tool"],
    "supported_scan_tools": [
        "amass",
        "massdns",
        "sublist3r",
        "nmap",
        "nmap-vulscan",
        "nikto",
        "wafw00f",
        "curl-headers",
        "shodan-cli",
        "httpx",
        "katana",
        "ffuf",
        "subfinder",
        "naabu",
        "dirsearch",
        "arjun",
        "gospider",
        "nuclei",
        "whatweb",
        "wapiti",
        "wfuzz",
        "wpscan",
        "sqlmap",
        "interactsh-client",
        "jwt_tool",
        "semgrep",
        "bandit",
        "trufflehog",
        "gitleaks",
        "trivy",
        "zaproxy",
        "retire",
        "eslint",
        "jshint",
        "ast-grep",
        "tree-sitter",
        "js-beautify",
        "js-snooper",
        "jsniper",
    ],
}


def get_canonical_group_tools() -> dict[str, list[str]]:
    """Return a defensive copy of canonical tools by worker group."""
    return {group: list(tools) for group, tools in CANONICAL_GROUP_TOOLS.items()}


def get_cyber_autoagent_tool_catalog() -> dict[str, list[str]]:
    """Return a defensive copy of the conceptual tool catalog aligned with Cyber-AutoAgent."""
    return {group: list(tools) for group, tools in CYBER_AUTOAGENT_TOOL_CATALOG.items()}


def _base_agent_contract() -> dict[str, Any]:
    return {
        "reasoning_loop": ["know", "think", "test", "validate"],
        "evidence_policy": "critical/high exigem prova reproduzivel; sem prova permanece hypothesis",
        "confidence_thresholds": {"high": 80, "medium": 50, "low": 0},
        "pivot_rule": "confianca<50 ou repeticao sem progresso => mudar estrategia",
    }


def _build_worker_agent_profiles(mode: ScanMode) -> dict[str, dict[str, Any]]:
    groups = get_worker_groups(mode)
    contract = _base_agent_contract()
    return {
        "reconhecimento": {
            "agent_id": "agent.recon",
            "agent_name": "Recon Agent",
            "worker_group": "reconhecimento",
            "queue": groups["reconhecimento"]["queue"],
            "purpose": "Mapear superficie de ataque e exposicao inicial de ativos.",
            "tools": list(groups["reconhecimento"]["tools"]),
            "contract": contract,
        },
        "analise_vulnerabilidade": {
            "agent_id": "agent.vuln",
            "agent_name": "Vulnerability Agent",
            "worker_group": "analise_vulnerabilidade",
            "queue": groups["analise_vulnerabilidade"]["queue"],
            "purpose": "Validar hipoteses tecnicas e produzir evidencias de explorabilidade.",
            "tools": list(groups["analise_vulnerabilidade"]["tools"]),
            "contract": contract,
        },
        "osint": {
            "agent_id": "agent.osint",
            "agent_name": "Threat Intel Agent",
            "worker_group": "osint",
            "queue": groups["osint"]["queue"],
            "purpose": "Correlacionar inteligencia externa e sinais de exposicao publica.",
            "tools": list(groups["osint"]["tools"]),
            "contract": contract,
        },
    }


def _build_worker_groups(mode: ScanMode, priorities: dict[str, int]) -> dict[str, dict[str, Any]]:
    mode_label = "UNITARIO" if mode == "unit" else "AGENDADO"
    recon_tools = list(CANONICAL_GROUP_TOOLS["recon"])
    osint_tools = list(CANONICAL_GROUP_TOOLS["osint"])
    vuln_tools = list(CANONICAL_GROUP_TOOLS["vuln"])

    return {
        "recon": _group_config(
            mode,
            "reconhecimento",
            f"[{mode_label}] Worker RECON — Descoberta de ativos (Amass, MassDns, Sublist3r, Nmap, Curl-Headers, WAFw00f)",
            recon_tools,
            priorities["recon"],
        ),
        "osint": _group_config(
            mode,
            "osint",
            f"[{mode_label}] Worker OSINT — Inteligência de ameaças (Shodan.io)",
            osint_tools,
            priorities["osint"],
        ),
        "vuln": _group_config(
            mode,
            "analise_vulnerabilidade",
            f"[{mode_label}] Worker VULN — Análise de vulnerabilidades (Burp, Nmap Vulscan, Nikto)",
            vuln_tools,
            priorities["vuln"],
        ),
        # Aliases para compatibilidade com rotas/CLI
        "reconhecimento": _group_config(
            mode,
            "reconhecimento",
            f"[{mode_label}] Alias -> recon",
            recon_tools,
            priorities["recon"],
        ),
        "analise_vulnerabilidade": _group_config(
            mode,
            "analise_vulnerabilidade",
            f"[{mode_label}] Alias -> vuln",
            vuln_tools,
            priorities["vuln"],
        ),
    }


# Pentest.io pipeline (refatorado — 3 workers):
# 1) RECON (Amass, MassDns, Sublist3r, Nmap, Curl-Headers, WAFw00f) 
#    → 2a) OSINT (Shodan.io) + 2b) VULN (Burp, Nmap Vulscan, Nikto) [paralelo]
#    → 3) LLM (junta dados + valida risco + recomm)

UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = _build_worker_groups(
    mode="unit",
    priorities={"recon": 9, "osint": 8, "vuln": 9},
)

SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = _build_worker_groups(
    mode="scheduled",
    priorities={"recon": 6, "osint": 5, "vuln": 6},
)


def _validate_tool_parity() -> None:
    for group_name in ["recon", "osint", "vuln"]:
        unit_tools = UNIT_WORKER_GROUPS[group_name]["tools"]
        scheduled_tools = SCHEDULED_WORKER_GROUPS[group_name]["tools"]
        if unit_tools != scheduled_tools:
            raise RuntimeError(
                f"Tool drift detectado no grupo '{group_name}': unit={unit_tools} scheduled={scheduled_tools}"
            )


_validate_tool_parity()

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    """Return worker groups config for the given mode."""
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def get_worker_agent_profiles(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    """Return operational worker-agent profiles for the given mode."""
    return _build_worker_agent_profiles(mode)


def get_worker_agent_profile(group_name: str, mode: ScanMode = "unit") -> dict[str, Any]:
    profiles = get_worker_agent_profiles(mode)
    normalized = str(group_name or "").strip().lower()
    alias_map = {
        "recon": "reconhecimento",
        "reconhecimento": "reconhecimento",
        "vuln": "analise_vulnerabilidade",
        "analise_vulnerabilidade": "analise_vulnerabilidade",
        "osint": "osint",
    }
    key = alias_map.get(normalized, "reconhecimento")
    return dict(profiles.get(key, profiles["reconhecimento"]))


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    """Find which worker group contains the given tool."""
    normalized = tool_name.strip().lower()
    groups = get_worker_groups(mode)
    for group_name in ["recon", "osint", "vuln", "reconhecimento", "analise_vulnerabilidade"]:
        group = groups.get(group_name, {})
        if normalized in group.get("tools", []):
            return group_name
    return "recon"


def find_agent_by_tool(tool_name: str, mode: ScanMode = "unit") -> dict[str, Any]:
    group = find_group_by_tool(tool_name, mode)
    return get_worker_agent_profile(group, mode)


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
