from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(
    mode: ScanMode,
    queue_suffix: str,
    description: str,
    tools: list[str],
    priority: int,
) -> dict[str, Any]:
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
    }


# ── Tool assignments per worker group ────────────────────────────────────────

CANONICAL_GROUP_TOOLS: dict[str, list[str]] = {
    "scope_validation": [],
    "reconnaissance": [
        "subfinder", "amass", "dnsx", "shuffledns", "assetfinder", "alterx",
        "naabu", "nmap", "masscan", "httpx", "whatweb", "wafw00f", "curl-headers",
        "sslscan", "testssl", "katana", "hakrawler", "gau", "waybackurls",
        "gospider", "arjun", "paramspider",
    ],
    "weaponization": [
        "nuclei", "nmap-vulscan", "shodan-cli", "theHarvester", "h8mail",
        "trufflehog", "gitleaks", "subjack",
    ],
    "delivery": ["ffuf", "gobuster", "feroxbuster", "dirsearch", "arjun", "paramspider"],
    "exploitation": ["nuclei", "sqlmap", "dalfox", "wapiti", "wpscan", "nikto", "interactsh-client"],
    "installation": ["hydra", "medusa", "crackmapexec", "jwt_tool"],
    "command_control": ["nuclei", "interactsh-client", "testssl"],
    "actions_on_objectives": ["semgrep", "bandit", "trufflehog", "gitleaks", "retire", "trivy"],
    "reporting": [],
}


CYBER_AUTOAGENT_TOOL_CATALOG: dict[str, list[str]] = {
    "core_orchestration": ["supervisor", "strategic_planning", "evidence_adjudication"],
    "native_execution": ["shell", "http_request"],
    "memory_and_reflection": ["store_plan", "get_plan", "store_finding", "checkpoint_review"],
    "meta_tooling": ["editor", "load_tool"],
    "supported_scan_tools": sorted({t for tools in CANONICAL_GROUP_TOOLS.values() for t in tools}),
}


def get_canonical_group_tools() -> dict[str, list[str]]:
    return {group: list(tools) for group, tools in CANONICAL_GROUP_TOOLS.items()}


def get_cyber_autoagent_tool_catalog() -> dict[str, list[str]]:
    return {group: list(tools) for group, tools in CYBER_AUTOAGENT_TOOL_CATALOG.items()}


def _base_agent_contract() -> dict[str, Any]:
    return {
        "reasoning_loop": ["know", "think", "test", "validate", "adapt"],
        "evidence_policy": "critical/high require reproducible proof; without it stays hypothesis",
        "confidence_thresholds": {"high": 80, "medium": 50, "low": 0},
        "pivot_rule": "confidence<50 or stagnation × 3 iterations → change tools/approach",
        "circuit_breaker": {"tool_failure_threshold": 5, "cooldown_seconds": 60},
    }


def _build_worker_agent_profiles(mode: ScanMode) -> dict[str, dict[str, Any]]:
    groups = get_worker_groups(mode)
    contract = _base_agent_contract()

    profiles: dict[str, dict[str, Any]] = {}
    for group_key, cfg in [
        ("reconhecimento", "recon"),
        ("analise_vulnerabilidade", "vuln"),
        ("osint", "osint"),
        ("exploit", "exploit"),
        ("api", "api"),
        ("code", "code"),
    ]:
        group_data = groups.get(cfg) or groups.get(group_key) or {}
        profiles[group_key] = {
            "agent_id": f"agent.{cfg}",
            "agent_name": f"{cfg.title()} Agent",
            "worker_group": group_key,
            "queue": group_data.get("queue", f"worker.{mode}.{group_key}"),
            "purpose": group_data.get("description", ""),
            "tools": list(group_data.get("tools") or CANONICAL_GROUP_TOOLS.get(cfg, [])),
            "contract": contract,
        }
    return profiles


def _build_worker_groups(mode: ScanMode, priorities: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Materializes one entry per Kill Chain phase. Each entry gets a celery
    queue name `worker.{mode}.{group}` and inherits the tool list from
    CANONICAL_GROUP_TOOLS. Legacy aliases (`recon`, `vuln`, ...) point to the
    same configs so persisted state and old callers keep working.
    """
    label = "UNIT" if mode == "unit" else "SCHED"
    groups: dict[str, dict[str, Any]] = {}

    specs = [
        ("scope_validation",      f"[{label}] SCOPE VALIDATION"),
        ("reconnaissance",        f"[{label}] RECON — Subdomain/Port/Web Crawl/Fingerprint"),
        ("weaponization",         f"[{label}] WEAPONIZATION — CVE/OSINT/Secrets correlation"),
        ("delivery",              f"[{label}] DELIVERY — Dir/Param/Vhost discovery"),
        ("exploitation",          f"[{label}] EXPLOITATION — Nuclei/Nikto/Wapiti/SQLMap/Dalfox"),
        ("installation",          f"[{label}] INSTALLATION — Auth bruteforce, JWT, AD"),
        ("command_control",       f"[{label}] C2 — Persistence + outbound risk"),
        ("actions_on_objectives", f"[{label}] AOO — SAST/secrets/dependency"),
        ("reporting",             f"[{label}] REPORTING — Executive narrative"),
    ]

    default_priority = priorities.get("reconnaissance", 7)
    for group_key, description in specs:
        priority = priorities.get(group_key, default_priority)
        tools = list(CANONICAL_GROUP_TOOLS.get(group_key, []))
        groups[group_key] = _group_config(mode, group_key, description, tools, priority)

    # Backward-compat aliases — older code/state references the legacy group
    # names. Each alias is just a pointer to the new Kill Chain entry.
    aliases = {
        "recon":                  "reconnaissance",
        "reconhecimento":         "reconnaissance",
        "osint":                  "weaponization",
        "vuln":                   "exploitation",
        "analise_vulnerabilidade":"exploitation",
        "exploit":                "installation",
        "api":                    "delivery",
        "code":                   "actions_on_objectives",
    }
    for alias, target in aliases.items():
        if target in groups:
            groups[alias] = dict(groups[target])

    return groups


_UNIT_PRIORITIES = {
    "scope_validation": 10, "reconnaissance": 9, "weaponization": 9,
    "delivery": 8, "exploitation": 8, "installation": 7,
    "command_control": 6, "actions_on_objectives": 6, "reporting": 5,
}
_SCHED_PRIORITIES = {k: max(1, v - 3) for k, v in _UNIT_PRIORITIES.items()}

UNIT_WORKER_GROUPS: dict[str, dict[str, Any]] = _build_worker_groups(mode="unit", priorities=_UNIT_PRIORITIES)
SCHEDULED_WORKER_GROUPS: dict[str, dict[str, Any]] = _build_worker_groups(mode="scheduled", priorities=_SCHED_PRIORITIES)

WORKER_GROUPS = UNIT_WORKER_GROUPS


def get_worker_groups(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
    return UNIT_WORKER_GROUPS if mode == "unit" else SCHEDULED_WORKER_GROUPS


def get_worker_agent_profiles(mode: ScanMode = "unit") -> dict[str, dict[str, Any]]:
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
        "exploit": "exploit",
        "api": "api",
        "code": "code",
    }
    key = alias_map.get(normalized, "reconhecimento")
    return dict(profiles.get(key, profiles["reconhecimento"]))


_TOOL_TO_GROUP: dict[str, str] = {}
for _group, _tools in CANONICAL_GROUP_TOOLS.items():
    for _t in _tools:
        if _t not in _TOOL_TO_GROUP:
            _TOOL_TO_GROUP[_t] = _group


def find_group_by_tool(tool_name: str, mode: ScanMode = "unit") -> str:
    normalized = str(tool_name or "").strip().lower()
    return _TOOL_TO_GROUP.get(normalized, "recon")


def find_agent_by_tool(tool_name: str, mode: ScanMode = "unit") -> dict[str, Any]:
    group = find_group_by_tool(tool_name, mode)
    return get_worker_agent_profile(group, mode)


def group_queue(group_name: str, mode: ScanMode = "unit") -> str:
    groups = get_worker_groups(mode)
    group = groups.get(group_name) or groups.get("recon") or next(iter(groups.values()))
    return str(group["queue"])


def all_queues(mode: ScanMode) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for group in get_worker_groups(mode).values():
        q = str(group["queue"])
        if q not in seen:
            seen.add(q)
            result.append(q)
    return result


# Public queue names for scan routing
SCAN_UNIT_QUEUE = "scan.unit"
SCAN_SCHEDULED_QUEUE = "scan.scheduled"
