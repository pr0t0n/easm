from typing import Any, Literal

ScanMode = Literal["unit", "scheduled"]


def _group_config(
    mode: ScanMode,
    queue_suffix: str,
    description: str,
    tools: list[str],
    priority: int,
) -> dict[str, Any]:
    mission = CANONICAL_GROUP_MISSIONS.get(queue_suffix, {})
    return {
        "queue": f"worker.{mode}.{queue_suffix}",
        "description": description,
        "tools": tools,
        "priority": priority,
        "mission": mission.get("mission", description),
        "techniques": list(mission.get("techniques", [])),
        "phases": list(mission.get("phases", [])),
        "evidence_focus": list(mission.get("evidence_focus", [])),
        "decision_rules": list(mission.get("decision_rules", [])),
    }


# ── Tool assignments per worker group ────────────────────────────────────────

CANONICAL_GROUP_TOOLS: dict[str, list[str]] = {
    "scope_validation": [],
    "reconnaissance": [
        "code-analyzer",
        # Subdomain enum (article §1-§2): use parallel sources, dedupe later.
        # Removed: massdns (no profile/binary in our Kali image).
        "subfinder", "amass", "amass-brute", "amass-intel", "sublist3r", "findomain",
        "assetfinder", "alterx", "shuffledns",
        # DNS recon (article §4-§5)
        "dnsx", "dnsrecon-brt", "dnsrecon-zt", "dnsenum",
        # Port/service scan (article §8-§10)
        "naabu", "nmap", "masscan",
        # Web fingerprint (article §6, §8)
        "httpx", "whatweb", "wafw00f", "curl-headers", "sslscan", "testssl",
        # Content/JS/parameter discovery — removed: js-snooper, jsniper (no profile).
        "katana", "hakrawler", "gau", "waybackurls", "gospider",
        "arjun", "paramspider",
        "ffuf-params", "ffuf-values", "wfuzz",
        # Header misconfig — runs early, complements code-analyzer
        "nikto",
    ],
    "weaponization": [
        # Templated DAST + multi-NSE vuln scanners. nmap is intentionally
        # listed in BOTH recon (service detect) and weaponization (vuln NSE),
        # via distinct tool aliases (`nmap` vs `nmap-vulscan`/`nmap-http-enum`/…).
        # Removed: metagoofil (no profile in our Kali image).
        "nuclei",
        "nmap-vulscan", "nmap-http-enum", "nmap-smb-vuln",
        "nmap-dns-vuln", "nmap-ssh-audit", "nmap-ssl-vuln",
        "shodan-cli", "theHarvester", "h8mail",
        "trufflehog", "gitleaks", "subjack",
    ],
    "delivery": ["ffuf", "ffuf-files", "ffuf-params", "ffuf-values", "ffuf-post", "wfuzz", "gobuster", "feroxbuster", "dirsearch", "arjun", "paramspider"],
    # Removed: impacket, evilwinrm (no profiles/binaries in our Kali image yet).
    "exploitation": ["nuclei", "sqlmap", "dalfox", "wapiti", "wpscan", "nikto", "interactsh-client", "katana", "arjun", "curl-headers", "ffuf-params", "ffuf-post", "hydra", "medusa", "crackmapexec", "jwt_tool", "sslscan", "testssl", "nmap"],
    "installation": ["hydra", "medusa", "crackmapexec", "jwt_tool", "nuclei", "curl-headers", "arjun"],
    "command_control": ["nuclei", "interactsh-client", "testssl"],
    # Removed: eslint, jshint, ast-grep (no profiles/binaries in our Kali image).
    "actions_on_objectives": ["semgrep", "bandit", "trufflehog", "gitleaks", "retire", "trivy"],
    "reporting": [],
}

CANONICAL_GROUP_MISSIONS: dict[str, dict[str, Any]] = {
    "scope_validation": {
        "mission": "Validar escopo autorizado, normalizar alvos e bloquear qualquer execucao fora do contrato.",
        "phases": ["preflight"],
        "techniques": ["scope normalization", "authorization gate", "target canonicalization"],
        "evidence_focus": ["authorized target", "blocked target reason", "scan mode"],
        "decision_rules": ["sem escopo aprovado, nao executar ferramentas ofensivas"],
    },
    "reconnaissance": {
        "mission": "Mapear superficie externa, portas, tecnologias, endpoints, parametros, cabecalhos OWASP Top 10 e sinais HTTP/TLS antes de testes intrusivos, incluindo fuzzing leve de nomes de parametros.",
        "phases": ["P01", "P02", "P03", "P04", "P05", "P06", "P18"],
        "techniques": ["subdomain enumeration", "port/service fingerprinting", "web crawling", "parameter discovery", "GET parameter-name fuzzing", "OWASP security-header analysis", "TLS certificate/protocol/cipher fingerprint", "WAF/TLS fingerprint"],
        "evidence_focus": ["asset", "port", "service", "url", "parameter", "header", "OWASP category", "certificate", "cipher", "technology"],
        "decision_rules": ["priorizar ferramentas passivas/baixa intrusividade antes de validacoes ativas"],
    },
    "weaponization": {
        "mission": "Correlacionar OSINT, CVEs, takeover, vazamentos e exposicoes externas para orientar hipoteses de risco.",
        "phases": ["P07", "P08", "P09", "P10", "P11", "P21"],
        "techniques": ["CVE correlation", "takeover checks", "leak intelligence", "cloud exposure review", "secret discovery"],
        "evidence_focus": ["CVE id", "template id", "public exposure", "leak source", "takeover signal"],
        "decision_rules": ["promover apenas com evidencia observavel ou correlacao forte com ativo do escopo"],
    },
    "delivery": {
        "mission": "Executar fuzzing controlado para descobrir caminhos, arquivos nao indexados, parametros GET/POST, valores de parametros, vhosts e formularios que alimentam validacoes de vulnerabilidade.",
        "phases": ["P04", "P15", "P16"],
        "techniques": ["ffuf Seclists directory fuzzing", "ffuf Seclists file fuzzing", "ffuf parameter-name fuzzing", "ffuf parameter-value fuzzing", "ffuf POST/form fuzzing", "wfuzz anomaly fuzzing", "API surface expansion"],
        "evidence_focus": ["path", "status code", "content length", "parameter", "payload value", "form field", "wordlist profile"],
        "decision_rules": ["controlar taxa de requisicoes, registrar wordlist usada e registrar skips quando parametro/formulario exigido nao existir"],
    },
    "exploitation": {
        "mission": "Validar vulnerabilidades web/API com prova reproduzivel, payload minimo e impacto demonstravel sem acoes destrutivas.",
        "phases": ["P11", "P12", "P13", "P16", "P17", "P19", "P20"],
        "techniques": ["template validation", "SQLi validation", "XSS validation", "SSRF/OOB validation", "API abuse", "IDOR/BOLA two-account reproduction", "fuzzing-informed payload validation"],
        "evidence_focus": ["request", "response", "payload", "endpoint", "artifact path", "impact"],
        "decision_rules": ["critical/high exige repro_steps, technical_evidence e artifact"],
    },
    "installation": {
        "mission": "Testar controles de autenticacao, autorizacao, JWT e credenciais apenas em escopo explicitamente autorizado.",
        "phases": ["P14", "P19"],
        "techniques": ["Hydra -L/-P controlled credential fuzzing", "JWT analysis", "auth bypass checks", "role/tenant validation", "IDOR authorization delta"],
        "evidence_focus": ["account precondition", "user/pass list path", "protocol", "token claim", "rate limit", "authorization delta"],
        "decision_rules": ["nao executar ataque volumetrico; Hydra so roda com SCAN_AUTH_USERLIST, SCAN_AUTH_PASSLIST e SCAN_AUTH_PROTOCOL definidos"],
    },
    "command_control": {
        "mission": "Avaliar risco de callbacks, interacoes outbound, TLS fraco e sinais de persistencia apenas como validacao defensiva.",
        "phases": ["P13", "P18"],
        "techniques": ["OOB interaction validation", "TLS weakness validation", "certificate chain review", "callback evidence review"],
        "evidence_focus": ["OOB callback", "cipher", "certificate chain", "certificate expiry", "egress behavior", "timestamp"],
        "decision_rules": ["usar listeners controlados e nunca manter persistencia real"],
    },
    "actions_on_objectives": {
        "mission": "Correlacionar secrets, SAST, dependencias e supply chain para impacto tecnico e plano de remediacao.",
        "phases": ["P21", "P22"],
        "techniques": ["secret scanning", "SAST triage", "dependency risk review", "supply-chain correlation"],
        "evidence_focus": ["file path", "secret fingerprint", "dependency id", "rule id", "fix version"],
        "decision_rules": ["mascarar segredos e priorizar evidencia minima sem exfiltracao"],
    },
    "reporting": {
        "mission": "Consolidar evidencias, separar hipotese de achado comprovado e produzir narrativa tecnica/executiva.",
        "phases": ["governance", "executive_analyst"],
        "techniques": ["evidence adjudication", "FAIR/AGE summarization", "remediation narrative", "false-positive separation"],
        "evidence_focus": ["severity", "confidence", "business impact", "reproducibility", "remediation"],
        "decision_rules": ["sem prova, manter como hipotese/backlog de validacao"],
    },
}


CYBER_AUTOAGENT_TOOL_CATALOG: dict[str, list[str]] = {
    "core_orchestration": ["supervisor", "skill_selector", "skill_planner", "tool_selector", "tool_executor", "evidence_gate"],
    "native_execution": ["shell", "http_request"],
    "memory_and_reflection": ["store_plan", "get_plan", "store_finding", "checkpoint_review"],
    "meta_tooling": ["editor", "load_tool"],
    "supported_scan_tools": sorted({t for tools in CANONICAL_GROUP_TOOLS.values() for t in tools}),
}


def get_canonical_group_tools() -> dict[str, list[str]]:
    tools_by_group = {group: list(tools) for group, tools in CANONICAL_GROUP_TOOLS.items()}
    aliases = {
        "recon": "reconnaissance",
        "reconhecimento": "reconnaissance",
        "osint": "weaponization",
        "vuln": "exploitation",
        "analise_vulnerabilidade": "exploitation",
        "exploit": "installation",
        "api": "delivery",
        "code": "actions_on_objectives",
    }
    for alias, target in aliases.items():
        if target in tools_by_group:
            tools_by_group[alias] = list(tools_by_group[target])
    return tools_by_group


def get_canonical_group_missions() -> dict[str, dict[str, Any]]:
    return {group: dict(mission) for group, mission in CANONICAL_GROUP_MISSIONS.items()}


def get_cyber_autoagent_tool_catalog() -> dict[str, list[str]]:
    return {group: list(tools) for group, tools in CYBER_AUTOAGENT_TOOL_CATALOG.items()}


def _base_agent_contract() -> dict[str, Any]:
    return {
        "reasoning_loop": ["know", "think", "test", "validate", "adapt"],
        "knowledge_loop": [
            "retrieve skill memory from MCP/RAG",
            "ground execution on accepted learning and tests",
            "dispatch selected tool via MCP -> Kali",
        ],
        "evidence_policy": "critical/high require reproducible proof; without it stays hypothesis",
        "confidence_thresholds": {"high": 80, "medium": 50, "low": 0},
        "pivot_rule": "confidence<50 or stagnation × 3 iterations → change tools/approach",
        "circuit_breaker": {"tool_failure_threshold": 5, "cooldown_seconds": 60},
        "tool_execution_path": "mcp_to_kali",
    }


def _build_worker_agent_profiles(mode: ScanMode) -> dict[str, dict[str, Any]]:
    groups = get_worker_groups(mode)
    contract = _base_agent_contract()

    profiles: dict[str, dict[str, Any]] = {}
    for group_key, agent_slug in [
        ("scope_validation", "scope"),
        ("reconnaissance", "recon"),
        ("weaponization", "weaponization"),
        ("delivery", "delivery"),
        ("exploitation", "vuln"),
        ("installation", "installation"),
        ("command_control", "c2"),
        ("actions_on_objectives", "aoo"),
        ("reporting", "reporting"),
    ]:
        group_data = groups.get(group_key) or {}
        profiles[group_key] = {
            "agent_id": f"agent.{agent_slug}",
            "agent_name": f"{agent_slug.replace('_', ' ').title()} Agent",
            "worker_group": group_key,
            "queue": group_data.get("queue", f"worker.{mode}.{group_key}"),
            "purpose": group_data.get("description", ""),
            "mission": group_data.get("mission", group_data.get("description", "")),
            "techniques": list(group_data.get("techniques") or []),
            "phases": list(group_data.get("phases") or []),
            "evidence_focus": list(group_data.get("evidence_focus") or []),
            "decision_rules": list(group_data.get("decision_rules") or []),
            "tools": list(group_data.get("tools") or CANONICAL_GROUP_TOOLS.get(group_key, [])),
            "contract": contract,
            "skill_context": {
                "retrieval_required": True,
                "selector_invocation_required": True,
                "knowledge_sources": ["accepted_learning", "repo_tests", "mcp_rag"],
                "execution_path": "mcp_to_kali",
                "pre_execution_step": "run skill_selector and skill_planner before selecting/dispatching tool",
            },
            "operational_sequence": [
                "skill_selector",
                "skill_planner",
                "retrieve_skill_memory",
                "select_learning_guided_technique",
                "dispatch_tool_via_mcp",
                "validate_evidence",
                "update_learning_feedback",
            ],
        }

    aliases = {
        "recon": "reconnaissance",
        "reconhecimento": "reconnaissance",
        "osint": "weaponization",
        "vuln": "exploitation",
        "analise_vulnerabilidade": "exploitation",
        "exploit": "installation",
        "api": "delivery",
        "code": "actions_on_objectives",
    }
    for alias, target in aliases.items():
        if target in profiles:
            profiles[alias] = dict(profiles[target], worker_group=alias)
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
        "reconnaissance": "reconnaissance",
        "weaponization": "weaponization",
        "delivery": "delivery",
        "exploitation": "exploitation",
        "installation": "installation",
        "command_control": "command_control",
        "actions_on_objectives": "actions_on_objectives",
        "reporting": "reporting",
        "scope_validation": "scope_validation",
        "vuln": "analise_vulnerabilidade",
        "analise_vulnerabilidade": "analise_vulnerabilidade",
        "osint": "osint",
        "exploit": "exploit",
        "api": "api",
        "code": "code",
    }
    key = alias_map.get(normalized, "reconhecimento")
    return dict(profiles.get(key, profiles["reconhecimento"]))


def validate_worker_group_contracts(mode: ScanMode = "unit") -> dict[str, Any]:
    groups = get_worker_groups(mode)
    canonical_groups = list(CANONICAL_GROUP_TOOLS.keys())
    missing: dict[str, list[str]] = {}
    for group in canonical_groups:
        data = groups.get(group) or {}
        absent = [
            field
            for field in ["queue", "mission", "techniques", "tools", "evidence_focus", "decision_rules"]
            if not data.get(field)
        ]
        if group in {"scope_validation", "reporting"}:
            absent = [field for field in absent if field != "tools"]
        if absent:
            missing[group] = absent
    return {
        "ok": not missing,
        "mode": mode,
        "missing": missing,
        "groups": canonical_groups,
    }


_TOOL_TO_GROUP: dict[str, str] = {}
for _group, _tools in CANONICAL_GROUP_TOOLS.items():
    for _t in _tools:
        _normalized_tool = str(_t or "").strip().lower()
        if _normalized_tool and _normalized_tool not in _TOOL_TO_GROUP:
            _TOOL_TO_GROUP[_normalized_tool] = _group


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
