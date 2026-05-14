"""Cyber Kill Chain phase taxonomy + aliases for the existing graph nodes.

We keep the original capability-node names (`asset_discovery`, `risk_assessment`
etc.) for back-compat with persisted state and the LangGraph wiring, while
also exposing a Kill Chain narrative (`SCOPE_VALIDATION → RECONNAISSANCE →
WEAPONIZATION_SIMULATION → DELIVERY_MAPPING → EXPLOITATION_VALIDATION →
INSTALLATION_RISK_ANALYSIS → COMMAND_AND_CONTROL_RISK → ACTIONS_ON_OBJECTIVES
→ REPORTING`) that drives the executive frontend.

This file is the single mapping point so the rest of the codebase stays
unchanged.
"""
from __future__ import annotations

from typing import Any


# Canonical phase ids (UPPER_SNAKE_CASE, stable for DB/UI)
KILL_CHAIN_PHASES: list[str] = [
    "SCOPE_VALIDATION",
    "RECONNAISSANCE",
    "WEAPONIZATION_SIMULATION",
    "DELIVERY_MAPPING",
    "EXPLOITATION_VALIDATION",
    "INSTALLATION_RISK_ANALYSIS",
    "COMMAND_AND_CONTROL_RISK",
    "ACTIONS_ON_OBJECTIVES",
    "REPORTING",
]


# Map graph node → Kill Chain phase
# Only nodes that actually exist in build_graph() are listed here.
# Capability labels (asset_discovery, threat_intel, risk_assessment) are tracked
# in completed_capabilities, not in node_history — so they use the "completed" check.
NODE_TO_PHASE: dict[str, str] = {
    "supervisor":        "SCOPE_VALIDATION",
    "asset_discovery":   "RECONNAISSANCE",           # capability label in completed_capabilities
    "threat_intel":      "WEAPONIZATION_SIMULATION",  # capability label in completed_capabilities
    "skill_selector":    "DELIVERY_MAPPING",
    "risk_assessment":   "EXPLOITATION_VALIDATION",   # capability label in completed_capabilities
    "evidence_gate":     "INSTALLATION_RISK_ANALYSIS",
    "governance":        "COMMAND_AND_CONTROL_RISK",
    "executive_analyst": "REPORTING",
    # ACTIONS_ON_OBJECTIVES is derived from finding severity + exposure (no dedicated node).
}

# Reverse lookup
PHASE_TO_NODE: dict[str, str] = {v: k for k, v in NODE_TO_PHASE.items()}


def phase_for_node(node_name: str) -> str:
    return NODE_TO_PHASE.get(str(node_name or "").strip().lower(), "REPORTING")


def node_for_phase(phase_id: str) -> str:
    return PHASE_TO_NODE.get(str(phase_id or "").strip().upper(), "executive_analyst")


# Human-readable + audience-tailored copy per phase
PHASE_META: dict[str, dict[str, Any]] = {
    "SCOPE_VALIDATION": {
        "label": "Validação de Escopo",
        "summary": "Validar autorização, alvos, allowlist e contrato de execução.",
        "executive_pitch": "Antes de qualquer probe, garantimos que cada alvo testado está dentro do escopo aprovado e auditado.",
        "node": "strategic_planning",
    },
    "RECONNAISSANCE": {
        "label": "Reconhecimento",
        "summary": "Mapeamento da superfície externa: subdomínios, portas, tecnologias, TLS, parâmetros.",
        "executive_pitch": "Inventário do que está exposto antes de mensurar risco.",
        "node": "asset_discovery",
    },
    "WEAPONIZATION_SIMULATION": {
        "label": "Simulação de Armamentização",
        "summary": "Correlação CVE/EPSS, leaks de credencial, fingerprint OSINT — sem disparo de exploit.",
        "executive_pitch": "Estimamos o que um adversário conseguiria preparar a partir do que está visível.",
        "node": "threat_intel",
    },
    "DELIVERY_MAPPING": {
        "label": "Mapeamento de Entrega",
        "summary": "Identificação de vetores de entrega: paths web, formulários, parâmetros, takeover, OOB.",
        "executive_pitch": "Vias por onde o ataque chegaria à aplicação ou ao funcionário.",
        "node": "adversarial_hypothesis",
    },
    "EXPLOITATION_VALIDATION": {
        "label": "Validação de Exploração",
        "summary": "Probes ativos read-only que provam injeções, XSS, SSRF e CMS-known-vulns.",
        "executive_pitch": "Confirmação técnica de que cada finding crítico/high é reproduzível.",
        "node": "risk_assessment",
    },
    "INSTALLATION_RISK_ANALYSIS": {
        "label": "Risco de Instalação",
        "summary": "Avalia se um atacante poderia obter persistência (auth fraca, config exposta).",
        "executive_pitch": "O blast radius caso o vetor seja explorado.",
        "node": "evidence_adjudication",
    },
    "COMMAND_AND_CONTROL_RISK": {
        "label": "Risco de C2",
        "summary": "Postura governance + canais que poderiam servir de comando e controle.",
        "executive_pitch": "Capacidade do adversário manter contato após a invasão inicial.",
        "node": "governance",
    },
    "ACTIONS_ON_OBJECTIVES": {
        "label": "Ações sobre Objetivos",
        "summary": "Estimativa de exfiltração/data damage com base em SAST + secrets + dependency CVEs.",
        "executive_pitch": "Dano financeiro esperado se a cadeia for completada.",
        "node": "evidence_adjudication",
    },
    "REPORTING": {
        "label": "Relatório Executivo",
        "summary": "Narrativa, FAIR breakdown, rating ScriptKidd.o e recomendações priorizadas.",
        "executive_pitch": "Material assinável para o board e o PRA do cliente.",
        "node": "executive_analyst",
    },
}


# ─────────────────────────────────────────────────────────────────────
# Kill-chain GATING — enforces the canonical pentest order.
# Without this, the supervisor can be steered by a tech-stack auto-lock
# directly to vuln-injection (exploitation) without running nmap, amass,
# httpx, nuclei first. The user requirement is recon → vuln-analysis →
# exploitation → actions-on-objectives, in that order.
# ─────────────────────────────────────────────────────────────────────

# Logical stage names — coarser than KILL_CHAIN_PHASES on purpose so the
# supervisor's gate has a small finite state machine to walk.
KILL_CHAIN_STAGES: list[str] = [
    "RECONNAISSANCE",      # nmap, amass, subfinder, httpx, whatweb, theHarvester, shodan
    "VULNERABILITY_ANALYSIS",  # nuclei CVE templates, nmap-vulscan, sslscan/testssl, wafw00f
    "EXPLOITATION",        # sqlmap, dalfox, wapiti, ffuf fuzzing, hydra, wpscan
    "ACTIONS_ON_OBJECTIVES",   # post-exploit (mimikatz/bloodhound/crackmapexec/responder/empire)
]

# Allowed skills per stage (catalog ids). A skill not listed here is
# blocked from selection in that stage. A skill may be re-allowed in a
# later stage — e.g. tech-cms-fingerprint runs in RECON but wpscan-style
# exploitation belongs to EXPLOITATION.
STAGE_ALLOWED_SKILLS: dict[str, set[str]] = {
    "RECONNAISSANCE": {
        "recon-subdomain-enum",
        "recon-port-service",
        "recon-web-crawl",
        # P04 Parameter Discovery is reconnaissance/delivery work. The skill
        # also owns deeper P15/P16 fuzzing, but in this stage the supervisor
        # constrains it to parameter-discovery tools only.
        "vuln-directory-enum",
        "tech-http-fingerprint",
        "tech-owasp-header-analysis",
        "tech-cms-fingerprint",
        "osint-exposure-intel",
        "osint-email-infra",
        "osint-subdomain-takeover",
        "osint-cloud-exposure",
    },
    "VULNERABILITY_ANALYSIS": {
        # nuclei + nmap-vulscan + targeted NSE batteries (http/smb/ssh/ssl/dns)
        # belong here. The skill `vuln-nuclei-cve` declares them all in its
        # playbook so kill-chain just needs to allow the skill.
        "vuln-nuclei-cve",
        "vuln-ssl-tls",
        "vuln-information-disclosure",
        "tech-http-fingerprint",
        "tech-owasp-header-analysis",
        "waf-aware-validation",
        "weak-cryptography",
        "code-secrets-sast",
        "code-supply-chain-deps",
    },
    "EXPLOITATION": {
        "vuln-injection",
        "vuln-directory-enum",
        "vuln-auth-bypass",
        "vuln-idor-access-control",
        "vuln-api-graphql",
        "vuln-ssrf-redirect",
        # CMS-scan-with-wpscan is exploitation territory even though detection
        # happens in recon — keep tech-cms-fingerprint here too so the skill
        # remains selectable once the env demands it.
        "tech-cms-fingerprint",
    },
    "ACTIONS_ON_OBJECTIVES": {
        # No web-side catalog entries yet; placeholder for future post-exploit
        # skills (mimikatz, bloodhound, crackmapexec, responder, empire).
        "evidence-proof-pack",
    },
}

# Minimum signal needed to leave each stage. Checked by advance_kill_chain_stage.
# - tool_runs: number of distinct tools that ran (any status) under any skill
#              labelled to the current stage
# - tech_stack_required: bool — must have at least one tech-stack tag
# - port_or_asset_required: bool — must have discovered_ports OR lista_ativos
# - vuln_analysis_tool_required: skill in {vuln-nuclei-cve, vuln-ssl-tls,
#                                          waf-aware-validation, vuln-information-disclosure}
# - finding_severity_required: minimum severity of at least one promoted finding
STAGE_EXIT_CRITERIA: dict[str, dict[str, Any]] = {
    "RECONNAISSANCE": {
        # Broad coverage of the article's checklist before exit. The user
        # observed 9% coverage (5/53 tools) in scan #14 — we now require
        # 12 distinct tools AND specific coverage groups so the agent
        # cannot skip categories (subdomain enum, port scan, web finger).
        "tool_runs": 12,
        "mandatory_tools_all_of": [
            # Article §1: subdomain enum — at least one passive source ran
            ["subfinder", "amass", "sublist3r", "assetfinder", "findomain"],
            # Article §4-§5: DNS recon
            ["dnsx", "dnsrecon-brt", "dnsenum"],
            # Article §8-§10: port/service scan
            ["naabu", "nmap", "masscan"],
            # Article §6, §8: HTTP fingerprint + alive check
            ["httpx", "whatweb", "curl-headers", "nikto"],
            # Code-analyzer: ALWAYS — it produces param matrix evidence
            ["code-analyzer"],
            # Content/JS extraction
            ["katana", "gau", "waybackurls", "gospider", "hakrawler"],
            # P04: active/passive parameter discovery.
            ["arjun", "paramspider", "ffuf-params", "wfuzz"],
        ],
        "min_tools_by_group": [
            {
                "name": "P04 Parameter Discovery",
                "tools": ["arjun", "paramspider", "ffuf-params", "wfuzz"],
                "count": 2,
            },
        ],
        # ANY of these counts as "I learned something about the target".
        "recon_evidence_any_of": True,
    },
    "VULNERABILITY_ANALYSIS": {
        # User reported failures here too — we now require 5 distinct tools
        # including BOTH templated and protocol audits to ensure depth.
        "tool_runs": 5,
        "vuln_analysis_tool_required": True,
        "mandatory_tools_all_of": [
            # Templated DAST and web-server audit are both mandatory; nikto
            # complements nuclei and catches IIS/ASP.NET misconfigurations
            # that generic templates may not report.
            ["nuclei"],
            ["nikto"],
            # Protocol audit on HTTPS targets; curl-headers covers HTTP-only.
            ["sslscan", "testssl", "wafw00f", "curl-headers", "nmap-ssl-vuln"],
            # At least one NSE-targeted scan beyond generic --script vuln.
            ["nmap-http-enum", "nmap-ssl-vuln", "nmap-ssh-audit", "nmap-smb-vuln"],
        ],
    },
    "EXPLOITATION": {
        # Real exploitation: at least 1 injection-class scanner AND 1
        # curl-based validator (auth/ssrf/rce/xxe) AND 1 brute/cred tool.
        "tool_runs": 5,
        "mandatory_tools_all_of": [
            # Injection/automation scanners
            ["sqlmap", "dalfox", "wapiti", "wpscan"],
            # Curl-based validators (the cheap probes)
            ["curl-headers"],
            # Content/param fuzz
            ["ffuf", "ffuf-params", "ffuf-files", "wfuzz", "gobuster", "feroxbuster"],
        ],
    },
    "ACTIONS_ON_OBJECTIVES": {},  # terminal
}


def initial_kill_chain_stage() -> str:
    return KILL_CHAIN_STAGES[0]


def next_kill_chain_stage(current: str) -> str:
    try:
        idx = KILL_CHAIN_STAGES.index(str(current or "").strip().upper())
    except ValueError:
        return KILL_CHAIN_STAGES[0]
    if idx + 1 >= len(KILL_CHAIN_STAGES):
        return KILL_CHAIN_STAGES[-1]
    return KILL_CHAIN_STAGES[idx + 1]


def stage_allows_skill(stage: str, skill_id: str) -> bool:
    """Returns True when the supervisor may select this skill in this stage."""
    stage_key = str(stage or "").strip().upper() or "RECONNAISSANCE"
    skill_key = str(skill_id or "").strip()
    return skill_key in STAGE_ALLOWED_SKILLS.get(stage_key, set())


def advance_kill_chain_stage(state: dict) -> tuple[str, bool, str]:
    """Inspect state and decide if the current stage can advance.

    Returns (new_stage, advanced, reason).
    Pure read of state — caller is responsible for assigning back.
    """
    current = str(state.get("kill_chain_stage") or "").strip().upper() or KILL_CHAIN_STAGES[0]
    if current not in KILL_CHAIN_STAGES:
        current = KILL_CHAIN_STAGES[0]
    criteria = STAGE_EXIT_CRITERIA.get(current, {})
    if not criteria:
        return current, False, "terminal_stage"

    findings = list(state.get("vulnerabilidades_encontradas") or [])
    executed_runs = list(state.get("executed_tool_runs") or [])
    tech_stack = list(state.get("detected_tech_stack") or [])
    discovered_ports = list(state.get("discovered_ports") or [])
    lista_ativos = list(state.get("lista_ativos") or [])

    # Count distinct tools executed (run_id contains "|tool" suffix)
    distinct_tools = {run.split("|")[-1] for run in executed_runs if "|" in run}
    distinct_tools.discard("")

    min_tool_runs = int(criteria.get("tool_runs", 0))
    if min_tool_runs and len(distinct_tools) < min_tool_runs:
        return current, False, f"need_tool_runs>={min_tool_runs}_have={len(distinct_tools)}"

    # mandatory_tools_any_of: each inner group requires at least one match.
    for group in (criteria.get("mandatory_tools_any_of") or []):
        if not any(t in distinct_tools for t in group):
            return current, False, f"missing_any_of:{','.join(group[:6])}"

    # mandatory_tools_all_of: each inner group requires at least one match
    # — same semantics as any_of but iterating over multiple groups.
    for group in (criteria.get("mandatory_tools_all_of") or []):
        if not any(t in distinct_tools for t in group):
            return current, False, f"missing_group:{','.join(group[:6])}"

    for group_spec in (criteria.get("min_tools_by_group") or []):
        tools = {
            str(tool).strip().lower()
            for tool in list(group_spec.get("tools") or [])
            if str(tool).strip()
        }
        required = int(group_spec.get("count", 0) or 0)
        if not tools or required <= 0:
            continue
        have = len(tools & distinct_tools)
        if have < required:
            name = str(group_spec.get("name") or ",".join(sorted(tools)))
            return current, False, f"missing_min_tools:{name}:need={required}:have={have}"

    if criteria.get("tech_stack_required") and not tech_stack:
        return current, False, "tech_stack_empty"

    if criteria.get("port_or_asset_required") and not (discovered_ports or lista_ativos):
        return current, False, "no_ports_or_assets_yet"

    if criteria.get("recon_evidence_any_of"):
        evidence_signals = bool(tech_stack) or bool(discovered_ports) or bool(lista_ativos) or len(findings) >= 2
        if not evidence_signals:
            return current, False, "no_recon_evidence_yet"

    if criteria.get("vuln_analysis_tool_required"):
        vuln_tools = {
            "nuclei", "nmap-vulscan", "nmap-http-enum", "nmap-smb-vuln",
            "nmap-ssh-audit", "nmap-ssl-vuln", "nmap-dns-vuln",
            "sslscan", "testssl", "wafw00f",
        }
        if not (vuln_tools & distinct_tools):
            return current, False, "no_vuln_analysis_tool_ran_yet"

    sev_req = str(criteria.get("finding_severity_required") or "").lower()
    if sev_req:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(sev_req, 0)
        max_sev = 0
        for f in findings:
            sev = str(f.get("severity") or "").lower()
            details = f.get("details") or {}
            if not isinstance(details, dict):
                continue
            if str(details.get("validation_status") or "").lower() in {"verified"} and order.get(sev, 0) >= threshold:
                max_sev = max(max_sev, order.get(sev, 0))
        if max_sev < threshold:
            return current, False, f"no_verified_finding_at_severity_{sev_req}"

    new_stage = next_kill_chain_stage(current)
    if new_stage == current:
        return current, False, "already_terminal"
    return new_stage, True, "criteria_met"


def render_kill_chain_summary(state: dict) -> dict:
    """Given a workflow state, returns one item per Kill Chain phase with
    completion status. Drives the frontend Kill Chain widget."""
    completed_caps: list[str] = list(state.get("completed_capabilities") or [])
    visited_nodes: list[str] = list(state.get("node_history") or [])
    out: list[dict[str, Any]] = []
    for phase in KILL_CHAIN_PHASES:
        meta = PHASE_META.get(phase, {})
        node = meta.get("node")
        out.append({
            "phase": phase,
            "label": meta.get("label", phase),
            "summary": meta.get("summary", ""),
            "executive_pitch": meta.get("executive_pitch", ""),
            "node": node,
            "completed": bool(node and node in completed_caps),
            "visited": bool(node and node in visited_nodes),
        })
    return {"phases": out, "total": len(KILL_CHAIN_PHASES)}
