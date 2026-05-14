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
        "tech-http-fingerprint",
        "tech-owasp-header-analysis",
        "tech-cms-fingerprint",
        "osint-exposure-intel",
        "osint-email-infra",
        "osint-subdomain-takeover",
        "osint-cloud-exposure",
    },
    "VULNERABILITY_ANALYSIS": {
        "vuln-nuclei-cve",
        "vuln-ssl-tls",
        "vuln-information-disclosure",
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
        # Need at least 4 distinct recon tools so that the stage actually
        # produces a useful inventory before moving on (httpx/whatweb/curl-
        # headers/nikto, or katana/gau/wayback, or nmap/naabu).
        "tool_runs": 4,
        # ANY of these counts as "I learned something about the target".
        # tech_stack proves fingerprinting succeeded; ports/assets prove
        # surface mapping found something; findings >=2 means we already
        # have enough recon signal to graduate.
        "recon_evidence_any_of": True,
    },
    "VULNERABILITY_ANALYSIS": {
        # Need at least 2 vuln-analysis tool runs so we get coverage from
        # both template-driven (nuclei) AND protocol/TLS audit (sslscan/
        # testssl/wafw00f) before opening exploitation.
        "tool_runs": 2,
        "vuln_analysis_tool_required": True,
    },
    "EXPLOITATION": {
        # At least one exploitation attempt before we'd consider going to
        # actions-on-objectives. No severity gate — give the supervisor
        # freedom to pivot once exploitation has been attempted.
        "tool_runs": 1,
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

    if criteria.get("tech_stack_required") and not tech_stack:
        return current, False, "tech_stack_empty"

    if criteria.get("port_or_asset_required") and not (discovered_ports or lista_ativos):
        return current, False, "no_ports_or_assets_yet"

    if criteria.get("recon_evidence_any_of"):
        evidence_signals = bool(tech_stack) or bool(discovered_ports) or bool(lista_ativos) or len(findings) >= 2
        if not evidence_signals:
            return current, False, "no_recon_evidence_yet"

    if criteria.get("vuln_analysis_tool_required"):
        vuln_tools = {"nuclei", "nmap-vulscan", "sslscan", "testssl", "wafw00f"}
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
