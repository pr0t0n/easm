from __future__ import annotations

from typing import Any

from app.graph.mission import build_autonomous_mission_contract


# xalgorix-inspired cognitive framework + strix-inspired scope contract
CYBER_AUTOAGENT_PROMPT_PRINCIPLES = {
    "mission_stance": [
        "GOAL-FIRST: every action must directly advance the pentest objective.",
        "EVIDENCE-FIRST: without reproducible proof, treat as hypothesis only.",
        "SCOPE-BOUND: never test assets outside authorized_targets; skip and log.",
        "MINIMAL-ACTION: smallest action that maximizes intelligence gained.",
        "WAF-AWARE: detect WAF signatures in tool output and adapt evasion strategy.",
        "CIRCUIT-BREAK: after 5 consecutive tool failures, pause 60s and pivot.",
    ],
    "cognitive_loop": {
        "KNOW": "Confirmed facts, scope constraints, and observed signals.",
        "THINK": "Hypothesis with numeric confidence 0..100 and candidate paths.",
        "TEST": "Smallest concrete action to validate the top hypothesis.",
        "VALIDATE": "Expected vs. observed; attach artifact if finding promoted.",
        "ADAPT": "Update confidence and strategy based on new evidence.",
    },
    "confidence_driven_execution": {
        "high_confidence": ">=80 → technical validation and impact confirmation",
        "medium_confidence": "50..79 → hypothesis testing and signal correlation",
        "low_confidence": "<50 → context gathering, recon pivot, OSINT expansion",
    },
    "evidence_policy": {
        "critical_high_requires_proof_pack": True,
        "proof_pack_fields": [
            "validation_status",   # "verified" | "hypothesis" | "unverified"
            "repro_steps",         # step-by-step reproduction
            "technical_evidence",  # raw tool output, screenshot reference, or payload
            "artifacts",           # supporting data (HTTP response, CVE ID, port/URL)
            "rationale",           # why this finding matters (business impact)
        ],
        "default_without_proof": "hypothesis",
    },
    # xalgorix-inspired: minimum phases before allowing FINISH
    "finish_gate": {
        "required_nodes_before_finish": [
            "strategic_planning",
            "asset_discovery",
            "threat_intel",
            "risk_assessment",
            "evidence_adjudication",
        ],
        "require_executive_summary": True,
        "premature_finish_action": "continue_with_highest_priority_node",
    },
    "checkpoints": [20, 40, 60, 80],
    "termination_policy": (
        "Terminate only when: (a) all required phases complete + executive_summary generated, "
        "OR (b) iteration budget exhausted, OR (c) objective_met=True with evidence."
    ),
}


CYBER_AUTOAGENT_RUBRIC = {
    "dimensions": ["methodology", "tooling", "evidence", "outcome"],
    "weights": {
        "methodology": 0.30,
        "tooling": 0.20,
        "evidence": 0.30,
        "outcome": 0.20,
    },
}

# Strix-inspired system prompt template (runtime-parameterized)
SUPERVISOR_SYSTEM_PROMPT_TEMPLATE = """
You are a Senior Penetration Tester operating as an autonomous EASM agent.

## MISSION
Target: {target}
Objective: {objective}
Authorized Scope: {authorized_targets}
Max Iterations: {max_iterations}

## COGNITIVE FRAMEWORK
For each action, follow KNOW → THINK → TEST → VALIDATE → ADAPT:
- KNOW: List confirmed facts about the target surface.
- THINK: State your top hypothesis with confidence (0-100).
- TEST: Run the smallest tool/check that validates the hypothesis.
- VALIDATE: Compare expected vs. actual result; extract evidence.
- ADAPT: Update confidence; pivot if stagnated (same findings × 3 iterations).

## SCOPE ENFORCEMENT
Only test assets within: {authorized_targets}
Out-of-scope actions MUST be skipped and logged.

## EVIDENCE STANDARDS
- CRITICAL/HIGH findings require a proof pack: repro_steps + technical_evidence + artifact.
- Without proof pack, severity stays "hypothesis" and goes to validation_backlog.
- MEDIUM/LOW: evidence encouraged, unverified acceptable.

## ACTIVE SKILLS (prioritized for this target)
{skills_summary}

## TOOL CATALOG (only INSTALLED tools you may invoke)
{tool_catalog}

When choosing a tool:
- Match by purpose (description, when_to_use), never invent tool names.
- Verify prerequisites are satisfied before invoking; otherwise skip and log.
- Wire INPUTS from prior phase outputs (recon → vuln → exploit pipeline).
- A tool not listed here is NOT installed — do not call it.

## COVERAGE POLICY (MANDATORY — non-negotiable)
The 22-phase pipeline MUST be exercised end-to-end. Each capability node owns
specific phases and MUST attempt every applicable installed tool exactly once
per scan, not just one tool per iteration. Skipping a phase requires a logged
reason (e.g. "out of scope", "prerequisite missing"). Specifically:

- asset_discovery owns P01-P06: subdomain enum (subfinder/amass/dnsx/massdns/
  shuffledns/assetfinder/alterx), port/service (naabu/nmap/httpx),
  crawl+JS (katana/hakrawler/gau/waybackurls/gospider),
  param discovery (arjun/paramspider/ffuf), HTTP/TLS fingerprint
  (whatweb/sslscan/wafw00f/curl-headers).
- threat_intel owns P07-P10 + P21: OSINT (shodan-cli/theHarvester/h8mail/
  metagoofil), email posture (theHarvester), takeover (subjack/nuclei),
  cloud exposure (nuclei/shodan-cli/trufflehog), secrets (trufflehog/gitleaks).
- risk_assessment owns P11-P20 + P22: CVE scan (nuclei/nmap-vulscan),
  injection (sqlmap/dalfox/wapiti/burp-cli/nikto), SSRF (nuclei/interactsh-client),
  auth bypass (hydra/jwt_tool), dir enum (ffuf/gobuster/feroxbuster/dirsearch),
  API (nuclei/burp-cli/arjun/wapiti), TLS (sslscan/testssl), CMS (wpscan),
  deps (retire/trivy/eslint/semgrep).
- governance + executive_analyst do NOT run tools — they aggregate evidence.

After your first full sweep, the `phase_monitor` summary is checked: any phase
flagged "node_completed_no_phase_tools" or "attempted_failed" with installed
tools available MUST be retried.

## CIRCUIT BREAKER
- 5 consecutive tool failures → log and pause 60s.
- 3 iterations with no new findings → pivot strategy (change tools/approach).
- Budget approaching limit (≤2 iterations remaining) → force governance + executive_analyst.

## TERMINATION POLICY
{termination_policy}
"""


def build_supervisor_prompt_contract(
    target: str,
    objective: str,
    max_iterations: int,
    active_skills: list[dict[str, Any]] | None = None,
    authorized_targets: list[str] | None = None,
) -> dict[str, Any]:
    skills = list(active_skills or [])
    scope = list(authorized_targets or ([target] if target else []))
    skills_summary = "\n".join(
        f"  - [{skill.get('category', '')}] {skill.get('id', '')}: "
        f"{skill.get('description', '')} | tools: {', '.join(skill.get('playbook', [])[:5])}"
        for skill in skills
    )

    # Inject the live tool catalog so the agent sees only INSTALLED tools.
    try:
        from app.services.tool_catalog import render_tool_catalog_for_prompt

        tool_catalog = render_tool_catalog_for_prompt(only_installed=True)
    except Exception:
        tool_catalog = "(tool catalog unavailable)"

    prompt = SUPERVISOR_SYSTEM_PROMPT_TEMPLATE.format(
        target=str(target or ""),
        objective=str(objective or f"Assess external attack surface for {target}"),
        authorized_targets=", ".join(scope) if scope else str(target),
        max_iterations=int(max_iterations),
        skills_summary=skills_summary or "  (no skills loaded yet — will be selected post-discovery)",
        tool_catalog=tool_catalog,
        termination_policy=CYBER_AUTOAGENT_PROMPT_PRINCIPLES["termination_policy"],
    )
    return {
        "persona": "Senior Penetration Tester / Autonomous EASM Agent",
        "target": str(target or ""),
        "objective": str(objective or f"Assess external attack surface for {target}"),
        "authorized_targets": scope,
        "max_iterations": int(max_iterations),
        "principles": CYBER_AUTOAGENT_PROMPT_PRINCIPLES,
        "cognitive_loop": CYBER_AUTOAGENT_PROMPT_PRINCIPLES["cognitive_loop"],
        "expected_loop": ["know", "think", "test", "validate", "adapt"],
        "autonomy_contract": build_autonomous_mission_contract(max_iterations=max_iterations),
        "system_prompt": prompt.strip(),
        "active_skills": skills,
        "skills_summary": [
            {
                "id": str(skill.get("id") or ""),
                "category": str(skill.get("category") or ""),
                "description": str(skill.get("description") or ""),
                "playbook": list(skill.get("playbook") or []),
                "phases": list(skill.get("phases") or []),
            }
            for skill in skills
        ],
    }


def evaluate_execution_quality(final_state: dict[str, Any]) -> dict[str, Any]:
    findings = list(final_state.get("vulnerabilidades_encontradas") or [])
    logs = list(final_state.get("logs_terminais") or [])
    metrics = dict(final_state.get("mission_metrics") or {})

    tools_attempted = int(metrics.get("tools_attempted", 0) or 0)
    tools_success = int(metrics.get("tools_success", 0) or 0)
    success_ratio = (tools_success / tools_attempted) if tools_attempted > 0 else 0.0

    verified = 0
    critical_high = 0
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        details = dict(finding.get("details") or {})
        if sev in {"critical", "high"}:
            critical_high += 1
        if str(details.get("validation_status") or "").lower() == "verified":
            verified += 1

    completed = list(final_state.get("completed_capabilities") or [])
    required_nodes = CYBER_AUTOAGENT_PROMPT_PRINCIPLES["finish_gate"]["required_nodes_before_finish"]
    phases_done_ratio = len([n for n in required_nodes if n in completed]) / max(1, len(required_nodes))
    has_adjudication = "evidence_adjudication" in completed
    has_governance = "governance" in completed
    methodology_score = min(1.0, phases_done_ratio * 0.6 + (0.2 if has_adjudication else 0) + (0.2 if has_governance else 0))

    tooling_score = min(1.0, success_ratio + 0.1)
    evidence_score = (
        (verified / max(1, critical_high)) if critical_high > 0
        else (1.0 if findings else 0.5)
    )

    objective_met = bool(final_state.get("objective_met"))
    termination_reason = str(final_state.get("termination_reason") or "")
    outcome_score = (
        1.0 if objective_met
        else (0.75 if termination_reason in {"max_iterations_reached", "forced_finalize_guardrail"} else 0.5)
    )

    weights = CYBER_AUTOAGENT_RUBRIC["weights"]
    overall = (
        methodology_score * float(weights["methodology"])
        + tooling_score * float(weights["tooling"])
        + evidence_score * float(weights["evidence"])
        + outcome_score * float(weights["outcome"])
    )

    risk_flags: list[str] = []
    if success_ratio < 0.4:
        risk_flags.append("low_tool_success_ratio")
    if critical_high > 0 and verified == 0:
        risk_flags.append("critical_high_without_verified_evidence")
    if not objective_met and not termination_reason:
        risk_flags.append("termination_without_explicit_reason")
    if phases_done_ratio < 0.6:
        risk_flags.append("incomplete_phase_coverage")

    return {
        "rubric": CYBER_AUTOAGENT_RUBRIC,
        "scores": {
            "methodology": round(methodology_score * 100, 2),
            "tooling": round(tooling_score * 100, 2),
            "evidence": round(evidence_score * 100, 2),
            "outcome": round(outcome_score * 100, 2),
            "overall": round(overall * 100, 2),
        },
        "summary": {
            "findings_total": len(findings),
            "critical_high_total": critical_high,
            "verified_total": verified,
            "tools_attempted": tools_attempted,
            "tools_success": tools_success,
            "objective_met": objective_met,
            "termination_reason": termination_reason,
            "phases_completed": completed,
            "phases_done_ratio": round(phases_done_ratio, 2),
        },
        "risk_flags": risk_flags,
    }
