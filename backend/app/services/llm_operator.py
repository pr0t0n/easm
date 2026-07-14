"""llm_operator.py — L3: LLM as a real offensive operator.

Periodically during a scan, queries Ollama (or OpenAI-compatible API) with:
  - All confirmed/candidate findings so far
  - Detected technology stack
  - Scan targets and phases completed

Asks the LLM to propose 3-5 novel attack chains, then converts its response into
prioritized ScanWorkItems for Kali to execute.

This implements "adaptive strategy" — the scan plan evolves based on what was found.

Config:
  settings.ollama_url     — Ollama server URL (default: http://ollama:11434)
  settings.llm_model      — Model to use (default: llama3.2:3b)
  settings.llm_operator_enabled — Feature flag (default: False)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests

from app.core.config import settings
from app.services.untrusted_content import normalize_adversarial_text, wrap_untrusted

logger = logging.getLogger(__name__)

OLLAMA_DEFAULT_URL = "http://ollama:11434"
DEFAULT_MODEL = "llama3.2:3b"

# Blast-radius limiter: this call creates new ScanWorkItems from an LLM
# response built from attacker-influenced findings/tech-stack text (see
# untrusted_content.py quarantine on the prompt side). The 15-minute rate
# limit below bounds frequency, not total spend over a long scan — cap the
# cumulative total too, so a compromised/hallucinating response can't drive
# unbounded tool execution across the scan's lifetime.
MAX_LLM_OPERATOR_CALLS_PER_SCAN = 10
MAX_LLM_OPERATOR_ITEMS_PER_SCAN = 30

OPERATOR_SYSTEM_PROMPT = """You are an expert penetration tester analyzing an attack surface.
Your role is to identify novel attack chains based on evidence from automated scanning tools.

Rules:
- Only suggest attacks that are DIRECTLY supported by the evidence provided
- Prioritize critical business-impact paths (auth bypass, RCE, data exfiltration)
- Be specific: name the exact tool to run and the target
- Format your response as a JSON array of attack chain objects
- Each object: {"tool": "tool_name", "target": "target_host", "phase": "P09", "rationale": "why", "priority": 1-10}

Available tools: nuclei, sqlmap, dalfox, wpscan, hydra, nikto, ffuf, gobuster, arjun,
nuclei-sqli, nuclei-xss, nuclei-ssrf, nuclei-rce, nuclei-lfi, nuclei-ssti, nuclei-cors,
nuclei-jwt, nuclei-graphql, nuclei-default-credentials, nuclei-exposure

Respond ONLY with valid JSON array. No markdown, no explanation outside the JSON."""


def _build_operator_prompt(
    targets: list[str],
    findings: list[dict],
    tech_stack: list[dict],
    phases_done: list[str],
) -> str:
    """Build the prompt for the LLM operator.

    `title`/`domain`/`tech`/`version` are attacker-controlled (echoed from
    HTTP responses/banners) and this prompt's output directly creates new
    ScanWorkItems for Kali to execute — the highest-risk LLM call in the
    platform for indirect prompt injection. Normalize before interpolating,
    and wrap the target-derived blocks so the model can tell data from
    instruction.
    """
    findings_summary = []
    for f in findings[:20]:  # cap at 20 to avoid token overflow
        findings_summary.append({
            "title": normalize_adversarial_text(str(f.get("title") or "")),
            "severity": f.get("severity"),
            "tool": f.get("tool"),
            "domain": normalize_adversarial_text(str(f.get("domain") or "")),
            "verification_status": f.get("verification_status", "candidate"),
        })

    tech_summary = [
        {
            "target": t.get("target"),
            "tech": normalize_adversarial_text(str(t.get("tech") or "")),
            "version": normalize_adversarial_text(str(t.get("version") or "")),
        }
        for t in tech_stack[:10]
    ]

    tech_block = wrap_untrusted(json.dumps(tech_summary, indent=2), label="tech_stack_do_alvo")
    findings_block = wrap_untrusted(json.dumps(findings_summary, indent=2), label="findings_do_alvo")

    prompt = f"""Analyze this attack surface and propose 3-5 novel attack chains:

TARGETS: {json.dumps(targets[:10])}

COMPLETED PHASES: {json.dumps(phases_done)}

TECHNOLOGY STACK DETECTED:
{tech_block}

FINDINGS SO FAR ({len(findings)} total, showing top {len(findings_summary)}):
{findings_block}

Based on this evidence, what are the most promising attack chains to pursue?
Focus on gaps — what critical checks haven't been run yet given the tech stack?
Return JSON array only."""

    return prompt


def query_llm(prompt: str, model: str | None = None) -> str:
    """Send prompt to Ollama and return raw response text."""
    ollama_url = str(getattr(settings, "ollama_base_url", "") or OLLAMA_DEFAULT_URL)
    model_name = (
        model
        or str(getattr(settings, "llm_primary_model", "") or "")
        or str(getattr(settings, "ollama_qwen_model", "") or "")
        or str(getattr(settings, "ollama_model", "") or "")
        or DEFAULT_MODEL
    )

    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model_name,
                "prompt": prompt,
                "system": OPERATOR_SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.2,  # lower temperature = more focused/deterministic
                    "top_p": 0.9,
                    "num_predict": 1024,
                },
            },
            timeout=120,  # LLM generation can take a while
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data.get("response") or "")
    except Exception as e:
        logger.debug("LLM query failed: %s", e)
        return ""


def parse_attack_chains(llm_response: str) -> list[dict[str, Any]]:
    """Parse LLM JSON response into attack chain dicts.

    Handles both clean JSON and JSON embedded in markdown code blocks.
    """
    if not llm_response.strip():
        return []

    # Try to extract JSON array from response
    text = llm_response.strip()

    # Strip markdown code blocks
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"```", "", text)
    text = text.strip()

    # Find JSON array
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        chains = json.loads(text)
        if not isinstance(chains, list):
            return []

        # Validate and sanitize each chain
        valid = []
        valid_tools = {
            "nuclei", "sqlmap", "dalfox", "wpscan", "hydra", "nikto", "ffuf",
            "gobuster", "arjun", "nuclei-sqli", "nuclei-xss", "nuclei-ssrf",
            "nuclei-rce", "nuclei-lfi", "nuclei-ssti", "nuclei-cors", "nuclei-jwt",
            "nuclei-graphql", "nuclei-default-credentials", "nuclei-exposure",
            "nuclei-cves", "feroxbuster", "dirsearch", "wfuzz", "katana",
        }
        valid_phases = {f"P{i:02d}" for i in range(1, 23)}

        for chain in chains:
            if not isinstance(chain, dict):
                continue
            tool = str(chain.get("tool") or "").strip().lower()
            target = str(chain.get("target") or "").strip()
            phase = str(chain.get("phase") or "P09").strip().upper()
            rationale = str(chain.get("rationale") or "")[:500]
            priority = int(chain.get("priority") or 5)

            # Validate
            if tool not in valid_tools:
                continue
            if not target or len(target) > 500:
                continue
            if phase not in valid_phases:
                phase = "P09"

            valid.append({
                "tool": tool,
                "target": target,
                "phase": phase,
                "rationale": rationale,
                "priority": max(1, min(10, priority)),
            })

        return valid[:5]  # max 5 chains per LLM response

    except (json.JSONDecodeError, ValueError) as e:
        logger.debug("Failed to parse LLM attack chains: %s | Response: %s...", e, llm_response[:200])
        return []


def seed_attack_chain_items(
    db,
    job,
    chains: list[dict[str, Any]],
) -> int:
    """Create ScanWorkItems from LLM-proposed attack chains.

    Returns count of items created.
    """
    from app.models.models import ScanWorkItem, ScanLog
    from app.services.scan_work_queue import apply_phase_tool_metadata, resource_class_for_tool
    from datetime import datetime

    created = 0

    for chain in chains:
        tool = chain["tool"]
        target = chain["target"]
        phase = chain["phase"]
        priority = chain["priority"]

        # Dedup: skip if similar item already exists
        existing = db.query(ScanWorkItem.id).filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id == phase,
            ScanWorkItem.tool_name == tool[:120],
            ScanWorkItem.target == target[:500],
            ScanWorkItem.status.notin_(["completed", "done", "failed", "skipped"]),
        ).first()
        if existing:
            continue

        rc = resource_class_for_tool(tool)
        item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id=phase,
            target=target[:500],
            tool_name=tool[:120],
            profile="",
            resource_class=rc,
            priority=int(50 - (priority * 3)),  # priority 10 → work queue priority 20
            status="queued",
            max_attempts=1,
            item_metadata=apply_phase_tool_metadata({
                "source": "llm_operator",
                "rationale": chain.get("rationale", "")[:300],
                "llm_proposed": True,
            }, phase, tool[:120], source="llm_operator"),
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        db.add(item)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()

    if created:
        db.add(ScanLog(
            scan_job_id=job.id,
            source="llm-operator",
            level="INFO",
            message=f"llm_operator_seeded scan={job.id} chains_proposed={len(chains)} items_created={created}",
        ))
        db.commit()

    return created


def run_llm_operator(db, job) -> dict[str, Any]:
    """Main entry point — query LLM with current scan state and seed new work items.

    Called periodically during a scan (e.g., after P09 completes) and at the
    end of aggressive phases.
    """
    if not getattr(settings, "llm_operator_enabled", False):
        return {"skipped": "feature_disabled"}

    state = dict(job.state_data or {})

    call_count = int(state.get("llm_operator_call_count") or 0)
    items_total = int(state.get("llm_operator_items_total") or 0)
    if call_count >= MAX_LLM_OPERATOR_CALLS_PER_SCAN:
        return {"skipped": "call_budget_exhausted", "call_count": call_count}
    if items_total >= MAX_LLM_OPERATOR_ITEMS_PER_SCAN:
        return {"skipped": "item_budget_exhausted", "items_total": items_total}

    # Rate limit: don't run more than once per 15 minutes per scan
    import time
    last_run = state.get("llm_operator_last_run", 0)
    now = time.time()
    if now - float(last_run or 0) < 900:
        return {"skipped": "rate_limited", "seconds_until_next": int(900 - (now - float(last_run)))}

    # Gather context
    from app.models.models import Finding, ScanWorkItem

    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id)
        .order_by(Finding.risk_score.desc())
        .limit(30)
        .all()
    )
    findings_dicts = [
        {
            "title": f.title,
            "severity": f.severity,
            "tool": f.tool,
            "domain": f.domain,
            "verification_status": f.verification_status,
            "cve": f.cve,
        }
        for f in findings
    ]

    tech_stack = list(state.get("tech_stack") or job.tech_stack or [])

    # Collect completed phases
    done_phases = list({
        str(item.phase_id)
        for item in db.query(ScanWorkItem.phase_id)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.status.in_(["completed", "done"]),
        )
        .all()
    })

    # Collect unique targets
    target_rows = (
        db.query(ScanWorkItem.target)
        .filter(ScanWorkItem.scan_job_id == job.id, ScanWorkItem.target != "__batch__")
        .distinct()
        .limit(20)
        .all()
    )
    targets = [str(r[0]) for r in target_rows if r[0]]

    if not findings_dicts and not tech_stack:
        return {"skipped": "no_context"}

    # Query LLM
    prompt = _build_operator_prompt(targets, findings_dicts, tech_stack, done_phases)
    llm_response = query_llm(prompt)

    if not llm_response:
        return {"skipped": "llm_unavailable"}

    # Parse and seed
    chains = parse_attack_chains(llm_response)
    items_created = seed_attack_chain_items(db, job, chains)

    # Update rate limit timestamp + cumulative budget counters
    state["llm_operator_last_run"] = now
    state["llm_operator_last_chains"] = chains
    state["llm_operator_call_count"] = call_count + 1
    state["llm_operator_items_total"] = items_total + items_created
    job.state_data = state
    db.commit()

    logger.info(
        "llm_operator scan=%d chains_parsed=%d items_created=%d",
        job.id, len(chains), items_created,
    )

    return {
        "chains_proposed": len(chains),
        "items_created": items_created,
        "chains": chains,
    }
