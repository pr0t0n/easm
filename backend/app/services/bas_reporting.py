"""BAS Operations Center reporting: framework coverage, exposure, findings,
crown jewels, a MITRE ATT&CK heatmap, and a risk score.

Honesty rule carried through every panel here: nothing computes a fabricated
verdict implying a real posture gap was found or a real vulnerability was
proven when it wasn't. Whether a given BasJob/Finding is real or simulated
depends entirely on which BasAgent ran it (`agent.kind` -- "stub" for
bas_agent_stub, which always fabricates its tunnel's response content;
"real" for a genuine agent, cryptographically proven via a CA-signed mTLS
cert at enroll -- see bas_ca.py -- whose relay and result are real). This
module never assumes one or the other; every row it returns carries its own
`simulated` flag sourced from the underlying Finding/BasJob (see
bas_exclusion.py, bas_scheduler.py).
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import BasAgent, BasJob, BasSchedule, Finding
from app.services.bas_exclusion import BAS_FINDING_TOOL
from app.services.bas_technique_catalog import list_techniques
from app.services.crown_jewel_analyzer import identify_crown_jewels

# Compliance-framework relevance per BAS category. This is a coarse, static,
# code-defined mapping (like the rest of this module's catalogs) -- a full
# control-by-control crosswalk is out of scope; this says "this category of
# internal test is broadly relevant to this framework family", not "this
# finding maps to control X.Y.Z".
_CATEGORY_FRAMEWORK_RELEVANCE: dict[str, set[str]] = {
    "ad": {"nist", "iso27001", "pci", "cis_v8"},
    "ntlm": {"nist", "iso27001", "pci", "cis_v8"},
    "smb": {"nist", "iso27001", "cis_v8"},
    "windows": {"nist", "iso27001", "cis_v8"},
    "linux": {"nist", "iso27001", "cis_v8"},
    "vmware": {"nist", "iso27001", "cis_v8"},
    "firewall": {"nist", "pci", "cis_v8"},
    "cloud": {"nist", "iso27001", "pci", "cis_v8"},
    "network": {"nist", "pci", "cis_v8"},
    "web": {"nist", "iso27001", "pci", "cis_v8"},
    "cicd": {"nist", "iso27001", "cis_v8"},
}
_FRAMEWORK_LABELS = {"nist": "NIST CSF", "iso27001": "ISO 27001", "pci": "PCI DSS 4.0", "cis_v8": "CIS Controls"}


def _real_agent_technique_keys(db: Session, *, group_ids: list[int] | None = None) -> set[str]:
    """Technique keys dispatched at least once through a REAL (non-stub)
    agent. A stub-agent dispatch always fabricates its response content, so
    it's not a genuine "this was tested" signal -- only a real-agent
    dispatch counts as coverage/tested here."""
    query = (
        db.query(BasJob.technique_key)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .filter(BasAgent.kind == "real")
        .distinct()
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    return {row[0] for row in query.all()}


def framework_coverage(db: Session, *, group_ids: list[int] | None = None) -> dict[str, Any]:
    """Per framework: how many of the BAS-catalog techniques relevant to it
    have actually been dispatched at least once through a REAL agent
    (tested_count/total_count). A stub-only dispatch never counts as
    coverage -- see _real_agent_technique_keys."""
    tested_keys = _real_agent_technique_keys(db, group_ids=group_ids)

    result: dict[str, Any] = {}
    for fw, label in _FRAMEWORK_LABELS.items():
        relevant = [t for t in list_techniques() if fw in _CATEGORY_FRAMEWORK_RELEVANCE.get(t["category"], set())]
        tested = [t for t in relevant if t["technique_key"] in tested_keys]
        total = len(relevant)
        result[fw] = {
            "label": label,
            "tested": len(tested),
            "total": total,
            "coverage_pct": round(100 * len(tested) / total, 1) if total else 0,
        }
    return result


def exposure_summary(db: Session, *, group_ids: list[int] | None = None) -> dict[str, Any]:
    """Raw dispatch ACTIVITY (including stub-agent smoke-test traffic) --
    unlike framework_coverage/risk_score, this never claims coverage was
    proven, so blending stub + real dispatches here is fine."""
    query = db.query(BasJob)
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    jobs = query.all()

    # target_hint isn't stored on BasJob itself (it lives on the schedule) --
    # derive distinct targets tested from schedules that actually have jobs.
    sched_query = db.query(BasSchedule.target_hint).distinct()
    if group_ids is not None:
        sched_query = sched_query.filter(BasSchedule.access_group_id.in_(group_ids))
    targets = {row[0] for row in sched_query.all() if row[0]}

    categories_tested = {
        t["category"] for t in list_techniques() if t["technique_key"] in {j.technique_key for j in jobs}
    }
    real_tunnel_roundtrips = sum(1 for j in jobs if j.status == "completed")

    return {
        "distinct_targets_tested": len(targets),
        "categories_tested": sorted(categories_tested),
        "total_dispatches": len(jobs),
        "real_tunnel_roundtrips": real_tunnel_roundtrips,
        "failed_dispatches": sum(1 for j in jobs if j.status == "failed"),
    }


def bas_findings_view(db: Session, *, group_ids: list[int] | None = None, limit: int = 100) -> list[dict[str, Any]]:
    query = db.query(Finding).filter(Finding.tool == BAS_FINDING_TOOL).order_by(Finding.created_at.desc())
    if group_ids is not None:
        query = query.join(BasJob, BasJob.finding_id == Finding.id).filter(BasJob.access_group_id.in_(group_ids))
    rows = query.limit(limit).all()
    return [
        {
            "id": f.id, "title": f.title, "created_at": f.created_at,
            "technique_key": (f.details or {}).get("technique_key"),
            "category": (f.details or {}).get("category"),
            "risk_tier": (f.details or {}).get("risk_tier"),
            # Per-dispatch, not a blanket constant -- see bas_exclusion.py.
            "simulated": bool((f.details or {}).get("simulated", True)),
        }
        for f in rows
    ]


def crown_jewels_view(db: Session, *, group_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """Reuses the platform's real crown-jewel keyword identifier
    (crown_jewel_analyzer.identify_crown_jewels) against BAS schedules'
    target_hints -- the same "does this hostname look high-value" signal
    used for external targets, applied to internal ones."""
    query = db.query(BasSchedule)
    if group_ids is not None:
        query = query.filter(BasSchedule.access_group_id.in_(group_ids))
    schedules = query.all()

    hints = [s.target_hint for s in schedules if s.target_hint]
    jewels = identify_crown_jewels(hints)
    jewel_map = {t: (boost, label) for t, boost, label in jewels}

    job_counts = Counter()
    for row in db.query(BasJob).all():
        sched = next((s for s in schedules if s.id == row.schedule_id), None)
        if sched and sched.target_hint:
            job_counts[sched.target_hint] += 1

    return [
        {"target": target, "label": label, "boost": boost, "jobs_run": job_counts.get(target, 0)}
        for target, (boost, label) in sorted(jewel_map.items(), key=lambda kv: kv[1][0])
    ]


def risk_score(db: Session, *, group_ids: list[int] | None = None) -> dict[str, Any]:
    """0-100: share of REAL-agent dispatches whose relay actually completed
    vs. genuinely failed/blocked at the network or tool level -- exactly the
    "how many techniques worked vs. were blocked" metric requested. Stub
    dispatches are excluded entirely: bas_agent_stub always fabricates its
    response content, so its "completed" status carries no security signal
    at all -- counting it here would make the score meaningless the moment
    any real agent activity mixes in. A high score means most REAL
    dispatches completed their relay; it does not by itself mean a specific
    vulnerability was proven. Jobs still queued/running/skipped are excluded
    from the ratio -- they have no resolved outcome yet."""
    query = db.query(BasJob.status).join(BasAgent, BasAgent.id == BasJob.agent_id).filter(BasAgent.kind == "real")
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    statuses = [row[0] for row in query.all()]
    completed = sum(1 for s in statuses if s == "completed")
    failed = sum(1 for s in statuses if s == "failed")
    resolved = completed + failed
    return {
        "score": round(100 * completed / resolved) if resolved else None,
        "worked": completed,
        "blocked": failed,
        "resolved_total": resolved,
    }


def attack_heatmap(db: Session, *, group_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """One row per cataloged MITRE technique reference: how many times it's
    been dispatched (0 = never tested -- a coverage gap, not a finding).
    Dispatch/completion counts here are raw ACTIVITY (stub + real blended),
    same scope note as exposure_summary -- for a real-agent-only coverage
    claim use framework_coverage instead."""
    query = db.query(BasJob.technique_key, BasJob.status)
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    counts = Counter()
    completed_counts = Counter()
    for technique_key, status in query.all():
        counts[technique_key] += 1
        if status == "completed":
            completed_counts[technique_key] += 1

    rows = []
    for t in list_techniques():
        for mitre_id in t["mitre_refs"]:
            rows.append({
                "mitre_id": mitre_id,
                "technique_key": t["technique_key"],
                "display_name": t["display_name"],
                "category": t["category"],
                "availability": t["availability"],
                "times_tested": counts.get(t["technique_key"], 0),
                "times_completed": completed_counts.get(t["technique_key"], 0),
            })
    return sorted(rows, key=lambda r: (-r["times_tested"], r["mitre_id"]))


def executive_report(db: Session, *, group_ids: list[int] | None = None) -> dict[str, Any]:
    """Assembles the "Relatório BAS" document payload from the panels above --
    no new computation beyond a short narrative summary string built from
    those same real numbers. Every figure here is either a coverage/activity
    metric or the worked-vs-blocked risk_score ratio -- same honesty rule as
    the rest of this module (see module docstring)."""
    coverage = framework_coverage(db, group_ids=group_ids)
    exposure = exposure_summary(db, group_ids=group_ids)
    score = risk_score(db, group_ids=group_ids)
    jewels = crown_jewels_view(db, group_ids=group_ids)
    heatmap = attack_heatmap(db, group_ids=group_ids)
    findings = bas_findings_view(db, group_ids=group_ids, limit=50)

    total_techniques = len(list_techniques())
    tested_techniques = sum(1 for row in heatmap if row["times_tested"] > 0)
    jewels_touched = sum(1 for j in jewels if j["jobs_run"] > 0)

    if score["resolved_total"] == 0:
        narrative = (
            f"Nenhum job BAS foi resolvido ainda neste escopo. "
            f"{tested_techniques}/{total_techniques} técnicas catalogadas já foram disparadas ao menos uma vez."
        )
    else:
        narrative = (
            f"Neste escopo, {tested_techniques}/{total_techniques} técnicas catalogadas foram disparadas, "
            f"cobrindo {len(exposure['categories_tested'])} categoria(s) em {exposure['distinct_targets_tested']} alvo(s) interno(s). "
            f"Dos {score['resolved_total']} disparo(s) com resultado resolvido, {score['worked']} completaram o round-trip real do "
            f"túnel ({score['score']}/100) e {score['blocked']} falharam/foram bloqueados. "
            f"{jewels_touched}/{len(jewels)} alvo(s) de alto valor já foram testados ao menos uma vez."
        )

    return {
        "narrative": narrative,
        "total_techniques": total_techniques,
        "tested_techniques": tested_techniques,
        "risk_score": score,
        "framework_coverage": coverage,
        "exposure": exposure,
        "crown_jewels": jewels,
        "attack_heatmap": heatmap,
        "findings": findings,
    }
