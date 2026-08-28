from __future__ import annotations

from typing import Any


def _text(value: Any, limit: int = 1200) -> str:
    return str(value or "").strip()[:limit]


def _status(result: dict[str, Any], job_status: str | None) -> str:
    return _text(result.get("status") or job_status, 80).lower()


def _raw_evidence(result: dict[str, Any], key_findings: list[str]) -> str:
    if key_findings:
        return "\n".join(str(item) for item in key_findings[:20])
    for key in ("stdout", "stdout_full", "stdout_preview", "stderr"):
        value = _text(result.get(key), 4000)
        if value:
            return value
    return ""


def _control_observed(technique: dict[str, Any], result: dict[str, Any], key_findings: list[str], severity: str) -> bool:
    if severity and severity != "info":
        return True
    if result.get("open_ports"):
        return True
    if key_findings and any(str(item).startswith("Nmap concluiu sem portas abertas") for item in key_findings):
        return True
    if key_findings and technique.get("category") in {"cloud", "cloud_identity", "saas", "identity"}:
        return True
    observation = result.get("egress_observation") or result.get("egress_context") or {}
    return bool(observation)


def build_bas_proof(
    *,
    technique: dict[str, Any],
    job: Any,
    agent: Any,
    result: dict[str, Any],
    key_findings: list[str],
    severity: str,
) -> dict[str, Any]:
    agent_kind = _text(getattr(agent, "kind", ""), 40)
    command = _text(result.get("command"), 2000)
    target = _text(getattr(job, "target", "") or result.get("target"), 500)
    evidence = _raw_evidence(result, key_findings)
    job_status = _text(getattr(job, "status", ""), 80)
    execution_status = _status(result, job_status)
    executed = execution_status in {"executed", "done", "completed"} or job_status == "completed"
    requirements = {
        "command_executed": bool(command and executed),
        "target_bound": bool(target),
        "parsed_evidence": bool(key_findings),
        "objective_evidence": bool(evidence),
        "impact_or_control_observed": _control_observed(technique, result, key_findings, severity),
        "replay_available": bool(command and target and technique.get("technique_key") and getattr(agent, "id", None)),
    }
    valid = agent_kind == "real" and all(requirements.values())
    if agent_kind != "real":
        status = "simulated"
    elif job_status == "failed" or execution_status == "failed":
        status = "failed"
    elif valid:
        status = "validated"
    else:
        status = "insufficient_evidence"
    return {
        "valid": valid,
        "status": status,
        "requirements": requirements,
        "technique_key": technique.get("technique_key"),
        "target": target,
        "command": command,
        "evidence": evidence[:4000],
        "impact": severity if severity != "info" else "",
        "control_observed": requirements["impact_or_control_observed"],
        "replay": {
            "agent_id": getattr(agent, "id", None),
            "schedule_id": getattr(job, "schedule_id", None),
            "job_id": getattr(job, "id", None),
            "scan_job_id": getattr(job, "scan_job_id", None),
            "technique_key": technique.get("technique_key"),
            "target": target,
            "command": command,
        },
    }
