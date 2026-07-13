"""Benchmark scoring for completed or in-progress scan jobs."""
from __future__ import annotations

from typing import Any

from app.services.benchmark_registry import list_benchmark_targets


HIGH_SEVERITIES = {"high", "critical"}
LOCAL_TARGET_MARKERS = ("localhost", "127.0.0.1", "host.docker.internal", ".local")


def _phase_entries(scan_job: Any) -> list[dict[str, Any]]:
    state = dict(getattr(scan_job, "state_data", None) or {})
    raw = state.get("phase_ledger_v2") or state.get("phase_ledger") or []
    if isinstance(raw, dict):
        return [dict(value or {}, phase_id=str(key)) for key, value in raw.items()]
    if isinstance(raw, list):
        return [dict(item or {}) for item in raw if isinstance(item, dict)]
    return []


def _is_local_or_simulated_target(scan_job: Any) -> bool:
    target = str(getattr(scan_job, "target_query", "") or "").strip().lower()
    if not target:
        return False
    if any(marker in target for marker in LOCAL_TARGET_MARKERS):
        return True
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return "." not in host


def _finding_has_proof_pack(finding: Any) -> bool:
    details = getattr(finding, "details", None) or {}
    if not isinstance(details, dict):
        details = {}
    return bool(
        details.get("proof_pack")
        or details.get("evidence_contract")
        or details.get("baseline_request") and details.get("exploit_request")
        or getattr(finding, "evidence", None)
    )


def evaluate_benchmark_scan(
    scan_job: Any,
    *,
    benchmark_id: str = "vuln-bank",
    findings: list[Any] | None = None,
) -> dict[str, Any]:
    benchmarks = {item["id"]: item for item in list_benchmark_targets()}
    benchmark = benchmarks.get(benchmark_id)
    if not benchmark:
        return {
            "benchmark_id": benchmark_id,
            "status": "unknown_benchmark",
            "score": 0,
            "gates": [{"id": "benchmark_exists", "passed": False, "detail": "Benchmark not found"}],
        }

    state = dict(getattr(scan_job, "state_data", None) or {})
    entries = _phase_entries(scan_job)
    completed_entries = [
        item for item in entries
        if str(item.get("status") or "").lower() in {"completed", "partial"}
    ]
    tools_success = {
        str(tool)
        for item in entries
        for tool in (item.get("tools_success") or item.get("tools_succeeded") or [])
    }
    findings = list(findings or [])
    high_findings = [
        finding for finding in findings
        if str(getattr(finding, "severity", "") or "").lower() in HIGH_SEVERITIES
    ]
    high_with_proof = [finding for finding in high_findings if _finding_has_proof_pack(finding)]

    local_required = benchmark["safe_execution"] in {"local_container_only", "simulated_network_only"}
    safe_scope = (not local_required) or _is_local_or_simulated_target(scan_job)
    phase_ratio = min(1.0, len(completed_entries) / 22)
    proof_ratio = 1.0 if not high_findings else len(high_with_proof) / max(1, len(high_findings))
    tool_ratio = min(1.0, len(tools_success) / 6)
    boundary_score = 1.0 if state.get("untrusted_content_wrapped") or state.get("agent_validation") else 0.5

    gates = [
        {
            "id": "safe_scope",
            "passed": safe_scope,
            "detail": "Benchmark target is local/simulated" if safe_scope else "Benchmark requires local/simulated scope",
        },
        {
            "id": "phase_coverage",
            "passed": phase_ratio >= 0.35,
            "detail": f"{len(completed_entries)} phase ledger entries completed or partial",
        },
        {
            "id": "tool_evidence",
            "passed": bool(tools_success),
            "detail": f"{len(tools_success)} successful tools in phase ledger",
        },
        {
            "id": "proof_pack",
            "passed": proof_ratio >= 1.0,
            "detail": f"{len(high_with_proof)}/{len(high_findings)} high/critical findings have proof packs",
        },
        {
            "id": "agent_boundary",
            "passed": boundary_score >= 1.0,
            "detail": "Agent validation or untrusted-content boundary marker present",
        },
    ]
    score = round(
        (
            (1.0 if safe_scope else 0.0) * 20
            + phase_ratio * 25
            + tool_ratio * 20
            + proof_ratio * 25
            + boundary_score * 10
        ),
        2,
    )
    return {
        "benchmark_id": benchmark_id,
        "benchmark_name": benchmark["name"],
        "status": "passed" if all(gate["passed"] for gate in gates) else "needs_attention",
        "score": score,
        "dimensions": {
            "safe_scope": 100 if safe_scope else 0,
            "phase_coverage": round(phase_ratio * 100, 2),
            "tool_evidence": round(tool_ratio * 100, 2),
            "proof_pack": round(proof_ratio * 100, 2),
            "agent_boundary": round(boundary_score * 100, 2),
        },
        "gates": gates,
        "recommended_next_step": _recommended_next_step(gates),
    }


def _recommended_next_step(gates: list[dict[str, Any]]) -> str:
    for gate in gates:
        if not gate.get("passed"):
            if gate["id"] == "safe_scope":
                return "Run this benchmark only against a local container or simulated network target."
            if gate["id"] == "phase_coverage":
                return "Broaden benchmark execution until more Kill Chain phases produce ledger entries."
            if gate["id"] == "tool_evidence":
                return "Ensure benchmark profiles persist successful tool runs in the phase ledger."
            if gate["id"] == "proof_pack":
                return "Keep high/critical findings capped until proof packs are attached."
            if gate["id"] == "agent_boundary":
                return "Persist agent validation or untrusted-content boundary markers for AI/RAG/MCP benchmarks."
    return "Benchmark gates passed; compare score against previous releases."
