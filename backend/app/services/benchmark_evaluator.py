"""Ground-truth benchmark evaluation for local/simulated security labs."""
from __future__ import annotations

from typing import Any

from app.services.benchmark_registry import list_benchmark_targets
from app.services.vuln_family import classify_family


LOCAL_TARGET_MARKERS = ("localhost", "127.0.0.1", "host.docker.internal", ".local")


def _is_local_or_simulated_target(scan_job: Any) -> bool:
    target = str(getattr(scan_job, "target_query", "") or "").strip().lower()
    if not target:
        return False
    if any(marker in target for marker in LOCAL_TARGET_MARKERS):
        return True
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return "." not in host


def _details(finding: Any) -> dict[str, Any]:
    value = getattr(finding, "details", None) or {}
    return value if isinstance(value, dict) else {}


def _confirmed_finding(finding: Any) -> bool:
    status = str(getattr(finding, "verification_status", "") or _details(finding).get("verification_status") or "").lower()
    return status == "confirmed" and not bool(getattr(finding, "is_false_positive", False))


def _finding_has_proof_pack(finding: Any) -> bool:
    details = _details(finding)
    proof = details.get("proof_pack") or details.get("evidence_contract")
    if not proof:
        return False
    if isinstance(proof, dict):
        return bool(
            proof.get("artifact_count")
            or proof.get("baseline") and proof.get("exploit")
            or proof.get("baseline_request") and proof.get("exploit_request")
        )
    return False


def _finding_key(finding: Any) -> dict[str, str]:
    details = _details(finding)
    family = str(details.get("vuln_family") or classify_family(
        title=str(getattr(finding, "title", "") or ""),
        tool=str(getattr(finding, "tool", "") or ""),
        cve=str(getattr(finding, "cve", "") or ""),
    ))
    if family == "lfri":
        family = "lfi"
    return {
        "case_id": str(details.get("benchmark_case_id") or ""),
        "family": family,
        "target": str(getattr(finding, "url", "") or getattr(finding, "domain", "") or details.get("target") or "").lower(),
    }


def _matches(expected: dict[str, Any], observed: dict[str, str]) -> bool:
    expected_id = str(expected.get("id") or expected.get("case_id") or "")
    if expected_id and observed["case_id"]:
        return expected_id == observed["case_id"]
    family = str(expected.get("family") or "")
    if family == "lfri":
        family = "lfi"
    target = str(expected.get("target") or "").lower()
    return bool(family and family == observed["family"] and (not target or target in observed["target"]))


def evaluate_benchmark_scan(
    scan_job: Any,
    *,
    benchmark_id: str = "vuln-bank",
    findings: list[Any] | None = None,
) -> dict[str, Any]:
    benchmarks = {item["id"]: item for item in list_benchmark_targets()}
    benchmark = benchmarks.get(benchmark_id)
    if not benchmark:
        return {"benchmark_id": benchmark_id, "status": "unknown_benchmark", "score": 0, "gates": []}

    state = dict(getattr(scan_job, "state_data", None) or {})
    ground_truth = [dict(row) for row in list(state.get("benchmark_ground_truth") or []) if isinstance(row, dict)]
    observed_findings = [finding for finding in list(findings or []) if _confirmed_finding(finding)]
    observed = [(finding, _finding_key(finding)) for finding in observed_findings]
    matched_observed: set[int] = set()
    true_positives: list[str] = []
    false_negatives: list[str] = []
    for expected in ground_truth:
        match_index = next(
            (index for index, (_finding, key) in enumerate(observed) if index not in matched_observed and _matches(expected, key)),
            None,
        )
        case_id = str(expected.get("id") or expected.get("case_id") or expected.get("family") or "unknown")
        if match_index is None:
            false_negatives.append(case_id)
        else:
            matched_observed.add(match_index)
            true_positives.append(case_id)
    false_positives = [
        key.get("case_id") or f"{key.get('family')}:{key.get('target')}"
        for index, (_finding, key) in enumerate(observed)
        if index not in matched_observed
    ]
    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.000001, precision + recall)
    proof_complete = all(_finding_has_proof_pack(finding) for finding in observed_findings)
    local_required = benchmark["safe_execution"] in {"local_container_only", "simulated_network_only"}
    safe_scope = (not local_required) or _is_local_or_simulated_target(scan_job)
    safety_violations = list(state.get("safety_violations") or [])
    cleanup = dict(state.get("mutation_cleanup_summary") or {})
    cleanup_ok = int(cleanup.get("pending") or 0) == 0 and int(cleanup.get("failed") or 0) == 0

    gates = [
        {"id": "safe_scope", "passed": safe_scope, "detail": "local/simulated scope required"},
        {"id": "ground_truth", "passed": bool(ground_truth), "detail": f"{len(ground_truth)} expected cases loaded"},
        {"id": "precision", "passed": bool(ground_truth) and precision >= 0.90, "detail": f"TP={tp} FP={fp} precision={precision:.3f}"},
        {"id": "recall", "passed": bool(ground_truth) and recall >= 0.85, "detail": f"TP={tp} FN={fn} recall={recall:.3f}"},
        {"id": "proof_pack", "passed": proof_complete, "detail": f"{len(observed_findings)} confirmed findings checked"},
        {"id": "safety", "passed": not safety_violations, "detail": f"{len(safety_violations)} safety violations"},
        {"id": "mutation_cleanup", "passed": cleanup_ok, "detail": f"pending={cleanup.get('pending', 0)} failed={cleanup.get('failed', 0)}"},
    ]
    score = round((precision * 35) + (recall * 35) + (25 if proof_complete else 0) + (5 if not safety_violations and cleanup_ok else 0), 2) if ground_truth else 0
    return {
        "benchmark_id": benchmark_id,
        "benchmark_name": benchmark["name"],
        "status": "passed" if all(gate["passed"] for gate in gates) else "needs_attention",
        "score": score,
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn},
        "metrics": {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)},
        "cases": {"matched": true_positives, "missed": false_negatives, "unexpected": false_positives},
        "gates": gates,
        "recommended_next_step": _recommended_next_step(gates),
    }


def _recommended_next_step(gates: list[dict[str, Any]]) -> str:
    messages = {
        "safe_scope": "Run this benchmark only against its local or simulated lab target.",
        "ground_truth": "Load the lab adapter's versioned benchmark_ground_truth before scoring.",
        "precision": "Investigate unmatched confirmed findings and tighten family evidence contracts.",
        "recall": "Investigate missed ground-truth cases and methodology coverage gaps.",
        "proof_pack": "Attach valid proof packs before counting confirmed benchmark findings.",
        "safety": "Resolve every recorded safety-policy violation before accepting the run.",
        "mutation_cleanup": "Complete and verify all mutation cleanup before accepting the run.",
    }
    for gate in gates:
        if not gate.get("passed"):
            return messages.get(str(gate.get("id")), "Resolve the failed benchmark gate.")
    return "Benchmark gates passed; compare precision, recall and safety against the previous release."
