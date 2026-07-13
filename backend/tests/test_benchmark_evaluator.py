from __future__ import annotations

from types import SimpleNamespace

from app.services.benchmark_evaluator import evaluate_benchmark_scan


def _scan(target: str, state_data: dict) -> SimpleNamespace:
    return SimpleNamespace(id=1, target_query=target, state_data=state_data)


def _finding(severity: str, details: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(severity=severity, details=details or {}, evidence="")


def test_benchmark_evaluator_passes_local_scan_with_proof_pack() -> None:
    scan = _scan(
        "http://vuln-bank:3000",
        {
            "agent_validation": {"score": 88},
            "phase_ledger_v2": [
                {"phase_id": f"P{i:02d}", "status": "completed", "tools_success": [f"tool-{i}"]}
                for i in range(1, 10)
            ],
        },
    )
    finding = _finding("critical", {"proof_pack": {"baseline": "EV-1", "exploit": "EV-2"}})

    result = evaluate_benchmark_scan(scan, benchmark_id="vuln-bank", findings=[finding])

    assert result["status"] == "passed"
    assert result["score"] >= 80
    assert all(gate["passed"] for gate in result["gates"])


def test_benchmark_evaluator_blocks_external_target_for_local_lab() -> None:
    scan = _scan(
        "https://example.com",
        {
            "phase_ledger_v2": [
                {"phase_id": "P01", "status": "completed", "tools_success": ["subfinder"]}
            ],
        },
    )
    finding = _finding("high")

    result = evaluate_benchmark_scan(scan, benchmark_id="vuln-bank", findings=[finding])

    failed_gate_ids = {gate["id"] for gate in result["gates"] if not gate["passed"]}
    assert result["status"] == "needs_attention"
    assert "safe_scope" in failed_gate_ids
    assert "proof_pack" in failed_gate_ids
    assert result["recommended_next_step"].startswith("Run this benchmark only")


def test_benchmark_evaluator_handles_unknown_benchmark() -> None:
    result = evaluate_benchmark_scan(_scan("localhost", {}), benchmark_id="missing")

    assert result["status"] == "unknown_benchmark"
    assert result["score"] == 0
