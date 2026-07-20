"""Deterministic offline evaluation for endpoint and pentest intelligence."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.models.models import OffensiveHypothesis
from app.services.attack_path_correlation import correlate_attack_signals
from app.services.endpoint_analysis_pipeline import analyze_endpoint_contract
from app.services.hypothesis_planner import score_hypothesis
from app.services.poc_outcome import classify_poc_work_item
from app.services.pentest_validators import _classify_auth_observations, _looks_like_bola


ENDPOINT_CASES = (
    {
        "id": "object_api",
        "url": "https://fixture.invalid/api/orders/42?user_id=42",
        "tags": ["api"],
        "expected": {"auth_requirement", "object_authorization", "parameter:query:user_id:idor_bola"},
    },
    {
        "id": "admin_boundary",
        "url": "https://fixture.invalid/admin/users",
        "expected": {"auth_requirement"},
    },
    {
        "id": "search_input",
        "url": "https://fixture.invalid/search?q=hello",
        "expected": {"parameter:query:q:xss_sqli"},
    },
    {
        "id": "api_spec",
        "url": "https://fixture.invalid/openapi.json",
        "expected": {"auth_requirement", "api_spec"},
    },
    {
        "id": "static_asset",
        "url": "https://fixture.invalid/assets/app.js",
        "expected": set(),
    },
)


def run_offline_intelligence_evaluation() -> dict[str, Any]:
    endpoint_expected: set[str] = set()
    endpoint_predicted: set[str] = set()
    endpoint_rows = []
    for case in ENDPOINT_CASES:
        analysis = analyze_endpoint_contract(case["url"], tags=list(case.get("tags") or []))
        predicted = {test["test_class"] for test in analysis["test_matrix"] if test["test_class"] != "read_only_baseline"}
        expected = set(case["expected"])
        endpoint_expected.update(f"{case['id']}:{value}" for value in expected)
        endpoint_predicted.update(f"{case['id']}:{value}" for value in predicted)
        endpoint_rows.append({"id": case["id"], "expected": sorted(expected), "predicted": sorted(predicted)})

    endpoint_metrics = _classification_metrics(endpoint_expected, endpoint_predicted)
    planner_metrics = _planner_evaluation()
    poc_metrics = _poc_evaluation()
    path_metrics = _path_evaluation()
    authorization_metrics = _authorization_evaluation()
    dimensions = {
        "endpoint_analysis": endpoint_metrics,
        "hypothesis_planner": planner_metrics,
        "poc_outcome": poc_metrics,
        "attack_path": path_metrics,
        "authorization_assertion": authorization_metrics,
    }
    score = round(sum(float(row["f1"]) for row in dimensions.values()) / len(dimensions) * 100, 2)
    gates = [
        {"id": key, "passed": float(value["precision"]) >= 0.9 and float(value["recall"]) >= 0.9, **value}
        for key, value in dimensions.items()
    ]
    return {
        "suite": "offline-synthetic-pentest-intelligence-v4",
        "network_access": False,
        "external_targets": False,
        "excluded_platforms": ["juice-shop", "dvwa", "idor-lab"],
        "status": "passed" if all(gate["passed"] for gate in gates) else "failed",
        "score": score,
        "gates": gates,
        "endpoint_cases": endpoint_rows,
    }


def _planner_evaluation() -> dict[str, float | int]:
    job = SimpleNamespace(state_data={"crown_jewels": [{"target": "admin.fixture.invalid"}]}, tech_stack=[])
    rows = [
        OffensiveHypothesis(id=1, scan_job_id=1, hypothesis_type="information_disclosure", title="Info", target_ref="https://fixture.invalid/debug", source_signal="path:debug", confidence=90, status="open", required_identities=[], hypothesis_metadata={}),
        OffensiveHypothesis(id=2, scan_job_id=1, hypothesis_type="idor_bola", title="IDOR", target_ref="https://fixture.invalid/api/orders/{id}", source_signal="param:id", confidence=75, status="open", required_identities=["user_a", "user_b"], hypothesis_metadata={}),
        OffensiveHypothesis(id=3, scan_job_id=1, hypothesis_type="rce", title="RCE", target_ref="https://admin.fixture.invalid/exec", source_signal="param:cmd", confidence=70, status="open", required_identities=[], hypothesis_metadata={}),
    ]
    ranked = sorted(rows, key=lambda row: -score_hypothesis(job, row, {})["score"])
    predicted = [row.id for row in ranked]
    expected = [3, 2, 1]
    correct_pairs = sum(1 for index, item in enumerate(expected) if predicted[index] == item)
    value = correct_pairs / len(expected)
    return {"precision": value, "recall": value, "f1": value, "true_positive": correct_pairs, "false_positive": len(expected) - correct_pairs, "false_negative": len(expected) - correct_pairs}


def _poc_evaluation() -> dict[str, float | int]:
    cases = [
        (SimpleNamespace(status="completed", tool_name="sqlmap", result={"stdout_full": "parameter id is vulnerable", "parsed_result": {}}), "confirmed"),
        (SimpleNamespace(status="completed", tool_name="sqlmap", result={"stdout_full": "no injection point", "parsed_result": {}}), "refuted"),
        (SimpleNamespace(status="completed", tool_name="nuclei", result={"stdout_full": "finished", "parsed_result": []}), "candidate"),
        (SimpleNamespace(status="failed", tool_name="dalfox", result={"stdout_full": ""}), "candidate"),
    ]
    correct = sum(1 for item, expected in cases if classify_poc_work_item(item)["result"] == expected)
    value = correct / len(cases)
    return {"precision": value, "recall": value, "f1": value, "true_positive": correct, "false_positive": len(cases) - correct, "false_negative": len(cases) - correct}


def _path_evaluation() -> dict[str, float | int]:
    paths = correlate_attack_signals(
        [
            {"id": "EV-1", "family": "secret_exposure", "target": "https://app.fixture.invalid/.env", "status": "confirmed", "severity": "high", "confidence": 0.9, "evidence_ids": ["EV-1"]},
            {"id": "EV-2", "family": "rce", "target": "https://admin.fixture.invalid/exec", "status": "confirmed", "severity": "critical", "confidence": 0.95, "evidence_ids": ["EV-2"]},
        ],
        [{"target": "admin.fixture.invalid", "label": "admin"}],
    )
    checks = [bool(paths and paths[0]["objective_reachable"] and paths[0]["chain_proven"] and paths[0]["step_count"] == 2)]
    partial = correlate_attack_signals([
        {"id": "EV-3", "family": "secret_exposure", "target": "https://app.fixture.invalid/.env", "status": "candidate", "severity": "high", "evidence_ids": []},
        {"id": "EV-4", "family": "rce", "target": "https://admin.fixture.invalid/exec", "status": "confirmed", "severity": "critical", "evidence_ids": ["EV-4"]},
    ], [{"target": "admin.fixture.invalid", "label": "admin"}])
    checks.append(bool(partial and partial[0]["objective_reachable"] and not partial[0]["chain_proven"]))
    wrong_host = correlate_attack_signals([
        {"id": "EV-5", "family": "secret_exposure", "target": "https://admin.fixture.invalid/.env", "status": "confirmed", "severity": "high", "evidence_ids": ["EV-5"]},
        {"id": "EV-6", "family": "rce", "target": "https://app.fixture.invalid/exec", "status": "confirmed", "severity": "critical", "evidence_ids": ["EV-6"]},
    ], [{"target": "admin.fixture.invalid", "label": "admin"}])
    checks.append(bool(wrong_host and not wrong_host[0]["objective_reachable"]))
    correct = sum(int(value) for value in checks)
    score = correct / len(checks)
    return {"precision": score, "recall": score, "f1": score, "true_positive": correct, "false_positive": len(checks) - correct, "false_negative": len(checks) - correct}


def _authorization_evaluation() -> dict[str, float | int]:
    auth_cases = [
        (_classify_auth_observations({"ok": True, "status_code": 401, "headers": {}}, [{"ok": True, "status_code": 200}])[0], True),
        (_classify_auth_observations({"ok": True, "status_code": 302, "headers": {"location": "/login"}}, [])[0], True),
        (_classify_auth_observations({"ok": True, "status_code": 200, "headers": {}, "body_preview": "public"}, [])[0], False),
    ]
    baseline = {"ok": True, "status_code": 200, "body_len": 100, "body_preview": '{"id":1}', "json_keys": ["id"]}
    negative = {"ok": True, "status_code": 404, "body_len": 10, "body_preview": "missing", "json_keys": []}
    idor_cases = [
        (_looks_like_bola(baseline, dict(baseline), negative), True),
        (_looks_like_bola(baseline, {**baseline, "body_preview": '{"id":2}'}, negative), False),
        (_looks_like_bola(baseline, dict(baseline), dict(baseline)), False),
    ]
    cases = auth_cases + idor_cases
    correct = sum(1 for actual, expected in cases if actual is expected)
    score = correct / len(cases)
    return {"precision": score, "recall": score, "f1": score, "true_positive": correct, "false_positive": len(cases) - correct, "false_negative": len(cases) - correct}


def _classification_metrics(expected: set[str], predicted: set[str]) -> dict[str, float | int]:
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.0001, precision + recall)
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "true_positive": tp, "false_positive": fp, "false_negative": fn}
