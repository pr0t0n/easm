from types import SimpleNamespace

from app.services.finding_experiment import build_finding_intelligence


def _finding(**overrides):
    base = {
        "id": 10,
        "scan_job_id": 1,
        "title": "SQL Injection on /api/users",
        "severity": "high",
        "confidence_score": 55,
        "verification_status": "candidate",
        "tool": "nuclei-sqli",
        "domain": "api.example.test",
        "url": "https://api.example.test/api/users?id=1",
        "details": {},
        "is_false_positive": False,
        "retest_status": None,
        "created_at": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_high_candidate_without_proof_has_contradiction():
    result = build_finding_intelligence(None, _finding())

    assert result["experiment"]["family"] == "sqli"
    assert result["proof_pack"]["has_reproducible_proof"] is False
    assert result["promotion"]["can_promote"] is False
    assert any(c["type"] == "severity_without_replayable_proof" for c in result["contradictions"])
    assert any(e["signal"] == "missing_reproducible_proof" for e in result["confidence_ledger"])


def test_confirmed_finding_with_reproduction_is_promotable():
    finding = _finding(
        confidence_score=82,
        verification_status="confirmed",
        tool="sqlmap",
        details={
            "reproduction": {
                "commands": [{"tool": "sqlmap", "command": "sqlmap -u https://api.example.test/api/users?id=1 --batch"}],
                "proof": [{"summary": "boolean-based blind confirmed", "output": "parameter id appears injectable"}],
                "steps": ["Run sqlmap against the authorized endpoint"],
                "verifiable": True,
            },
            "evidence": "parameter id appears injectable",
        },
    )

    result = build_finding_intelligence(None, finding)

    assert result["proof_pack"]["has_reproducible_proof"] is True
    assert result["final_confidence"] >= 90
    assert result["promotion"]["can_promote"] is True
    assert result["contradictions"] == []
    assert result["experiment"]["verdict"] == "confirmed"


def test_refuted_retest_creates_negative_ledger():
    finding = _finding(
        confidence_score=80,
        verification_status="refuted",
        retest_status="refuted",
        details={"evidence": "initial scanner output only"},
    )

    result = build_finding_intelligence(None, finding)

    signals = {entry["signal"] for entry in result["confidence_ledger"]}
    assert "verification_refuted" in signals
    assert "retest_refuted" in signals
    assert result["final_confidence"] < 50
    assert result["experiment"]["verdict"] == "refuted"
