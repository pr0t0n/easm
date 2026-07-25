from app.services.cache_deception_validator import adjudicate_cache_deception


def test_cache_miss_without_authenticated_replay_is_refuted():
    result = adjudicate_cache_deception({
        "evidence": "Cache-Control: max-age=14400 | X-Cache: 'MISS'",
    })

    assert result["result"] == "refuted"
    assert "cache_hit" in result["missing"]
    assert "authenticated_baseline" in result["missing"]


def test_authenticated_shared_cache_replay_is_confirmed():
    result = adjudicate_cache_deception({
        "evidence": "X-Cache: 'HIT'",
        "authenticated_baseline": True,
        "anonymous_replay": True,
        "sensitive_response_diff": True,
    })

    assert result["result"] == "confirmed"
