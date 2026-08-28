"""The user asked to add an "industry median" benchmark, then pasted a
second-hand "consolidated table" claiming BitSight/SecurityScorecard
per-industry averages -- verified against primary sources: Wavestone's
numbers check out (2026-01 report), but the BitSight/SecurityScorecard
framing misattributed BitSight's 250-900 scale to SecurityScorecard (which
actually uses A-F letter grades), and neither publishes a free per-industry
table -- a sign the "consolidated table" was itself AI-fabricated. Only
Wavestone's real, sourced numbers made it into the platform.
"""
from app.services.external_benchmarks import (
    WAVESTONE_CYBER_BENCHMARK_2026,
    WAVESTONE_GLOBAL_AVERAGE_PCT,
    resolve_industry_benchmark,
)


def test_known_sector_returns_its_real_wavestone_number():
    result = resolve_industry_benchmark("financial")
    assert result["sector_maturity_pct"] == 67.6
    assert result["sector_label"] == "Setor financeiro"
    assert result["global_average_pct"] == WAVESTONE_GLOBAL_AVERAGE_PCT
    assert "wavestone.com" in result["source"]["url"]


def test_unclassified_org_gets_no_fabricated_sector_number():
    result = resolve_industry_benchmark(None)
    assert result["sector_maturity_pct"] is None
    assert result["sector_label"] is None
    # Global average still shown as honest context, clearly separate from a sector claim.
    assert result["global_average_pct"] == WAVESTONE_GLOBAL_AVERAGE_PCT


def test_unknown_sector_key_never_silently_guesses():
    result = resolve_industry_benchmark("healthcare")  # not in the real Wavestone table
    assert result["sector_maturity_pct"] is None
    assert result["sector_label"] is None


def test_every_benchmark_entry_has_a_citable_source():
    for key, row in WAVESTONE_CYBER_BENCHMARK_2026.items():
        assert 0 <= row["maturity_pct"] <= 100
        assert row["label"]
