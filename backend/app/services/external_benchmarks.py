"""Real, sourced external cyber-maturity benchmarks -- used ONLY to show a
"how does this compare to the outside world" reference next to our own
resilience_score, never blended into it.

Every number below was fetched and read directly from the primary source
PDF (not from a secondhand summary) on 2026-08-28. Two other sources
(BitSight, SecurityScorecard) were checked and rejected: their per-industry
averages are a paid-platform feature, not a freely published table, and a
secondhand "consolidated table" the user received elsewhere misattributed
BitSight's 250-900 rating scale to SecurityScorecard (which actually uses
A-F letter grades) -- a clear sign of AI-fabricated synthesis. Only
Wavestone publishes a single, current, citable, percentage-scale table.

IMPORTANT METHODOLOGY CAVEAT, always show this alongside the number: this
is a consultant-assessed maturity score against NIST CSF 2.0 / ISO 27001
control frameworks (paper/interview-based), not a simulated-attack outcome
like our own resilience_score (real BAS technique dispatches actually
attempted against a target). The two are both 0-100 scales measuring
"how good is this org's security", but via fundamentally different
methods -- never claim they are the same measurement.
"""
from __future__ import annotations

from typing import Any

WAVESTONE_SOURCE = {
    "name": "Wavestone Cyber Benchmark 2026",
    "url": "https://www.wavestone.com/en/insight/cyber-benchmark-2026-progress-slows-as-complexity-rises-1/",
    "published": "2026-01",
    "sample": "200+ large organizations (100+ with revenue >EUR1B), ~7M employees",
    "methodology": (
        "Consultant-led maturity assessment against NIST CSF 2.0 / ISO 27001, "
        "via interviews with security leaders -- NOT a simulated attack outcome."
    ),
}

# key -> {label, maturity_pct}. maturity_pct is Wavestone's own 0-100% scale.
WAVESTONE_CYBER_BENCHMARK_2026: dict[str, dict[str, Any]] = {
    "financial": {"label": "Setor financeiro", "maturity_pct": 67.6},
    "luxury_retail": {"label": "Luxo & varejo", "maturity_pct": 56.9},
    "industry": {"label": "Indústria", "maturity_pct": 52.7},
    "energy_utilities": {"label": "Energia & utilities", "maturity_pct": 50.2},
    "services": {"label": "Serviços", "maturity_pct": 48.7},
}
WAVESTONE_GLOBAL_AVERAGE_PCT = 55.3
WAVESTONE_TOP_DECILE_PCT = 78.0

SECTOR_OPTIONS = [
    {"key": key, "label": row["label"]} for key, row in WAVESTONE_CYBER_BENCHMARK_2026.items()
]


def resolve_industry_benchmark(sector_key: str | None) -> dict[str, Any] | None:
    """None when the org hasn't declared a sector, or declared one Wavestone
    doesn't cover -- never guess a sector, never fall back to a fabricated
    number. The global average is still returned as context in that case,
    clearly labeled as "global", not sector-specific."""
    row = WAVESTONE_CYBER_BENCHMARK_2026.get(sector_key) if sector_key else None
    return {
        "sector": sector_key,
        "sector_label": row["label"] if row else None,
        "sector_maturity_pct": row["maturity_pct"] if row else None,
        "global_average_pct": WAVESTONE_GLOBAL_AVERAGE_PCT,
        "top_decile_pct": WAVESTONE_TOP_DECILE_PCT,
        "source": WAVESTONE_SOURCE,
    }
