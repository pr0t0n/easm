"""Lanes de concorrência fast/slow do runner (Fase 4 do LANGGRAPH_BRAIN_PLAN).

Ferramentas lentas (timeout > 240s: sqlmap, nuclei, nmap, testssl) esgotavam
o pool único e travavam as rápidas (httpx, dnsx, curl-headers) em fila. O
runner agora tem dois pools físicos; a lane rápida nunca espera pela lenta.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import (  # noqa: E402
    DEFAULT_TIMEOUT,
    LANE_FAST_MAX,
    LANE_SLOW_MAX,
    MAX_PARALLEL,
    _SLOW_LANE_THRESHOLD_SECONDS,
    executor_for_lane,
    lane_for_profile,
)


def test_lane_classification_by_timeout():
    assert lane_for_profile({"timeout": 60}) == "fast"
    assert lane_for_profile({"timeout": 240}) == "fast"
    assert lane_for_profile({"timeout": 241}) == "slow"
    assert lane_for_profile({"timeout": 900}) == "slow"


def test_lane_classification_default_timeout_is_slow():
    # Sem timeout explícito herda DEFAULT_TIMEOUT (300s) → slow (classe das
    # ferramentas de análise pesada, que é o caso da maioria dos profiles).
    assert DEFAULT_TIMEOUT > _SLOW_LANE_THRESHOLD_SECONDS
    assert lane_for_profile({}) == "slow"
    assert lane_for_profile({"timeout": None}) == "slow"


def test_lane_executors_are_distinct():
    assert executor_for_lane("fast") is not executor_for_lane("slow")


def test_lane_caps_fit_global_parallelism():
    assert LANE_FAST_MAX + LANE_SLOW_MAX <= MAX_PARALLEL
    assert LANE_FAST_MAX >= 2
    assert LANE_SLOW_MAX >= 1


def test_threshold_is_configurable():
    assert _SLOW_LANE_THRESHOLD_SECONDS > 0
