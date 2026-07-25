"""Evidence contract for Web Cache Deception findings."""
from __future__ import annotations

from typing import Any


def adjudicate_cache_deception(details: dict[str, Any] | None) -> dict[str, Any]:
    evidence = str((details or {}).get("evidence") or "")
    metadata = dict(details or {})
    cache_hit = any(
        marker in evidence.upper()
        for marker in ("X-CACHE: 'HIT'", "CF-CACHE-STATUS: 'HIT'", "TCP_HIT")
    )
    authenticated_baseline = bool(
        metadata.get("authenticated_baseline")
        or metadata.get("victim_response_artifact_id")
    )
    anonymous_replay = bool(
        metadata.get("anonymous_replay")
        or metadata.get("attacker_response_artifact_id")
    )
    sensitive_diff = bool(metadata.get("sensitive_response_diff"))
    confirmed = cache_hit and authenticated_baseline and anonymous_replay and sensitive_diff
    if confirmed:
        return {
            "result": "confirmed",
            "reason": "authenticated_sensitive_response_replayed_from_shared_cache",
            "checks": {
                "cache_hit": True,
                "authenticated_baseline": True,
                "anonymous_replay": True,
                "sensitive_response_diff": True,
            },
        }
    missing = [
        name for name, present in (
            ("cache_hit", cache_hit),
            ("authenticated_baseline", authenticated_baseline),
            ("anonymous_replay", anonymous_replay),
            ("sensitive_response_diff", sensitive_diff),
        )
        if not present
    ]
    return {
        "result": "refuted",
        "reason": "cache_deception_evidence_contract_not_met",
        "missing": missing,
        "checks": {
            "cache_hit": cache_hit,
            "authenticated_baseline": authenticated_baseline,
            "anonymous_replay": anonymous_replay,
            "sensitive_response_diff": sensitive_diff,
        },
    }
