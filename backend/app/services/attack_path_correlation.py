"""Generic, evidence-aware attack-path correlation."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit


FAMILY_STAGE: dict[str, tuple[int, str, str]] = {
    "exposed_git": (10, "credential_access", "Credentials from exposed source control"),
    "secret_exposure": (10, "credential_access", "Exposed secret or token"),
    "information_disclosure": (15, "discovery", "Sensitive information disclosure"),
    "default_credentials": (20, "initial_access", "Valid/default account access"),
    "auth_bypass": (20, "initial_access", "Authentication boundary bypass"),
    "jwt": (20, "initial_access", "Token trust weakness"),
    "xss": (25, "initial_access", "Client-side execution foothold"),
    "sqli": (30, "collection", "Database boundary compromise"),
    "lfi": (30, "discovery", "Local file disclosure"),
    "path_traversal": (30, "discovery", "Filesystem boundary traversal"),
    "ssrf": (35, "lateral_movement", "Server-side pivot"),
    "idor_bola": (40, "privilege_escalation", "Cross-object authorization bypass"),
    "object_reference": (40, "privilege_escalation", "Object authorization weakness"),
    "bfla_authz": (42, "privilege_escalation", "Function-level authorization bypass"),
    "business_logic_mass_assignment": (45, "privilege_escalation", "Unauthorized state manipulation"),
    "rce": (50, "execution", "Remote command execution"),
    "data_exposure": (60, "impact", "Sensitive data access"),
}
VERIFIED_STATUSES = {"confirmed", "validated", "proven", "success"}
COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.br", "net.br", "org.br", "gov.br",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.za", "com.mx",
}


def correlate_attack_signals(
    signals: list[dict[str, Any]],
    objectives: list[dict[str, Any]] | None = None,
    *,
    max_paths: int = 20,
) -> list[dict[str, Any]]:
    normalized = [_normalize_signal(signal) for signal in signals]
    normalized = [signal for signal in normalized if signal.get("family") in FAMILY_STAGE]
    by_affinity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in normalized:
        by_affinity[_affinity(signal.get("target", ""))].append(signal)

    objective_rows = [dict(row) for row in list(objectives or []) if isinstance(row, dict)]
    paths: list[dict[str, Any]] = []
    for affinity, rows in by_affinity.items():
        linked = list(rows)
        # Credential and SSRF signals legitimately bridge hosts in the same root domain.
        if any(row["family"] in {"exposed_git", "secret_exposure", "ssrf"} for row in rows):
            root = _root_domain(affinity)
            for other_affinity, other_rows in by_affinity.items():
                if other_affinity != affinity and root and _root_domain(other_affinity) == root:
                    linked.extend(other_rows)
        linked = _dedupe_signals(linked)
        linked.sort(key=lambda row: (FAMILY_STAGE[row["family"]][0], -row["confidence"], row["id"]))
        if len(linked) < 2 and not any(row["verified"] and row["severity"] in {"critical", "high"} for row in linked):
            continue
        matched_objectives = [row for row in objective_rows if _objective_matches(row, affinity)]
        objective = matched_objectives[0] if matched_objectives else {"target": affinity, "label": "highest demonstrated impact"}
        stages = {FAMILY_STAGE[row["family"]][1] for row in linked}
        verified = [row for row in linked if row["verified"]]
        confidence = round(min(0.99, sum(row["confidence"] for row in linked) / max(1, len(linked)) * (0.7 + min(0.25, len(stages) * 0.05))), 3)
        impact_signals = [
            row for row in verified
            if FAMILY_STAGE[row["family"]][1] in {"execution", "impact", "privilege_escalation"}
        ]
        if matched_objectives:
            objective_host = _affinity(str(objective.get("target") or objective.get("subdomain") or ""))
            impact_signals = [row for row in impact_signals if _affinity(row["target"]) == objective_host]
        reached = bool(impact_signals)
        steps = [
            {
                "step": index,
                "signal_id": row["id"],
                "family": row["family"],
                "stage": FAMILY_STAGE[row["family"]][1],
                "description": row.get("title") or FAMILY_STAGE[row["family"]][2],
                "target": row["target"],
                "severity": row["severity"],
                "confirmed": row["verified"],
                "confidence": row["confidence"],
                "evidence_ids": row["evidence_ids"],
            }
            for index, row in enumerate(linked[:12], start=1)
        ]
        path_payload = {"affinity": affinity, "objective": objective.get("target"), "signals": [row["id"] for row in linked]}
        evidence_complete = bool(steps and all(step["evidence_ids"] for step in steps if step["confirmed"]))
        chain_proven = bool(reached and evidence_complete and all(step["confirmed"] for step in steps))
        paths.append({
            "attack_path_id": "AP-" + hashlib.sha256(json.dumps(path_payload, sort_keys=True).encode()).hexdigest()[:16],
            "objective": str(objective.get("target") or affinity),
            "label": str(objective.get("label") or "highest demonstrated impact"),
            "status": "proven" if chain_proven else "candidate",
            "objective_reachable": reached,
            "chain_proven": chain_proven,
            "confidence": confidence,
            "stages": sorted(stages, key=lambda stage: min(value[0] for value in FAMILY_STAGE.values() if value[1] == stage)),
            "steps": steps,
            "step_count": len(steps),
            "evidence_complete": evidence_complete,
            "next_actions": _next_actions(linked, reached),
        })
    paths.sort(key=lambda row: (not row["objective_reachable"], -row["confidence"], -row["step_count"]))
    return paths[:max_paths]


def _normalize_signal(signal: dict[str, Any]) -> dict[str, Any]:
    family = _family_alias(str(signal.get("family") or signal.get("hypothesis_type") or ""))
    status = str(signal.get("status") or signal.get("verification_status") or "candidate").lower()
    confidence = float(signal.get("confidence") or signal.get("confidence_score") or 0.5)
    if confidence > 1:
        confidence /= 100.0
    return {
        "id": str(signal.get("id") or signal.get("signal_id") or signal.get("evidence_id") or "unknown"),
        "family": family,
        "target": str(signal.get("target") or signal.get("target_ref") or signal.get("url") or ""),
        "title": str(signal.get("title") or signal.get("description") or "")[:255],
        "severity": str(signal.get("severity") or "medium").lower(),
        "status": status,
        "verified": status in VERIFIED_STATUSES,
        "confidence": max(0.0, min(1.0, confidence)),
        "evidence_ids": [str(item) for item in list(signal.get("evidence_ids") or []) if str(item)],
    }


def _family_alias(raw: str) -> str:
    value = raw.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "sql_injection": "sqli", "xss_sqli": "sqli", "remote_code_execution": "rce",
        "lfi_ssti_path_traversal": "path_traversal", "bola": "idor_bola", "idor": "idor_bola",
        "api_spec_exposure": "information_disclosure", "ssrf_open_redirect": "ssrf",
        "credentials": "secret_exposure", "secrets": "secret_exposure",
        "info_exposure": "information_disclosure", "lfri": "lfi",
        "jwt_oauth": "jwt", "broken_access_control": "bfla_authz",
        "bola_bfla": "idor_bola", "mass_assignment": "business_logic_mass_assignment",
        "business_logic": "business_logic_mass_assignment", "excessive_data_exposure": "data_exposure",
    }
    return aliases.get(value, value)


def _affinity(target: str) -> str:
    value = str(target or "").lower()
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        return parsed.hostname or value.split("/", 1)[0]
    except ValueError:
        return value.split("/", 1)[0]


def _root_domain(host: str) -> str:
    parts = [part for part in str(host or "").split(".") if part]
    if len(parts) >= 3 and ".".join(parts[-2:]) in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else str(host or "")


def _objective_matches(objective: dict[str, Any], affinity: str) -> bool:
    target = str(objective.get("target") or objective.get("subdomain") or "").lower()
    return bool(target and (target in affinity or affinity in target or _root_domain(target) == _root_domain(affinity)))


def _dedupe_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for signal in signals:
        key = (signal["family"], signal["target"])
        if key not in best or (signal["verified"], signal["confidence"]) > (best[key]["verified"], best[key]["confidence"]):
            best[key] = signal
    return list(best.values())


def _next_actions(signals: list[dict[str, Any]], reached: bool) -> list[str]:
    if reached:
        return ["preserve complete evidence chain", "retest every confirmed step after remediation"]
    unverified = [signal for signal in signals if not signal["verified"]]
    actions = [f"validate {signal['family']} on {signal['target']}" for signal in unverified[:3]]
    return actions or ["collect an independently validated impact signal"]
