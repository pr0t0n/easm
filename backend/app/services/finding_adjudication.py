"""Evidence adjudication and persistent validation wires.

The central invariant is that an LLM may identify an evidence gap and select a
closed action recipe, but only a deterministic evidence decision may promote or
refute a finding.  ``ValidationWire`` is the durable return edge that binds a
gap to the exact target/context re-tested by a P21 work item and causes the
finding to be adjudicated again when that item reaches a terminal state.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.artifact_store import redact
from app.services.evidence_contract_service import evaluate_finding_promotion
from app.services.finding_experiment import build_finding_intelligence
from app.services.llm_determinism import ollama_generate_payload
from app.services.scan_scope import authorized_scope_for_scan, host_from_scope_reference, is_host_in_scope
from app.services.untrusted_content import normalize_adversarial_text, wrap_untrusted


logger = logging.getLogger(__name__)

PROMPT_VERSION = "finding-adjudication-v1"
MAX_CYCLES_PER_FINDING = 3
MAX_WIRES_PER_FINDING = 3

TERMINAL_VERDICTS = {
    "confirmed", "refuted", "not_applicable", "invalid_evidence",
    "blocked", "needs_human_review",
}
ALLOWED_PROPOSED_VERDICTS = TERMINAL_VERDICTS | {"inconclusive", "candidate"}
ALLOWED_ACTIONS = {
    "collect_full_artifact",
    "repeat_same_validator",
    "collect_baseline",
    "collect_negative_control",
    "run_family_validator",
    "compare_two_identities",
    "compare_two_objects",
    "verify_product_version",
    "verify_configuration_state",
    "verify_cve_applicability",
    "lookup_cve_intelligence",
    "lookup_public_exploit",
    "rebuild_attack_path",
    "request_human_input",
}
NON_EXECUTABLE_ACTIONS = {
    "verify_cve_applicability", "lookup_cve_intelligence", "lookup_public_exploit",
    "rebuild_attack_path", "request_human_input",
}
AUTH_REQUIREMENTS = {"authenticated_identity", "second_authenticated_identity", "object_pair"}
ACTION_SIGNALS: dict[str, dict[str, str]] = {
    "collect_full_artifact": {
        "positive": "complete parser input and parsed result bound to the source artifact",
        "negative": "collector failure or still-truncated artifact; never refutes the finding",
    },
    "collect_baseline": {
        "positive": "baseline response captured for the exact method, target, parameter and identity",
        "negative": "baseline could not be collected; finding remains inconclusive",
    },
    "collect_negative_control": {
        "positive": "negative-control response differs from the attempted condition as required by the family contract",
        "negative": "control is indistinguishable or failed; finding remains inconclusive",
    },
    "compare_two_identities": {
        "positive": "same exact object requested by both bound identities with authorization-boundary evidence",
        "negative": "lower-privilege identity is explicitly denied while the owner/control identity succeeds",
    },
    "compare_two_objects": {
        "positive": "both pre-existing bound object fixtures are observed under the same exact request contract",
        "negative": "object fixtures or ownership preconditions are not reproducible",
    },
    "verify_product_version": {
        "positive": "product and version parsed from target-grounded tool output",
        "negative": "version remains unknown; CVE applicability cannot be decided",
    },
    "verify_configuration_state": {
        "positive": "configuration state is observed on the bound target",
        "negative": "configuration precondition is explicitly absent on a functioning check",
    },
    "run_family_validator": {
        "positive": "family-specific promotion artifacts satisfy the deterministic evidence contract",
        "negative": "explicit negative observation with validator preconditions satisfied",
    },
}


def _canonical_hash(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _target_for_finding(finding: Any) -> str:
    details = dict(getattr(finding, "details", None) or {})
    return str(
        getattr(finding, "url", None)
        or details.get("matched_at")
        or details.get("matched-at")
        or details.get("url")
        or details.get("asset")
        or getattr(finding, "domain", None)
        or ""
    ).strip()[:1000]


def _parameter_for_finding(finding: Any) -> str:
    details = dict(getattr(finding, "details", None) or {})
    return str(details.get("parameter") or details.get("param") or details.get("parameter_name") or "").strip()[:255]


def _available_identities(db: Session, scan_id: int) -> list[dict[str, str]]:
    from app.models.models import ScanIdentity

    rows = db.query(ScanIdentity).filter(ScanIdentity.scan_job_id == scan_id).order_by(ScanIdentity.id.asc()).all()
    return [
        {"identity_key": str(row.identity_key), "role": str(row.role or "")}
        for row in rows if str(row.identity_key or "")
    ]


def _evidence_rows(db: Session, finding_id: int) -> list[dict[str, Any]]:
    from app.models.models import EvidenceArtifact

    rows = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.finding_id == finding_id)
        .order_by(EvidenceArtifact.created_at.asc(), EvidenceArtifact.id.asc())
        .all()
    )
    return [
        {
            "artifact_id": row.id,
            "artifact_type": row.artifact_type,
            "tool": row.tool_name,
            "target": row.target,
            "identity_key": row.identity_key,
            "validation_status": row.validation_status,
            "confidence_score": row.confidence_score,
            "has_baseline": bool(row.baseline_request and row.baseline_response_ref),
            "has_attempt": bool(row.exploit_request and row.exploit_response_ref),
            "has_negative_control": bool((row.artifact_metadata or {}).get("negative_control")),
            "diff_summary": redact(str(row.diff_summary or "")[:1200]),
            "workspace_ref": str(row.workspace_path or ""),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def _latest_intelligence(db: Session, finding_id: int) -> dict[str, Any]:
    from app.models.models import FindingIntelligenceSnapshot

    row = (
        db.query(FindingIntelligenceSnapshot)
        .filter(FindingIntelligenceSnapshot.finding_id == finding_id)
        .order_by(FindingIntelligenceSnapshot.fetched_at.desc(), FindingIntelligenceSnapshot.id.desc())
        .first()
    )
    if row is None:
        return {}
    return {
        "snapshot_id": row.id,
        "cve_id": row.cve_id,
        "applicability": row.applicability,
        "cvss": {
            "version": row.cvss_version,
            "vector": row.cvss_vector,
            "score": row.cvss_score,
            "source": row.cvss_source,
        },
        "epss": {"score": row.epss_score, "percentile": row.epss_percentile},
        "kev": row.kev,
        "public_exploit_status": row.public_exploit_status,
        "references": list(row.references or []),
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
    }


def _skill_context_for_family(family: str) -> list[dict[str, Any]]:
    """Retrieve versioned P21 tradecraft from the local approved skill catalog."""
    try:
        from app.services.skill_runtime import resolve_skill_for_phase

        aliases = {
            "idor_bola": {"idor", "bola", "object", "access_control"},
            "bfla_authz": {"bfla", "rbac", "authorization", "access_control"},
            "sqli": {"sql", "sqli", "injection"},
            "xss": {"xss", "cross_site"},
            "ssrf": {"ssrf", "server_side"},
            "rce": {"rce", "command", "execution"},
        }
        tokens = aliases.get(family, {part for part in family.split("_") if part})
        ranked: list[tuple[int, dict[str, Any]]] = []
        for skill in resolve_skill_for_phase("P21"):
            haystack = " ".join(
                str(skill.get(key) or "").lower()
                for key in ("skill_id", "name", "category", "source_file")
            )
            score = sum(1 for token in tokens if token in haystack)
            if score:
                ranked.append((score, skill))
        context: list[dict[str, Any]] = []
        for _, skill in sorted(ranked, key=lambda row: (-row[0], str(row[1].get("skill_id"))))[:3]:
            excerpt = ""
            source = str(skill.get("source_file") or "")
            try:
                excerpt = Path(source).read_text(encoding="utf-8")[:3500]
            except OSError:
                pass
            context.append({
                "skill_id": skill.get("skill_id"),
                "version": skill.get("version"),
                "evidence_required": list(skill.get("evidence_required") or []),
                "exit_criteria": dict(skill.get("exit_criteria") or {}),
                "required_tools": list(skill.get("required_tools") or []),
                "source_file": source,
                "approved_excerpt": excerpt,
            })
        return context
    except Exception:
        logger.debug("P21 skill retrieval unavailable family=%s", family, exc_info=True)
        return []


def build_adjudication_dossier(db: Session, job: Any, finding: Any) -> dict[str, Any]:
    """Build the compact, redacted, source-addressable input for one review."""
    from app.models.models import FindingAdjudication, ValidationWire
    from app.services.pentest_outcome_learning import calibration_map
    from app.services.vuln_family import classify_family

    details = dict(finding.details or {})
    target = _target_for_finding(finding)
    identities = _available_identities(db, job.id)
    experiment = build_finding_intelligence(db, finding)
    promotion = evaluate_finding_promotion(db, finding)
    validator_metrics = calibration_map(db, job, "validator")
    cycle_count = db.query(func.count(FindingAdjudication.id)).filter(FindingAdjudication.finding_id == finding.id).scalar() or 0
    wire_count = db.query(func.count(ValidationWire.id)).filter(ValidationWire.finding_id == finding.id).scalar() or 0
    family = classify_family(
        title=finding.title,
        tool=finding.tool,
        owasp=str(details.get("owasp_category") or ""),
        cve=finding.cve,
        learning_family=(details.get("learning_source") or {}).get("vuln_family"),
    )
    selected_context = {
        key: details.get(key)
        for key in (
            "template_id", "parameter", "param", "method", "product", "version", "technology",
            "configuration", "identity_key", "secondary_identity_key", "object_id", "secondary_object_id", "object_id_source",
            "parser_error", "stdout_truncated_for_parser", "grounding", "poc_outcome",
            "cve_applicability", "cve_applicability_reason", "cve_applicability_checked_at",
        )
        if details.get(key) not in (None, "", [], {})
    }
    evidence = _evidence_rows(db, finding.id)
    required = list(promotion.required_artifacts or [])
    missing = list(promotion.missing_artifacts or [])
    if not promotion.can_promote and not missing:
        missing.append("positive_reproduction")
    if any(token in str(finding.title or "").lower() for token in ("idor", "bola", "access control", "authorization")):
        if len(identities) < 2:
            missing.append("second_authenticated_identity")
    intelligence = _latest_intelligence(db, finding.id)
    if str(finding.cve or "").upper().startswith("CVE-"):
        if not any(details.get(key) for key in ("version", "product_version", "detected_version", "affected_version")):
            missing.append("product_version")
        if not intelligence:
            missing.append("cve_intelligence")
        elif str(intelligence.get("applicability") or "unknown").lower() == "unknown":
            missing.append(
                "human_cve_applicability"
                if details.get("cve_applicability_checked_at")
                else "cve_applicability"
            )

    return redact({
        "finding": {
            "id": finding.id,
            "scan_job_id": finding.scan_job_id,
            "title": str(finding.title or "")[:500],
            "family": family,
            "claim": details.get("claim") or (experiment.get("experiment") or {}).get("claim") or finding.title,
            "severity_claimed": finding.severity,
            "verification_status": finding.verification_status or details.get("verification_status") or "candidate",
            "tool": finding.tool,
            "cve": finding.cve,
        },
        "target": {
            "target_ref": target,
            "host": host_from_scope_reference(target),
            "parameter_ref": _parameter_for_finding(finding),
            "in_scope": is_host_in_scope(host_from_scope_reference(target), authorized_scope_for_scan(db, job.id)),
        },
        "context": {
            "details": selected_context,
            "available_identities": identities,
            "crown_jewels": list((job.state_data or {}).get("crown_jewels") or [])[:20],
        },
        "experiment": experiment.get("experiment") or {},
        "proof_pack": experiment.get("proof_pack") or {},
        "evidence": evidence,
        "quality": {
            "required_artifacts": required,
            "missing_artifacts": list(dict.fromkeys(missing)),
            "contradictions": list(experiment.get("contradictions") or []),
            "promotion": experiment.get("promotion") or {},
            "deterministic_decision": promotion.to_dict(),
        },
        "intelligence": intelligence,
        "historical_calibration": {
            "validator": validator_metrics.get(str(finding.tool or "unknown"), {}),
            "policy": "historical results are a prior only and never override current evidence",
        },
        "approved_skill_context": _skill_context_for_family(family),
        "budgets": {
            "cycles_used": int(cycle_count),
            "cycles_remaining": max(0, MAX_CYCLES_PER_FINDING - int(cycle_count)),
            "wires_used": int(wire_count),
            "wires_remaining": max(0, MAX_WIRES_PER_FINDING - int(wire_count)),
        },
    })


def deterministic_verdict(dossier: dict[str, Any]) -> dict[str, Any]:
    """Single source of truth for final evidence state; never calls an LLM."""
    finding = dict(dossier.get("finding") or {})
    quality = dict(dossier.get("quality") or {})
    target = dict(dossier.get("target") or {})
    intelligence = dict(dossier.get("intelligence") or {})
    status = str(finding.get("verification_status") or "candidate").lower()
    missing = [str(item) for item in list(quality.get("missing_artifacts") or []) if str(item)]
    contradictions = list(quality.get("contradictions") or [])
    promotion = dict(quality.get("deterministic_decision") or {})
    details = dict((dossier.get("context") or {}).get("details") or {})

    if details.get("parser_error") or details.get("stdout_truncated_for_parser"):
        return {"verdict": "invalid_evidence", "reason_code": "parser_or_artifact_incomplete", "confidence": 0.95}
    if not target.get("in_scope"):
        return {"verdict": "blocked", "reason_code": "scope_blocked", "confidence": 1.0}
    if str(intelligence.get("applicability") or "").lower() == "not_applicable":
        return {"verdict": "not_applicable", "reason_code": "cve_version_not_affected", "confidence": 0.98}
    if status == "refuted":
        return {"verdict": "refuted", "reason_code": "explicit_negative_observation", "confidence": 0.95}
    if status == "confirmed" and bool(promotion.get("can_promote")) and not contradictions:
        return {"verdict": "confirmed", "reason_code": "positive_reproduction", "confidence": 0.98}
    if any(item in AUTH_REQUIREMENTS for item in missing) and not (dossier.get("context") or {}).get("available_identities"):
        return {"verdict": "blocked", "reason_code": "missing_authenticated_identity", "confidence": 1.0}
    if missing:
        return {"verdict": "inconclusive", "reason_code": _reason_for_missing(missing[0]), "confidence": 0.85}
    if contradictions:
        return {"verdict": "inconclusive", "reason_code": "contradictory_evidence", "confidence": 0.8}
    return {"verdict": "inconclusive", "reason_code": "insufficient_evidence", "confidence": 0.75}


def _reason_for_missing(requirement: str) -> str:
    return {
        "proof_pack": "missing_proof_pack",
        "baseline_vs_exploit": "missing_baseline_or_attempt",
        "authenticated_identity": "missing_authenticated_identity",
        "second_authenticated_identity": "missing_second_identity",
        "object_pair": "missing_object_pair",
        "positive_reproduction": "missing_positive_reproduction",
        "product_version": "missing_product_version",
        "configuration_state": "missing_configuration_state",
        "cve_intelligence": "missing_cve_intelligence",
        "cve_applicability": "missing_cve_applicability",
        "human_cve_applicability": "cve_applicability_requires_human_evidence",
    }.get(str(requirement), f"missing_{str(requirement)[:80]}")


def _extract_json(raw: str) -> dict[str, Any]:
    text = str(raw or "").strip().replace("```json", "").replace("```", "")
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        text = text[start:end + 1]
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def validate_llm_proposal(value: dict[str, Any], dossier: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed validation of the model's advisory response."""
    verdict = str(value.get("proposed_verdict") or "inconclusive").lower()
    if verdict not in ALLOWED_PROPOSED_VERDICTS:
        return {}
    try:
        confidence = max(0.0, min(1.0, float(value.get("confidence") or 0.0)))
    except (TypeError, ValueError):
        return {}
    available_evidence = {str(item.get("artifact_id")) for item in list(dossier.get("evidence") or [])}
    supporting = [str(item) for item in list(value.get("supporting_evidence_ids") or [])]
    contradicting = [str(item) for item in list(value.get("contradicting_evidence_ids") or [])]
    if any(item.removeprefix("E-") not in available_evidence for item in supporting + contradicting):
        return {}
    action = value.get("next_action")
    if action is not None:
        if not isinstance(action, dict) or str(action.get("action_id") or "") not in ALLOWED_ACTIONS:
            return {}
        if str(action.get("target_ref") or "") != str((dossier.get("target") or {}).get("target_ref") or ""):
            return {}
    return {
        "proposed_verdict": verdict,
        "confidence": confidence,
        "reason_code": str(value.get("reason_code") or "")[:120],
        "reasoning_summary": str(value.get("reasoning_summary") or "")[:2000],
        "supporting_evidence_ids": supporting,
        "contradicting_evidence_ids": contradicting,
        "missing_evidence": list(value.get("missing_evidence") or [])[:20],
        "next_action": action,
        "cvss_metric_proposal": value.get("cvss_metric_proposal"),
        "attack_path_observation": value.get("attack_path_observation"),
    }


def review_with_llm(dossier: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    if not bool(getattr(settings, "finding_adjudication_use_ollama", False)):
        return {}, {"reason": "disabled"}
    model = str(getattr(settings, "llm_primary_model", "") or getattr(settings, "ollama_model", "") or "llama3.2:3b")
    schema_instruction = (
        "Return only one JSON object with proposed_verdict, confidence, reason_code, reasoning_summary, "
        "supporting_evidence_ids, contradicting_evidence_ids, missing_evidence and next_action. "
        f"proposed_verdict must be one of {sorted(ALLOWED_PROPOSED_VERDICTS)}. "
        f"next_action.action_id must be one of {sorted(ALLOWED_ACTIONS)}. "
        "The target_ref must be copied exactly from the dossier. Never write a command, URL, hostname, "
        "payload, token, cookie, CVE, exploit URL or score that is not already present. A historical prior "
        "never overrides current evidence. Missing information is inconclusive, never a false positive."
    )
    untrusted = wrap_untrusted(
        normalize_adversarial_text(json.dumps(redact(dossier), ensure_ascii=False, default=str)),
        label="finding_adjudication_dossier",
    )
    prompt = f"{schema_instruction}\n\n{untrusted}"
    prompt_hash = _canonical_hash(prompt)
    try:
        timeout = min(20.0, max(3.0, float(getattr(settings, "finding_adjudication_timeout_seconds", 12))))
        with httpx.Client(timeout=timeout) as client:
            response = client.post(
                f"{str(settings.ollama_base_url).rstrip('/')}/api/generate",
                json=ollama_generate_payload(model, prompt, stream=False, format="json", options={"num_predict": 900}),
            )
            response.raise_for_status()
            raw = str((response.json() or {}).get("response") or "")
        proposal = validate_llm_proposal(_extract_json(raw), dossier)
        return proposal, {"model": model, "prompt_hash": prompt_hash, "reason": "ok" if proposal else "invalid_response"}
    except Exception as exc:  # noqa: BLE001
        return {}, {"model": model, "prompt_hash": prompt_hash, "reason": f"{type(exc).__name__}:{exc}"[:300]}


def _default_action(dossier: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    missing = list((dossier.get("quality") or {}).get("missing_artifacts") or [])
    family = str((dossier.get("finding") or {}).get("family") or "")
    identities = list((dossier.get("context") or {}).get("available_identities") or [])
    details = dict((dossier.get("context") or {}).get("details") or {})
    if "second_authenticated_identity" in missing or (family in {"idor_bola", "bfla_authz"} and len(identities) < 2):
        action_id = "request_human_input" if len(identities) < 2 else "compare_two_identities"
    elif "object_pair" in missing:
        action_id = "compare_two_objects" if details.get("object_id") and details.get("secondary_object_id") else "request_human_input"
    elif "authenticated_identity" in missing or "human_cve_applicability" in missing:
        action_id = "request_human_input"
    elif "baseline_vs_exploit" in missing:
        action_id = "collect_baseline"
    elif "negative_control" in missing:
        action_id = "collect_negative_control"
    elif "product_version" in missing:
        action_id = "verify_product_version"
    elif "cve_intelligence" in missing:
        action_id = "lookup_cve_intelligence"
    elif "cve_applicability" in missing:
        action_id = "verify_cve_applicability"
    elif "configuration_state" in missing:
        action_id = "verify_configuration_state"
    elif decision.get("reason_code") == "parser_or_artifact_incomplete":
        action_id = "collect_full_artifact"
    else:
        action_id = "run_family_validator"
    return {
        "action_id": action_id,
        "target_ref": str((dossier.get("target") or {}).get("target_ref") or ""),
        "input_bindings": {},
    }


def _wire_tool(action_id: str, finding: Any, parent_wire: Any = None) -> tuple[str | None, str]:
    from app.services.poc_validator import _select_validation_tool

    if action_id in {"compare_two_identities", "compare_two_objects"}:
        return "bl-test", "bl-test"
    if action_id == "verify_product_version":
        return "httpx", "httpx"
    if action_id == "verify_configuration_state":
        return "nuclei", "nuclei"
    if action_id in {"repeat_same_validator", "collect_full_artifact"} and parent_wire is not None:
        tool = str(parent_wire.tool_name or "")
        return (tool or None), str(parent_wire.profile or tool)
    tool, _ = _select_validation_tool(finding)
    return tool, str(tool or "")


def _resolve_endpoint_id(db: Session, scan_id: int, target: str) -> int | None:
    from app.models.models import OffensiveEndpoint

    rows = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == scan_id).order_by(OffensiveEndpoint.id.asc()).all()
    for row in rows:
        if str(row.normalized_url or row.url or "").strip() == target:
            return int(row.id)
    return None


def create_validation_wire(
    db: Session,
    job: Any,
    finding: Any,
    adjudication: Any,
    dossier: dict[str, Any],
    action: dict[str, Any],
    *,
    parent_wire: Any = None,
) -> Any:
    from app.models.models import ValidationWire

    action_id = str(action.get("action_id") or "")
    if action_id not in ALLOWED_ACTIONS:
        raise ValueError("unknown_validation_wire_action")
    target = str((dossier.get("target") or {}).get("target_ref") or "")
    if str(action.get("target_ref") or target) != target:
        raise ValueError("wire_target_must_match_dossier")
    identities = list((dossier.get("context") or {}).get("available_identities") or [])
    finding_context = dict((dossier.get("context") or {}).get("details") or {})
    identity_key = str(
        (action.get("input_bindings") or {}).get("identity_key")
        or finding_context.get("identity_key")
        or (identities[0].get("identity_key") if identities else "")
    )
    secondary = str(
        (action.get("input_bindings") or {}).get("secondary_identity_key")
        or finding_context.get("secondary_identity_key")
        or (identities[1].get("identity_key") if len(identities) > 1 else "")
    )
    source_artifacts = list(dossier.get("evidence") or [])
    source_artifact_id = int(source_artifacts[-1]["artifact_id"]) if source_artifacts else None
    tool, profile = _wire_tool(action_id, finding, parent_wire)
    action_bindings = dict(action.get("input_bindings") or {})
    method = str(action_bindings.get("method") or finding_context.get("method") or "GET").upper()[:16]
    object_id = str(
        action_bindings.get("object_id")
        or finding_context.get("object_id")
        or ""
    )[:500]
    secondary_object_id = str(
        action_bindings.get("secondary_object_id")
        or finding_context.get("secondary_object_id")
        or ""
    )[:500]
    payload = {
        "finding_id": finding.id,
        "dossier_hash": adjudication.dossier_hash,
        "action_id": action_id,
        "target": target,
        "parameter": str((dossier.get("target") or {}).get("parameter_ref") or ""),
        "identity": identity_key,
        "secondary_identity": secondary,
        "method": method,
        "object_id": object_id,
        "secondary_object_id": secondary_object_id,
        "source_artifact_id": source_artifact_id,
    }
    key = "wire:" + _canonical_hash(payload)[:150]
    existing = db.query(ValidationWire).filter(ValidationWire.idempotency_key == key).first()
    if existing is not None:
        return existing
    reusable = (
        db.query(ValidationWire)
        .filter(
            ValidationWire.finding_id == finding.id,
            ValidationWire.action_id == action_id,
            ValidationWire.target_ref == target,
            ValidationWire.status.in_(["planned", "queued", "blocked", "failed", "awaiting_evidence"]),
        )
        .order_by(ValidationWire.id.desc())
        .first()
    )
    if reusable is not None:
        return reusable
    host = host_from_scope_reference(target)
    prerequisite_errors: list[str] = []
    if action_id == "compare_two_identities" and not (identity_key and secondary):
        prerequisite_errors.append("two_exact_identities_required")
    if action_id == "compare_two_objects" and not (object_id and secondary_object_id):
        prerequisite_errors.append("two_exact_object_fixtures_required")
    policy_allowed = bool(
        host
        and is_host_in_scope(host, authorized_scope_for_scan(db, job.id))
        and not prerequisite_errors
    )
    status = "planned" if policy_allowed else "blocked"
    if action_id in NON_EXECUTABLE_ACTIONS:
        status = "blocked" if action_id == "request_human_input" else "planned"
    wire = ValidationWire(
        scan_job_id=job.id,
        finding_id=finding.id,
        adjudication_id=adjudication.id,
        parent_wire_id=getattr(parent_wire, "id", None),
        source_artifact_id=source_artifact_id,
        endpoint_id=_resolve_endpoint_id(db, job.id, target),
        action_id=action_id,
        status=status,
        reason_code=(
            prerequisite_errors[0]
            if prerequisite_errors
            else str(adjudication.reason_code or "missing_evidence")
        ),
        target_ref=target,
        parameter_ref=str((dossier.get("target") or {}).get("parameter_ref") or "") or None,
        identity_key=identity_key or None,
        secondary_identity_key=secondary or None,
        tool_name=tool,
        profile=profile or None,
        input_bindings={
            **action_bindings,
            "finding_id": finding.id,
            "endpoint_id": _resolve_endpoint_id(db, job.id, target),
            "target_ref": target,
            "parameter_ref": str((dossier.get("target") or {}).get("parameter_ref") or ""),
            "method": method,
            "object_id": object_id,
            "secondary_object_id": secondary_object_id,
            "identity_key": identity_key,
            "secondary_identity_key": secondary,
            "source_artifact_id": source_artifact_id,
        },
        expected_signals=ACTION_SIGNALS.get(action_id, {
            "positive": "action-specific evidence persisted against this exact wire",
            "negative": "action failed or remained ambiguous; never implicit refutation",
        }),
        policy_decision={
            "allowed": policy_allowed,
            "scope_checked": True,
            "closed_action_catalog": True,
            "reason": (
                "allowed" if policy_allowed else
                prerequisite_errors[0] if prerequisite_errors else
                "target_out_of_scope_or_unresolvable"
            ),
        },
        idempotency_key=key,
    )
    db.add(wire)
    db.flush()
    return wire


def materialize_validation_wire(db: Session, job: Any, finding: Any, wire: Any) -> bool:
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import apply_phase_tool_metadata

    if wire.status != "planned" or wire.action_id in NON_EXECUTABLE_ACTIONS:
        return False
    if not bool((wire.policy_decision or {}).get("allowed")) or not wire.tool_name or not wire.target_ref:
        wire.status = "blocked"
        db.add(wire)
        db.flush()
        return False
    storage_target = str(wire.target_ref)[:500]
    suffix = f"#easm-wire-{wire.id}"
    if len(storage_target) + len(suffix) <= 500:
        storage_target += suffix
    else:
        storage_target = storage_target[:500 - len(suffix)] + suffix
    post_scan_revalidation = str(getattr(job, "status", "") or "").lower() in {
        "completed", "completed_with_gaps", "failed", "cancelled", "canceled",
    }
    meta = {
        "validation_wire_id": wire.id,
        "verifies_finding_id": finding.id,
        "adjudication_id": wire.adjudication_id,
        "adjudication_action_id": wire.action_id,
        "execution_target": wire.target_ref,
        "target_parameter": wire.parameter_ref,
        "identity_key": wire.identity_key,
        "secondary_identity_key": wire.secondary_identity_key,
        "input_bindings": dict(wire.input_bindings or {}),
        "expected_signals": dict(wire.expected_signals or {}),
        "validation_wire": {
            "id": wire.id,
            "action_id": wire.action_id,
            "target_ref": wire.target_ref,
            "parameter_ref": wire.parameter_ref,
            "identity_key": wire.identity_key,
            "secondary_identity_key": wire.secondary_identity_key,
            "input_bindings": dict(wire.input_bindings or {}),
            "expected_signals": dict(wire.expected_signals or {}),
        },
        "poc_validation": True,
        "wire_re_evaluate_on_terminal": True,
        "post_scan_revalidation": post_scan_revalidation,
        "queue_ready_at": datetime.now().isoformat(),
    }
    item = ScanWorkItem(
        scan_job_id=job.id,
        execution_context="internal" if wire.identity_key else "external",
        phase_id="P21",
        target=storage_target,
        tool_name=str(wire.tool_name),
        profile=str(wire.profile or wire.tool_name),
        resource_class="heavy" if wire.tool_name in {"sqlmap", "dalfox", "bl-test", "jwt_tool"} else "medium",
        priority=25,
        status="queued",
        max_attempts=max(1, int(wire.max_attempts or 2)),
        item_metadata=apply_phase_tool_metadata(meta, "P21", str(wire.tool_name), source="validation_wire"),
    )
    db.add(item)
    db.flush()
    wire.work_item_id = item.id
    if str(item.status or "").lower() == "skipped":
        wire.status = "blocked"
        wire.result_summary = {
            "work_item_id": item.id,
            "reason": "scan_terminal_when_wire_materialized",
            "work_item_metadata": dict(item.item_metadata or {}).get("rejected_for_terminal_scan") or {},
        }
        db.add(wire)
        db.flush()
        return False
    wire.status = "queued"
    wire.attempt = int(wire.attempt or 0) + 1
    db.add(wire)
    db.flush()
    return True


def retry_blocked_post_scan_wire(db: Session, job: Any, finding: Any) -> dict[str, Any] | None:
    """Repair the historical terminal-scan materialisation failure in place.

    The failed transport row and its wire are reused, so clicking Reavaliar
    does not consume another adjudication cycle or wire budget.  Only the exact
    failure produced by the former terminal-scan guard is eligible.
    """
    from app.models.models import FindingAdjudication, ScanWorkItem, ValidationWire

    if str(getattr(job, "status", "") or "").lower() not in {
        "completed", "completed_with_gaps", "failed", "cancelled", "canceled",
    }:
        return None
    wire = (
        db.query(ValidationWire)
        .filter(ValidationWire.finding_id == finding.id, ValidationWire.status == "blocked")
        .order_by(ValidationWire.id.desc())
        .first()
    )
    if wire is None:
        return None
    prior = dict(wire.result_summary or {})
    if str(prior.get("reason") or "") not in {
        "scan_terminal_when_wire_materialized",
        "terminal_scan_work_item_purged",
    }:
        return None
    adjudication = (
        db.query(FindingAdjudication)
        .filter(FindingAdjudication.id == wire.adjudication_id)
        .first()
    )
    if adjudication is None:
        return None

    item = None
    if wire.work_item_id:
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == wire.work_item_id).first()
    if item is None:
        wire.status = "planned"
        wire.work_item_id = None
        db.add(wire)
        db.flush()
        if not materialize_validation_wire(db, job, finding, wire):
            return None
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == wire.work_item_id).first()
    else:
        metadata = dict(item.item_metadata or {})
        metadata.pop("rejected_for_terminal_scan", None)
        metadata.update({
            "post_scan_revalidation": True,
            "validation_wire_id": wire.id,
            "verifies_finding_id": finding.id,
            "adjudication_id": adjudication.id,
            "wire_re_evaluate_on_terminal": True,
            "queue_ready_at": datetime.now().isoformat(),
            "recovered_from": str(prior.get("reason") or "terminal_scan_guard"),
        })
        item.item_metadata = metadata
        item.status = "queued"
        item.lease_until = None
        item.started_at = None
        item.finished_at = None
        item.last_error = None
        item.result = None
        item.updated_at = datetime.now()
        db.add(item)
        wire.status = "queued"
        wire.attempt = int(wire.attempt or 0) + 1

    wire.result_summary = {
        **prior,
        "reason": "post_scan_revalidation_recovered",
        "recovered_at": datetime.now().isoformat(),
        "work_item_id": item.id if item else wire.work_item_id,
    }
    adjudication.status = "awaiting_evidence"
    adjudication.final_verdict = "inconclusive"
    adjudication.reason_code = str(wire.reason_code or "missing_evidence")
    adjudication.completed_at = None
    db.add(wire)
    db.add(adjudication)
    project_adjudication_to_finding(db, finding, adjudication)
    db.flush()
    return adjudication_to_dict(adjudication, wires=_wires_for_adjudication(db, adjudication.id))


def adjudicate_finding(db: Session, job: Any, finding: Any, *, force: bool = False) -> dict[str, Any]:
    from app.models.models import FindingAdjudication, ValidationWire

    dossier = build_adjudication_dossier(db, job, finding)
    dossier_hash = _canonical_hash(dossier)
    latest = (
        db.query(FindingAdjudication)
        .filter(FindingAdjudication.finding_id == finding.id)
        .order_by(FindingAdjudication.cycle.desc())
        .first()
    )
    if latest is not None and latest.dossier_hash == dossier_hash and not force:
        return adjudication_to_dict(latest, wires=_wires_for_adjudication(db, latest.id))
    decision = deterministic_verdict(dossier)
    cycle = int(getattr(latest, "cycle", 0) or 0) + 1
    if cycle > MAX_CYCLES_PER_FINDING:
        if latest is not None:
            terminal_after_wire = decision["verdict"] in {"confirmed", "refuted", "not_applicable"} or (
                decision["verdict"] == "blocked" and decision["reason_code"] == "scope_blocked"
            )
            if terminal_after_wire:
                # A wire launched in the last available cycle is allowed to
                # close that same cycle.  The budget limits new experiments;
                # it must never discard terminal evidence that already ran.
                latest.status = "completed"
                latest.dossier_hash = dossier_hash
                latest.dossier = dossier
                latest.final_verdict = str(decision["verdict"])
                latest.reason_code = str(decision["reason_code"])
                latest.confidence = float(decision["confidence"])
                latest.missing_evidence = list((dossier.get("quality") or {}).get("missing_artifacts") or [])
                latest.contradictions = list((dossier.get("quality") or {}).get("contradictions") or [])
                latest.supporting_evidence_ids = [item.get("artifact_id") for item in list(dossier.get("evidence") or [])]
                latest.completed_at = datetime.now()
                project_adjudication_to_finding(db, finding, latest)
                record_adjudication_feedback(db, job, finding, latest)
                db.add(latest)
                db.add(finding)
                db.flush()
                persist_attack_paths(db, job)
                return adjudication_to_dict(latest, wires=_wires_for_adjudication(db, latest.id))
            latest.status = "budget_exhausted"
            latest.final_verdict = "needs_human_review"
            latest.reason_code = "adjudication_budget_exhausted"
            latest.completed_at = datetime.now()
            project_adjudication_to_finding(db, finding, latest)
            record_adjudication_feedback(db, job, finding, latest)
            db.add(latest)
            db.add(finding)
            db.flush()
            return adjudication_to_dict(latest, wires=_wires_for_adjudication(db, latest.id))
        raise RuntimeError("adjudication_budget_exhausted")

    proposal: dict[str, Any] = {}
    model_meta: dict[str, str] = {"reason": "not_needed"}
    if decision["verdict"] == "inconclusive":
        proposal, model_meta = review_with_llm(dossier)
    adjudication = FindingAdjudication(
        scan_job_id=job.id,
        finding_id=finding.id,
        cycle=cycle,
        status="reviewing",
        dossier_hash=dossier_hash,
        dossier=dossier,
        proposed_verdict=proposal.get("proposed_verdict"),
        final_verdict=str(decision["verdict"]),
        reason_code=str(decision["reason_code"]),
        confidence=float(decision["confidence"]),
        missing_evidence=list((dossier.get("quality") or {}).get("missing_artifacts") or []),
        contradictions=list((dossier.get("quality") or {}).get("contradictions") or []),
        supporting_evidence_ids=[item.get("artifact_id") for item in list(dossier.get("evidence") or [])],
        model_name=model_meta.get("model"),
        prompt_hash=model_meta.get("prompt_hash"),
        model_response=proposal,
        decision_metadata={
            "llm": model_meta,
            "single_judge": "deterministic_evidence_gate",
            "shadow_mode": bool(getattr(settings, "finding_adjudication_shadow_mode", True)),
        },
    )
    db.add(adjudication)
    db.flush()

    wires: list[Any] = []
    terminal_without_followup = decision["verdict"] in {"confirmed", "refuted", "not_applicable"} or (
        decision["verdict"] == "blocked" and decision["reason_code"] == "scope_blocked"
    )
    if terminal_without_followup:
        adjudication.status = "completed"
        adjudication.completed_at = datetime.now()
    else:
        total_wires = db.query(func.count(ValidationWire.id)).filter(ValidationWire.finding_id == finding.id).scalar() or 0
        if int(total_wires) >= MAX_WIRES_PER_FINDING:
            adjudication.status = "budget_exhausted"
            adjudication.final_verdict = "needs_human_review"
            adjudication.reason_code = "validation_wire_budget_exhausted"
            adjudication.completed_at = datetime.now()
        else:
            # Shadow mode records/calibrates the model proposal but keeps the
            # established deterministic recipe in control of execution.
            model_action = proposal.get("next_action") if not bool(
                getattr(settings, "finding_adjudication_shadow_mode", True)
            ) else None
            action = dict(model_action or _default_action(dossier, decision))
            wire = create_validation_wire(db, job, finding, adjudication, dossier, action)
            wires.append(wire)
            if wire.action_id == "request_human_input" or wire.status == "blocked":
                adjudication.status = "blocked"
                adjudication.final_verdict = "blocked"
                adjudication.reason_code = wire.reason_code or "missing_required_input"
                adjudication.completed_at = datetime.now()
            elif wire.action_id in {"lookup_cve_intelligence", "lookup_public_exploit", "verify_cve_applicability"}:
                refresh_finding_intelligence(db, job, finding)
                wire.status = "completed"
                wire.completed_at = datetime.now()
                adjudication.status = "awaiting_re_evaluation"
            elif wire.action_id == "rebuild_attack_path":
                persist_attack_paths(db, job)
                wire.status = "completed"
                wire.completed_at = datetime.now()
                adjudication.status = "awaiting_re_evaluation"
            elif materialize_validation_wire(db, job, finding, wire):
                adjudication.status = "awaiting_evidence"
            else:
                adjudication.status = "blocked"
                adjudication.final_verdict = "blocked"
                adjudication.reason_code = "wire_not_materializable"
                adjudication.completed_at = datetime.now()

    details = dict(finding.details or {})
    details["adjudication"] = {
        "id": adjudication.id,
        "cycle": adjudication.cycle,
        "status": adjudication.status,
        "final_verdict": adjudication.final_verdict,
        "reason_code": adjudication.reason_code,
        "wire_ids": [wire.id for wire in wires],
    }
    finding.details = details
    project_adjudication_to_finding(db, finding, adjudication)
    record_adjudication_feedback(db, job, finding, adjudication)
    db.add(finding)
    db.add(adjudication)
    db.flush()
    persist_attack_paths(db, job)
    if wires and wires[0].action_id in {
        "lookup_cve_intelligence", "lookup_public_exploit", "verify_cve_applicability",
    } and wires[0].status == "completed":
        # Internal evidence actions have already changed the persisted dossier;
        # do not strand them in awaiting_re_evaluation until another scan gate.
        return adjudicate_finding(db, job, finding, force=True)
    return adjudication_to_dict(adjudication, wires=[wire_to_dict(wire) for wire in wires])


def project_adjudication_to_finding(db: Session, finding: Any, adjudication: Any) -> None:
    """Project the evidence decision into every legacy consumer of Finding.

    The adjudication table remains the audit source of truth, while this
    projection prevents risk/report/attack-path code from continuing to use a
    stale pre-adjudication status.
    """
    from app.models.models import CoverageItem

    verdict = str(adjudication.final_verdict or "inconclusive").lower()
    reason = str(adjudication.reason_code or "insufficient_evidence")
    finding.verification_status = verdict
    finding.is_false_positive = verdict in {"refuted", "not_applicable"}
    details = dict(finding.details or {})
    if verdict == "confirmed" and not str(finding.recommendation or "").strip():
        try:
            from app.services.findings_extractor import _finding_recommendation_text

            finding.recommendation = _finding_recommendation_text(
                details,
                str(finding.severity or "medium"),
                finding.cve,
            )
        except Exception:
            logger.debug("deterministic recommendation projection failed finding=%s", finding.id, exc_info=True)
    if verdict == "confirmed" and not str(finding.cve or "").upper().startswith("CVE-"):
        estimate = estimate_cvss31_for_finding(finding)
        details["adjudicated_cvss"] = estimate
        if finding.cvss is None:
            finding.cvss = float(estimate["score"])
    details["adjudication"] = {
        **dict(details.get("adjudication") or {}),
        "id": adjudication.id,
        "cycle": adjudication.cycle,
        "status": adjudication.status,
        "final_verdict": verdict,
        "reason_code": reason,
        "false_positive": bool(finding.is_false_positive),
        "false_positive_cause": (
            "incorrect_information" if verdict in {"refuted", "not_applicable"} else
            "missing_information" if verdict in {"inconclusive", "blocked", "needs_human_review"} else
            "invalid_evidence" if verdict == "invalid_evidence" else None
        ),
    }
    finding.details = details
    db.add(finding)
    rows = db.query(CoverageItem).filter(
        CoverageItem.scan_job_id == finding.scan_job_id,
        CoverageItem.finding_id == finding.id,
    ).all()
    for row in rows:
        row.status = verdict
        row.blocking_reason = None if verdict == "confirmed" else reason
        db.add(row)


def record_adjudication_feedback(db: Session, job: Any, finding: Any, adjudication: Any) -> None:
    """Calibrate model proposals only after a deterministic terminal answer exists."""
    metadata = dict(adjudication.decision_metadata or {})
    if metadata.get("feedback_recorded") or not adjudication.proposed_verdict:
        return
    final = str(adjudication.final_verdict or "")
    if final not in TERMINAL_VERDICTS:
        return
    try:
        from app.services.pentest_outcome_learning import record_outcome

        agreed = str(adjudication.proposed_verdict) == final
        record_outcome(
            db,
            job,
            dimension="adjudication_model",
            metric_key=str(adjudication.model_name or "unknown"),
            outcome="success" if agreed else "failed",
            context=str((adjudication.dossier or {}).get("finding", {}).get("family") or "global"),
            metadata={
                "finding_id": finding.id,
                "cycle": adjudication.cycle,
                "proposed_verdict": adjudication.proposed_verdict,
                "final_verdict": final,
                "agreement": agreed,
                "reason_code": adjudication.reason_code,
            },
        )
        metadata["feedback_recorded"] = True
        metadata["model_agreed_with_final"] = agreed
        adjudication.decision_metadata = metadata
        db.add(adjudication)
    except Exception:
        logger.debug("adjudication feedback persistence failed finding=%s", finding.id, exc_info=True)


def _cvss_round_up(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def estimate_cvss31_for_finding(finding: Any) -> dict[str, Any]:
    """Produce a transparent CVSS 3.1 estimate for confirmed non-CVE logic flaws."""
    from app.services.vuln_family import classify_family

    details = dict(finding.details or {})
    family = classify_family(
        title=finding.title,
        tool=finding.tool,
        owasp=str(details.get("owasp_category") or ""),
        cve=None,
        learning_family=(details.get("learning_source") or {}).get("vuln_family"),
    )
    ui = "R" if family in {"xss", "csrf", "clickjacking"} else "N"
    scope = "C" if family in {"xss", "ssrf"} else "U"
    pr = "L" if details.get("identity_key") or details.get("authenticated") else "N"
    impacts = {
        "rce": ("H", "H", "H"),
        "sqli": ("H", "H", "H"),
        "auth_bypass": ("H", "H", "N"),
        "idor_bola": ("H", "H", "N"),
        "bfla_authz": ("H", "H", "N"),
        "business_logic_mass_assignment": ("L", "H", "N"),
        "secret_exposure": ("H", "L", "N"),
        "data_exposure": ("H", "N", "N"),
        "information_disclosure": ("L", "N", "N"),
        "xss": ("L", "L", "N"),
        "ssrf": ("H", "L", "L"),
    }
    confidentiality, integrity, availability = impacts.get(
        family,
        ("L", "L", "N") if str(finding.severity or "").lower() in {"low", "medium"} else ("H", "L", "N"),
    )
    av_v, ac_v, ui_v = 0.85, 0.77, 0.62 if ui == "R" else 0.85
    pr_values = {("N", "U"): 0.85, ("L", "U"): 0.62, ("H", "U"): 0.27, ("N", "C"): 0.85, ("L", "C"): 0.68, ("H", "C"): 0.50}
    impact_value = {"N": 0.0, "L": 0.22, "H": 0.56}
    isc = 1 - (
        (1 - impact_value[confidentiality])
        * (1 - impact_value[integrity])
        * (1 - impact_value[availability])
    )
    impact = (
        6.42 * isc
        if scope == "U"
        else 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    )
    exploitability = 8.22 * av_v * ac_v * pr_values[(pr, scope)] * ui_v
    score = 0.0 if impact <= 0 else _cvss_round_up(min(10.0, (impact + exploitability) * (1.08 if scope == "C" else 1.0)))
    vector = f"CVSS:3.1/AV:N/AC:L/PR:{pr}/UI:{ui}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    return {
        "version": "3.1",
        "vector": vector,
        "score": score,
        "source": "deterministic_platform_estimate",
        "family": family,
        "justification": "metrics derived from confirmed family, authentication precondition and demonstrated impact; not an official NVD score",
    }


def link_existing_work_item_wire(db: Session, job: Any, finding: Any, item: Any) -> Any:
    """Wrap a legacy poc_validator item in a durable wire without rescheduling it."""
    from app.models.models import ValidationWire

    key = f"wire:existing-work-item:{item.id}"
    existing = db.query(ValidationWire).filter(ValidationWire.idempotency_key == key).first()
    if existing is not None:
        return existing
    details = dict(finding.details or {})
    target = str((item.item_metadata or {}).get("execution_target") or _target_for_finding(finding))
    wire = ValidationWire(
        scan_job_id=job.id,
        finding_id=finding.id,
        work_item_id=item.id,
        phase_id="P21",
        action_id="run_family_validator",
        status="queued",
        reason_code="missing_positive_reproduction",
        target_ref=target,
        parameter_ref=str((item.item_metadata or {}).get("target_parameter") or _parameter_for_finding(finding)) or None,
        identity_key=str((item.item_metadata or {}).get("identity_key") or details.get("identity_key") or "") or None,
        secondary_identity_key=str((item.item_metadata or {}).get("secondary_identity_key") or details.get("secondary_identity_key") or "") or None,
        tool_name=item.tool_name,
        profile=item.profile,
        input_bindings={
            "finding_id": finding.id,
            "target_ref": target,
            "parameter_ref": str((item.item_metadata or {}).get("target_parameter") or ""),
            "source": "legacy_poc_validator",
        },
        expected_signals={
            "positive": "tool-specific positive proof",
            "negative": "explicit negative observation",
        },
        policy_decision={"allowed": True, "source": "existing_guarded_work_item"},
        attempt=max(1, int(item.attempts or 0)),
        max_attempts=max(1, int(item.max_attempts or 2)),
        idempotency_key=key,
    )
    db.add(wire)
    db.flush()
    metadata = dict(item.item_metadata or {})
    metadata["validation_wire_id"] = wire.id
    metadata["wire_re_evaluate_on_terminal"] = True
    item.item_metadata = metadata
    db.add(item)
    db.flush()
    return wire


def classify_validation_wire_result(wire: Any, item: Any, finding: Any) -> dict[str, Any]:
    """Validate the observed signal against the bound claim, not tool syntax.

    ``matched-at`` only means that a Nuclei template matched.  It does not mean
    that an unrelated HIGH credential-exposure claim was reproduced.  The wire
    therefore compares structured template metadata with the finding family,
    claim and severity before accepting the generic PoC classifier's signal.
    """
    from app.services.poc_outcome import classify_poc_work_item
    from app.services.vuln_family import classify_family

    base = classify_poc_work_item(item)
    if str(getattr(wire, "action_id", "") or "") != "run_family_validator":
        return base
    if str(getattr(item, "status", "") or "").lower() not in {"completed", "done"}:
        return base
    result = dict(getattr(item, "result", None) or {})
    parsed = result.get("parsed_result") or result.get("parsed") or []
    observations = parsed if isinstance(parsed, list) else [parsed]
    observations = [row for row in observations if isinstance(row, dict)]
    family = classify_family(
        title=getattr(finding, "title", None),
        tool=getattr(finding, "tool", None),
        owasp=str((getattr(finding, "details", None) or {}).get("owasp_category") or ""),
        cve=getattr(finding, "cve", None),
        learning_family=((getattr(finding, "details", None) or {}).get("learning_source") or {}).get("vuln_family"),
    )
    if family not in {"info_exposure", "information_disclosure", "secret_exposure", "data_exposure"}:
        return base

    claim = " ".join(filter(None, [
        str(getattr(finding, "title", "") or ""),
        str((getattr(finding, "details", None) or {}).get("claim") or ""),
    ])).lower()
    claim_requires_secret = any(token in claim for token in (
        "credential", "password", "senha", "secret", "api key", "api-key", "access token", "private key",
    ))
    observed_metadata: list[str] = []
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    observed_max = -1
    for row in observations:
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        severity = str(row.get("severity") or info.get("severity") or "info").lower()
        observed_max = max(observed_max, severity_rank.get(severity, -1))
        observed_metadata.extend([
            str(row.get("template-id") or row.get("template_id") or ""),
            str(info.get("name") or ""),
            str(info.get("description") or ""),
            " ".join(str(value) for value in list(info.get("tags") or [])),
        ])
    metadata_blob = " ".join(observed_metadata).lower()
    secret_signal = any(token in metadata_blob for token in (
        "credential", "password", "secret", "api-key", "api key", "access-token", "private-key", "private key",
    ))
    claimed_rank = severity_rank.get(str(getattr(finding, "severity", "") or "").lower(), 0)

    if claim_requires_secret and not secret_signal:
        return {
            "result": "refuted",
            "reason": "claim_mismatch:no_credential_or_secret_exposure_observed",
            "positive_signal": False,
            "negative_signal": True,
            "generic_tool_outcome": base,
            "observed_templates": [value for value in observed_metadata if value][:20],
        }
    if observations and observed_max < claimed_rank:
        return {
            "result": "refuted",
            "reason": "claim_mismatch:observed_severity_below_claimed_severity",
            "positive_signal": False,
            "negative_signal": True,
            "generic_tool_outcome": base,
            "observed_max_severity_rank": observed_max,
            "claimed_severity_rank": claimed_rank,
        }
    if not observations and str(base.get("result") or "") != "confirmed":
        return {
            "result": "refuted",
            "reason": "explicit_negative_signal:completed_exact_validator_without_matching_observation",
            "positive_signal": False,
            "negative_signal": True,
            "generic_tool_outcome": base,
        }
    return base


def consume_validation_wire_result(
    db: Session,
    job: Any,
    item: Any,
    *,
    force_reconcile: bool = False,
) -> dict[str, Any]:
    from app.models.models import Finding, ValidationWire

    metadata = dict(item.item_metadata or {})
    wire_id = metadata.get("validation_wire_id")
    wire = None
    if wire_id:
        wire = db.query(ValidationWire).filter(ValidationWire.id == int(wire_id)).first()
    if wire is None:
        wire = db.query(ValidationWire).filter(ValidationWire.work_item_id == item.id).first()
    if wire is None:
        return {"consumed": False, "reason": "work_item_has_no_validation_wire"}
    previous = dict(wire.result_summary or {})
    if (
        not force_reconcile
        and previous.get("consumed_work_item_id") == item.id
        and wire.status in {"completed", "failed"}
    ):
        return {"consumed": False, "wire_id": wire.id, "reason": "wire_result_already_consumed"}
    status = str(item.status or "").lower()
    finding = db.query(Finding).filter(Finding.id == wire.finding_id).first()
    if finding is None:
        from app.services.poc_outcome import classify_poc_work_item

        decision = classify_poc_work_item(item)
    else:
        decision = classify_validation_wire_result(wire, item, finding)
    wire.status = "completed" if status in {"completed", "done"} else "failed"
    wire.completed_at = datetime.now()
    wire.result_summary = {
        "work_item_id": item.id,
        "work_item_status": status,
        "poc_outcome": decision,
        "finished_at": item.finished_at.isoformat() if item.finished_at else None,
        "consumed_work_item_id": item.id,
    }
    db.add(wire)
    if finding is None:
        db.flush()
        return {"consumed": True, "wire_id": wire.id, "reason": "finding_missing"}
    details = dict(finding.details or {})
    reproduction = dict(details.get("reproduction") or {})
    reproduction.update({
        "source": "validation_wire",
        "wire_id": wire.id,
        "tool": wire.tool_name,
        "profile": wire.profile,
        "exact_target": wire.target_ref,
        "parameter": wire.parameter_ref,
        "identity_refs": [key for key in (wire.identity_key, wire.secondary_identity_key) if key],
        "preconditions": [
            f"scope policy allowed={bool((wire.policy_decision or {}).get('allowed'))}",
            *(["primary authenticated identity available"] if wire.identity_key else []),
            *(["secondary authenticated identity available"] if wire.secondary_identity_key else []),
        ],
        "steps": [
            f"Execute the closed action {wire.action_id} with profile {wire.profile or wire.tool_name} on the exact bound target.",
            "Preserve the raw and parsed result under the work-item reference.",
            "Compare the observation with the wire positive and negative signals; do not infer refutation from failure or timeout.",
        ],
        "expected_signals": dict(wire.expected_signals or {}),
        "observed_result_ref": f"scan-work-item:{item.id}",
        "observed_outcome": decision,
    })
    details["reproduction"] = reproduction
    details["poc_outcome"] = decision
    if str(decision.get("result") or "") in {"confirmed", "refuted"}:
        finding.verification_status = str(decision["result"])
        finding.is_false_positive = decision["result"] == "refuted"
        try:
            from app.services.exploitation_evidence import persist_p21_validation_record

            validation_record = persist_p21_validation_record(
                db,
                job,
                finding,
                item,
                confirmed=decision["result"] == "confirmed",
            )
            details["p21_validation_record"] = validation_record
            details["proof_pack_missing"] = False
        except Exception:
            logger.warning("wire proof-pack persistence failed wire=%s item=%s", wire.id, item.id, exc_info=True)
    finding.details = details
    db.add(finding)
    if wire.action_id == "collect_full_artifact" and wire.status == "completed":
        raw_result = dict(item.result or {}) if isinstance(item.result, dict) else {}
        if raw_result.get("stdout_full") or raw_result.get("parsed_result") or raw_result.get("parsed"):
            details = dict(finding.details or {})
            details["stdout_truncated_for_parser"] = False
            if raw_result.get("parsed_result") or raw_result.get("parsed"):
                details["parser_error"] = False
            details["full_artifact_recollected_by_wire_id"] = wire.id
            finding.details = details
            db.add(finding)
    if wire.action_id == "verify_product_version" and wire.status == "completed":
        raw_result = dict(item.result or {}) if isinstance(item.result, dict) else {}
        parsed = raw_result.get("parsed_result") or raw_result.get("parsed") or {}
        candidates = parsed if isinstance(parsed, list) else [parsed]
        product = version = ""
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            product = str(candidate.get("product") or candidate.get("technology") or candidate.get("name") or product)
            version = str(candidate.get("version") or candidate.get("product_version") or candidate.get("detected_version") or version)
            if version:
                break
        if product or version:
            details = dict(finding.details or {})
            if product:
                details["product"] = product[:255]
            if version:
                details["version"] = version[:120]
            details["version_verified_by_wire_id"] = wire.id
            finding.details = details
            db.add(finding)
    db.flush()
    adjudication = adjudicate_finding(db, job, finding, force=True)
    try:
        from app.services.pentest_outcome_learning import record_outcome

        record_outcome(
            db,
            job,
            dimension="validation_wire_action",
            metric_key=str(wire.action_id),
            outcome=str(adjudication.get("final_verdict") or "candidate"),
            context=str(wire.tool_name or "internal"),
            metadata={
                "finding_id": finding.id,
                "wire_id": wire.id,
                "work_item_id": item.id,
                "reason_code": adjudication.get("reason_code"),
            },
        )
    except Exception:
        logger.debug("wire action feedback persistence failed wire=%s", wire.id, exc_info=True)
    persist_attack_paths(db, job)
    return {"consumed": True, "wire_id": wire.id, "adjudication": adjudication}


def consume_terminal_validation_wire(db: Session, job: Any, item: Any) -> dict[str, Any]:
    """Single terminal hook shared by local execution and asynchronous polling."""
    metadata = dict(getattr(item, "item_metadata", None) or {})
    status = str(getattr(item, "status", "") or "").lower()
    if str(getattr(item, "phase_id", "") or "") != "P21" or not metadata.get("validation_wire_id"):
        return {"consumed": False, "reason": "not_a_validation_wire_item"}
    if status not in {"completed", "done", "failed", "timeout", "skipped"}:
        return {"consumed": False, "reason": "work_item_not_terminal"}
    return consume_validation_wire_result(db, job, item)


def _version_parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", str(value or ""))[:6])


def _compare_versions(left: str, right: str) -> int | None:
    a, b = _version_parts(left), _version_parts(right)
    if not a or not b:
        return None
    width = max(len(a), len(b))
    padded_a, padded_b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (padded_a > padded_b) - (padded_a < padded_b)


def _cpe_product(criteria: str) -> tuple[str, str]:
    parts = str(criteria or "").split(":")
    return (
        parts[3].replace("_", " ").lower() if len(parts) > 3 else "",
        parts[4].replace("_", " ").lower() if len(parts) > 4 else "",
    )


def determine_cve_applicability(
    *, product: str, version: str, affected_ranges: list[dict[str, Any]],
) -> tuple[str, str]:
    """Conservatively match an observed product/version to NVD CPE ranges."""
    product_norm = str(product or "").replace("_", " ").lower().strip()
    if not product_norm or not _version_parts(version):
        return "unknown", "observed_product_or_version_missing"
    matched_product = False
    indeterminate = False
    for raw in affected_ranges:
        row = dict(raw or {})
        vendor, cpe_product = _cpe_product(str(row.get("criteria") or ""))
        if not cpe_product or not (
            cpe_product in product_norm or product_norm in cpe_product
            or (vendor and vendor in product_norm)
        ):
            continue
        matched_product = True
        comparisons = {
            key: _compare_versions(version, str(row.get(key) or ""))
            for key in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
            )
            if row.get(key)
        }
        if any(value is None for value in comparisons.values()):
            indeterminate = True
            continue
        applies = True
        if "versionStartIncluding" in comparisons:
            applies &= comparisons["versionStartIncluding"] >= 0
        if "versionStartExcluding" in comparisons:
            applies &= comparisons["versionStartExcluding"] > 0
        if "versionEndIncluding" in comparisons:
            applies &= comparisons["versionEndIncluding"] <= 0
        if "versionEndExcluding" in comparisons:
            applies &= comparisons["versionEndExcluding"] < 0
        # An NVD CPE with no explicit bounds can encode an exact version in
        # the criteria field.  Treat wildcard as affected, exact otherwise.
        if not comparisons:
            cpe_parts = str(row.get("criteria") or "").split(":")
            cpe_version = cpe_parts[5] if len(cpe_parts) > 5 else "*"
            if cpe_version not in {"", "*", "-"}:
                exact_cmp = _compare_versions(version, cpe_version)
                if exact_cmp is None:
                    indeterminate = True
                    continue
                applies = exact_cmp == 0
        if applies:
            return "applicable", "observed_version_matches_nvd_affected_range"
    if matched_product and not indeterminate:
        return "not_applicable", "observed_version_outside_nvd_affected_ranges"
    return "unknown", "no_deterministic_product_range_match"


def refresh_finding_intelligence(db: Session, job: Any, finding: Any) -> dict[str, Any]:
    from app.models.models import FindingIntelligenceSnapshot
    from app.services.cve_enrichment_service import enrichment_service
    from app.services.epss_service import get_epss_scores
    from app.services.exploitdb_check import check_exploitdb

    cve = str(finding.cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        return {"refreshed": False, "reason": "finding_has_no_cve"}
    data = enrichment_service.enrich(cve)
    epss = get_epss_scores([cve]).get(cve, {})
    exploit = check_exploitdb(cve)
    vector = str(data.get("cvss_vector") or "") or None
    version = vector.split("/")[0].replace("CVSS:", "") if vector and vector.startswith("CVSS:") else None
    refs = [
        {"source": "nvd", "url": f"https://nvd.nist.gov/vuln/detail/{cve}", "verified": bool(data)},
        *[
            {"source": "exploitdb", **dict(ref), "verified": True}
            for ref in list(exploit.get("refs") or [])
        ],
    ]
    details = dict(finding.details or {})
    observed_product = str(details.get("product") or details.get("technology") or "")
    observed_version = str(
        details.get("version") or details.get("product_version")
        or details.get("detected_version") or ""
    )
    applicability, applicability_reason = determine_cve_applicability(
        product=observed_product,
        version=observed_version,
        affected_ranges=list(data.get("affected_ranges") or []),
    )
    snapshot = FindingIntelligenceSnapshot(
        scan_job_id=job.id,
        finding_id=finding.id,
        cve_id=cve,
        applicability=applicability,
        cvss_version=version,
        cvss_vector=vector,
        cvss_score=float(data["cvss_base_score"]) if data.get("cvss_base_score") is not None else finding.cvss,
        cvss_source="NVD" if data.get("cvss_base_score") is not None else None,
        epss_score=float(epss["epss"]) if epss.get("epss") is not None else None,
        epss_percentile=float(epss["percentile"]) if epss.get("percentile") is not None else None,
        kev=True if data.get("known_exploited") else False if data else None,
        public_exploit_status="found" if exploit.get("available") is True else "not_found" if exploit.get("available") is False else "unknown",
        references=refs,
        source_payload={
            "nvd_kev": data,
            "epss": epss,
            "exploitdb": exploit,
            "applicability": {
                "status": applicability,
                "reason": applicability_reason,
                "observed_product": observed_product,
                "observed_version": observed_version,
            },
        },
    )
    db.add(snapshot)
    db.flush()
    details = dict(finding.details or {})
    details["cve_applicability"] = applicability
    details["cve_applicability_reason"] = applicability_reason
    details["cve_applicability_checked_at"] = datetime.now().isoformat()
    details["intelligence_snapshot"] = {
        "id": snapshot.id,
        "cve": cve,
        "applicability": applicability,
        "cvss_vector": vector,
        "epss": epss,
        "kev": snapshot.kev,
        "public_exploit_status": snapshot.public_exploit_status,
    }
    finding.details = details
    if snapshot.cvss_score is not None:
        finding.cvss = snapshot.cvss_score
    db.add(finding)
    db.flush()
    return {"refreshed": True, "snapshot_id": snapshot.id, **details["intelligence_snapshot"]}


def persist_attack_paths(db: Session, job: Any) -> dict[str, Any]:
    """Persist the current evidence-aware graph snapshot after every wire result."""
    from app.services.attack_path import build_attack_paths

    result = build_attack_paths(db, job.id, job=job)
    state = dict(job.state_data or {})
    state["adjudicated_attack_paths"] = {
        "generated_at": datetime.now().isoformat(),
        "source": "validation_wire_re_evaluation",
        **result,
    }
    job.state_data = state
    db.add(job)
    db.flush()
    return result


def build_finding_assessment(db: Session, job: Any, finding: Any) -> dict[str, Any]:
    """Answer the complete P21/P22 question set from persisted, attributed data."""
    from app.models.models import FindingAdjudication, FindingIntelligenceSnapshot, ScanWorkItem, ValidationWire

    adjudication = (
        db.query(FindingAdjudication)
        .filter(FindingAdjudication.finding_id == finding.id)
        .order_by(FindingAdjudication.cycle.desc())
        .first()
    )
    wires = (
        db.query(ValidationWire)
        .filter(ValidationWire.finding_id == finding.id)
        .order_by(ValidationWire.id.asc())
        .all()
    )
    intelligence = (
        db.query(FindingIntelligenceSnapshot)
        .filter(FindingIntelligenceSnapshot.finding_id == finding.id)
        .order_by(FindingIntelligenceSnapshot.fetched_at.desc(), FindingIntelligenceSnapshot.id.desc())
        .first()
    )
    work_item_ids = [int(wire.work_item_id) for wire in wires if wire.work_item_id is not None]
    work_items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id == "P21",
            ScanWorkItem.id.in_(work_item_ids),
        )
        .all()
        if work_item_ids else []
    )
    work_by_id = {int(item.id): item for item in work_items}
    details = dict(finding.details or {})
    verdict = str(getattr(adjudication, "final_verdict", None) or finding.verification_status or "inconclusive")
    reason = str(getattr(adjudication, "reason_code", None) or "insufficient_evidence")
    missing = list(getattr(adjudication, "missing_evidence", None) or [])
    false_positive = verdict in {"refuted", "not_applicable"}
    false_positive_cause = (
        "incorrect_information" if false_positive else
        "missing_information" if verdict in {"inconclusive", "blocked", "needs_human_review"} else
        "invalid_evidence" if verdict == "invalid_evidence" else None
    )

    recs = dict(details.get("recommendations") or {})
    system_rec = recs.get("system") if isinstance(recs.get("system"), dict) else {}
    recommendation = str(
        finding.recommendation
        or details.get("remediation")
        or details.get("blue_team_action")
        or system_rec.get("text")
        or ""
    ).strip()
    reproduction = dict(details.get("reproduction") or {})
    raw_steps = reproduction.get("steps") or details.get("reproduction_steps") or details.get("steps_to_reproduce") or []
    steps = [str(item) for item in raw_steps] if isinstance(raw_steps, list) else [str(raw_steps)] if raw_steps else []
    raw_payloads = reproduction.get("payloads") or []
    payloads = list(raw_payloads) if isinstance(raw_payloads, list) else [raw_payloads] if raw_payloads else []
    if reproduction.get("payload"):
        payloads.append(reproduction.get("payload"))
    if details.get("payload"):
        payloads.append(details.get("payload"))
    observed_runs: list[dict[str, Any]] = []
    for wire in wires:
        item = work_by_id.get(int(wire.work_item_id)) if wire.work_item_id is not None else None
        observed_runs.append({
            "wire": wire_to_dict(wire),
            "work_item_status": str(getattr(item, "status", "") or "") or None,
            "poc_outcome": dict((wire.result_summary or {}).get("poc_outcome") or {}),
            "result_ref": f"scan-work-item:{item.id}" if item is not None else None,
        })

    intel = _latest_intelligence(db, finding.id)
    exploit_refs = [
        ref for ref in list(intel.get("references") or [])
        if str(ref.get("source") or "").lower() not in {"nvd"}
    ]
    attack_paths = [
        path for path in list(((job.state_data or {}).get("adjudicated_attack_paths") or {}).get("paths") or [])
        if any(str(step.get("signal_id") or "") == f"F-{finding.id}" for step in list(path.get("steps") or []))
    ]
    cvss = dict((intel.get("cvss") or {}))
    if cvss.get("score") is None and details.get("adjudicated_cvss"):
        cvss = dict(details.get("adjudicated_cvss") or {})
    elif cvss.get("score") is None and finding.cvss is not None:
        cvss = {
            "score": float(finding.cvss),
            "vector": details.get("cvss_vector") or details.get("cvss_metrics"),
            "source": details.get("cvss_source") or "finding_source",
        }
    if false_positive:
        # Scores, exploit lookup and remediation belong to an accepted
        # vulnerability.  Keeping the scanner's original 7.5 after a refutation
        # makes the P22 answers contradict the final evidence verdict.
        cvss = {"score": None, "vector": None, "source": "not_applicable_refuted_finding"}
        recommendation = ""
        exploit_refs = []

    return redact({
        "finding_id": finding.id,
        "answers": {
            "does_it_make_sense": {
                "answer": True if verdict == "confirmed" else False if false_positive else None,
                "verdict": verdict,
                "reason_code": reason,
                "confidence": float(getattr(adjudication, "confidence", 0.0) or 0.0),
            },
            "false_positive": {
                "answer": True if false_positive else False if verdict == "confirmed" else None,
                "cause": false_positive_cause,
                "missing_information": missing if false_positive_cause == "missing_information" else [],
                "incorrect_information_reason": reason if false_positive else None,
            },
            "missing_evidence": missing,
            "what_was_executed": observed_runs,
            "recommendation": {
                "status": "not_applicable" if false_positive else "available" if recommendation else "missing",
                "text": recommendation,
                "retest_required": verdict == "confirmed",
            },
            "poc": {
                "status": "reproduced" if verdict == "confirmed" else "refuted" if false_positive else "available" if steps or payloads else "missing",
                "exact_target": _target_for_finding(finding),
                "preconditions": list(reproduction.get("preconditions") or []),
                "steps": steps,
                "payloads": list(dict.fromkeys(str(item) for item in payloads if str(item))),
                "observed_runs": observed_runs,
            },
            "public_exploit": {
                "exists": False if false_positive else True if intel.get("public_exploit_status") == "found" else False if intel.get("public_exploit_status") == "not_found" else None,
                "status": "not_applicable" if false_positive else intel.get("public_exploit_status") or "unknown",
                "urls": [ref.get("url") for ref in exploit_refs if ref.get("url")],
                "sources": exploit_refs,
            },
            "attack_path": {
                "mounted": bool(attack_paths),
                "paths": attack_paths,
                "needs_rebuild": not bool(attack_paths) and verdict == "confirmed",
            },
            "cve": {
                "exists": False if false_positive else bool(str(finding.cve or "").upper().startswith("CVE-")),
                "id": None if false_positive else finding.cve,
                "applicability": "not_applicable" if false_positive else intel.get("applicability") or "unknown",
                "source": None if false_positive else "NVD" if intelligence is not None else None,
            },
            "cvss": cvss or {"score": None, "vector": None, "source": "unknown"},
            "additional_context": {
                "contradictions": list(getattr(adjudication, "contradictions", None) or []),
                "scope_allowed": bool((getattr(adjudication, "dossier", None) or {}).get("target", {}).get("in_scope")) if adjudication else None,
                "cycles": int(getattr(adjudication, "cycle", 0) or 0),
                "wire_budget_exhausted": str(getattr(adjudication, "status", "")) == "budget_exhausted",
            },
        },
    })


def _wires_for_adjudication(db: Session, adjudication_id: int) -> list[dict[str, Any]]:
    from app.models.models import ValidationWire

    rows = db.query(ValidationWire).filter(ValidationWire.adjudication_id == adjudication_id).order_by(ValidationWire.id.asc()).all()
    return [wire_to_dict(row) for row in rows]


def wire_to_dict(wire: Any) -> dict[str, Any]:
    return {
        "id": wire.id,
        "finding_id": wire.finding_id,
        "adjudication_id": wire.adjudication_id,
        "parent_wire_id": wire.parent_wire_id,
        "work_item_id": wire.work_item_id,
        "action_id": wire.action_id,
        "status": wire.status,
        "reason_code": wire.reason_code,
        "target_ref": wire.target_ref,
        "parameter_ref": wire.parameter_ref,
        "identity_key": wire.identity_key,
        "secondary_identity_key": wire.secondary_identity_key,
        "tool_name": wire.tool_name,
        "profile": wire.profile,
        "input_bindings": dict(wire.input_bindings or {}),
        "expected_signals": dict(wire.expected_signals or {}),
        "policy_decision": dict(wire.policy_decision or {}),
        "result_summary": dict(wire.result_summary or {}),
        "attempt": wire.attempt,
        "max_attempts": wire.max_attempts,
    }


def adjudication_to_dict(row: Any, *, wires: list[Any] | None = None) -> dict[str, Any]:
    return {
        "id": row.id,
        "scan_job_id": row.scan_job_id,
        "finding_id": row.finding_id,
        "cycle": row.cycle,
        "status": row.status,
        "dossier_hash": row.dossier_hash,
        "dossier": dict(row.dossier or {}),
        "proposed_verdict": row.proposed_verdict,
        "final_verdict": row.final_verdict,
        "reason_code": row.reason_code,
        "confidence": row.confidence,
        "missing_evidence": list(row.missing_evidence or []),
        "contradictions": list(row.contradictions or []),
        "supporting_evidence_ids": list(row.supporting_evidence_ids or []),
        "model_name": row.model_name,
        "model_response": dict(row.model_response or {}),
        "prompt_version": row.prompt_version,
        "decision_metadata": dict(row.decision_metadata or {}),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "wires": list(wires or []),
    }
