from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy.orm import Session

from app.models.models import EvidenceArtifact, ObservedRequest, OffensiveEndpoint, ValidationWire


MUTATING_METHODS = {"POST", "PUT", "PATCH"}


def _request(value: Any) -> tuple[str, str, str]:
    if not isinstance(value, dict):
        return "", "", ""
    target = str(value.get("target") or value.get("url") or "").strip()
    method = str(value.get("method") or "").upper().strip()
    body = str(value.get("body") or value.get("request_body") or "").strip()
    return target, method, body


def _has_parameter(target: str, parameter: str) -> bool:
    if not parameter:
        return bool(parse_qsl(urlsplit(target).query, keep_blank_values=True))
    return any(name == parameter for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True))


def resolve_validation_execution_context(
    db: Session,
    item: Any,
    *,
    wire: Any | None = None,
) -> dict[str, Any]:
    metadata = dict(getattr(item, "item_metadata", None) or {})
    wire_id = metadata.get("validation_wire_id")
    if wire is None and wire_id:
        wire = db.query(ValidationWire).filter(ValidationWire.id == int(wire_id)).first()
    if wire is None:
        return {"status": "not_required", "execution_target": str(metadata.get("execution_target") or item.target)}

    bindings = dict(getattr(wire, "input_bindings", None) or {})
    parameter = str(getattr(wire, "parameter_ref", None) or bindings.get("parameter_ref") or "").strip()
    expected_method = str(bindings.get("method") or "").upper().strip()
    source_id = getattr(wire, "source_artifact_id", None)
    artifacts: list[Any] = []
    if source_id:
        source = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == int(source_id)).first()
        if source is not None:
            artifacts.append(source)
    finding_id = getattr(wire, "finding_id", None)
    if finding_id:
        artifacts.extend(
            db.query(EvidenceArtifact)
            .filter(EvidenceArtifact.finding_id == int(finding_id))
            .order_by(EvidenceArtifact.created_at.desc(), EvidenceArtifact.id.desc())
            .all()
        )

    candidates: list[tuple[int, str, str, str, int | None, str]] = []
    for artifact in artifacts:
        for field in ("baseline_request", "exploit_request"):
            target, method, body = _request(getattr(artifact, field, None))
            if target:
                candidates.append((100 if field == "baseline_request" else 80, target, method, body, None, f"artifact:{artifact.id}:{field}"))
    endpoint_id = getattr(wire, "endpoint_id", None) or bindings.get("endpoint_id")
    endpoints: list[Any] = []
    if endpoint_id:
        endpoint = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.id == int(endpoint_id)).first()
        if endpoint is not None:
            endpoints.append(endpoint)
    if not endpoints and finding_id:
        endpoints = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == int(getattr(item, "scan_job_id"))).all()
    for endpoint in endpoints:
        target = str(endpoint.url or endpoint.normalized_url or "").strip()
        if target:
            candidates.append((70, target, str(endpoint.method or "GET").upper(), "", int(endpoint.id), f"endpoint:{endpoint.id}"))

    requested_target = str(getattr(wire, "target_ref", None) or metadata.get("execution_target") or item.target).split("#easm-wire-", 1)[0].strip()
    if requested_target.startswith("http://") or requested_target.startswith("https://"):
        candidates.append((60, requested_target, expected_method, "", None, "wire_target"))
    candidates = [candidate for candidate in candidates if candidate[1].startswith(("http://", "https://"))]
    candidates.sort(key=lambda candidate: (candidate[0], bool(expected_method and candidate[2] == expected_method), bool(parameter and _has_parameter(candidate[1], parameter))), reverse=True)

    selected = None
    for candidate in candidates:
        _, target, method, body, candidate_endpoint_id, source = candidate
        if expected_method and method and method != expected_method:
            continue
        if parameter and method in {"GET", "HEAD"} and not _has_parameter(target, parameter):
            continue
        selected = candidate
        break
    if selected is None:
        return {
            "status": "awaiting_evidence",
            "reason": "required_evidence_absent:exact_request_contract",
            "wire_id": int(wire.id),
            "parameter_ref": parameter,
        }

    _, target, method, body, selected_endpoint_id, source = selected
    method = method or expected_method or "GET"
    if method in MUTATING_METHODS and not body:
        observed = (
            db.query(ObservedRequest)
            .filter(
                ObservedRequest.scan_job_id == int(item.scan_job_id),
                ObservedRequest.url == target,
                ObservedRequest.method == method,
                ObservedRequest.is_mutating.is_(True),
            )
            .order_by(ObservedRequest.created_at.desc())
            .first()
        )
        if observed is not None:
            body = str((observed.request_body or {}).get("body") or "").strip()
    if method in MUTATING_METHODS and not body:
        return {
            "status": "awaiting_evidence",
            "reason": "required_evidence_absent:post_body",
            "wire_id": int(wire.id),
            "execution_target": target,
            "method": method,
            "parameter_ref": parameter,
        }

    return {
        "status": "resolved",
        "wire_id": int(wire.id),
        "execution_target": target,
        "method": method,
        "parameter_ref": parameter,
        "endpoint_id": selected_endpoint_id or (int(endpoint_id) if endpoint_id else None),
        "source": source,
        "body": body,
    }
