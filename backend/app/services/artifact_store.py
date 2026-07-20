"""Armazenamento e replay de artefatos de evidência."""
from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import EvidenceArtifact, ScanJob
from app.services.evidence_contract_service import create_evidence_artifact
from app.services.pentest_contracts import EvidenceContract


SENSITIVE_KEYS = re.compile(r"(?i)(authorization|cookie|token|secret|password|passwd|api[-_]?key|set-cookie)")


def storage_root() -> Path:
    return Path(os.getenv("EVIDENCE_STORAGE_PATH") or getattr(settings, "evidence_storage_path", "/tmp/easm-evidence"))


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if SENSITIVE_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)(token|secret|password|api_key|apikey)=([^&\s]+)", r"\1=[REDACTED]", value)
    return value


def write_artifact_file(scan_id: int, artifact_type: str, payload: Any, *, suffix: str = ".json") -> str:
    root = storage_root() / f"scan-{scan_id}" / datetime.now().strftime("%Y%m%d")
    root.mkdir(parents=True, exist_ok=True)
    name = f"{artifact_type}-{datetime.now().strftime('%H%M%S')}-{secrets.token_hex(4)}{suffix}"
    path = root / name
    if suffix == ".json":
        path.write_text(json.dumps(redact(payload), indent=2, sort_keys=True, default=str), encoding="utf-8")
    else:
        path.write_text(str(redact(payload)), encoding="utf-8")
    return str(path)


def create_request_response_artifact(
    db: Session,
    scan: ScanJob,
    *,
    target: str,
    tool_name: str,
    phase_id: str = "",
    skill_id: str = "",
    identity_key: str = "",
    baseline_request: dict[str, Any] | None = None,
    baseline_response: dict[str, Any] | None = None,
    exploit_request: dict[str, Any] | None = None,
    exploit_response: dict[str, Any] | None = None,
    negative_control: dict[str, Any] | None = None,
    payload: str = "",
    diff_summary: str = "",
    validation_status: str = "candidate",
    confidence_score: int = 50,
    metadata: dict[str, Any] | None = None,
) -> EvidenceArtifact:
    artifact_payload = {
        "target": target,
        "tool_name": tool_name,
        "identity_key": identity_key,
        "baseline_request": baseline_request or {},
        "baseline_response": baseline_response or {},
        "exploit_request": exploit_request or {},
        "exploit_response": exploit_response or {},
        "negative_control": negative_control or {},
        "diff_summary": diff_summary,
        "metadata": metadata or {},
    }
    path = write_artifact_file(scan.id, "proof-pack", artifact_payload)
    contract = EvidenceContract(
        scan_job_id=scan.id,
        phase_id=phase_id,
        skill_id=skill_id,
        tool_name=tool_name,
        target=target,
        identity_key=identity_key,
        artifact_type="request_response_pair",
        validation_status=validation_status,
        confidence_score=confidence_score,
        baseline_request=redact(baseline_request or {}),
        baseline_response_ref=path if baseline_response else "",
        exploit_request=redact(exploit_request or {}),
        exploit_response_ref=path if exploit_response else "",
        payload=payload,
        diff_summary=diff_summary,
        reproduction_steps=_steps(target, baseline_request, exploit_request),
        workspace_path=path,
        metadata={**(metadata or {}), "negative_control": redact(negative_control or {}), "artifact_path": path},
    )
    return create_evidence_artifact(db, contract)


def replay_artifact(db: Session, artifact: EvidenceArtifact, *, timeout: int = 20) -> dict[str, Any]:
    request_data = dict(artifact.exploit_request or artifact.baseline_request or {})
    method = str(request_data.get("method") or "GET").upper()
    url = str(request_data.get("url") or artifact.target or "")
    headers = {str(k): str(v) for k, v in dict(request_data.get("headers") or {}).items() if not SENSITIVE_KEYS.search(str(k))}
    body = request_data.get("body") or request_data.get("json")
    if not url.startswith("http"):
        return {"ok": False, "error": "artifact_has_no_replayable_url", "artifact_id": artifact.id}
    try:
        resp = requests.request(method, url, headers=headers, json=body if isinstance(body, dict) else None, data=body if not isinstance(body, dict) else None, timeout=timeout, verify=False)
        replay = {
            "ok": True,
            "artifact_id": artifact.id,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "body_preview": resp.text[:2000],
        }
    except Exception as exc:  # noqa: BLE001
        replay = {"ok": False, "artifact_id": artifact.id, "error": type(exc).__name__, "detail": str(exc)[:500]}
    path = write_artifact_file(artifact.scan_job_id, "replay", replay)
    meta = dict(artifact.artifact_metadata or {})
    meta.setdefault("replays", []).append({"path": path, "created_at": datetime.now().isoformat(), "ok": replay.get("ok")})
    artifact.artifact_metadata = meta
    db.add(artifact)
    db.flush()
    return replay


def replay_artifact_pair(
    db: Session,
    artifact: EvidenceArtifact,
    *,
    timeout: int = 20,
    operational_headers: dict[str, str] | None = None,
    operational_cookies: dict[str, str] | None = None,
    baseline_operational_headers: dict[str, str] | None = None,
    baseline_operational_cookies: dict[str, str] | None = None,
    exploit_operational_headers: dict[str, str] | None = None,
    exploit_operational_cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Replay baseline and attempt and require the original differential to persist."""
    baseline_request = dict(artifact.baseline_request or {})
    exploit_request = dict(artifact.exploit_request or {})
    if not exploit_request:
        return {"ok": False, "error": "artifact_has_no_exploit_request", "artifact_id": artifact.id}
    baseline = _execute_request(
        baseline_request or {"method": "GET", "url": artifact.target},
        timeout=timeout,
        operational_headers=baseline_operational_headers or operational_headers,
        operational_cookies=baseline_operational_cookies or operational_cookies,
    )
    exploit = _execute_request(
        exploit_request,
        timeout=timeout,
        operational_headers=exploit_operational_headers or operational_headers,
        operational_cookies=exploit_operational_cookies or operational_cookies,
    )
    delta = bool(
        baseline.get("ok")
        and exploit.get("ok")
        and (
            baseline.get("status_code") != exploit.get("status_code")
            or baseline.get("location") != exploit.get("location")
            or abs(int(baseline.get("body_len") or 0) - int(exploit.get("body_len") or 0)) > 80
            or set(exploit.get("json_keys") or []) != set(baseline.get("json_keys") or [])
        )
    )
    metadata = dict(artifact.artifact_metadata or {})
    negative_url = str(metadata.get("negative_control_url") or "")
    negative = _execute_request(
        {"method": exploit_request.get("method") or "GET", "url": negative_url},
        timeout=timeout,
        operational_headers=exploit_operational_headers or operational_headers,
        operational_cookies=exploit_operational_cookies or operational_cookies,
    ) if negative_url else {}
    negative_distinct = not negative_url or not (
        negative.get("ok")
        and exploit.get("ok")
        and negative.get("status_code") == exploit.get("status_code")
        and negative.get("body_preview") == exploit.get("body_preview")
    )
    indicators = [str(item) for item in list(metadata.get("expected_indicators") or []) if str(item)]
    payload = str(artifact.payload or "")
    if payload and len(payload) <= 160:
        indicators.append(payload)
    body = str(exploit.get("body_preview") or "")
    indicator_match = any(indicator in body for indicator in indicators)
    tool_name = str(artifact.tool_name or "").lower()
    same_object_cross_identity = bool(
        any(token in tool_name for token in ("idor", "bola"))
        and baseline.get("ok")
        and exploit.get("ok")
        and str(baseline.get("body_preview") or "")
        and baseline.get("body_preview") == exploit.get("body_preview")
    )
    replay = {
        "ok": bool(baseline.get("ok") and exploit.get("ok")),
        "artifact_id": artifact.id,
        "baseline": baseline,
        "exploit": exploit,
        "negative_control": negative,
        "differential_persisted": delta,
        "negative_control_distinct": negative_distinct,
        "indicator_match": indicator_match,
        "same_object_cross_identity": same_object_cross_identity,
        "confirmed": bool((delta or indicator_match or same_object_cross_identity) and negative_distinct),
    }
    path = write_artifact_file(artifact.scan_job_id, "retest-pair", replay)
    metadata.setdefault("retests", []).append({
        "path": path,
        "created_at": datetime.now().isoformat(),
        "confirmed": replay["confirmed"],
    })
    artifact.artifact_metadata = metadata
    db.add(artifact)
    db.flush()
    return replay


def _execute_request(
    request_data: dict[str, Any],
    *,
    timeout: int,
    operational_headers: dict[str, str] | None = None,
    operational_cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    method = str(request_data.get("method") or "GET").upper()
    url = str(request_data.get("url") or "")
    if not url.startswith("http"):
        return {"ok": False, "error": "request_has_no_replayable_url"}
    headers = {str(k): str(v) for k, v in dict(request_data.get("headers") or {}).items()}
    headers.update({str(k): str(v) for k, v in dict(operational_headers or {}).items()})
    cookies = {str(k): str(v) for k, v in dict(operational_cookies or {}).items()}
    body = request_data.get("body") or request_data.get("json")
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            json=body if isinstance(body, dict) else None,
            data=body if body is not None and not isinstance(body, dict) else None,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        return {
            "ok": True,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "location": response.headers.get("location", ""),
            "body_len": len(response.content or b""),
            "json_keys": _json_keys(response.text),
            "body_preview": response.text[:2000],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:500]}


def _json_keys(text: str) -> list[str]:
    try:
        value = json.loads(text)
    except Exception:
        return []
    if isinstance(value, dict):
        return sorted(str(key) for key in value)[:60]
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return sorted(str(key) for key in value[0])[:60]
    return []


def _steps(target: str, baseline_request: dict[str, Any] | None, exploit_request: dict[str, Any] | None) -> list[str]:
    steps = [f"Target: {target}"]
    if baseline_request:
        steps.append(f"Baseline: {baseline_request.get('method', 'GET')} {baseline_request.get('url', target)}")
    if exploit_request:
        steps.append(f"Attempt: {exploit_request.get('method', 'GET')} {exploit_request.get('url', target)}")
    return steps
