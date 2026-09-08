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
        value = re.sub(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
            value,
            flags=re.I,
        )
        value = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED JWT]", value)
        value = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED CLOUD KEY]", value)
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
    # A caller putting "negative_control" inside `metadata=` instead of using
    # the dedicated `negative_control=` kwarg used to have it silently
    # clobbered to {} by the merge below -- evaluate_finding_promotion reads
    # this exact key to decide confirmed vs candidate, so that clobber
    # silently stranded confirmed findings at "candidate" forever. Honor
    # whichever was actually supplied, preferring the dedicated kwarg.
    _meta = dict(metadata or {})
    _meta_negative_control = _meta.pop("negative_control", None)
    resolved_negative_control = negative_control if negative_control is not None else _meta_negative_control
    artifact_payload = {
        "target": target,
        "tool_name": tool_name,
        "identity_key": identity_key,
        "baseline_request": baseline_request or {},
        "baseline_response": baseline_response or {},
        "exploit_request": exploit_request or {},
        "exploit_response": exploit_response or {},
        "negative_control": resolved_negative_control or {},
        "diff_summary": diff_summary,
        "metadata": _meta,
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
        metadata={**_meta, "negative_control": redact(resolved_negative_control or {}), "artifact_path": path},
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
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"ok": False, "error": "mutation_retest_requires_family_validator", "artifact_id": artifact.id}
    if not _url_in_scan_scope(db, artifact.scan_job_id, url):
        return {"ok": False, "error": "artifact_url_out_of_scope", "artifact_id": artifact.id}
    try:
        resp = requests.request(method, url, headers=headers, json=body if isinstance(body, dict) else None, data=body if not isinstance(body, dict) else None, timeout=timeout, verify=False, allow_redirects=False)
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


def expire_retained_artifact_payloads(db: Session, *, now: datetime | None = None, limit: int = 500) -> int:
    current = now or datetime.now()
    rows = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.artifact_metadata.isnot(None))
        .order_by(EvidenceArtifact.created_at.asc())
        .limit(max(1, int(limit)))
        .all()
    )
    expired = 0
    for artifact in rows:
        metadata = dict(artifact.artifact_metadata or {})
        expires_at_raw = str(metadata.get("expires_at") or "").strip()
        policy = str(metadata.get("retention_policy") or "").strip()
        if policy != "delete_after_retest_or_expiry" or not expires_at_raw:
            continue
        try:
            expires_at = datetime.fromisoformat(expires_at_raw)
        except ValueError:
            continue
        if expires_at > current or metadata.get("retention_expired_at"):
            continue
        path = str(artifact.workspace_path or metadata.get("artifact_path") or "").strip()
        if path:
            try:
                candidate = Path(path)
                if candidate.exists() and candidate.is_file():
                    candidate.unlink()
            except OSError:
                pass
        artifact.baseline_request = {}
        artifact.exploit_request = {}
        artifact.baseline_response_ref = None
        artifact.exploit_response_ref = None
        artifact.payload = ""
        artifact.diff_summary = "retention_expired"
        artifact.workspace_path = None
        metadata["retention_expired_at"] = current.isoformat()
        metadata["artifact_path"] = ""
        artifact.artifact_metadata = metadata
        db.add(artifact)
        expired += 1
    if expired:
        db.flush()
    return expired


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
    replay_requests = [baseline_request or {"method": "GET", "url": artifact.target}, exploit_request]
    for request_row in replay_requests:
        method = str(request_row.get("method") or "GET").upper()
        url = str(request_row.get("url") or artifact.target or "")
        if method not in {"GET", "HEAD", "OPTIONS"}:
            return {"ok": False, "error": "mutation_retest_requires_family_validator", "artifact_id": artifact.id}
        if not _url_in_scan_scope(db, artifact.scan_job_id, url):
            return {"ok": False, "error": "artifact_url_out_of_scope", "artifact_id": artifact.id}
    baseline = _execute_request_stable(
        baseline_request or {"method": "GET", "url": artifact.target},
        timeout=timeout,
        operational_headers=baseline_operational_headers or operational_headers,
        operational_cookies=baseline_operational_cookies or operational_cookies,
    )
    exploit = _execute_request_stable(
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
    if negative_url and not _url_in_scan_scope(db, artifact.scan_job_id, negative_url):
        return {"ok": False, "error": "negative_control_url_out_of_scope", "artifact_id": artifact.id}
    negative = _execute_request_stable(
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
    unstable = bool(
        baseline.get("unstable")
        or exploit.get("unstable")
        or negative.get("unstable")
        or not baseline.get("ok")
        or not exploit.get("ok")
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
        "inconclusive": unstable,
        "inconclusive_reason": "unstable_or_failed_replay_sample" if unstable else "",
        "confirmed": bool(not unstable and (delta or indicator_match or same_object_cross_identity) and negative_distinct),
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


def _response_signature(row: dict[str, Any]) -> tuple[Any, ...]:
    if not row.get("ok"):
        return ("error", str(row.get("error") or ""), str(row.get("detail") or "")[:120])
    return (
        "ok",
        int(row.get("status_code") or 0),
        str(row.get("content_type") or "").split(";", 1)[0].strip().lower(),
        str(row.get("location") or ""),
        int(row.get("body_len") or 0) // 100,
        tuple(row.get("json_keys") or []),
    )


def _execute_request_stable(
    request_data: dict[str, Any],
    *,
    timeout: int,
    operational_headers: dict[str, str] | None = None,
    operational_cookies: dict[str, str] | None = None,
    samples: int = 2,
) -> dict[str, Any]:
    attempts = [
        _execute_request(
            request_data,
            timeout=timeout,
            operational_headers=operational_headers,
            operational_cookies=operational_cookies,
        )
        for _ in range(max(1, int(samples or 1)))
    ]
    signatures = [_response_signature(row) for row in attempts]
    if len(set(signatures)) > 1:
        return {
            **attempts[-1],
            "ok": False,
            "unstable": True,
            "error": "unstable_replay_response",
            "samples": attempts,
        }
    stable = dict(attempts[-1])
    stable["samples"] = len(attempts)
    stable["stable_signature"] = signatures[-1]
    return stable


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
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"ok": False, "error": "mutation_retest_requires_family_validator"}
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


def _url_in_scan_scope(db: Session, scan_job_id: int, url: str) -> bool:
    from app.services.scan_scope import authorized_scope_for_scan, host_from_scope_reference, is_host_in_scope

    host = host_from_scope_reference(url)
    return bool(host and is_host_in_scope(host, authorized_scope_for_scan(db, scan_job_id)))


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
