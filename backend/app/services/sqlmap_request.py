from urllib.parse import parse_qsl, urlsplit

from sqlalchemy.orm import Session

from app.models.models import ObservedRequest


def resolve_sqlmap_request(
    db: Session,
    scan_job_id: int,
    target: str,
    profile: str = "",
    env: dict | None = None,
) -> dict:
    arguments = dict(env or {})
    method = str(arguments.get("SCAN_HTTP_METHOD") or "").upper()
    requires_body = (
        profile == "sqlmap_body"
        or method in {"POST", "PUT", "PATCH"}
        or bool(str(arguments.get("SCAN_FUZZ_POST_DATA") or "").strip())
    )
    if not requires_body and parse_qsl(urlsplit(target).query, keep_blank_values=True):
        return {"profile": "sqlmap_basic", "arguments": {}, "reason": ""}
    body = str(arguments.get("SCAN_FUZZ_POST_DATA") or "")
    if body.strip():
        return {
            "profile": "sqlmap_body",
            "arguments": {
                "SCAN_HTTP_METHOD": method or "POST",
                "SCAN_FUZZ_POST_DATA": body,
                "SCAN_FUZZ_CONTENT_TYPE": str(arguments.get("SCAN_FUZZ_CONTENT_TYPE") or "application/x-www-form-urlencoded"),
            },
            "reason": "",
        }
    query = db.query(ObservedRequest).filter(
        ObservedRequest.scan_job_id == scan_job_id,
        ObservedRequest.url == target,
        ObservedRequest.method.in_([method] if method else ["POST", "PUT", "PATCH"]),
        ObservedRequest.is_mutating.is_(True),
    )
    for observed in query.order_by(ObservedRequest.created_at.desc()).all():
        body = str((observed.request_body or {}).get("body") or "")
        if body.strip():
            return {
                "profile": "sqlmap_body",
                "arguments": {
                    "SCAN_HTTP_METHOD": str(observed.method),
                    "SCAN_FUZZ_POST_DATA": body,
                    "SCAN_FUZZ_CONTENT_TYPE": str(observed.request_content_type or "application/x-www-form-urlencoded"),
                },
                "reason": "",
            }
    return {"reason": "required_evidence_absent:post_body"}
