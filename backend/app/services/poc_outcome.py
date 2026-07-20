"""Conservative PoC outcome classification: exit code zero is never proof."""
from __future__ import annotations

import json
from typing import Any


NEGATIVE_PATTERNS = (
    "no vulnerabilities found", "no vulnerability found", "not vulnerable",
    "no results found", "no issues found", "no injection point",
)
POSITIVE_PATTERNS: dict[str, tuple[str, ...]] = {
    "sqlmap": ("is vulnerable", "identified the following injection point", "sql injection vulnerability"),
    "dalfox": ("[poc]", "[v]", "vulnerable"),
    "nuclei": ("matched-at", '"matched"', "[critical]", "[high]"),
    "jwt_tool": ("vulnerable", "exploit", "signature bypass"),
    "nuclei-exposure": ("[exposure]", "[critical]", "[high]"),
}


def classify_poc_work_item(item: Any) -> dict[str, Any]:
    result = dict(getattr(item, "result", None) or {})
    status = str(getattr(item, "status", "") or "").lower()
    tool = str(getattr(item, "tool_name", "") or "").lower()
    parsed = result.get("parsed_result") or result.get("parsed")
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "")
    blob = (stdout + "\n" + json.dumps(parsed, default=str)).lower()

    if status in {"failed", "timeout", "skipped"}:
        return {
            "result": "candidate",
            "reason": f"validator_{status}_is_not_negative_proof",
            "positive_signal": False,
            "negative_signal": False,
        }
    if status not in {"completed", "done"}:
        return {"result": "candidate", "reason": "validator_not_terminal", "positive_signal": False, "negative_signal": False}

    negative = next((pattern for pattern in NEGATIVE_PATTERNS if pattern in blob), "")
    positive = _structured_positive(parsed) or next(
        (pattern for prefix, patterns in POSITIVE_PATTERNS.items() if tool.startswith(prefix) for pattern in patterns if pattern in blob),
        "",
    )
    if positive and not negative:
        return {"result": "confirmed", "reason": f"tool_specific_positive_signal:{positive}", "positive_signal": True, "negative_signal": False}
    if negative and not positive:
        return {"result": "refuted", "reason": f"explicit_negative_signal:{negative}", "positive_signal": False, "negative_signal": True}
    return {
        "result": "candidate",
        "reason": "successful_execution_without_vulnerability_proof",
        "positive_signal": bool(positive),
        "negative_signal": bool(negative),
    }


def _structured_positive(parsed: Any) -> str:
    if isinstance(parsed, list) and parsed:
        actionable = [item for item in parsed if isinstance(item, dict) and _dict_positive(item)]
        return "structured_actionable_result" if actionable else ""
    if isinstance(parsed, dict) and _dict_positive(parsed):
        return "structured_actionable_result"
    return ""


def _dict_positive(value: dict[str, Any]) -> bool:
    if value.get("vulnerable") is True or value.get("confirmed") is True or value.get("matched") is True:
        return True
    if int(value.get("findings_count") or value.get("matched_count") or value.get("vulnerabilities") or 0) > 0:
        return True
    info = value.get("info") if isinstance(value.get("info"), dict) else {}
    severity = str(value.get("severity") or info.get("severity") or "").lower()
    return severity in {"critical", "high", "medium", "low"} and bool(value.get("matched-at") or value.get("matched_at") or value.get("template-id"))
