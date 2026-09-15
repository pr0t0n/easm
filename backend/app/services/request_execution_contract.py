from __future__ import annotations

from typing import Any


MUTATING_METHODS = {"POST", "PUT", "PATCH"}
BODY_CONTRACT_FIELDS = {
    "{env_SCAN_HTTP_METHOD}",
    "{env_SCAN_FUZZ_POST_DATA}",
    "{env_SCAN_FUZZ_CONTENT_TYPE}",
}


def _command_fields(spec: dict[str, Any]) -> set[str]:
    command = spec.get("command") or spec.get("cmd") or []
    if isinstance(command, str):
        command = [command]
    rendered = " ".join(str(part) for part in command)
    return {field for field in BODY_CONTRACT_FIELDS if field in rendered}


def resolve_request_capability_profile(
    execution: dict[str, Any],
    profile_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if profile_catalog is None:
        from app.services.kali_catalog import get_kali_profiles

        payload = get_kali_profiles()
        if not payload.get("reachable"):
            return {"profile": None, "reason": "capability_catalog_unavailable", "catalog": payload}
        profiles = dict(payload.get("profiles") or {})
    else:
        profiles = dict(profile_catalog or {})
    current_profile = str(execution.get("profile") or "").strip()
    requested_tool = str(execution.get("tool_name") or "").strip().lower()
    current_spec = dict(profiles.get(current_profile) or {})
    tool_family = str(current_spec.get("tool") or requested_tool).strip().lower()
    candidates: list[tuple[int, str]] = []
    for profile_name, raw_spec in profiles.items():
        spec = dict(raw_spec or {})
        if str(spec.get("tool") or "").strip().lower() != tool_family:
            continue
        fields = _command_fields(spec)
        if "{env_SCAN_FUZZ_POST_DATA}" not in fields or "{env_SCAN_HTTP_METHOD}" not in fields:
            continue
        score = 0
        if profile_name == current_profile:
            score += 100
        if bool(spec.get("command_executable_available", True)):
            score += 10
        score += len(fields)
        candidates.append((score, str(profile_name)))
    if not candidates:
        return {
            "profile": None,
            "reason": "capability_contract_degraded:request_body_unsupported",
            "tool_family": tool_family,
        }
    candidates.sort(key=lambda row: (-row[0], row[1]))
    return {"profile": candidates[0][1], "reason": None, "tool_family": tool_family}


def adapt_execution_to_request_contract(
    execution: dict[str, Any],
    resolution: dict[str, Any] | None,
    *,
    profile_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    execution = {**dict(execution or {}), "arguments": dict((execution or {}).get("arguments") or {})}
    contract = dict(resolution or {})
    if contract.get("status") != "resolved":
        return {"compatible": True, "adapted": False, "execution": execution}
    method = str(contract.get("method") or "GET").upper()
    location = str(contract.get("parameter_location") or "").lower()
    body = str(contract.get("body") or "")
    if method not in MUTATING_METHODS and location != "body":
        return {"compatible": True, "adapted": False, "execution": execution}
    if not body.strip():
        return {
            "compatible": False,
            "adapted": False,
            "reason": "required_evidence_absent:request_body",
            "execution": execution,
        }
    capability = resolve_request_capability_profile(execution, profile_catalog)
    profile = capability.get("profile")
    if not profile:
        return {
            "compatible": False,
            "adapted": False,
            "reason": capability.get("reason") or "capability_contract_degraded:request_body_unsupported",
            "capability_resolution": capability,
            "execution": execution,
        }
    arguments = dict(execution.get("arguments") or {})
    env_vars = dict(arguments.get("env_vars") or {})
    env_vars.update({
        "SCAN_HTTP_METHOD": method,
        "SCAN_FUZZ_POST_DATA": body,
        "SCAN_FUZZ_CONTENT_TYPE": str(contract.get("content_type") or "application/x-www-form-urlencoded"),
    })
    parameter = str(contract.get("parameter_ref") or "").strip()
    if parameter:
        env_vars["SCAN_FUZZ_PARAM"] = parameter
    arguments["env_vars"] = env_vars
    arguments["request_contract"] = {
        "method": method,
        "parameter_location": location or "body",
        "parameter_ref": parameter,
        "source": contract.get("source"),
        "endpoint_id": contract.get("endpoint_id"),
    }
    execution["profile"] = profile
    execution["arguments"] = arguments
    return {
        "compatible": True,
        "adapted": True,
        "profile": profile,
        "execution": execution,
        "request_contract": arguments["request_contract"],
        "capability_resolution": capability,
    }
