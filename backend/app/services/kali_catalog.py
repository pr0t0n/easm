"""Live execution catalog and worker/skill mapping.

Kali tools are available when the runner exposes a profile and executable.
Backend-local virtual tools are available through backend adapters and should
not be reported as missing Kali binaries.
"""
from __future__ import annotations

import re
import time
from typing import Any

import requests

from app.core.config import settings
from app.services.kali_executor import TOOL_TO_PROFILE


CACHE_TTL_SECONDS = 30
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
BACKEND_LOCAL_PROFILES = {
    "code_analyzer_backend",
    "business_logic_backend",
    "semgrep_backend",
    # zap-api (OpenAPI/Swagger-driven scan) runs against the dedicated `zap`
    # container via zap_scanner.py, never through a kali_runner profile — see
    # workers/tasks.py's ZAP post-processing hook.
    "zap_api_scan",
}
RUNNER_BUILTIN_EXECUTABLES = {"bash", "sh", "python", "python3"}


def _runner_base() -> str:
    return str(settings.kali_runner_url or "http://kali_runner:8088").rstrip("/")


def _normalize_tool_name(value: str | None) -> str:
    return str(value or "").strip().lower()


def _runner_get(path: str, timeout: int) -> dict[str, Any]:
    response = requests.get(f"{_runner_base()}{path}", timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _cached(name: str, loader, *, force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    if not force:
        cached = _CACHE.get(name)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            return dict(cached[1])
    try:
        payload = loader()
    except Exception as exc:  # noqa: BLE001
        payload = {"reachable": False, "error": str(exc)}
    _CACHE[name] = (now, dict(payload))
    return dict(payload)


def get_kali_profiles(*, force: bool = False) -> dict[str, Any]:
    def _load() -> dict[str, Any]:
        payload = _runner_get("/profiles", timeout=8)
        profiles = payload.get("profiles") if isinstance(payload.get("profiles"), dict) else {}
        return {
            "reachable": True,
            "count": int(payload.get("count") or len(profiles)),
            "profiles": profiles,
        }

    return _cached("profiles", _load, force=force)


def get_kali_tools(*, force: bool = False) -> dict[str, Any]:
    def _load() -> dict[str, Any]:
        payload = _runner_get("/tools", timeout=12)
        tools = payload.get("tools") if isinstance(payload.get("tools"), list) else []
        by_name = {
            _normalize_tool_name(item.get("name")): item
            for item in tools
            if isinstance(item, dict) and item.get("name")
        }
        return {
            "reachable": True,
            "count": int(payload.get("count") or len(tools)),
            "tools": tools,
            "tools_by_name": by_name,
        }

    return _cached("tools", _load, force=force)


def _profile_binary_candidates(profile: dict[str, Any], tool_name: str) -> set[str]:
    candidates = {
        _normalize_tool_name(tool_name),
        _normalize_tool_name(profile.get("tool")),
        _normalize_tool_name(profile.get("command_executable")),
    }
    command = profile.get("command")
    if isinstance(command, list) and command:
        candidates.add(_normalize_tool_name(command[0]))
    return {item for item in candidates if item}


def _tool_availability(tool_name: str, profiles_payload: dict[str, Any], tools_payload: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_tool_name(tool_name)
    profile_id = TOOL_TO_PROFILE.get(normalized)
    # Backend-local virtual tools: declared in TOOL_TO_PROFILE with a sentinel
    # profile id (e.g. "code_analyzer_backend") but executed inside the backend
    # itself. They are always "available" — no Kali round-trip needed.
    if profile_id in BACKEND_LOCAL_PROFILES:
        return {
            "available": True,
            "status": "backend_local",
            "profile": profile_id,
            "executable": normalized,
            "binary_candidates": [normalized],
        }
    if not profiles_payload.get("reachable") or not tools_payload.get("reachable"):
        return {
            "available": False,
            "status": "runner_unreachable",
            "profile": profile_id,
            "binary_candidates": [],
        }
    if not profile_id:
        return {
            "available": False,
            "status": "missing_profile_mapping",
            "profile": None,
            "binary_candidates": [],
        }

    profiles = profiles_payload.get("profiles") if isinstance(profiles_payload.get("profiles"), dict) else {}
    profile = profiles.get(profile_id)
    if not isinstance(profile, dict):
        return {
            "available": False,
            "status": "profile_not_loaded",
            "profile": profile_id,
            "binary_candidates": [],
        }

    candidates = sorted(_profile_binary_candidates(profile, normalized))
    tools_by_name = tools_payload.get("tools_by_name") if isinstance(tools_payload.get("tools_by_name"), dict) else {}
    executable = next((candidate for candidate in candidates if candidate in tools_by_name), "")
    if not executable:
        executable = next(
            (
                candidate
                for candidate in candidates
                if candidate in RUNNER_BUILTIN_EXECUTABLES or candidate.startswith("/")
            ),
            "",
        )
    return {
        "available": bool(executable),
        "status": "ready" if executable else "missing_kali_binary",
        "profile": profile_id,
        "profile_tool": profile.get("tool"),
        "executable": executable,
        "binary_candidates": candidates,
    }


def is_kali_tool_available(tool_name: str) -> bool:
    profiles_payload = get_kali_profiles()
    tools_payload = get_kali_tools()
    return bool(_tool_availability(tool_name, profiles_payload, tools_payload).get("available"))


def _worker_maps() -> tuple[dict[str, str], dict[str, str]]:
    from app.workers.worker_groups import get_canonical_group_tools, get_worker_groups

    tool_to_group: dict[str, str] = {}
    for group, tools in get_canonical_group_tools().items():
        for tool in tools:
            tool_to_group.setdefault(_normalize_tool_name(tool), group)

    group_to_queue: dict[str, str] = {}
    for group, data in get_worker_groups("unit").items():
        group_to_queue[group] = str((data or {}).get("queue") or "")
    return tool_to_group, group_to_queue


def _skill_maps() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    from app.graph.mission import PENTEST_PHASES, SKILL_CATALOG

    tool_to_skills: dict[str, list[str]] = {}
    for skill in SKILL_CATALOG:
        skill_id = str(skill.get("id") or "")
        for tool in skill.get("playbook") or []:
            if skill_id:
                tool_to_skills.setdefault(_normalize_tool_name(tool), []).append(skill_id)

    tool_to_phases: dict[str, list[str]] = {}
    for phase in PENTEST_PHASES:
        phase_id = str(phase.get("id") or "")
        for tool in phase.get("tools") or []:
            if phase_id:
                tool_to_phases.setdefault(_normalize_tool_name(tool), []).append(phase_id)
    return tool_to_skills, tool_to_phases


def _tool_meta(tool_name: str) -> dict[str, Any]:
    try:
        from app.services.tool_catalog import TOOL_CATALOG
    except Exception:
        return {}
    normalized = _normalize_tool_name(tool_name)
    for catalog_name, meta in TOOL_CATALOG.items():
        if _normalize_tool_name(catalog_name) == normalized:
            return dict(meta)
    return {}


SUPPORT_TOOL_RE = re.compile(
    r"^(?:apt|dpkg|systemctl|service|ssh|scp|python|pip|perl|ruby|node|npm|go|gcc|g\+\+|make|cmake|"
    r"bash|sh|zsh|cat|cp|mv|rm|ls|find|grep|awk|sed|tar|gzip|gunzip|zip|unzip|tee|xargs|"
    r"openssl|keytool|java|sqlite|psql|redis|celery|uvicorn|alembic)",
    re.IGNORECASE,
)

CLASSIFIERS: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("asset_discovery", "reconnaissance", "Reconhecimento de DNS, portas, HTTP e superfície externa.", ("dns", "sub", "enum", "nmap", "mass", "http", "whois", "trace", "snmp", "smb")),
    ("risk_assessment", "exploitation", "Validação de CVE, web, fuzzing, injeção e configuração fraca.", ("sql", "xss", "web", "dir", "fuzz", "nikto", "wpscan", "zap", "exploit", "vuln", "scan")),
    ("threat_intel", "weaponization", "OSINT, vazamentos, takeover e exposição pública.", ("osint", "harvest", "shodan", "leak", "email", "takeover", "cloud")),
    ("risk_assessment", "installation", "Autenticação, credenciais, brute force e validação controlada de acesso.", ("hydra", "john", "hash", "crack", "pass", "jwt", "kerb", "ldap")),
    ("evidence_adjudication", "actions_on_objectives", "Análise de código, dependências, secrets e evidência local.", ("sast", "semgrep", "bandit", "trivy", "retire", "secret", "git", "dep")),
]


def classify_unprofiled_kali_tool(tool_name: str) -> dict[str, Any]:
    normalized = _normalize_tool_name(tool_name)
    if not normalized:
        return {"catalog_status": "unknown"}
    if SUPPORT_TOOL_RE.search(normalized):
        return {
            "catalog_status": "support_binary",
            "worker_group": None,
            "skill_category": None,
            "need": "Binario de suporte do sistema Kali, nao deve ser chamado diretamente pelo agente.",
        }
    for node, group, need, keywords in CLASSIFIERS:
        if any(keyword in normalized for keyword in keywords):
            return {
                "catalog_status": "candidate_profile_needed",
                "worker_group": group,
                "skill_category": node,
                "need": need,
            }
    return {
        "catalog_status": "out_of_scope_or_manual_review",
        "worker_group": None,
        "skill_category": None,
        "need": "Ferramenta Kali detectada, mas sem profile seguro para execucao autonoma.",
    }


def build_kali_tool_matrix(*, include_unprofiled: bool = False, limit: int = 500, force: bool = False) -> dict[str, Any]:
    profiles_payload = get_kali_profiles(force=force)
    tools_payload = get_kali_tools(force=force)
    profiles = profiles_payload.get("profiles") if isinstance(profiles_payload.get("profiles"), dict) else {}
    tools = tools_payload.get("tools") if isinstance(tools_payload.get("tools"), list) else []

    tool_to_group, group_to_queue = _worker_maps()
    tool_to_skills, tool_to_phases = _skill_maps()

    mapped_tools: list[dict[str, Any]] = []
    ready_count = 0
    for tool_name, profile_id in sorted(TOOL_TO_PROFILE.items()):
        profile = profiles.get(profile_id) if isinstance(profiles, dict) else {}
        profile = profile if isinstance(profile, dict) else {}
        availability = _tool_availability(tool_name, profiles_payload, tools_payload)
        meta = _tool_meta(tool_name)
        normalized = _normalize_tool_name(tool_name)
        if availability.get("available"):
            ready_count += 1
        worker_group = tool_to_group.get(normalized, "unassigned")
        source = "backend_local" if availability.get("status") == "backend_local" else "kali_runner"
        mapped_tools.append(
            {
                "name": tool_name,
                "source": source,
                "status": availability.get("status"),
                "available": bool(availability.get("available")),
                "profile": availability.get("profile") or profile_id,
                "profile_tool": profile.get("tool") or (tool_name if source == "backend_local" else None),
                "executable": availability.get("executable") or "",
                "binary_candidates": availability.get("binary_candidates") or [],
                "category": profile.get("category") or meta.get("category") or "",
                "phase": profile.get("phase") or meta.get("phase") or "",
                "functionality": profile.get("description") or meta.get("description") or "",
                "need": meta.get("when_to_use") or profile.get("description") or "",
                "worker_group": worker_group,
                "worker_queue": group_to_queue.get(worker_group, ""),
                "skills": sorted(set(tool_to_skills.get(normalized, []))),
                "mission_phases": sorted(set(tool_to_phases.get(normalized, []))),
                "timeout": profile.get("timeout"),
                "profile_source": profile.get("source"),
            }
        )

    profiled_names = {
        _normalize_tool_name(item.get("executable") or item.get("profile_tool") or item.get("name"))
        for item in mapped_tools
    }
    unprofiled_rows: list[dict[str, Any]] = []
    classification_counts: dict[str, int] = {}
    for item in tools:
        if not isinstance(item, dict):
            continue
        name = _normalize_tool_name(item.get("name"))
        if not name or name in profiled_names:
            continue
        classification = classify_unprofiled_kali_tool(name)
        status_name = str(classification.get("catalog_status") or "unknown")
        classification_counts[status_name] = classification_counts.get(status_name, 0) + 1
        if include_unprofiled and len(unprofiled_rows) < max(1, min(limit, 5000)):
            unprofiled_rows.append(
                {
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "source": "kali_runner",
                    **classification,
                }
            )

    return {
        "source": "kali_runner",
        "runner_reachable": bool(profiles_payload.get("reachable") and tools_payload.get("reachable")),
        "runner_error": profiles_payload.get("error") or tools_payload.get("error") or "",
        "kali_tools_detected": int(tools_payload.get("count") or len(tools)),
        "profiles_loaded": int(profiles_payload.get("count") or len(profiles)),
        "profile_mappings_expected": len(TOOL_TO_PROFILE),
        "profiled_tools_ready": ready_count,
        "profiled_tools_missing": len(TOOL_TO_PROFILE) - ready_count,
        "coverage_ratio": round(ready_count / max(1, len(TOOL_TO_PROFILE)), 3),
        "tools": mapped_tools,
        "unprofiled_summary": {
            "total": max(0, len(tools) - len(profiled_names)),
            "classification_counts": classification_counts,
            "returned": len(unprofiled_rows),
        },
        "unprofiled_tools": unprofiled_rows,
    }


def kali_installation_report(expected_tools: list[str] | None = None) -> dict[str, Any]:
    expected = sorted({_normalize_tool_name(tool) for tool in (expected_tools or TOOL_TO_PROFILE.keys()) if tool})
    profiles_payload = get_kali_profiles()
    tools_payload = get_kali_tools()
    installed: list[str] = []
    missing: list[str] = []
    missing_detail: list[dict[str, Any]] = []

    for tool in expected:
        availability = _tool_availability(tool, profiles_payload, tools_payload)
        if availability.get("available"):
            installed.append(tool)
            continue
        missing.append(tool)
        missing_detail.append(
            {
                "tool": tool,
                "status": availability.get("status"),
                "profile": availability.get("profile"),
                "binary_candidates": availability.get("binary_candidates") or [],
            }
        )

    return {
        "source": "kali_runner",
        "runner_reachable": bool(profiles_payload.get("reachable") and tools_payload.get("reachable")),
        "runner_error": profiles_payload.get("error") or tools_payload.get("error") or "",
        "total": len(expected),
        "installed": installed,
        "missing": missing,
        "missing_detail": missing_detail,
        "coverage_ratio": round(len(installed) / max(1, len(expected)), 3),
        "kali_tools_detected": int(tools_payload.get("count") or 0),
        "profiles_loaded": int(profiles_payload.get("count") or 0),
    }
