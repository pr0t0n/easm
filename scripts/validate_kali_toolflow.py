#!/usr/bin/env python3
"""Validate the Kali-only tool execution contract.

This script checks the static contract without requiring Docker:
  - every worker tool has a Kali profile mapping;
  - every mapped profile exists in kali-runner/profiles/*.yaml;
  - every mapped tool is referenced by at least one worker group and mission skill.

With --live it also queries the running Kali runner and verifies profile/binary
availability from /profiles and /tools. It never checks local backend binaries.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.graph.mission import PENTEST_PHASES, SKILL_CATALOG  # noqa: E402
from app.services.kali_executor import TOOL_TO_PROFILE  # noqa: E402
from app.workers.worker_groups import get_canonical_group_tools  # noqa: E402


def normalize(value: str | None) -> str:
    return str(value or "").strip().lower()


def load_profile_specs() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted((ROOT / "kali-runner" / "profiles").glob("*.yaml")):
        current: str | None = None
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.rstrip()
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line.startswith(" ") and line.endswith(":"):
                current = line[:-1].strip()
                profiles[current] = {"source": path.name}
                continue
            if current and line.startswith("  ") and ":" in line:
                key, raw_value = line.strip().split(":", 1)
                value = raw_value.strip()
                if value.startswith("["):
                    try:
                        profiles[current][key] = ast.literal_eval(value)
                    except Exception:
                        profiles[current][key] = value
                else:
                    profiles[current][key] = value.strip("'\"")
    return profiles


def build_worker_tool_map() -> dict[str, str]:
    result: dict[str, str] = {}
    for group, tools in get_canonical_group_tools().items():
        for tool in tools:
            result.setdefault(normalize(tool), group)
    return result


def build_skill_maps() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    tool_to_skills: dict[str, list[str]] = {}
    for skill in SKILL_CATALOG:
        skill_id = str(skill.get("id") or "")
        for tool in skill.get("playbook") or []:
            if skill_id:
                tool_to_skills.setdefault(normalize(tool), []).append(skill_id)

    tool_to_phases: dict[str, list[str]] = {}
    for phase in PENTEST_PHASES:
        phase_id = str(phase.get("id") or "")
        for tool in phase.get("tools") or []:
            if phase_id:
                tool_to_phases.setdefault(normalize(tool), []).append(phase_id)
    return tool_to_skills, tool_to_phases


def http_json(base_url: str, path: str) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw or "{}")


def live_runner_matrix(base_url: str) -> dict[str, Any]:
    profiles_payload = http_json(base_url, "/profiles")
    tools_payload = http_json(base_url, "/tools")
    profiles = profiles_payload.get("profiles") if isinstance(profiles_payload.get("profiles"), dict) else {}
    tools = tools_payload.get("tools") if isinstance(tools_payload.get("tools"), list) else []
    tool_names = {normalize(item.get("name")) for item in tools if isinstance(item, dict)}

    rows = []
    for tool, profile_id in sorted(TOOL_TO_PROFILE.items()):
        profile = profiles.get(profile_id) if isinstance(profiles, dict) else None
        command = profile.get("command") if isinstance(profile, dict) else []
        candidates = {
            normalize(tool),
            normalize(profile.get("tool") if isinstance(profile, dict) else ""),
            normalize(profile.get("command_executable") if isinstance(profile, dict) else ""),
        }
        if isinstance(command, list) and command:
            candidates.add(normalize(command[0]))
        executable = next((candidate for candidate in sorted(candidates) if candidate in tool_names), "")
        rows.append(
            {
                "tool": tool,
                "profile": profile_id,
                "profile_loaded": bool(profile),
                "executable": executable,
                "ready": bool(profile and executable),
            }
        )
    return {
        "runner_reachable": True,
        "profiles_loaded": profiles_payload.get("count", len(profiles)),
        "kali_tools_detected": tools_payload.get("count", len(tools)),
        "ready": sum(1 for row in rows if row["ready"]),
        "expected": len(rows),
        "missing": [row for row in rows if not row["ready"]],
    }


def validate(group_filter: str | None = None, live: bool = False, runner_url: str = "") -> dict[str, Any]:
    profiles = load_profile_specs()
    worker_tools = build_worker_tool_map()
    skill_map, phase_map = build_skill_maps()

    expected_tools = sorted(TOOL_TO_PROFILE)
    if group_filter:
        group_name = normalize(group_filter)
        expected_tools = [
            tool for tool in expected_tools
            if normalize(worker_tools.get(tool)) in {group_name, normalize(group_filter)}
        ]

    rows: list[dict[str, Any]] = []
    for tool in expected_tools:
        profile_id = TOOL_TO_PROFILE[tool]
        profile = profiles.get(profile_id) or {}
        command = profile.get("cmd") if isinstance(profile.get("cmd"), list) else []
        executable = command[0] if command else profile.get("tool")
        rows.append(
            {
                "tool": tool,
                "profile": profile_id,
                "profile_exists": profile_id in profiles,
                "profile_tool": profile.get("tool"),
                "executable": executable,
                "worker_group": worker_tools.get(tool),
                "skills": sorted(set(skill_map.get(tool, []))),
                "mission_phases": sorted(set(phase_map.get(tool, []))),
            }
        )

    failures = []
    worker_tool_set = set(worker_tools)
    mapped_tool_set = set(TOOL_TO_PROFILE)
    for tool in sorted(worker_tool_set - mapped_tool_set):
        failures.append({"type": "worker_tool_without_kali_profile", "tool": tool})
    for tool in sorted(mapped_tool_set - worker_tool_set):
        failures.append({"type": "kali_profile_without_worker_group", "tool": tool})
    for row in rows:
        if not row["profile_exists"]:
            failures.append({"type": "missing_profile_yaml", "tool": row["tool"], "profile": row["profile"]})
        if not row["worker_group"]:
            failures.append({"type": "missing_worker_group", "tool": row["tool"]})
        if not row["skills"]:
            failures.append({"type": "missing_skill_mapping", "tool": row["tool"]})
        if not row["mission_phases"]:
            failures.append({"type": "missing_mission_phase", "tool": row["tool"]})

    live_payload: dict[str, Any] | None = None
    if live:
        try:
            live_payload = live_runner_matrix(runner_url)
            for row in live_payload.get("missing", []):
                failures.append({"type": "live_runner_tool_not_ready", **row})
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            live_payload = {"runner_reachable": False, "error": str(exc)}
            failures.append({"type": "live_runner_unreachable", "error": str(exc)})

    return {
        "ok": not failures,
        "source": "kali_runner",
        "group_filter": group_filter or "",
        "expected_tools": len(expected_tools),
        "profiles_loaded_from_yaml": len(profiles),
        "worker_tools": len(worker_tools),
        "rows": rows,
        "failures": failures,
        "live": live_payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Kali-only toolflow mapping")
    parser.add_argument("--group", default="", help="Optional worker group filter, e.g. reconnaissance or exploitation")
    parser.add_argument("--live", action="store_true", help="Query the running Kali runner")
    parser.add_argument(
        "--runner-url",
        default=os.getenv("KALI_RUNNER_URL", "http://localhost:8088"),
        help="Kali runner base URL for --live",
    )
    args = parser.parse_args()

    payload = validate(group_filter=args.group or None, live=args.live, runner_url=args.runner_url)
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
