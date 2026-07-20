#!/usr/bin/env python3
"""Run a live-contract/offline-target smoke tabletop for valid.com."""
from __future__ import annotations

import argparse
import json

import requests

from app.core.config import settings
from app.services.pentest_tabletop import run_valid_com_tabletop


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?", default="valid.com")
    parser.add_argument("--offline", action="store_true", help="skip internal platform profile/tool checks")
    args = parser.parse_args()

    profiles = None
    tools = None
    platform = {"checked": not args.offline, "healthy": True}
    if not args.offline:
        base = str(settings.kali_runner_url or "http://kali_runner:8088").rstrip("/")
        health_response = requests.get(f"{base}/healthz", timeout=8)
        health_response.raise_for_status()
        profiles_response = requests.get(f"{base}/profiles", timeout=8)
        profiles_response.raise_for_status()
        tools_response = requests.get(f"{base}/tools", timeout=12)
        tools_response.raise_for_status()
        health = health_response.json()
        profiles_payload = profiles_response.json()
        tools_payload = tools_response.json()
        profiles = dict(profiles_payload.get("profiles") or {})
        tools = {str(row.get("name") or "") for row in list(tools_payload.get("tools") or []) if isinstance(row, dict)}
        platform.update({
            "kali_status": health.get("status"),
            "profiles_loaded": health.get("profiles_loaded"),
            "tools_detected": health.get("kali_tools_detected"),
            "active_jobs_before": health.get("active_jobs"),
        })

    result = run_valid_com_tabletop(args.domain, live_profiles=profiles, live_tools=tools)
    result["platform_contract_smoke"] = platform
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result["status"] == "passed" and platform["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
