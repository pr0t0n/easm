#!/usr/bin/env python3
"""Validate tool timeouts in Kali runner profile YAML files."""
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_kali_toolflow import load_profile_specs  # noqa: E402


MIN_TIMEOUTS = {
    "curl-headers": 30,
    "sslscan": 60,
    "testssl": 300,
    "nikto": 300,
    "nuclei": 300,
    "nmap": 300,
    "nmap-vulscan": 300,
    "sqlmap": 300,
    "wapiti": 600,
    "feroxbuster": 300,
}


def main() -> int:
    profiles = load_profile_specs()
    failures: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []

    for profile_id, profile in sorted(profiles.items()):
        tool = str(profile.get("tool") or "")
        timeout_raw = profile.get("timeout") or 0
        try:
            timeout = int(timeout_raw)
        except (TypeError, ValueError):
            timeout = 0
        minimum = MIN_TIMEOUTS.get(tool)
        row = {
            "profile": profile_id,
            "tool": tool,
            "timeout": timeout,
            "minimum": minimum,
            "source": profile.get("source"),
        }
        rows.append(row)
        if timeout <= 0:
            failures.append({"type": "missing_timeout", **row})
        if minimum is not None and timeout < minimum:
            failures.append({"type": "timeout_too_low", **row})

    payload = {
        "ok": not failures,
        "profiles": len(profiles),
        "failures": failures,
        "rows": rows,
    }
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
