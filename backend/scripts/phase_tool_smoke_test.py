#!/usr/bin/env python3
"""Phase Tool Smoke Test — P01..P22.

Validates, for every tool referenced by every phase contract, that:
  1. the tool's kali profile resolves
  2. the tool actually executes on the kali runner
  3. it produces parseable output (not just exit 0 with empty stdout)

Run inside the worker/backend container:
    python3 /app/scripts/phase_tool_smoke_test.py [target]

Default target: valid.com

Output: a P01-P22 matrix + a unique-tool verdict table. Tools that fail are
listed with the captured error so the failure can be investigated and fixed.

This is a *smoke* test — it uses short timeouts / small wordlists where the
profile allows, because the goal is "does the tool run and emit output",
not "full-volume enumeration".
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request

sys.path.insert(0, "/app")

from app.services.offensive_operator_core import PHASE_CONTRACTS, default_tool_catalog  # noqa: E402

KALI_URL = "http://kali_runner:8088"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "valid.com"
POLL_TIMEOUT = 180  # seconds to wait per tool


def _post_job(profile: str, target: str) -> str | None:
    body = json.dumps({"profile": profile, "target": target}).encode()
    req = urllib.request.Request(f"{KALI_URL}/jobs", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read()).get("job_id")
    except Exception as exc:  # noqa: BLE001
        print(f"    dispatch error: {exc}")
        return None


def _poll_result(job_id: str) -> dict:
    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{KALI_URL}/jobs/{job_id}", timeout=15) as resp:
                data = json.loads(resp.read())
            if data.get("status") in {"done", "failed", "timeout", "skipped"}:
                return data
        except Exception:  # noqa: BLE001
            pass
        time.sleep(5)
    return {"status": "poll_timeout"}


def _classify(result: dict) -> tuple[str, str]:
    """Return (verdict, detail). verdict in OK / EMPTY / SKIP / FAIL."""
    status = str(result.get("status") or "")
    rc = result.get("return_code")
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or result.get("error") or "")
    lines = len([l for l in stdout.splitlines() if l.strip()])
    if status == "skipped":
        return "SKIP", stderr[:120] or "profile skipped (requires_env / scheme)"
    if status in {"failed", "timeout", "poll_timeout"}:
        return "FAIL", (stderr[:160] or f"status={status} rc={rc}")
    # status == done
    if lines > 0:
        return "OK", f"{lines} lines"
    return "EMPTY", f"ran rc={rc} but no stdout"


def main() -> int:
    catalog = {e.tool_name: e for e in default_tool_catalog()}
    # Collect unique tools across all phases
    phase_tools: dict[str, list[str]] = {}
    unique_tools: dict[str, str] = {}  # tool_name -> profile
    for pid, contract in PHASE_CONTRACTS.items():
        tools = list(dict.fromkeys(
            (contract.get("required_tools") or []) + (contract.get("optional_tools") or [])
        ))
        phase_tools[pid] = tools
        for t in tools:
            entry = catalog.get(t)
            if entry and t not in unique_tools:
                unique_tools[t] = entry.profile

    print(f"=== Phase Tool Smoke Test — target={TARGET} ===")
    print(f"Phases: {len(phase_tools)}  |  Unique tools: {len(unique_tools)}\n")

    # Test each unique tool once
    results: dict[str, tuple[str, str]] = {}
    for i, (tool, profile) in enumerate(sorted(unique_tools.items()), 1):
        print(f"[{i}/{len(unique_tools)}] {tool} (profile={profile}) ...", flush=True)
        job_id = _post_job(profile, TARGET)
        if not job_id:
            results[tool] = ("FAIL", "could not dispatch job")
            continue
        verdict, detail = _classify(_poll_result(job_id))
        results[tool] = (verdict, detail)
        print(f"    {verdict}: {detail}")

    # Tools in a phase contract but missing from the catalog
    for pid, tools in phase_tools.items():
        for t in tools:
            if t not in catalog and t not in results:
                results[t] = ("NOCAT", "tool not in backend catalog")

    # ─── Report ───────────────────────────────────────────────────────────
    print("\n\n=== PER-PHASE MATRIX ===")
    for pid in sorted(phase_tools):
        tools = phase_tools[pid]
        oks = [t for t in tools if results.get(t, ("?",))[0] == "OK"]
        bad = [t for t in tools if results.get(t, ("?",))[0] in {"FAIL", "NOCAT"}]
        empty = [t for t in tools if results.get(t, ("?",))[0] == "EMPTY"]
        print(f"  {pid}: {len(oks)}/{len(tools)} OK"
              + (f" | EMPTY: {empty}" if empty else "")
              + (f" | FAIL: {bad}" if bad else ""))

    print("\n=== UNIQUE TOOL VERDICTS ===")
    for verdict in ("FAIL", "NOCAT", "EMPTY", "SKIP", "OK"):
        group = sorted(t for t, (v, _) in results.items() if v == verdict)
        if group:
            print(f"\n  [{verdict}] ({len(group)})")
            for t in group:
                print(f"    {t}: {results[t][1]}")

    fails = [t for t, (v, _) in results.items() if v in {"FAIL", "NOCAT"}]
    print(f"\n=== SUMMARY: {len(results) - len(fails)}/{len(results)} tools OK/EMPTY/SKIP, {len(fails)} need fixing ===")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
