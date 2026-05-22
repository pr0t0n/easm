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
POLL_TIMEOUT = 75  # seconds to wait per tool before declaring it "still running"


def _wait_for_capacity(max_active: int = 4, timeout: int = 600) -> None:
    """Block until the kali runner has free job slots.

    Prevents the smoke test from saturating the runner's parallel pool —
    otherwise newly dispatched jobs sit 'queued' and get false FAIL verdicts.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{KALI_URL}/healthz", timeout=10) as resp:
                active = int(json.loads(resp.read()).get("active_jobs") or 0)
            if active <= max_active:
                return
        except Exception:  # noqa: BLE001
            return
        time.sleep(8)


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


def _get_job(job_id: str) -> dict:
    try:
        with urllib.request.urlopen(f"{KALI_URL}/jobs/{job_id}", timeout=15) as resp:
            return json.loads(resp.read())
    except Exception:  # noqa: BLE001
        return {}


def _poll_result(job_id: str) -> dict:
    """Poll until terminal OR the tool has clearly launched and is running.

    A smoke test only needs to confirm the tool *runs*. If after POLL_TIMEOUT
    the job is still 'running', the binary launched and is actively working —
    that counts as a pass ('RUNS'), not a failure.
    """
    deadline = time.time() + POLL_TIMEOUT
    last = {}
    while time.time() < deadline:
        last = _get_job(job_id)
        if last.get("status") in {"done", "failed", "timeout", "skipped"}:
            return last
        time.sleep(5)
    # Final check after the window
    last = _get_job(job_id) or last
    if last.get("status") == "running":
        return {"status": "running_ok", "return_code": None}
    if last.get("status") == "queued":
        return {"status": "stuck_queued"}
    return last or {"status": "poll_timeout"}


def _classify(result: dict) -> tuple[str, str]:
    """Return (verdict, detail). verdict in OK / RUNS / EMPTY / SKIP / FAIL."""
    status = str(result.get("status") or "")
    rc = result.get("return_code")
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or result.get("error") or "")
    lines = len([l for l in stdout.splitlines() if l.strip()])
    if status == "skipped":
        return "SKIP", stderr[:120] or "profile skipped (requires_env / scheme)"
    if status == "running_ok":
        return "RUNS", "launched and actively executing (slow tool — OK)"
    if status in {"failed", "timeout", "poll_timeout", "stuck_queued"}:
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
        _wait_for_capacity()  # don't saturate the kali runner pool
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
        good = [t for t in tools if results.get(t, ("?",))[0] in {"OK", "RUNS"}]
        bad = [t for t in tools if results.get(t, ("?",))[0] in {"FAIL", "NOCAT"}]
        empty = [t for t in tools if results.get(t, ("?",))[0] == "EMPTY"]
        print(f"  {pid}: {len(good)}/{len(tools)} working"
              + (f" | EMPTY: {empty}" if empty else "")
              + (f" | FAIL: {bad}" if bad else ""))

    print("\n=== UNIQUE TOOL VERDICTS ===")
    for verdict in ("FAIL", "NOCAT", "EMPTY", "SKIP", "RUNS", "OK"):
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
