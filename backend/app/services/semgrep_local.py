"""Backend-local Semgrep adapter.

Semgrep is SAST: it needs source code or a mounted artifact path. It should not
be treated as a Kali web scanner for arbitrary live URLs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse


def _local_path(target: str) -> Path | None:
    raw = str(target or "").strip()
    if not raw:
        return None
    if raw.startswith("file://"):
        raw = urlparse(raw).path
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"}:
        return None
    path = Path(raw).expanduser()
    return path if path.exists() else None


def run_as_tool(target: str) -> dict[str, Any]:
    path = _local_path(target)
    if path is None:
        return {
            "tool": "semgrep",
            "target": target,
            "scan_mode": "unit",
            "status": "blocked",
            "command": "semgrep scan --json <source>",
            "stdout": "",
            "stderr": "source_code_required",
            "dispatch_error": "source_code_required",
            "parsed": {"source_required": True},
            "findings_extracted": [],
        }

    binary = shutil.which("semgrep")
    if not binary:
        return {
            "tool": "semgrep",
            "target": str(path),
            "scan_mode": "unit",
            "status": "blocked",
            "command": "semgrep scan --json <source>",
            "stdout": "",
            "stderr": "semgrep_binary_missing",
            "dispatch_error": "semgrep_binary_missing",
            "parsed": {"source_path": str(path), "binary_missing": True},
            "findings_extracted": [],
        }

    config = os.getenv("SEMGREP_CONFIG", "p/security-audit")
    command = [binary, "scan", "--json", "--config", config, str(path)]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=int(os.getenv("SEMGREP_TIMEOUT", "900")))
    stdout = proc.stdout or ""
    parsed: dict[str, Any]
    try:
        parsed = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        parsed = {"parse_error": True}

    try:
        from app.services.findings_extractor import _extract_semgrep_findings

        findings = _extract_semgrep_findings(stdout, str(path))
    except Exception:  # noqa: BLE001
        findings = []

    status = "done" if proc.returncode in {0, 1} and isinstance(parsed, dict) else "failed"
    return {
        "tool": "semgrep",
        "target": str(path),
        "scan_mode": "unit",
        "status": status,
        "command": " ".join(command),
        "return_code": proc.returncode,
        "stdout": stdout[:200_000],
        "stderr": (proc.stderr or "")[:20_000],
        "parsed": parsed,
        "findings_extracted": findings,
    }
