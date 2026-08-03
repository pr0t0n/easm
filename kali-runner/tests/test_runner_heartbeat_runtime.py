from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_runner(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.setenv("KALI_HEARTBEAT_INTERVAL", "1")
    module_name = f"kali_runner_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "kali-runner" / "runner.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_silent_live_process_emits_heartbeat_without_output(monkeypatch, tmp_path) -> None:
    runner = _load_runner(monkeypatch, tmp_path)
    profile = {
        "tool": "silent-heartbeat-test",
        "cmd": ["python3", "-c", "import time; time.sleep(2.5)"],
        "timeout": 10,
        "heartbeat_interval": 1,
        "silence_timeout": 0,
        "parser": "raw",
    }
    request = runner.JobRequest(
        profile="silent-heartbeat-test",
        target="example.com",
        scan_id=1,
        authorized_scope=["example.com"],
    )
    job = runner._new_job_record(request, profile)
    runner._JOBS[job["job_id"]] = job

    runner._run_job(job["job_id"], profile, request)

    result = runner._JOBS[job["job_id"]]
    assert result["status"] == "done"
    assert result["heartbeat_sequence"] >= 2
    assert result["heartbeat_at"]
    assert result["output_bytes"] == 0
    assert result["timeout_policy"] == {
        "hard_timeout_seconds": 10,
        "silence_timeout_seconds": 0,
        "heartbeat_interval_seconds": 1,
        "silence_timeout_enabled": False,
    }


def test_output_is_persisted_incrementally_and_counted(monkeypatch, tmp_path) -> None:
    runner = _load_runner(monkeypatch, tmp_path)
    profile = {
        "tool": "stream-evidence-test",
        "cmd": [
            "python3",
            "-c",
            "import time; print('prefix', flush=True); time.sleep(1.5); print('suffix', flush=True)",
        ],
        "timeout": 10,
        "heartbeat_interval": 1,
        "silence_timeout": 0,
        "parser": "raw",
    }
    request = runner.JobRequest(
        profile="stream-evidence-test",
        target="example.com",
        scan_id=2,
        authorized_scope=["example.com"],
    )
    job = runner._new_job_record(request, profile)
    runner._JOBS[job["job_id"]] = job

    runner._run_job(job["job_id"], profile, request)

    result = runner._JOBS[job["job_id"]]
    evidence = Path(result["workdir"], "stdout.txt").read_text(encoding="utf-8")
    assert result["status"] == "done"
    assert result["output_activity_at"]
    assert result["output_bytes"] >= len("prefix\nsuffix\n")
    assert evidence == "prefix\nsuffix\n"
