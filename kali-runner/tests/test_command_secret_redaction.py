"""command.txt (and the job-status 'command' field) must never carry the raw
session credential _inject_auth_headers bakes into argv for the subprocess.
Popen executes argv directly (never the joined string), so redacting the
display string cannot affect what actually runs.
"""
from __future__ import annotations

import importlib.util
import shlex
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_runner(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_WORKSPACE", str(tmp_path / "workspace"))
    module_name = f"kali_runner_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "kali-runner" / "runner.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_redacts_bearer_token_from_display_command_but_keeps_it_in_argv(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    argv = ["ffuf", "-u", "https://valid.com/FUZZ"]
    auth_headers = {"Authorization": "Bearer super-secret-session-token"}

    injected = runner._inject_auth_headers(argv, auth_headers, "ffuf")
    assert "super-secret-session-token" in " ".join(injected)  # real argv keeps it

    command = " ".join(shlex.quote(a) for a in injected)
    redacted = runner._redact_secrets_from_command(command, auth_headers)

    assert "super-secret-session-token" not in redacted
    assert "***REDACTED***" in redacted


def test_redacts_cookie_value_for_sqlmap(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    argv = ["sqlmap", "-u", "https://valid.com/x"]
    auth_headers = {"Cookie": "session=abc123secretvalue"}

    injected = runner._inject_auth_headers(argv, auth_headers, "sqlmap")
    command = " ".join(shlex.quote(a) for a in injected)
    redacted = runner._redact_secrets_from_command(command, auth_headers)

    assert "abc123secretvalue" not in redacted
    assert "session=abc123secretvalue" in command  # sanity: it really was there


def test_no_auth_headers_leaves_command_unchanged(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    command = "nmap -sV valid.com"
    assert runner._redact_secrets_from_command(command, None) == command
    assert runner._redact_secrets_from_command(command, {}) == command


def test_wafw00f_gets_healthy_outbound_proxy(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner, "_proxy_connectable", lambda proxy: True)

    argv = runner._inject_outbound_proxy(
        ["wafw00f", "https://valid.com"],
        {"KALI_OUTBOUND_PROXY": "http://proxy.local:3128"},
        "wafw00f",
    )

    assert argv == ["wafw00f", "https://valid.com", "--proxy", "http://proxy.local:3128"]
    assert runner._egress_context(argv, {"KALI_OUTBOUND_PROXY": "http://proxy.local:3128"}, {"tool": "wafw00f"})["egress_mode_declared"] == "proxy"


def test_wafw00f_keeps_direct_route_when_proxy_is_unhealthy(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner, "_proxy_connectable", lambda proxy: False)

    argv = runner._inject_outbound_proxy(
        ["wafw00f", "https://valid.com"],
        {"KALI_OUTBOUND_PROXY": "http://proxy.local:3128"},
        "wafw00f",
    )

    assert argv == ["wafw00f", "https://valid.com"]
