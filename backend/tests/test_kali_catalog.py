from __future__ import annotations

from app.services import kali_catalog


def test_tool_availability_accepts_runner_wrapper_executables(monkeypatch) -> None:
    monkeypatch.setitem(kali_catalog.TOOL_TO_PROFILE, "wrapped-tool", "wrapped_profile")
    profiles_payload = {
        "reachable": True,
        "profiles": {
            "wrapped_profile": {
                "tool": "python3",
                "command": ["python3", "/opt/runner/wrapped_tool.py", "{target}"],
            }
        },
    }
    tools_payload = {"reachable": True, "tools_by_name": {}}

    result = kali_catalog._tool_availability("wrapped-tool", profiles_payload, tools_payload)

    assert result["available"] is True
    assert result["status"] == "ready"
    assert result["executable"] == "python3"


def test_tool_availability_accepts_absolute_runner_commands(monkeypatch) -> None:
    monkeypatch.setitem(kali_catalog.TOOL_TO_PROFILE, "absolute-tool", "absolute_profile")
    profiles_payload = {
        "reachable": True,
        "profiles": {
            "absolute_profile": {
                "tool": "absolute-tool",
                "command": ["/opt/pipx/venvs/tool/bin/python", "-m", "tool"],
            }
        },
    }
    tools_payload = {"reachable": True, "tools_by_name": {}}

    result = kali_catalog._tool_availability("absolute-tool", profiles_payload, tools_payload)

    assert result["available"] is True
    assert result["status"] == "ready"
    assert result["executable"] == "/opt/pipx/venvs/tool/bin/python"
