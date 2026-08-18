"""KALI-002 / SSOT-mirror regression test.

guardrail_policy.py's own docstring requires: "O MCP (gateway antes do kali)
tem um espelho desta deny-list -- mantenha os dois em sincronia." Nothing
previously enforced that mechanically. Loaded by direct file path (not via
`app.` package imports) since this backend module has zero external
dependencies beyond `re`, and this is the one place in the repo where both
backend/ and mcp-server/ are visible by relative path in the same test run
(neither is mounted into the other's own container).
"""
from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_by_path(rel_path: str):
    module_name = f"guardrail_consistency_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / rel_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_backend_and_mcp_server_deny_lists_stay_in_sync():
    guardrail_policy = _load_by_path("backend/app/services/guardrail_policy.py")
    mcp_server = _load_by_path("mcp-server/mcp_server.py")

    backend_tools = dict(guardrail_policy.FORBIDDEN_ARG_PATTERNS)
    mcp_tools = dict(mcp_server._GUARDRAIL_BY_TOOL)

    assert set(backend_tools.keys()) == set(mcp_tools.keys()), (
        "guardrail_policy.py and mcp_server.py cover a different set of tools "
        "-- the SSOT-mirror comment in guardrail_policy.py's docstring requires "
        "them to stay in sync"
    )
    for tool, patterns in backend_tools.items():
        assert sorted(patterns) == sorted(mcp_tools[tool]), (
            f"deny-list for {tool!r} diverged between guardrail_policy.py and mcp_server.py"
        )

    assert sorted(guardrail_policy._GLOBAL_FORBIDDEN) == sorted(mcp_server._GUARDRAIL_GLOBAL)
    assert guardrail_policy._THREAD_CAPS == mcp_server._GUARDRAIL_THREAD_CAPS
