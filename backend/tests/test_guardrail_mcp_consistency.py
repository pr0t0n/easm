"""KALI-002 regression tests.

crackmapexec's post_exploitation.yaml profile only ever runs `--shares`, but
the tool also supports credential-dump (--sam/--lsa/--ntds) and remote
command execution via SMB (-x/-X/--exec-method) -- previously uncovered by
either guardrail_policy.py (backend) or mcp_server.py's mirrored deny-list,
so an extra_arg (or a future profile) could reach either without being
stripped.

The SSOT-mirror consistency check (mcp-server/ isn't mounted into this
backend test container -- see docker-compose.yml's kali_runner service) lives
in kali-runner/tests/test_guardrail_mcp_consistency.py instead, run from the
host where both backend/ and mcp-server/ are visible by relative path.
"""
from __future__ import annotations


def test_crackmapexec_credential_dump_flags_are_stripped():
    from app.services.guardrail_policy import sanitize_tool_args

    clean, removed = sanitize_tool_args(
        "crackmapexec", ["smb", "target", "-u", "admin", "-p", "pw", "--sam", "--lsa", "--ntds"],
    )
    assert "--sam" in removed
    assert "--lsa" in removed
    assert "--ntds" in removed
    assert "-u" in clean and "-p" in clean  # legitimate auth flags untouched


def test_crackmapexec_remote_exec_flags_are_stripped():
    from app.services.guardrail_policy import sanitize_tool_args

    clean, removed = sanitize_tool_args(
        "crackmapexec", ["smb", "target", "-x", "whoami", "-X", "Get-Process", "--exec-method", "wmiexec"],
    )
    assert any(r.startswith("-x") for r in removed)
    assert any(r.startswith("-X") for r in removed)
    assert any("exec-method" in r for r in removed)


def test_crackmapexec_shares_listing_is_untouched():
    """The one flag the live profile actually uses must survive."""
    from app.services.guardrail_policy import sanitize_tool_args

    clean, removed = sanitize_tool_args("crackmapexec", ["smb", "target", "--shares"])
    assert "--shares" in clean
    assert removed == []
