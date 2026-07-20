from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_network_profiles_cannot_auto_expand_or_follow_redirects() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    executable_lines = [line for line in source.splitlines() if not line.lstrip().startswith("#")]
    executable_source = "\n".join(executable_lines)
    assert '"-tls-probe"' not in executable_source
    assert '"-follow-redirects"' not in executable_source
    assert '"-L"' not in executable_source
    assert '"--location"' not in executable_source
    assert executable_source.count('"-location"') >= 2
    assert executable_source.count('"-dr"') >= 3
    assert '"--no-redirect"' in executable_source
    assert '"--whitelist-domain", "{host}"' in executable_source


def test_runner_requires_authorized_scope() -> None:
    runner_source = (ROOT / "kali-runner" / "runner.py").read_text(encoding="utf-8")
    assert 'raise HTTPException(status_code=400, detail="authorized_scope is required")' in runner_source
    assert 'return False, "no_authorized_scope_provided"' in runner_source
