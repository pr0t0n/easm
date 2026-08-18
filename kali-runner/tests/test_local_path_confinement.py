"""KALI-003 regression tests.

_target_validation_error's local_path check only verified the path existed
and was a directory, with no confinement to WORKSPACE. gitleaks/trufflehog/
semgrep/bandit/trivy would then scan (and exfiltrate into Finding/Evidence
rows) whatever an operator-supplied source_path pointed at anywhere on the
container filesystem. The container has no bind mount for external source
code other than WORKSPACE, so confining to it is not a functional regression.
"""
from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_runner(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("KALI_WORKSPACE", str(workspace))
    module_name = f"kali_runner_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "kali-runner" / "runner.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module, workspace


def test_local_path_inside_workspace_is_allowed(monkeypatch, tmp_path):
    runner, workspace = _load_runner(monkeypatch, tmp_path)
    repo_dir = workspace / "repos" / "extracted-artifact"
    repo_dir.mkdir(parents=True)

    error = runner._target_validation_error({"target_type": "local_path"}, str(repo_dir))
    assert error == ""


def test_local_path_equal_to_workspace_root_is_allowed(monkeypatch, tmp_path):
    runner, workspace = _load_runner(monkeypatch, tmp_path)
    error = runner._target_validation_error({"target_type": "local_path"}, str(workspace))
    assert error == ""


def test_local_path_outside_workspace_is_rejected(monkeypatch, tmp_path):
    runner, workspace = _load_runner(monkeypatch, tmp_path)
    outside_dir = tmp_path / "not-the-workspace"
    outside_dir.mkdir()

    error = runner._target_validation_error({"target_type": "local_path"}, str(outside_dir))
    assert "must be confined under" in error


def test_local_path_traversal_out_of_workspace_is_rejected(monkeypatch, tmp_path):
    runner, workspace = _load_runner(monkeypatch, tmp_path)
    traversal = str(workspace / ".." / "not-the-workspace")
    (tmp_path / "not-the-workspace").mkdir()

    error = runner._target_validation_error({"target_type": "local_path"}, traversal)
    assert "must be confined under" in error


def test_sensitive_existing_paths_outside_workspace_are_rejected(monkeypatch, tmp_path):
    """Stand-in for the real concern (an operator-supplied source_path
    pointing at /etc, /app, /opt/tools inside the kali-runner container) --
    any existing directory outside WORKSPACE must be rejected, regardless of
    which one it is."""
    runner, workspace = _load_runner(monkeypatch, tmp_path)
    for sensitive in ["/etc", "/tmp", "/var"]:
        if not Path(sensitive).is_dir():
            continue
        error = runner._target_validation_error({"target_type": "local_path"}, sensitive)
        assert "must be confined under" in error, f"expected rejection for {sensitive}"
