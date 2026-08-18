"""SEC-004 regression tests.

kali-runner's scope check matched the literal hostname string against
authorized_scope but never resolved DNS, so a public-looking in-scope domain
whose record points at a private/loopback/link-local address (DNS rebinding)
sailed through unchecked. _disallowed_dns_rebind closes that gap.
"""
from __future__ import annotations

import importlib.util
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


def _fake_getaddrinfo(ips):
    def _impl(host, port, *args, **kwargs):
        return [(None, None, None, None, (ip, 0)) for ip in ips]
    return _impl


def test_literal_ip_target_is_not_subject_to_rebind_check(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    unsafe, reason = runner._disallowed_dns_rebind("93.184.216.34", ["93.184.216.34"])
    assert unsafe is False


def test_hostname_resolving_to_public_ip_is_allowed(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34"]))
    unsafe, reason = runner._disallowed_dns_rebind("example.com", ["example.com"])
    assert unsafe is False


def test_hostname_rebinding_to_loopback_is_rejected(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["127.0.0.1"]))
    unsafe, reason = runner._disallowed_dns_rebind("example.com", ["example.com"])
    assert unsafe is True
    assert "127.0.0.1" in reason


def test_hostname_rebinding_to_cloud_metadata_address_is_rejected(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["169.254.169.254"]))
    unsafe, reason = runner._disallowed_dns_rebind("example.com", ["example.com"])
    assert unsafe is True


def test_hostname_rebinding_to_rfc1918_is_rejected_when_not_explicitly_scoped(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["10.0.0.5"]))
    unsafe, reason = runner._disallowed_dns_rebind("example.com", ["example.com"])
    assert unsafe is True


def test_private_address_allowed_when_explicitly_authorized_by_cidr(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["10.0.0.5"]))
    # Operator explicitly authorized this internal range (e.g. staging host on
    # the docker bridge) -- must not be rejected as "rebinding".
    unsafe, reason = runner._disallowed_dns_rebind("internal-staging.example.com", ["10.0.0.0/8"])
    assert unsafe is False


def test_multi_record_host_rejected_if_any_record_is_private(monkeypatch, tmp_path):
    runner = _load_runner(monkeypatch, tmp_path)
    # A rebinding attempt might only make SOME records private -- must check all.
    monkeypatch.setattr(runner.socket, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34", "127.0.0.1"]))
    unsafe, reason = runner._disallowed_dns_rebind("example.com", ["example.com"])
    assert unsafe is True


def test_dns_resolution_failure_fails_open_to_allow_scope_decision_elsewhere(monkeypatch, tmp_path):
    # If DNS can't be resolved at all, _resolve_all_host_ips returns [] and
    # there's nothing to flag as a rebind -- the existing hostname-based scope
    # check (and _is_unsafe_target) are what gate this target, unchanged.
    runner = _load_runner(monkeypatch, tmp_path)

    def _raise(host, port, *args, **kwargs):
        raise OSError("resolution failed")

    monkeypatch.setattr(runner.socket, "getaddrinfo", _raise)
    unsafe, reason = runner._disallowed_dns_rebind("nonexistent.invalid", ["nonexistent.invalid"])
    assert unsafe is False
