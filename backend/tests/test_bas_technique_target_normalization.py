"""bas_dispatcher._normalize_target: a schedule (especially a chain) shares
ONE target_hint across every step, but different techniques' underlying
tools expect different target shapes. Confirmed live: nmap given
"192.168.1.65:8001" for a "host"-only step (port_service_scan) misresolved
to a bogus multicast address instead of scanning the intended IP -- these
tests lock in the fix."""
from __future__ import annotations

from app.services.bas_dispatcher import _normalize_target


def test_host_format_strips_port_from_host_port_input():
    assert _normalize_target("192.168.1.65:8001", "host") == "192.168.1.65"


def test_host_format_strips_scheme_and_path():
    assert _normalize_target("https://192.168.1.65:8001/docs", "host") == "192.168.1.65"


def test_host_format_passes_through_a_bare_host_unchanged():
    assert _normalize_target("192.168.1.65", "host") == "192.168.1.65"


def test_domain_format_behaves_like_host():
    assert _normalize_target("https://github.com/foo", "domain") == "github.com"


def test_host_port_format_keeps_the_port_when_present():
    assert _normalize_target("192.168.1.65:8001", "host_port") == "192.168.1.65:8001"


def test_host_port_format_leaves_a_bare_host_without_inventing_a_port():
    assert _normalize_target("192.168.1.65", "host_port") == "192.168.1.65"


def test_host_port_format_strips_a_scheme_but_keeps_host_and_port():
    assert _normalize_target("http://192.168.1.65:8001/docs", "host_port") == "192.168.1.65:8001"


def test_url_format_adds_http_scheme_to_a_bare_host():
    assert _normalize_target("192.168.1.65:8001", "url") == "http://192.168.1.65:8001"


def test_url_format_leaves_an_already_schemed_url_untouched():
    assert _normalize_target("https://github.com/octocat/Hello-World", "url") == "https://github.com/octocat/Hello-World"


def test_empty_target_hint_stays_empty_regardless_of_format():
    assert _normalize_target("", "host") == ""
    assert _normalize_target("", "url") == ""
