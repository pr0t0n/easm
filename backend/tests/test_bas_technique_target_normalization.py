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


def test_accepts_range_preserves_cidr_mask():
    assert _normalize_target("10.10.10.0/24", "host", accepts_range=True) == "10.10.10.0/24"


def test_accepts_range_still_normalizes_a_plain_single_host():
    """accepts_range=True doesn't change single-host behavior -- only a real
    multi-address CIDR takes the preserved-mask path."""
    assert _normalize_target("192.168.1.65:8001", "host", accepts_range=True) == "192.168.1.65"


def test_accepts_range_false_strips_the_mask_from_a_cidr_string():
    """Regression: without accepts_range, a technique that got a CIDR by
    mistake (or before this technique was marked accepts_range) must keep
    the old, safe behavior -- mangled to a bare host, not silently scanning
    an unintended range."""
    assert _normalize_target("10.10.10.0/24", "host", accepts_range=False) == "10.10.10.0"


def test_a_single_host_cidr_slash_32_does_not_take_the_range_path():
    """/32 has exactly one address -- treat it as the plain host it is."""
    assert _normalize_target("10.10.10.5/32", "host", accepts_range=True) == "10.10.10.5"
