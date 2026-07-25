from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "p02_p06_observer.py"
SPEC = importlib.util.spec_from_file_location("p02_p06_observer", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_jaccard_treats_matching_negative_observations_as_coherent():
    assert MODULE.jaccard_percent([], []) == 100.0
    assert MODULE.jaccard_percent([80, 443], [443, 8080]) == 33.33


def test_network_classification_detects_docker_egress_failure():
    result = MODULE.classify_network(
        dns_ok=True,
        canary_tcp_ok=False,
        target_tcp_attempted=True,
    )
    assert result["category"] == "scanner_egress_failure"
    assert result["coherence_percent"] == 0.0
    assert result["reliable_negative"] is False


def test_scope_is_exact_host_only():
    assert MODULE.in_exact_scope("https://valid.com/api", "valid.com")
    assert not MODULE.in_exact_scope("https://api.valid.com/api", "valid.com")
    assert not MODULE.in_exact_scope("https://example.com/?next=valid.com", "valid.com")


def test_parsers_keep_results_in_scope_and_in_memory():
    output = """
    valid.com:443
    80/tcp open http
    https://valid.com/api?id=7
    https://example.com/out-of-scope?q=1
    """
    assert MODULE.parse_open_ports(output) == {80, 443}
    urls = MODULE.parse_urls(output, "valid.com")
    assert urls == {"https://valid.com/api?id=7"}
    assert MODULE.parameters_from_urls(urls) == {"id"}


def test_phase_score_is_conservative():
    result = MODULE.phase_result(
        "P02",
        execution=100,
        coverage=100,
        agreement=0,
        evidence=0,
        observations={},
    )
    assert result["coherence_percent"] == 50.0
    assert result["reliable"] is False


def test_http_origins_prioritize_standard_ports():
    origins = MODULE.origins_for("valid.com", {21, 8080, 8443})
    assert origins[:2] == ["https://valid.com", "http://valid.com"]
    assert "https://valid.com:8443" in origins
    assert "http://valid.com:21" in origins


def test_surface_phases_collapse_same_host_http_redirect():
    probes = [
        {
            "url": "https://valid.com",
            "status": "completed",
            "http_status": 200,
            "location": None,
        },
        {
            "url": "http://valid.com",
            "status": "completed",
            "http_status": 301,
            "location": "https://valid.com/",
        },
    ]
    assert MODULE.collapse_same_host_redirects(probes, "valid.com") == ["https://valid.com"]


def test_p02_semantics_rejects_waf_port_explosion_and_nmap_host_timeout():
    result = MODULE.classify_p02_scanner_semantics(
        naabu_status="completed",
        naabu_ports=set(range(1, 401)),
        naabu_top_ports=1000,
        nmap_status="completed",
        nmap_ports=set(),
        nmap_output="Skipping host valid.com due to host timeout",
    )
    assert result["naabu_edge_accept_signature"] is True
    assert result["nmap_inconclusive"] is True
    assert result["reliable_scanner_count"] == 0
    assert result["confirmed_ports"] == set()


def test_p02_semantics_requires_scanner_intersection_when_both_are_reliable():
    result = MODULE.classify_p02_scanner_semantics(
        naabu_status="completed",
        naabu_ports={80, 443, 8080},
        naabu_top_ports=1000,
        nmap_status="completed",
        nmap_ports={80, 443},
        nmap_output="PORT STATE SERVICE\n80/tcp open http\n443/tcp open https",
    )
    assert result["confirmation_policy"] == "intersection_of_two_reliable_scanners"
    assert result["confirmed_ports"] == {80, 443}


def test_p02_semantics_marks_mass_ssl_guesses_as_edge_ambiguity():
    rows = "\n".join(
        f"{port}/tcp open ssl/service? unknown"
        for port in range(8000, 8012)
    )
    result = MODULE.classify_p02_scanner_semantics(
        naabu_status="completed",
        naabu_ports={80, 443},
        naabu_top_ports=1000,
        nmap_status="completed",
        nmap_ports=set(range(8000, 8012)),
        nmap_output=f"PORT STATE SERVICE VERSION\n{rows}",
    )
    assert result["nmap_edge_service_ambiguity"] is True
    assert result["service_identity_reliable"] is False


def test_cli_has_no_output_file_option():
    parser = MODULE.build_parser()
    destinations = {action.dest for action in parser._actions}
    assert "output" not in destinations
    assert "database" not in destinations
