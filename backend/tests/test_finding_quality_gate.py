from app.services.finding_quality_gate import (
    adjudicate_finding,
    has_concrete_endpoint,
    is_active_web_vulnerability,
    is_actionable_for_vulnerability_inventory,
)
from app.services.findings_extractor import _extract_shodan_kali_findings
from app.services.tech_vuln_correlator import _local_cve_applies, _valid_detected_tech


def test_sqli_on_apex_domain_is_refuted_without_concrete_endpoint() -> None:
    status, severity, details = adjudicate_finding(
        title="SQL Injection detectada",
        severity="critical",
        tool="sqlmap",
        details={"asset": "valid.com", "verification_status": "confirmed"},
        target="valid.com",
        url=None,
    )

    assert status == "refuted"
    assert severity == "info"
    assert details["false_positive_reason"] == "missing_concrete_endpoint"


def test_waf_response_refutes_active_web_finding_even_with_endpoint() -> None:
    status, severity, details = adjudicate_finding(
        title="SQL Injection detectada",
        severity="critical",
        tool="sqlmap",
        details={
            "asset": "valid.com",
            "url": "https://valid.com/search?q=1",
            "verification_status": "confirmed",
            "response_headers": {"Server": "cloudflare", "CF-Ray": "abc123"},
            "evidence": "HTTP/1.1 403 Forbidden - request blocked",
        },
        target="valid.com",
        url="https://valid.com/search?q=1",
    )

    assert status == "refuted"
    assert severity == "info"
    assert details["false_positive_reason"] == "edge_control_response_not_application"
    assert details["edge_control_detected"] is True


def test_active_web_requires_path_or_query_endpoint_for_inventory() -> None:
    assert has_concrete_endpoint("https://valid.com/login") is True
    assert has_concrete_endpoint("https://valid.com/?q=1") is True
    assert has_concrete_endpoint("https://valid.com") is False

    assert not is_actionable_for_vulnerability_inventory(
        title="SQL Injection detectada",
        severity="critical",
        tool="sqlmap",
        details={"asset": "valid.com"},
        verification_status="confirmed",
        url="https://valid.com",
    )


def test_shodan_ports_on_edge_provider_are_inventory_only() -> None:
    findings = _extract_shodan_kali_findings(
        {
            "ip": "203.0.113.10",
            "isp": "Cloudflare, Inc.",
            "org": "Cloudflare",
            "host": "valid.com",
            "ports": [80, 443, 8443],
            "vulns": [],
            "banners": [],
        },
        "",
        "valid.com",
    )

    assert findings
    item = findings[0]
    assert item["severity"] == "info"
    assert item["details"]["inventory_only"] is True
    assert item["details"]["verification_status"] == "hypothesis"


def test_security_header_resource_policy_is_not_rce() -> None:
    assert is_active_web_vulnerability("Header ausente: cross-origin-resource-policy", "curl-headers", {}) is False


def test_nmap_cve_without_proof_is_hypothesis_inventory() -> None:
    status, severity, details = adjudicate_finding(
        title="CVE-2007-6750",
        severity="high",
        tool="nmap",
        details={"evidence": "CVE-2007-6750 — porta 80/tcp", "verification_status": "candidate"},
        target="example.com",
    )

    assert status == "hypothesis"
    assert severity == "medium"
    assert details["inventory_only"] is True


def test_unverified_waf_origin_is_hypothesis_inventory() -> None:
    status, severity, details = adjudicate_finding(
        title="[WAF-BYPASS] Origem potencial exposta atrás do WAF",
        severity="high",
        tool="waf_origin_discovery",
        details={"candidate_origins": [{"ip": "203.0.113.10"}], "verification_status": "candidate"},
        target="example.com",
    )

    assert status == "hypothesis"
    assert severity == "medium"
    assert details["inventory_only"] is True


def test_nikto_internal_ip_without_proof_is_hypothesis_inventory() -> None:
    status, severity, details = adjudicate_finding(
        title='Location header may reveal internal or real IP "10.0.0.1"',
        severity="high",
        tool="nikto",
        details={"evidence": "internal or real IP in the Location header", "verification_status": "candidate"},
        target="example.com",
    )

    assert status == "hypothesis"
    assert severity == "medium"
    assert details["inventory_only"] is True


def test_local_cve_range_filter_blocks_newer_nginx_and_impossible_wordpress() -> None:
    nginx_cve = {
        "title": "nginx resolver Off-By-One Heap Write (< 1.20.1)",
        "remediation": "Atualizar nginx para >= 1.20.1",
    }
    wordpress_cve = {
        "title": "WordPress < 5.8.3 SQL Injection (WP_Query)",
        "remediation": "Atualizar para WordPress >= 5.8.3",
    }

    assert _local_cve_applies("nginx", "1.18.0", nginx_cve) is True
    assert _local_cve_applies("nginx", "1.28.0", nginx_cve) is False
    assert _local_cve_applies("WordPress", "5.7.0", wordpress_cve) is True
    assert _local_cve_applies("WordPress", "6.9.4", wordpress_cve) is False
    assert _valid_detected_tech("Strict-Transport-Security", "63072000") is False
    assert _valid_detected_tech("X-XSS-Protection", "1") is False
    assert _valid_detected_tech("WordPress", "99.1.2") is False
