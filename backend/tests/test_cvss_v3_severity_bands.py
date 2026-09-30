from app.services.cve_enricher import _severity_from_cvss_v3
from app.services.evidence_contract_service import _cap_severity, _severity_floor_from_cvss


def test_cve_enricher_uses_cvss_v3_bands_not_v2_baseseverity():
    # CVSS v2 has no "critical" band (7.0-10.0 all "HIGH"); v3 must yield critical.
    assert _severity_from_cvss_v3(9.8) == "critical"
    assert _severity_from_cvss_v3(9.0) == "critical"
    assert _severity_from_cvss_v3(8.9) == "high"
    assert _severity_from_cvss_v3(7.0) == "high"
    assert _severity_from_cvss_v3(6.9) == "medium"
    assert _severity_from_cvss_v3(4.0) == "medium"
    assert _severity_from_cvss_v3(3.9) == "low"
    assert _severity_from_cvss_v3(0.0) == "info"


def test_evidence_cap_never_drops_below_cvss_floor():
    # A CVSS-9.8 candidate finding capped to "high" must stay critical.
    assert _cap_severity("critical", "high", floor="critical") == "critical"
    # hypothesis cap to medium on a 9.8 stays critical
    assert _cap_severity("critical", "medium", floor="critical") == "critical"
    # without a floor, the cap still applies (unknown/absent CVSS)
    assert _cap_severity("critical", "high", floor=None) == "high"
    # floor never inflates above the finding's own severity beyond the band
    assert _cap_severity("low", "medium", floor=None) == "low"


def test_severity_floor_from_cvss():
    assert _severity_floor_from_cvss(9.8) == "critical"
    assert _severity_floor_from_cvss(7.5) == "high"
    assert _severity_floor_from_cvss(5.0) == "medium"
    assert _severity_floor_from_cvss(None) is None
    assert _severity_floor_from_cvss("bad") is None
