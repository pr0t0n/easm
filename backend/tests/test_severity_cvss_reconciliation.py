from app.services.findings_extractor import _reconcile_severity_cvss, _severity_from_cvss


def test_cvss_band_mapping():
    assert _severity_from_cvss(9.8) == "critical"
    assert _severity_from_cvss(9.0) == "critical"
    assert _severity_from_cvss(7.5) == "high"
    assert _severity_from_cvss(5.0) == "medium"
    assert _severity_from_cvss(2.0) == "low"
    assert _severity_from_cvss(0.0) is None
    assert _severity_from_cvss(None) is None


def test_high_cvss_upgrades_medium_to_critical():
    # Real bug: Apache mod_mime finding had CVSS 9.8 but severity "medium".
    sev, cvss = _reconcile_severity_cvss("medium", 9.8, "outros")
    assert sev == "critical"
    assert cvss == 9.8


def test_nosql_injection_floored_to_critical_with_representative_cvss():
    sev, cvss = _reconcile_severity_cvss("high", None, "nosql_injection")
    assert sev == "critical"
    assert cvss == 9.8


def test_upgrade_only_never_downgrades():
    # A tool's own higher rating must be preserved even with a low/absent CVSS.
    sev, cvss = _reconcile_severity_cvss("critical", 4.0, "outros")
    assert sev == "critical"
    assert cvss == 4.0


def test_info_finding_without_cvss_or_family_unchanged():
    sev, cvss = _reconcile_severity_cvss("info", None, "outros")
    assert sev == "info"
    assert cvss is None
