from app.services.scan_intelligence import preflight_skip_reason


def test_p02_is_not_skipped_by_backend_dns_dead_preflight() -> None:
    profile = {
        "status": "dns_dead",
        "reason": "host não resolve em DNS no backend",
    }

    assert preflight_skip_reason("P02", profile) is None


def test_p06_is_not_skipped_by_backend_dns_dead_preflight() -> None:
    profile = {
        "status": "dns_dead",
        "reason": "host não resolve em DNS no backend",
    }

    assert preflight_skip_reason("P06", profile) is None


def test_later_deep_phases_still_gate_dns_dead_until_qualified() -> None:
    profile = {
        "status": "dns_dead",
        "reason": "host não resolve em DNS no backend",
    }

    assert preflight_skip_reason("P03", profile) == "host não resolve em DNS no backend"
