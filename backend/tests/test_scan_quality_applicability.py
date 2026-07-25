from types import SimpleNamespace

from app.services.scan_quality import (
    _auth_classification_bucket,
    _coverage_bucket,
    _skill_runtime_attribution,
)


def test_discovery_coverage_is_inventory_not_actionable_surface_debt():
    row = SimpleNamespace(
        coverage_type="endpoint",
        test_class="discovery",
        status="discovered",
        blocking_reason=None,
    )

    assert _coverage_bucket(row) == "inventory"


def test_external_precondition_coverage_is_separated_from_applicable_denominator():
    row = SimpleNamespace(
        coverage_type="endpoint_auth",
        test_class="auth_matrix",
        status="blocked_missing_auth",
        blocking_reason="missing_valid_identity_pair",
    )

    assert _coverage_bucket(row) == "external_precondition"


def test_failed_anonymous_probe_is_reachability_not_auth_unknown():
    endpoint = SimpleNamespace(
        auth_required=None,
        endpoint_metadata={
            "auth_classification": {
                "reason": "anonymous_probe_failed",
                "anonymous": {"ok": False, "error": "ConnectTimeout"},
            }
        },
    )

    assert _auth_classification_bucket(endpoint) == "unclassifiable_reachability"


def test_passive_archive_endpoint_without_baseline_is_not_auth_actionable_yet():
    endpoint = SimpleNamespace(
        auth_required=None,
        status_code=None,
        source_tool="waybackurls",
        endpoint_metadata={},
    )

    assert _auth_classification_bucket(endpoint) == "unclassifiable_passive_archive"


def test_agent_runtime_success_attributes_required_phase_skill():
    job = SimpleNamespace(
        state_data={
            "agent_execution_runs": [
                {"phase_id": "P01", "status": "success"},
            ]
        }
    )

    attributed, executed = _skill_runtime_attribution(job)

    assert "skill.recon.subdomain_enumeration" in attributed
    assert "skill.recon.subdomain_enumeration" in executed
