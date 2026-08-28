from types import SimpleNamespace

from app.services.scan_quality import (
    _build_aggressive_depth_requirements,
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


def test_aggressive_depth_requirements_expose_shallow_stored_xss_flow():
    state = {
        "scan_level": "aggressive",
        "discovered_parameterized_urls": ["https://example.test/search?q=invoice"],
    }
    work_items = [
        SimpleNamespace(
            phase_id="P12",
            status="completed",
            tool_name="dalfox",
            target="https://example.test/search?q=invoice",
            item_metadata={"skill_id": "skill.vuln.xss"},
            result={"profile": "dalfox_xss"},
            last_error=None,
        )
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P12"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=False,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p12_reflected_xss_parameterized_surface"]["status"] == "met"
    # No mutating/state-changing surface was discovered anywhere on this
    # target -- there is nothing to run a stored-XSS flow against, so both
    # requirements are not_applicable (and non-blocking) rather than a
    # "missing"/"blocked_precondition" gap that can never be remediated.
    assert by_id["p12_stored_xss_mutating_body_surface"]["status"] == "not_applicable"
    assert by_id["p12_stored_xss_request_response_render_flow"]["status"] == "not_applicable"
    assert "state_changing_body_surface" in by_id["p12_stored_xss_request_response_render_flow"]["missing"]
    assert "stored_xss_request_response_render_validation" in by_id["p12_stored_xss_request_response_render_flow"]["missing"]
    assert requirements["unmet"] == 0
    assert "p12_stored_xss_request_response_render_flow" not in requirements["blocking_requirement_ids"]


def test_aggressive_depth_requirements_accept_complete_stored_xss_flow():
    state = {
        "scan_level": "aggressive",
        "discovered_parameterized_urls": ["https://example.test/search?q=invoice"],
        "discovered_parameterized_requests": [
            {
                "method": "POST",
                "url": "https://example.test/api/items",
                "body_parameters": ["description"],
                "body_template": '{"description":"FUZZ"}',
            }
        ],
    }
    work_items = [
        SimpleNamespace(
            phase_id="P12",
            status="completed",
            tool_name="dalfox",
            target="https://example.test/search?q=invoice",
            item_metadata={"skill_id": "skill.vuln.xss"},
            result={"profile": "dalfox_xss"},
            last_error=None,
        ),
        SimpleNamespace(
            phase_id="P12",
            status="completed",
            tool_name="curl",
            target="https://example.test/api/items",
            item_metadata={"skill_id": "skill.stored_xss_testing"},
            result={
                "profile": "curl_probe",
                "stdout": "SCAN_FUZZ_POST_DATA request_response_pair payload_used rendered_context negative_control",
            },
            last_error=None,
        ),
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P12"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=False,
    )

    assert requirements["unmet"] == 0
    assert requirements["met"] == 3
    assert all(row["status"] in {"met", "not_applicable"} for row in requirements["requirements"])


def test_aggressive_depth_requirements_cover_walkthrough_classes_beyond_xss():
    state = {
        "scan_level": "aggressive",
        "javascript_bundles": ["https://example.test/main.js"],
        "discovered_parameterized_urls": ["https://example.test/rest/products/search?q=apple"],
        "login_forms": ["https://example.test/#/login"],
        "object_reference_endpoints": ["https://example.test/api/BasketItems/1"],
        "upload_endpoints": ["https://example.test/file-upload"],
        "openapi_urls": ["https://example.test/swagger.json"],
        "state_changing_endpoints": ["https://example.test/api/BasketItems"],
        "captcha_endpoints": ["https://example.test/rest/captcha/"],
    }

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P08", "P10", "P13", "P14", "P15", "P16", "P19"],
        work_items=[],
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=True,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    expected_missing = {
        "p08_client_side_route_and_api_discovery",
        "p10_injection_request_response_controls",
        "p13_access_control_business_logic_matrix",
        "p14_auth_session_jwt_boundary",
        "p15_file_disclosure_upload_lfi_surface",
        "p16_api_schema_parameter_hpp_surface",
        "p19_post_auth_state_change_controls",
    }

    assert expected_missing <= set(by_id)
    assert all(by_id[requirement_id]["status"] == "missing" for requirement_id in expected_missing)


def test_p13_attribution_requirement_missing_when_matrix_ran_without_real_object_evidence():
    """A bl-test/idor validator run that completed proves *a* cross-identity
    request pair was sent -- not that the tested object was actually
    attributed to the identity the test claims. Without "observed_per_identity"
    anywhere in the P13 evidence text, the new sub-requirement must stay
    unmet even though the main matrix requirement is satisfied."""
    state = {
        "scan_level": "aggressive",
        "object_reference_endpoints": ["https://example.test/api/BasketItems/1"],
    }
    work_items = [
        SimpleNamespace(
            phase_id="P13",
            status="completed",
            tool_name="bl-test",
            target="https://example.test/api/BasketItems/1",
            item_metadata={},
            result={"parsed": {"wire_assessments": [{"object_attribution": "unverified_shared_endpoint"}]}},
            last_error=None,
        )
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P13"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=True,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p13_access_control_business_logic_matrix"]["status"] == "met"
    assert by_id["p13_cross_identity_object_attribution_verified"]["status"] == "missing"
    # medium severity -- documented as a gap, not a hard block.
    assert "p13_cross_identity_object_attribution_verified" not in requirements["blocking_requirement_ids"]


def test_p13_attribution_requirement_met_when_real_object_evidence_present():
    state = {
        "scan_level": "aggressive",
        "object_reference_endpoints": ["https://example.test/api/BasketItems/1"],
    }
    work_items = [
        SimpleNamespace(
            phase_id="P13",
            status="completed",
            tool_name="bl-test",
            target="https://example.test/api/BasketItems/1",
            item_metadata={},
            result={"parsed": {"wire_assessments": [{"object_attribution": "observed_per_identity"}]}},
            last_error=None,
        )
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P13"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=True,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p13_access_control_business_logic_matrix"]["status"] == "met"
    assert by_id["p13_cross_identity_object_attribution_verified"]["status"] == "met"
