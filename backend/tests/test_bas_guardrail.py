"""bas_guardrail_policy.check_bas_authorization: the gate a schedule must
pass before any technique above 'safe' tier is allowed to run."""
from __future__ import annotations

from types import SimpleNamespace

from app.services.bas_guardrail_policy import check_bas_authorization


def _schedule(max_tier="safe", attested=False, attested_by=None):
    return SimpleNamespace(
        max_authorized_risk_tier=max_tier,
        authorization_attested=attested,
        authorization_attested_by_id=attested_by,
    )


def test_safe_tier_always_allowed_regardless_of_attestation():
    result = check_bas_authorization(_schedule(max_tier="safe", attested=False), "smb_enum_cme")
    assert result["allowed"] is True
    assert result["reason"] == "safe_tier_always_allowed"


def test_elevated_tier_rejected_without_ceiling_raised():
    result = check_bas_authorization(_schedule(max_tier="safe"), "ad_kerberoast")
    assert result["allowed"] is False
    assert result["reason"] == "tier_not_authorized"


def test_elevated_tier_rejected_with_ceiling_raised_but_not_attested():
    result = check_bas_authorization(_schedule(max_tier="elevated", attested=False), "ad_kerberoast")
    assert result["allowed"] is False
    assert result["reason"] == "attestation_missing"


def test_elevated_tier_rejected_when_attested_flag_true_but_no_attester_id():
    result = check_bas_authorization(_schedule(max_tier="elevated", attested=True, attested_by=None), "ad_kerberoast")
    assert result["allowed"] is False
    assert result["reason"] == "attestation_missing"


def test_elevated_tier_allowed_when_ceiling_raised_and_attested():
    result = check_bas_authorization(_schedule(max_tier="elevated", attested=True, attested_by=7), "ad_kerberoast")
    assert result["allowed"] is True


def test_high_risk_tier_rejected_when_ceiling_is_only_elevated():
    result = check_bas_authorization(_schedule(max_tier="elevated", attested=True, attested_by=7), "ntlm_relay_smb")
    assert result["allowed"] is False
    assert result["reason"] == "tier_not_authorized"


def test_future_agent_required_technique_never_allowed_even_at_high_risk_ceiling():
    """ARP/DHCP poisoning: no kali tool onboarded at all, SOCKS5 CONNECT
    can't carry this anyway -- blocked no matter how permissive the
    schedule's authorization is. (LLMNR/NBT-NS/mDNS via Responder are a
    deliberate Phase 3 exception -- see test_bas_technique_catalog.py.)"""
    result = check_bas_authorization(_schedule(max_tier="high_risk", attested=True, attested_by=7), "arp_poisoning")
    assert result["allowed"] is False
    assert result["reason"] == "technique_not_executable:future_agent_required"


def test_host_only_technique_never_allowed_even_at_high_risk_ceiling():
    """Mimikatz/dotfile-harvesting/kubeconfig-theft need real code execution
    or filesystem access on an already-compromised host -- no SOCKS5 tunnel
    can carry these at all, so they stay blocked regardless of attestation,
    same as arp_poisoning/dhcp_spoofing above."""
    for key in ("credential_dumping_mimikatz", "dotfile_config_harvesting", "kubeconfig_theft"):
        result = check_bas_authorization(_schedule(max_tier="high_risk", attested=True, attested_by=7), key)
        assert result["allowed"] is False, key
        assert result["reason"] == "technique_not_executable:future_agent_required", key


def test_new_safe_tier_discovery_techniques_are_authorized_without_attestation():
    for key in (
        "network_share_discovery", "ad_scouting_ldap", "cloud_directory_scouting",
        "azure_entra_id_discovery", "m365_tenant_exposure_check",
        "port_service_scan", "chat_webhook_discovery", "owasp_web_app_scan",
        "pipeline_secrets_harvesting", "source_code_secrets_scan",
        "safe_credential_checks", "lateral_movement_simulation_safe",
    ):
        result = check_bas_authorization(_schedule(max_tier="safe", attested=False), key)
        assert result["allowed"] is True, key


def test_planned_cloud_identity_integrations_are_not_dispatchable_yet():
    for key in (
        "aws_iam_path_analysis", "google_workspace_exposure_check", "okta_misconfiguration_check",
        "mfa_bypass_simulation_safe", "token_abuse_simulation", "conditional_access_validation",
        "impossible_travel_telemetry",
    ):
        result = check_bas_authorization(_schedule(max_tier="high_risk", attested=True, attested_by=7), key)
        assert result["allowed"] is False, key
        assert result["reason"] == "technique_not_executable:planned", key


def test_netlogon_zerologon_check_is_elevated_tier_not_safe():
    result = check_bas_authorization(_schedule(max_tier="safe"), "netlogon_zerologon_check")
    assert result["allowed"] is False
    assert result["reason"] == "tier_not_authorized"

    result = check_bas_authorization(_schedule(max_tier="elevated", attested=True, attested_by=7), "netlogon_zerologon_check")
    assert result["allowed"] is True


def test_responder_poisoning_is_authorized_at_high_risk_ceiling_when_attested():
    """llmnr_nbtns_poisoning/mdns_poisoning are the deliberate Phase 3
    exception: availability="simulated", so the guardrail must actually let
    them through once the schedule's ceiling/attestation covers high_risk --
    the dispatch failing is supposed to happen for real, at the agent, not be
    pre-empted here."""
    for key in ("llmnr_nbtns_poisoning", "mdns_poisoning"):
        result = check_bas_authorization(_schedule(max_tier="high_risk", attested=True, attested_by=7), key)
        assert result["allowed"] is True, key


def test_unknown_technique_rejected():
    result = check_bas_authorization(_schedule(max_tier="high_risk", attested=True, attested_by=7), "not-a-real-technique")
    assert result["allowed"] is False
    assert result["reason"] == "unknown_technique"
