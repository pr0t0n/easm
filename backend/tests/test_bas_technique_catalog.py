"""bas_technique_catalog.py: the SOCKS5/proxychains capability boundary must
be encoded correctly, since bas_guardrail_policy and the dispatcher both
trust `availability` as a hard gate."""
from __future__ import annotations

from app.services.bas_technique_catalog import get_technique, list_techniques

# No tool onboarded at all for these two -- stay hard-blocked.
_NO_TOOL_POISONING_KEYS = {"arp_poisoning", "dhcp_spoofing"}
# Phase 3 deliberate exception: Responder IS dispatched for real, in passive
# analyze mode, so the tunnel's structural limitation shows up as an
# observed real result (confirmed live: Responder self-reports listening on
# kali_runner's own docker IP, not any customer network) rather than a
# guardrail assumption.
_DISPATCHED_BUT_INEFFECTIVE_POISONING_KEYS = {"llmnr_nbtns_poisoning", "mdns_poisoning"}
# Host-based: need real code execution / filesystem access on an already-
# compromised host. No SOCKS5 tunnel can carry these at all (unlike
# Responder, which IS a real dispatchable tool) -- stay hard-blocked with no
# kali_tool_name, same as the no-tool poisoning keys above.
_HOST_ONLY_NO_TOOL_KEYS = {"credential_dumping_mimikatz", "dotfile_config_harvesting", "kubeconfig_theft"}
_TUNNELABLE_KEYS = {
    "smb_enum_cme", "smb_enum_enum4linux", "ad_bloodhound_collect", "ad_kerberoast", "ntlm_relay_smb",
    "vmware_vcenter_default_creds", "firewall_segmentation_test",
    "network_share_discovery", "ad_scouting_ldap", "cloud_directory_scouting", "port_service_scan",
    "chat_webhook_discovery", "netlogon_zerologon_check", "owasp_web_app_scan",
    "pipeline_secrets_harvesting", "source_code_secrets_scan",
}


def test_poisoning_techniques_with_no_tool_onboarded_stay_hard_blocked():
    for key in _NO_TOOL_POISONING_KEYS:
        technique = get_technique(key)
        assert technique is not None, key
        assert technique["availability"] == "future_agent_required", key
        assert technique["requires_real_agent"] is True, key
        assert technique["execution_backend"] is None, key


def test_responder_poisoning_techniques_are_dispatched_but_still_flagged_as_needing_a_real_agent():
    """These ARE dispatchable (Phase 3 decision) -- but requires_real_agent/
    requires_udp/requires_l2 must stay true, since the tunnel genuinely can't
    make this technique meaningful; only a real agent on the customer's L2
    segment would."""
    for key in _DISPATCHED_BUT_INEFFECTIVE_POISONING_KEYS:
        technique = get_technique(key)
        assert technique is not None, key
        assert technique["availability"] == "simulated", key
        assert technique["execution_backend"] == "kali_direct_no_tunnel_effect", key
        assert technique["kali_tool_name"] == "responder-bas", key
        assert technique["requires_real_agent"] is True, key
        assert technique["requires_udp"] is True, key
        assert technique["requires_l2"] is True, key


def test_host_only_techniques_have_no_kali_tool_and_stay_hard_blocked():
    """Mimikatz/dotfile-harvesting/kubeconfig-theft need real code execution
    or filesystem access on an already-compromised host -- there is no
    command a SOCKS5 CONNECT tunnel can carry for these, so kali_tool_name
    must stay None (unlike Responder, which IS a real dispatchable tool)."""
    for key in _HOST_ONLY_NO_TOOL_KEYS:
        technique = get_technique(key)
        assert technique is not None, key
        assert technique["availability"] == "future_agent_required", key
        assert technique["requires_real_agent"] is True, key
        assert technique["execution_backend"] is None, key
        assert technique["kali_tool_name"] is None, key


def test_every_tunnelable_technique_has_a_kali_tool_mapped():
    for key in _TUNNELABLE_KEYS:
        technique = get_technique(key)
        assert technique is not None, key
        assert technique["availability"] in {"available", "simulated"}, key
        assert technique["execution_backend"] == "kali_proxychains", key
        assert technique["kali_tool_name"], key


def test_bas_dispatch_keys_never_collide_with_the_external_pipelines_bare_tool_names():
    """crackmapexec (bare) already dispatches to the external P01-P22
    pipeline's untunneled profile -- the BAS catalog must use a distinct
    dispatch key so it's never accidentally sent with no tunnel at all."""
    technique = get_technique("smb_enum_cme")
    assert technique["kali_tool_name"] != "crackmapexec"
    assert technique["kali_tool_name"].endswith("-bas")


def test_get_technique_returns_none_for_unknown_key():
    assert get_technique("does-not-exist") is None


def test_list_techniques_returns_every_registered_entry():
    keys = {t["technique_key"] for t in list_techniques()}
    assert _NO_TOOL_POISONING_KEYS <= keys
    assert _DISPATCHED_BUT_INEFFECTIVE_POISONING_KEYS <= keys
    assert _HOST_ONLY_NO_TOOL_KEYS <= keys
    assert _TUNNELABLE_KEYS <= keys
