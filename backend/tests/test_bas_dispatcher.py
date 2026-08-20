"""bas_dispatcher.dispatch_bas_technique: the only place a BasJob turns into
a real kali_runner call. Must refuse before ever reaching execute_via_kali
when the schedule's authorization doesn't cover the technique."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.services.bas_dispatcher import dispatch_bas_technique


def _schedule(max_tier="safe", attested=False, attested_by=None):
    return SimpleNamespace(
        max_authorized_risk_tier=max_tier,
        authorization_attested=attested,
        authorization_attested_by_id=attested_by,
    )


_STUB_ENV_VARS = {"BAS_TUNNEL_HOST": "bas_agent_stub", "BAS_TUNNEL_PORT": "1080"}


def test_dispatch_calls_execute_via_kali_with_the_catalogs_dispatch_key():
    with patch("app.services.bas_dispatcher.execute_via_kali", return_value={"status": "executed"}) as mock_exec:
        outcome = dispatch_bas_technique(
            technique_key="smb_enum_cme",
            target_hint="10.10.10.5",
            bas_agent=SimpleNamespace(id=1),
            scan_id=42,
            schedule=_schedule(),
        )

    assert outcome["dispatched"] is True
    mock_exec.assert_called_once_with("crackmapexec-bas", "10.10.10.5", scan_id=42, scan_mode="unit", env_vars=_STUB_ENV_VARS)


def test_dispatch_calls_execute_via_kali_for_new_discovery_techniques():
    # (expected_tool, expected_normalized_target) -- a bare "10.10.10.5" input
    # is reshaped per each technique's own target_format (see
    # test_bas_technique_target_normalization.py for the normalization rules
    # themselves): "url"-format techniques get "http://" prepended, others
    # pass the bare host through unchanged.
    cases = {
        "network_share_discovery": ("smbmap-bas", "10.10.10.5"),
        "ad_scouting_ldap": ("ldapsearch-bas", "10.10.10.5"),
        "cloud_directory_scouting": ("curl-clouddir-bas", "10.10.10.5"),
        "port_service_scan": ("nmap-portscan-bas", "10.10.10.5"),
        "chat_webhook_discovery": ("curl-chatwebhook-bas", "http://10.10.10.5"),
        "owasp_web_app_scan": ("nikto-owasp-bas", "10.10.10.5"),
        "pipeline_secrets_harvesting": ("curl-pipelinelogs-bas", "http://10.10.10.5"),
        "source_code_secrets_scan": ("gitleaks-bas", "http://10.10.10.5"),
    }
    for technique_key, (expected_tool, expected_target) in cases.items():
        with patch("app.services.bas_dispatcher.execute_via_kali", return_value={"status": "executed"}) as mock_exec:
            outcome = dispatch_bas_technique(
                technique_key=technique_key,
                target_hint="10.10.10.5",
                bas_agent=SimpleNamespace(id=1),
                scan_id=42,
                schedule=_schedule(),
            )
        assert outcome["dispatched"] is True, technique_key
        mock_exec.assert_called_once_with(expected_tool, expected_target, scan_id=42, scan_mode="unit", env_vars=_STUB_ENV_VARS)


def test_dispatch_routes_a_real_kind_agent_through_the_relay():
    """A real (non-stub) agent's dispatch must go through bas-relay's
    per-agent forwarding port (20000 + agent_id), never bas_agent_stub's
    fixed address and never the agent's own (irrelevant, possibly
    unreachable) self-reported tunnel_host -- this is what makes a real
    agent NOT need to be on the same host as the dev stack."""
    real_agent = SimpleNamespace(id=9, kind="real", tunnel_host="some-macs-hostname.local", tunnel_port=1080)
    with patch("app.services.bas_dispatcher.execute_via_kali", return_value={"status": "executed"}) as mock_exec:
        outcome = dispatch_bas_technique(
            technique_key="network_share_discovery",
            target_hint="127.0.0.1",
            bas_agent=real_agent,
            scan_id=42,
            schedule=_schedule(),
        )

    assert outcome["dispatched"] is True
    assert outcome["agent_kind"] == "real"
    mock_exec.assert_called_once_with(
        "smbmap-bas", "127.0.0.1", scan_id=42, scan_mode="unit",
        env_vars={"BAS_TUNNEL_HOST": "bas_relay", "BAS_TUNNEL_PORT": "20009"},
    )


def test_dispatch_relay_port_is_derived_from_agent_id_not_tunnel_port():
    """Unlike the stub path, a real agent's OWN tunnel_port is irrelevant --
    bas-relay's forwarding port is a deterministic function of agent_id."""
    real_agent = SimpleNamespace(id=10, kind="real", tunnel_host="whatever", tunnel_port=1081)
    with patch("app.services.bas_dispatcher.execute_via_kali", return_value={"status": "executed"}) as mock_exec:
        dispatch_bas_technique(
            technique_key="network_share_discovery", target_hint="127.0.0.1",
            bas_agent=real_agent, scan_id=42, schedule=_schedule(),
        )
    mock_exec.assert_called_once_with(
        "smbmap-bas", "127.0.0.1", scan_id=42, scan_mode="unit",
        env_vars={"BAS_TUNNEL_HOST": "bas_relay", "BAS_TUNNEL_PORT": "20010"},
    )


def test_dispatch_refuses_host_only_techniques_even_with_authorized_schedule():
    for technique_key in ("credential_dumping_mimikatz", "dotfile_config_harvesting", "kubeconfig_theft"):
        with patch("app.services.bas_dispatcher.execute_via_kali") as mock_exec:
            outcome = dispatch_bas_technique(
                technique_key=technique_key,
                target_hint="10.10.10.5",
                bas_agent=SimpleNamespace(id=1),
                scan_id=42,
                schedule=_schedule(max_tier="high_risk", attested=True, attested_by=7),
            )
        assert outcome["dispatched"] is False, technique_key
        assert outcome["reason"] == "technique_not_executable:future_agent_required", technique_key
        mock_exec.assert_not_called()


def test_dispatch_refuses_unauthorized_tier_without_ever_calling_kali():
    with patch("app.services.bas_dispatcher.execute_via_kali") as mock_exec:
        outcome = dispatch_bas_technique(
            technique_key="ntlm_relay_smb",  # high_risk
            target_hint="10.10.10.5",
            bas_agent=SimpleNamespace(id=1),
            scan_id=42,
            schedule=_schedule(max_tier="safe"),
        )

    assert outcome["dispatched"] is False
    assert outcome["reason"] == "tier_not_authorized"
    mock_exec.assert_not_called()


def test_dispatch_refuses_future_agent_required_technique_even_with_no_schedule():
    """A direct call with no schedule context still must never dispatch a
    technique SOCKS5/proxychains structurally cannot carry."""
    with patch("app.services.bas_dispatcher.execute_via_kali") as mock_exec:
        outcome = dispatch_bas_technique(
            technique_key="arp_poisoning",
            target_hint="10.10.10.5",
            bas_agent=SimpleNamespace(id=1),
            scan_id=42,
            schedule=None,
        )

    assert outcome["dispatched"] is False
    assert outcome["reason"] == "technique_not_executable:future_agent_required"
    mock_exec.assert_not_called()


def test_dispatch_unknown_technique_refused():
    with patch("app.services.bas_dispatcher.execute_via_kali") as mock_exec:
        outcome = dispatch_bas_technique(
            technique_key="not-a-real-technique",
            target_hint="10.10.10.5",
            bas_agent=SimpleNamespace(id=1),
            scan_id=42,
            schedule=_schedule(),
        )

    assert outcome["dispatched"] is False
    assert outcome["reason"] == "unknown_technique"
    mock_exec.assert_not_called()
