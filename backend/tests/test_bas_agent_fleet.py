from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.bas_agent_fleet import agent_to_fleet_dict, fleet_summary, normalize_tags, remote_config_payload


def _agent(**overrides):
    base = dict(
        id=9,
        label="branch-fw",
        hostname="branch-host",
        os="linux",
        os_version="debian",
        arch="amd64",
        agent_version="0.1",
        status="online",
        kind="real",
        last_heartbeat_at=datetime.now(),
        last_seen_ip="10.0.0.10",
        local_network_cidr="10.0.0.10/24",
        agent_metadata={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_agent_to_fleet_dict_computes_health_and_metadata():
    agent = _agent(agent_metadata={
        "tags": ["pci", "prod"],
        "agent_group": "sp-dc",
        "site": "sao-paulo",
        "capabilities": {"proxy": {"socks_port": 1080}},
        "local_policy": {"max_parallel_jobs": 1},
    })

    row = agent_to_fleet_dict(agent)

    assert row["tags"] == ["pci", "prod"]
    assert row["agent_group"] == "sp-dc"
    assert row["site"] == "sao-paulo"
    assert row["health"]["grade"] == "healthy"


def test_agent_health_degrades_when_heartbeat_and_capabilities_are_missing():
    agent = _agent(status="offline", last_heartbeat_at=datetime.now() - timedelta(minutes=10), local_network_cidr=None)

    row = agent_to_fleet_dict(agent)

    assert row["health"]["grade"] == "critical"
    assert "heartbeat_stale" in row["health"]["reasons"]
    assert "capabilities_missing" in row["health"]["reasons"]


def test_remote_config_payload_merges_policy_group_site_and_tags():
    agent = _agent(agent_metadata={
        "tags": ["identity"],
        "agent_group": "corp",
        "site": "rio",
        "local_policy": {"allowed_technique_tiers": ["safe", "elevated"]},
        "remote_config": {"config_revision": 4, "heartbeat_interval_seconds": 20},
    })

    payload = remote_config_payload(agent)

    assert payload["config_revision"] == 4
    assert payload["heartbeat_interval_seconds"] == 20
    assert payload["policy"]["allowed_technique_tiers"] == ["safe", "elevated"]
    assert payload["agent_group"] == "corp"
    assert payload["site"] == "rio"
    assert payload["tags"] == ["identity"]


def test_fleet_summary_groups_agents_by_group_or_site():
    result = fleet_summary([
        _agent(agent_metadata={"agent_group": "corp", "site": "sp", "tags": ["prod"], "capabilities": {"proxy": {"socks_port": 1080}}}),
        _agent(id=10, status="offline", agent_metadata={"agent_group": "corp", "site": "rj", "tags": ["dev"]}),
        _agent(id=11, agent_metadata={"site": "branch"}),
    ])

    assert result["summary"]["agents"] == 3
    corp = next(group for group in result["groups"] if group["key"] == "corp")
    assert corp["agents"] == 2
    assert corp["sites"] == ["rj", "sp"]
    assert corp["tags"] == ["dev", "prod"]


def test_normalize_tags_trims_deduplicates_and_caps():
    assert normalize_tags([" prod ", "prod", "", "pci"]) == ["prod", "pci"]
