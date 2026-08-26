"""agent_heartbeat now accepts an optional body reporting the agent's
self-detected local_network_cidr (bas-agent/network.go's net.Interfaces()
read, or the stub's best-effort docker-bridge approximation), recalculated
every heartbeat so the platform self-corrects if the agent's network
changes without a re-enroll. Older agent binaries send no body at all --
must not error, must not clobber an existing value with blank.
"""
from types import SimpleNamespace

from app.api import routes_bas


class _FakeDb:
    def __init__(self):
        self.committed = False

    def commit(self):
        self.committed = True


def test_heartbeat_stores_reported_local_network_cidr():
    agent = SimpleNamespace(last_heartbeat_at=None, status="offline", local_network_cidr=None)
    db = _FakeDb()
    payload = routes_bas.AgentHeartbeatRequest(local_network_cidr="10.10.10.5/24")

    result = routes_bas.agent_heartbeat(payload=payload, db=db, agent=agent)

    assert agent.local_network_cidr == "10.10.10.5/24"
    assert agent.status == "online"
    assert agent.last_heartbeat_at is not None
    assert db.committed is True
    assert result["status"] == "ok"


def test_heartbeat_with_no_body_does_not_error_or_clobber_existing_value():
    """An older agent binary (pre-Marco 3.6) sends no JSON body at all."""
    agent = SimpleNamespace(last_heartbeat_at=None, status="offline", local_network_cidr="10.10.10.5/24")
    db = _FakeDb()

    routes_bas.agent_heartbeat(payload=None, db=db, agent=agent)

    assert agent.local_network_cidr == "10.10.10.5/24"  # untouched, not blanked
    assert agent.status == "online"


def test_heartbeat_with_blank_cidr_in_payload_does_not_clobber_existing_value():
    agent = SimpleNamespace(last_heartbeat_at=None, status="offline", local_network_cidr="10.10.10.5/24")
    db = _FakeDb()
    payload = routes_bas.AgentHeartbeatRequest(local_network_cidr="")

    routes_bas.agent_heartbeat(payload=payload, db=db, agent=agent)

    assert agent.local_network_cidr == "10.10.10.5/24"


def test_heartbeat_updates_cidr_when_agents_network_changed():
    agent = SimpleNamespace(last_heartbeat_at=None, status="offline", local_network_cidr="10.10.10.5/24")
    db = _FakeDb()
    payload = routes_bas.AgentHeartbeatRequest(local_network_cidr="10.20.30.5/23")

    routes_bas.agent_heartbeat(payload=payload, db=db, agent=agent)

    assert agent.local_network_cidr == "10.20.30.5/23"
