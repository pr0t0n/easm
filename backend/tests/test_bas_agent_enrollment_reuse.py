from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import routes_bas
from app.core.security import get_password_hash
from app.models.models import BasAgent, BasEnrollmentToken


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None


class _Db:
    def __init__(self, token, agents):
        self.token = token
        self.agents = agents
        self.added = []
        self.commits = 0

    def query(self, model):
        if model is BasEnrollmentToken:
            return _Query([self.token] if self.token else [])
        if model is BasAgent:
            return _Query(self.agents)
        return _Query([])

    def add(self, obj):
        self.added.append(obj)
        if getattr(obj, "id", None) is None:
            obj.id = 99

    def commit(self):
        self.commits += 1

    def refresh(self, obj):
        return None


def _request(host="198.51.100.7"):
    return SimpleNamespace(client=SimpleNamespace(host=host))


def _token(status="exhausted", used_count=1, max_uses=1):
    return SimpleNamespace(
        id=11,
        owner_id=3,
        access_group_id=4,
        username="bas-agent",
        code="enroll-code",
        secret_hash=get_password_hash("agent-pass"),
        status=status,
        max_uses=max_uses,
        used_count=used_count,
        expires_at=None,
        last_used_at=None,
    )


def _payload(**overrides):
    values = {
        "code": "enroll-code",
        "username": "bas-agent",
        "password": "agent-pass",
        "hostname": "workstation-01",
        "os": "linux",
        "os_version": "debian",
        "arch": "amd64",
        "agent_version": "0.1.0",
        "local_network_cidr": "10.20.30.5/24",
    }
    values.update(overrides)
    return routes_bas.AgentEnrollRequest(**values)


def test_enroll_reuses_existing_agent_for_same_exhausted_token_and_updates_network():
    token = _token()
    agent = SimpleNamespace(
        id=42,
        owner_id=3,
        access_group_id=4,
        enrollment_token_id=11,
        hostname="workstation-01",
        os="linux",
        os_version="old",
        arch="amd64",
        agent_version="0.0.9",
        status="offline",
        kind="real",
        tunnel_host="",
        tunnel_port=None,
        last_heartbeat_at=None,
        last_seen_ip="10.1.1.10",
        enrolled_via_host="",
        enrolled_via_port=None,
        local_network_cidr="10.1.1.10/24",
        agent_metadata={},
    )
    db = _Db(token, [agent])

    result = routes_bas.enroll_agent(_payload(), request=_request("203.0.113.12"), db=db)

    assert result["agent_id"] == 42
    assert result["reused_agent"] is True
    assert token.used_count == 1
    assert token.status == "exhausted"
    assert agent.status == "online"
    assert agent.local_network_cidr == "10.20.30.5/24"
    assert agent.last_seen_ip == "203.0.113.12"
    assert db.added == []


def test_enroll_rejects_exhausted_token_when_existing_agent_identity_does_not_match():
    token = _token()
    agent = SimpleNamespace(id=42, hostname="other-host", os="windows", arch="amd64", status="offline")
    db = _Db(token, [agent])

    with pytest.raises(HTTPException) as exc:
        routes_bas.enroll_agent(_payload(), request=_request(), db=db)

    assert exc.value.status_code == 401
    assert db.added == []
