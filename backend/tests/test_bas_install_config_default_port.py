"""GET /api/bas/install-config used to default callback_port to the
hardcoded "8000" -- the container-internal port the app listens on, never
reachable by a real BAS agent installed outside Docker (it needs
BACKEND_HOST_PORT, the host-mapped port from docker-compose.yml, default
8001). Now sourced from settings.backend_host_port so a fresh install
(nothing ever saved via PUT) already returns a usable value instead of one
guaranteed to fail enrollment.
"""
from types import SimpleNamespace

from app.api import routes_bas


class _FakeQuery:
    def filter(self, *a, **k):
        return self

    def first(self):
        return None


class _FakeDb:
    def query(self, model):
        return _FakeQuery()


def test_install_config_defaults_port_to_configured_backend_host_port(monkeypatch):
    monkeypatch.setattr(routes_bas.settings, "backend_host_port", 8001)

    result = routes_bas._install_config_payload(db=_FakeDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_port"] == "8001"
    assert result["callback_host"] == "backend"
    assert result["requires_explicit_callback_host"] is True


def test_install_config_reflects_a_different_configured_port(monkeypatch):
    """Confirms the value is actually read from settings, not still a
    literal "8001" string -- would catch a regression back to hardcoding."""
    monkeypatch.setattr(routes_bas.settings, "backend_host_port", 9099)

    result = routes_bas._install_config_payload(db=_FakeDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_port"] == "9099"


def test_install_config_saved_override_still_wins_over_default(monkeypatch):
    monkeypatch.setattr(routes_bas.settings, "backend_host_port", 8001)

    class _SavedQuery:
        def filter(self, *a, **k):
            return self

        def first(self):
            return SimpleNamespace(value="8443")

    class _SavedDb:
        def query(self, model):
            return _SavedQuery()

    result = routes_bas._install_config_payload(db=_SavedDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_port"] == "8443"


def test_install_config_returns_browser_host_as_candidate_not_saved_value(monkeypatch):
    monkeypatch.setattr(routes_bas.settings, "backend_host_port", 8001)
    monkeypatch.setattr(routes_bas, "_tcp_reachable", lambda host, port: host == "192.168.16.154")

    result = routes_bas._install_config_payload(browser_host="10.125.136.227", db=_FakeDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_host"] == "backend"
    browser_candidate = next(candidate for candidate in result["host_candidates"] if candidate["host"] == "10.125.136.227")
    assert browser_candidate["reachable_from_backend"] is False


def test_install_host_candidates_include_saved_host_first(monkeypatch):
    monkeypatch.setattr(routes_bas, "_tcp_reachable", lambda host, port: host == "192.168.16.154")

    candidates = routes_bas._install_host_candidates(
        saved_host="192.168.16.154", callback_port="8001", browser_host="10.125.136.227",
    )

    assert candidates[0] == {
        "host": "192.168.16.154",
        "port": "8001",
        "source": "saved",
        "confidence": "configured",
        "saved": True,
        "reachable_from_backend": True,
    }
