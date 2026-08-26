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

    result = routes_bas.install_config(db=_FakeDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_port"] == "8001"
    assert result["callback_host"] == "backend"


def test_install_config_reflects_a_different_configured_port(monkeypatch):
    """Confirms the value is actually read from settings, not still a
    literal "8001" string -- would catch a regression back to hardcoding."""
    monkeypatch.setattr(routes_bas.settings, "backend_host_port", 9099)

    result = routes_bas.install_config(db=_FakeDb(), current_user=SimpleNamespace(id=1))

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

    result = routes_bas.install_config(db=_SavedDb(), current_user=SimpleNamespace(id=1))

    assert result["callback_port"] == "8443"
