from pathlib import Path

from app.mtls import app


def test_mtls_app_exposes_bas_routes_only():
    paths = {route.path for route in app.routes}

    assert "/api/bas/agents/heartbeat" in paths
    assert "/api/scans" not in paths
    assert "/api/auth/login" not in paths
    assert not app.router.on_startup


def test_start_script_uses_dedicated_mtls_app():
    script = (Path(__file__).parents[1] / "start.sh").read_text(encoding="utf-8")

    assert "uvicorn app.mtls:app" in script
    assert script.count("uvicorn app.main:app") == 1
