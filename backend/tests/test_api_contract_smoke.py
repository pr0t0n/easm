from fastapi.testclient import TestClient

from app.main import app


def test_openapi_exposes_unified_control_plane_and_paginated_report_contract():
    schema = TestClient(app).get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/dashboard/control-plane" in paths
    assert "/api/pentest/scans/{scan_id}/report-contract" in paths
    parameters = paths["/api/pentest/scans/{scan_id}/report-contract"]["get"]["parameters"]
    assert {parameter["name"] for parameter in parameters} >= {"findings_limit", "findings_offset"}


def test_health_endpoint_is_available_without_authentication():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
