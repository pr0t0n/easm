import pytest
from fastapi import HTTPException

from app.api.routes_management import _validated_email
from app.main import app
from app.schemas.auth import MeResponse


def test_own_password_route_precedes_dynamic_user_password_route() -> None:
    put_paths = [
        route.path
        for route in app.routes
        if "PUT" in getattr(route, "methods", set())
    ]

    assert put_paths.index("/api/users/me/password") < put_paths.index("/api/users/{user_id}/password")


def test_management_email_validation_rejects_invalid_address() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _validated_email("not-an-email")

    assert exc_info.value.status_code == 400


def test_me_response_handles_legacy_invalid_email_without_server_error() -> None:
    response = MeResponse(id=1, email="legacy-value", is_admin=True, group_ids=[])

    assert response.email == "legacy-value"
