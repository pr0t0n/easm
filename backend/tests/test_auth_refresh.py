from types import SimpleNamespace
from unittest.mock import MagicMock

from app.api.routes_auth import refresh
from app.core.security import create_refresh_token, decode_access_token, decode_refresh_token


def _db_with_user(user):
    db = MagicMock()
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = user
    return db


def test_refresh_accepts_numeric_subject_from_login_flow() -> None:
    user = SimpleNamespace(id=42, email="admin@example.com", is_active=True)

    response = refresh({"refresh_token": create_refresh_token("42")}, _db_with_user(user))

    assert decode_access_token(response["access_token"]) == "42"
    assert decode_refresh_token(response["refresh_token"]) == "42"


def test_refresh_migrates_legacy_email_subject_to_numeric_subject() -> None:
    user = SimpleNamespace(id=42, email="admin@example.com", is_active=True)

    response = refresh(
        {"refresh_token": create_refresh_token("admin@example.com")},
        _db_with_user(user),
    )

    assert decode_access_token(response["access_token"]) == "42"
    assert decode_refresh_token(response["refresh_token"]) == "42"
