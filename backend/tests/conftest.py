"""conftest.py — Test fixtures and environment mock for unit tests.

Tests that import app modules with pydantic-settings require env vars
(DATABASE_URL, REDIS_URL, etc.) to be set before import. This conftest
patches the Settings class so tests can run without a full Docker stack.
"""
from __future__ import annotations

import os
import sys

# ── Inject minimal env vars before ANY app module is imported ─────────────────
# pydantic-settings reads from os.environ at class definition time.
_TEST_ENV = {
    "DATABASE_URL":         "postgresql://test:test@localhost/test",
    "REDIS_URL":            "redis://localhost:6379/0",
    "CELERY_BROKER_URL":    "redis://localhost:6379/0",
    "CELERY_RESULT_BACKEND": "redis://localhost:6379/0",
    "SECRET_KEY":           "test-secret-key-for-unit-tests-only",
    "ADMIN_EMAIL":          "admin@test.local",
    "ADMIN_PASSWORD":       "test-admin-pass",
    "APP_ENV":              "test",
}
for _k, _v in _TEST_ENV.items():
    os.environ.setdefault(_k, _v)

import pytest


@pytest.fixture(autouse=False)
def mock_settings(monkeypatch):
    """Override settings fields for tests that need specific values."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "app_env", "test")
    yield settings


@pytest.fixture(autouse=False)
def mock_db(monkeypatch):
    """Provide a minimal mock DB session for unit tests."""
    from unittest.mock import MagicMock
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    session.query.return_value.filter.return_value.count.return_value = 0
    yield session
