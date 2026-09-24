"""Regression: execute_via_kali's extra_args is a list of CLI argv strings
(kali_executor.py iterates it directly into the runner payload). Passing a
dict there silently degenerates into iterating its bare key names -- every
real value (auth token, capture flags) was being dropped on the floor.
cdp_capture.py's argv contract is positional: [target, wait, TOKEN, USER,
PASS, ROUTES], so chromium-capture needs a real ordered list, not a dict.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.models.models import ScanJob
from app.services.auth_session_manager import AuthMaterial
from app.services.browser_capture_service import _GENERIC_SPA_ROUTES, _run_chromium_capture

_ROUTES_CSV = ",".join(_GENERIC_SPA_ROUTES)


def test_chromium_capture_sends_extra_args_as_a_list_not_a_dict():
    db = MagicMock()
    scan = ScanJob(id=1, owner_id=1, target_query="valid.com")

    with patch("app.services.kali_executor.execute_via_kali", return_value={"status": "done"}) as mock_exec:
        _run_chromium_capture(db, scan, "https://valid.com", identity_key="")

    mock_exec.assert_called_once()
    assert isinstance(mock_exec.call_args.kwargs["extra_args"], list)


def test_chromium_capture_passes_real_captured_token_positionally():
    db = MagicMock()
    scan = ScanJob(id=1, owner_id=1, target_query="valid.com")
    material = AuthMaterial(
        identity_key="low_priv_user", role="member", auth_type="bearer_token",
        headers={"Authorization": "Bearer abc123"}, cookies={}, valid=True, status="valid",
    )

    with patch("app.services.auth_session_manager.AuthSessionManager.get_material", return_value=material), \
         patch("app.services.kali_executor.execute_via_kali", return_value={"status": "done"}) as mock_exec:
        _run_chromium_capture(db, scan, "https://valid.com", identity_key="low_priv_user")

    extra_args = mock_exec.call_args.kwargs["extra_args"]
    assert extra_args == ["abc123", "-", "-", _ROUTES_CSV]


def test_chromium_capture_never_invents_a_token_without_a_valid_session():
    db = MagicMock()
    scan = ScanJob(id=1, owner_id=1, target_query="valid.com")

    with patch("app.services.auth_session_manager.AuthSessionManager.get_material", return_value=None), \
         patch("app.services.kali_executor.execute_via_kali", return_value={"status": "done"}) as mock_exec:
        _run_chromium_capture(db, scan, "https://valid.com", identity_key="ghost")

    # "-" (not ""): execute_via_kali drops any extra_arg where str(arg).strip()
    # is falsy, which would otherwise shift ROUTES left into the USER slot.
    assert mock_exec.call_args.kwargs["extra_args"] == ["-", "-", "-", _ROUTES_CSV]


def test_chromium_capture_always_sends_generic_spa_routes_to_expand_surface():
    # cdp_capture.py's ROUTES navigation (argv[6]) existed since it was
    # written but no caller ever populated it -- chromium-capture only ever
    # saw the handful of XHRs that fire on the home page load. Confirmed live
    # on scan #41 (Juice Shop aggressive): only 6 API endpoints captured, none
    # of the app's real REST surface (basket, profile, search, ...).
    db = MagicMock()
    scan = ScanJob(id=1, owner_id=1, target_query="valid.com")

    with patch("app.services.kali_executor.execute_via_kali", return_value={"status": "done"}) as mock_exec:
        _run_chromium_capture(db, scan, "https://valid.com", identity_key="")

    routes_arg = mock_exec.call_args.kwargs["extra_args"][3]
    assert routes_arg == _ROUTES_CSV
    assert len(_GENERIC_SPA_ROUTES) > 5


def test_chromium_capture_extra_args_never_contain_an_empty_string():
    # execute_via_kali (kali_executor.py) drops any extra_arg where
    # str(arg).strip() is falsy before it ever reaches the runner -- an
    # empty-string placeholder for an unused positional slot (USER/PASS)
    # silently vanishes, shifting every argument after it one slot left.
    # Confirmed live: this put the ROUTES csv in cdp_capture.py's TOKEN slot,
    # corrupting localStorage with garbage and mis-triggering token-injection
    # logic. Every element must be non-empty ("-" is the "no value" sentinel).
    db = MagicMock()
    scan = ScanJob(id=1, owner_id=1, target_query="valid.com")

    with patch("app.services.kali_executor.execute_via_kali", return_value={"status": "done"}) as mock_exec:
        _run_chromium_capture(db, scan, "https://valid.com", identity_key="")

    for arg in mock_exec.call_args.kwargs["extra_args"]:
        assert str(arg).strip(), f"empty extra_arg would be silently dropped, shifting positions: {mock_exec.call_args.kwargs['extra_args']!r}"
