from datetime import datetime, timedelta, timezone

from app.api.routes_scans import _as_utc_datetime


def test_as_utc_datetime_adds_utc_to_naive_value() -> None:
    value = datetime(2026, 9, 23, 12, 30)

    assert _as_utc_datetime(value) == value.replace(tzinfo=timezone.utc)


def test_as_utc_datetime_converts_aware_value_to_utc() -> None:
    local_timezone = timezone(timedelta(hours=-3))
    value = datetime(2026, 9, 23, 12, 30, tzinfo=local_timezone)

    assert _as_utc_datetime(value) == datetime(2026, 9, 23, 15, 30, tzinfo=timezone.utc)
