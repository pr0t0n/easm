from fastapi import HTTPException
import pytest

from app.api.routes_management import _validate_industry_sector


def test_none_and_empty_are_accepted_as_unclassified():
    assert _validate_industry_sector(None) is None
    assert _validate_industry_sector("") is None


def test_known_wavestone_sector_key_is_accepted():
    assert _validate_industry_sector("financial") == "financial"


def test_unknown_sector_key_is_rejected_not_silently_stored():
    with pytest.raises(HTTPException) as exc:
        _validate_industry_sector("healthcare")
    assert exc.value.status_code == 400
