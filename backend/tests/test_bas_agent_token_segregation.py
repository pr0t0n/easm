"""BAS agent tokens (type="bas_agent") must be a fully separate credential
space from human access_token/refresh_token -- neither decoder accepts the
other's token, so a leaked agent token can't be replayed as a user session
and vice versa."""
from __future__ import annotations

from app.core.security import (
    create_access_token,
    create_bas_agent_token,
    decode_access_token,
    decode_bas_agent_token,
)


def test_bas_agent_token_decodes_to_the_agent_id():
    token = create_bas_agent_token(42)
    assert decode_bas_agent_token(token) == 42


def test_bas_agent_token_rejected_by_decode_access_token():
    token = create_bas_agent_token(42)
    assert decode_access_token(token) is None


def test_human_access_token_rejected_by_decode_bas_agent_token():
    token = create_access_token("7")
    assert decode_bas_agent_token(token) is None


def test_garbage_token_rejected_by_decode_bas_agent_token():
    assert decode_bas_agent_token("not-a-real-jwt") is None
    assert decode_bas_agent_token("") is None
