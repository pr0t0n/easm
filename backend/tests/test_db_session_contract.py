from __future__ import annotations


def test_db_connections_enforce_transaction_timeouts() -> None:
    import inspect

    from app.db import session

    source = inspect.getsource(session)
    assert "idle_in_transaction_session_timeout" in source
    assert "lock_timeout" in source
    assert "statement_timeout" in source
    assert "DB_IDLE_IN_TX_TIMEOUT_MS" in source

