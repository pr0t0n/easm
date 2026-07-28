import os

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


# Must stay >= postgres's own `idle_in_transaction_session_timeout` (docker-compose.yml,
# 1800000ms) — that server-level value was deliberately widened after a 5min timeout
# killed active scan #31 mid P01 tool fan-out. This per-connection SET used to default
# to 60000ms and silently re-tightened the server's fix on every connection, which is
# exactly what killed scan #48's `full`-profile P01 dispatch (idle-in-tx at 60s).
_IDLE_IN_TX_TIMEOUT_MS = int(os.getenv("DB_IDLE_IN_TX_TIMEOUT_MS", "1800000"))
_LOCK_TIMEOUT_MS = int(os.getenv("DB_LOCK_TIMEOUT_MS", "30000"))
_STATEMENT_TIMEOUT_MS = int(os.getenv("DB_STATEMENT_TIMEOUT_MS", "900000"))

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    # Tier 1-G: Sized for 9 workers × 16 threads each.  pool_size=20 handles
    # typical load; max_overflow=40 absorbs bursts; pool_recycle=1800 avoids
    # stale-connection errors from Postgres idle-timeout (default 10min).
    pool_size=int(os.getenv("DB_POOL_SIZE", "20")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "40")),
    pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
    pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
)


@event.listens_for(engine, "connect")
def _set_connection_timeouts(dbapi_connection, _connection_record) -> None:
    """Make long DB locks impossible to survive silently.

    SQLAlchemy sessions open a transaction even for SELECTs. If task code then
    waits on network/LLM/Kali or simply loses a poll message, that transaction
    can sit "idle in transaction" and block the whole scan. PostgreSQL must be
    the final guardrail: every app connection receives strict session-level
    timeouts so a forgotten transaction is killed by the database itself.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f"SET idle_in_transaction_session_timeout = {_IDLE_IN_TX_TIMEOUT_MS}")
        cursor.execute(f"SET lock_timeout = {_LOCK_TIMEOUT_MS}")
        cursor.execute(f"SET statement_timeout = {_STATEMENT_TIMEOUT_MS}")
    finally:
        cursor.close()


def enforce_connection_timeouts(db) -> None:
    """Apply DB timeout contract to an already-open SQLAlchemy session."""
    db.execute(text(f"SET idle_in_transaction_session_timeout = {_IDLE_IN_TX_TIMEOUT_MS}"))
    db.execute(text(f"SET lock_timeout = {_LOCK_TIMEOUT_MS}"))
    db.execute(text(f"SET statement_timeout = {_STATEMENT_TIMEOUT_MS}"))


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
