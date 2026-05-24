from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    # Tier 1-G: Sized for 9 workers × 16 threads each.  pool_size=20 handles
    # typical load; max_overflow=40 absorbs bursts; pool_recycle=1800 avoids
    # stale-connection errors from Postgres idle-timeout (default 10min).
    pool_size=int(__import__("os").getenv("DB_POOL_SIZE", "20")),
    max_overflow=int(__import__("os").getenv("DB_MAX_OVERFLOW", "40")),
    pool_recycle=int(__import__("os").getenv("DB_POOL_RECYCLE", "1800")),
    pool_timeout=int(__import__("os").getenv("DB_POOL_TIMEOUT", "30")),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
