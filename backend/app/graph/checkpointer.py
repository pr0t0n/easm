from contextlib import suppress

from langgraph.checkpoint.memory import MemorySaver

from app.core.config import settings


def _sqlalchemy_to_psycopg_dsn(url: str) -> str:
    if url.startswith("postgresql+psycopg2://"):
        return url.replace("postgresql+psycopg2://", "postgresql://", 1)
    return url


def create_checkpointer():
    # Produção: usa checkpointer PostgreSQL dedicado; fallback para memória em dev.
    dsn = settings.langgraph_checkpointer_dsn or _sqlalchemy_to_psycopg_dsn(settings.database_url)
    with suppress(Exception):
        from langgraph.checkpoint.postgres import PostgresSaver

        return PostgresSaver.from_conn_string(dsn)
    return MemorySaver()
