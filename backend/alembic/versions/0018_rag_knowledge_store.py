"""rag_knowledge_store: RAG lexical+semântico unificado em pgvector

Substitui o knowledge_store.json (arquivo flat no volume mcp_chroma_data) por
uma tabela PostgreSQL indexada. Benefícios:
- Busca semântica real (cosine similarity, 384-dim bge-small)
- Busca lexical via tokens JSONB (mesma heurística do mcp_server atual)
- Transações, auditoria, sem race condition em escrita concorrente
- Sem volume Docker extra (mcp_chroma_data pode ser removido)

Revision ID: 0018
Revises: 0017
"""
from alembic import op


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS rag_knowledge_store (
            id          BIGSERIAL PRIMARY KEY,
            chunk_id    TEXT        NOT NULL UNIQUE,
            source      TEXT        NOT NULL DEFAULT 'unknown',
            source_kind TEXT,
            content     TEXT        NOT NULL,
            metadata    JSONB       NOT NULL DEFAULT '{}',
            tokens      JSONB       NOT NULL DEFAULT '[]',
            embedding   vector(384),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    # Índice de cosine para busca semântica (ANN via IVFFlat).
    # lists=1: seguro para tabela vazia no momento da criação. O índice é
    # recriado automaticamente após o primeiro batch de ingest (rag_repository
    # chama _rebuild_embedding_index_if_needed). Regra geral: lists ~ sqrt(N).
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rag_ks_embedding
            ON rag_knowledge_store
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 1)
        """
    )

    # Índice GIN em tokens para busca lexical eficiente via @> (contains).
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rag_ks_tokens
            ON rag_knowledge_store
            USING gin (tokens jsonb_path_ops)
        """
    )

    # Índice em source para limpeza por origem (DELETE WHERE source = ?).
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rag_ks_source
            ON rag_knowledge_store (source)
        """
    )

    # Índice em source_kind para deleção por kind (ex: "skill", "learning").
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rag_ks_source_kind
            ON rag_knowledge_store (source_kind)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS rag_knowledge_store")
