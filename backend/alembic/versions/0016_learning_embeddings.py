"""pgvector: embeddings semânticos dos aprendizados HackerOne

Frente A — inteligência viva. Adiciona um vetor por learning para matching
semântico do contexto do alvo (tech-stack + endpoints) contra os ~10k
aprendizados, em vez de só contar famílias.

Dimensão 384 = BAAI/bge-small-en-v1.5 (fastembed/ONNX em CPU). Índice ivfflat
com distância de cosseno para ANN.

Revision ID: 0016
Revises: 0015
"""
from alembic import op


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.execute(
        """
        ALTER TABLE vulnerability_learnings
            ADD COLUMN IF NOT EXISTS embedding vector(384)
        """
    )
    # Modelo usado para gerar o vetor (auditoria / re-embed quando trocar).
    op.execute(
        """
        ALTER TABLE vulnerability_learnings
            ADD COLUMN IF NOT EXISTS embedding_model VARCHAR(80)
        """
    )
    # IVFFlat (cosine) — lists=100 cobre confortavelmente ~10k linhas.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vuln_learnings_embedding
            ON vulnerability_learnings
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_vuln_learnings_embedding")
    op.execute("ALTER TABLE vulnerability_learnings DROP COLUMN IF EXISTS embedding_model")
    op.execute("ALTER TABLE vulnerability_learnings DROP COLUMN IF EXISTS embedding")
