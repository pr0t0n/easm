"""pgvector: enable vector extension + scan_embeddings table

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-29

Adds cross-scan memory via pgvector:
  - vector extension
  - scan_embeddings table: stores finding embeddings for similarity search
    across scans (detect recurring vulnerabilities, track remediation)
"""

from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable pgvector extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Create scan_embeddings table
    # Each row: one finding → 1536-dim embedding (OpenAI/local model)
    # Indexed with ivfflat for approximate nearest-neighbour search
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_embeddings (
            id              SERIAL PRIMARY KEY,
            scan_job_id     INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            finding_id      INTEGER REFERENCES findings(id) ON DELETE CASCADE,
            embedding_type  VARCHAR(40) NOT NULL DEFAULT 'finding',
            model           VARCHAR(80) NOT NULL DEFAULT 'local',
            vector          vector(1536),
            content_hash    VARCHAR(64),
            metadata        JSONB DEFAULT '{}',
            created_at      TIMESTAMP DEFAULT NOW()
        )
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_embeddings_scan_id
            ON scan_embeddings(scan_job_id)
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_embeddings_type
            ON scan_embeddings(embedding_type)
    """)

    # IVFFlat index for ANN search (cosine distance)
    # lists=100 is appropriate for up to ~1M rows
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_embeddings_vector
            ON scan_embeddings USING ivfflat (vector vector_cosine_ops)
            WITH (lists = 100)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS scan_embeddings CASCADE")
    op.execute("DROP EXTENSION IF EXISTS vector CASCADE")
