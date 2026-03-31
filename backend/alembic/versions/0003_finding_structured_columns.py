"""Add structured columns to findings: cvss, domain, tool, recommendation

Revision ID: 0003_finding_structured_columns
Revises: 0002_easm_infrastructure
Create Date: 2026-03-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_finding_structured_columns"
down_revision = ("0002_easm_infrastructure", "0002_scheduled_scans_last_run_at")
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("cvss", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("domain", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("tool", sa.String(length=100), nullable=True))
    op.add_column("findings", sa.Column("recommendation", sa.Text(), nullable=True))
    op.create_index("ix_findings_domain", "findings", ["domain"])
    op.create_index("ix_findings_tool", "findings", ["tool"])

    # Backfill existing findings from JSONB details
    op.execute("""
        UPDATE findings
        SET tool = COALESCE(
                details->>'tool',
                details->'details'->>'tool'
            ),
            domain = COALESCE(
                details->>'asset',
                details->>'target',
                details->'details'->>'asset'
            ),
            cvss = CASE
                WHEN (details->>'cvss') IS NOT NULL
                    AND (details->>'cvss') ~ '^[0-9]+\\.?[0-9]*$'
                THEN (details->>'cvss')::float
                ELSE NULL
            END,
            recommendation = COALESCE(
                details->>'qwen_recomendacao_pt',
                details->>'cloudcode_recomendacao_pt'
            )
        WHERE tool IS NULL
    """)


def downgrade() -> None:
    op.drop_index("ix_findings_tool", table_name="findings")
    op.drop_index("ix_findings_domain", table_name="findings")
    op.drop_column("findings", "recommendation")
    op.drop_column("findings", "tool")
    op.drop_column("findings", "domain")
    op.drop_column("findings", "cvss")
