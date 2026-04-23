"""scan_job target_query: varchar(500) -> text

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-23
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_scan_job_target_query_text"
down_revision = "0004_executed_tool_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "scan_jobs",
        "target_query",
        existing_type=sa.String(500),
        type_=sa.Text(),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Truncate values > 500 chars before reverting (safety)
    op.execute(
        "UPDATE scan_jobs SET target_query = LEFT(target_query, 500) WHERE LENGTH(target_query) > 500"
    )
    op.alter_column(
        "scan_jobs",
        "target_query",
        existing_type=sa.Text(),
        type_=sa.String(500),
        existing_nullable=False,
    )
