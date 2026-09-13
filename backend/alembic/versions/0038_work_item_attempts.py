"""add execution attempt contract"""
from alembic import op
import sqlalchemy as sa

revision = "0038_work_item_attempts"
down_revision = "0037"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "work_item_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("scan_work_items.id"), nullable=False),
        sa.Column("attempt_key", sa.String(80), nullable=False, unique=True),
        sa.Column("state", sa.String(40), nullable=False, server_default="claimed"),
        sa.Column("worker_id", sa.String(120)),
        sa.Column("mcp_request_id", sa.String(160)),
        sa.Column("runner_job_id", sa.String(160)),
        sa.Column("error_class", sa.String(80)),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_work_item_attempts_work_item_id", "work_item_attempts", ["work_item_id"])
    op.create_index("ix_work_item_attempts_attempt_key", "work_item_attempts", ["attempt_key"], unique=True)

def downgrade():
    op.drop_table("work_item_attempts")
