"""add attempt state history"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0039_attempt_state_history"
down_revision = "0038_work_item_attempts"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("work_item_attempts", sa.Column("state_history", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("work_item_attempts", sa.Column("heartbeat_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("work_item_attempts", "heartbeat_at")
    op.drop_column("work_item_attempts", "state_history")
