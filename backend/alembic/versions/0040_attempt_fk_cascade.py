"""cascade work item attempt deletion"""
from alembic import op

revision = "0040_attempt_fk_cascade"
down_revision = "0039_attempt_state_history"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("work_item_attempts_work_item_id_fkey", "work_item_attempts", type_="foreignkey")
    op.create_foreign_key("work_item_attempts_work_item_id_fkey", "work_item_attempts", "scan_work_items", ["work_item_id"], ["id"], ondelete="CASCADE")


def downgrade():
    op.drop_constraint("work_item_attempts_work_item_id_fkey", "work_item_attempts", type_="foreignkey")
    op.create_foreign_key("work_item_attempts_work_item_id_fkey", "work_item_attempts", "scan_work_items", ["work_item_id"], ["id"])
