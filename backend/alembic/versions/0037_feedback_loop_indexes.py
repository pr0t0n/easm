"""Indexes for execution-to-evidence feedback correlation."""
from alembic import op


revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_findings_details_work_item_id",
        "findings",
        ["details"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_validation_wires_finding_status",
        "validation_wires",
        ["finding_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_validation_wires_finding_status", table_name="validation_wires")
    op.drop_index("ix_findings_details_work_item_id", table_name="findings")
