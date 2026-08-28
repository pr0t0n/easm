"""BasNetworkSegmentTag: operator-declared business_unit/criticality/controls
per network segment (CIDR or AD domain), joined into the BAS CMDB view.

Revision ID: 0033
Revises: 0032
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bas_network_segment_tags",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True, index=True),
        sa.Column("match_type", sa.String(20), nullable=False, index=True),
        sa.Column("match_value", sa.String(255), nullable=False, index=True),
        sa.Column("business_unit", sa.String(255), nullable=False, server_default=""),
        sa.Column("criticality", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("controls", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("bas_network_segment_tags")
