from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0043_jev_decisions"
down_revision = "0042_runtime_support_tables"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())

    if "jev_decisions" not in existing_tables:
        op.create_table(
            "jev_decisions",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("scan_job_id", sa.Integer(), nullable=True),
            sa.Column("question_id", sa.String(length=120), nullable=False),
            sa.Column("kind", sa.String(length=10), nullable=False),
            sa.Column("question", sa.Text(), nullable=False),
            sa.Column("answer", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("probability", sa.Float(), nullable=False),
            sa.Column("threshold", sa.Float(), nullable=False),
            sa.Column("source", sa.String(length=10), nullable=False),
            sa.Column("shadow", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_jev_decisions_id", "jev_decisions", ["id"])
        op.create_index("ix_jev_decisions_scan_job_id", "jev_decisions", ["scan_job_id"])
        op.create_index("ix_jev_decisions_question_id", "jev_decisions", ["question_id"])
        op.create_index("ix_jev_decisions_kind", "jev_decisions", ["kind"])
        op.create_index("ix_jev_decisions_source", "jev_decisions", ["source"])
        op.create_index("ix_jev_decisions_created_at", "jev_decisions", ["created_at"])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if "jev_decisions" in set(inspector.get_table_names()):
        op.drop_table("jev_decisions")
