from alembic import op
import sqlalchemy as sa


revision = "0044_scan_validation_metrics"
down_revision = "0043_jev_decisions"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())

    if "scan_validation_metrics" not in existing_tables:
        op.create_table(
            "scan_validation_metrics",
            sa.Column("scan_job_id", sa.Integer(), nullable=False),
            sa.Column("findings_total", sa.Integer(), nullable=False),
            sa.Column("candidates", sa.Integer(), nullable=False),
            sa.Column("confirmed", sa.Integer(), nullable=False),
            sa.Column("refuted", sa.Integer(), nullable=False),
            sa.Column("not_applicable", sa.Integer(), nullable=False),
            sa.Column("needs_human_review", sa.Integer(), nullable=False),
            sa.Column("blocked", sa.Integer(), nullable=False),
            sa.Column("inconclusive", sa.Integer(), nullable=False),
            sa.Column("hypothesis", sa.Integer(), nullable=False),
            sa.Column("orphans_total", sa.Integer(), nullable=False),
            sa.Column("orphans_adjudicated", sa.Integer(), nullable=False),
            sa.Column("wires_total", sa.Integer(), nullable=False),
            sa.Column("wires_completed", sa.Integer(), nullable=False),
            sa.Column("wires_failed", sa.Integer(), nullable=False),
            sa.Column("jev_decisions", sa.Integer(), nullable=False),
            sa.Column("candidate_residual_pct", sa.Float(), nullable=False),
            sa.Column("quality_gate_grade", sa.String(length=4), nullable=True),
            sa.Column("computed_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
            sa.PrimaryKeyConstraint("scan_job_id"),
        )


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if "scan_validation_metrics" in set(inspector.get_table_names()):
        op.drop_table("scan_validation_metrics")
