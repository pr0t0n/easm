"""external G0 and authenticated internal G1 execution contexts

Revision ID: 0025
Revises: 0024
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def _context_column(table: str) -> None:
    op.add_column(
        table,
        sa.Column("execution_context", sa.String(length=20), nullable=False, server_default="external"),
    )
    op.create_index(f"ix_{table}_execution_context", table, ["execution_context"], unique=False)


def upgrade() -> None:
    op.create_table(
        "scan_execution_contexts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("context_type", sa.String(length=20), nullable=False, server_default="external"),
        sa.Column("auth_session_id", sa.Integer(), sa.ForeignKey("scan_auth_sessions.id"), nullable=True),
        sa.Column("identity_key", sa.String(length=120), nullable=True),
        sa.Column("role", sa.String(length=120), nullable=True),
        sa.Column("session_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="pending"),
        sa.Column("inventory_fingerprint", sa.String(length=80), nullable=True),
        sa.Column("blocking_reason", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("scan_job_id", "context_type", name="uq_scan_execution_contexts_scan_type"),
    )
    for column in ("scan_job_id", "context_type", "auth_session_id", "identity_key", "role", "status", "inventory_fingerprint", "created_at"):
        op.create_index(f"ix_scan_execution_contexts_{column}", "scan_execution_contexts", [column], unique=False)

    for table in (
        "evidence_artifacts",
        "offensive_hypotheses",
        "validation_runs",
        "coverage_items",
        "executed_tool_runs",
        "scan_work_items",
    ):
        _context_column(table)

    op.add_column("scan_work_items", sa.Column("auth_session_revision", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_scan_work_items_auth_session_revision", "scan_work_items", ["auth_session_revision"], unique=False)

    op.drop_constraint("uq_scan_work_items_scan_phase_tool_target", "scan_work_items", type_="unique")
    op.create_unique_constraint(
        "uq_scan_work_items_scan_phase_tool_target",
        "scan_work_items",
        ["scan_job_id", "execution_context", "phase_id", "tool_name", "target"],
    )
    op.drop_constraint("uq_offensive_hypotheses_signal", "offensive_hypotheses", type_="unique")
    op.create_unique_constraint(
        "uq_offensive_hypotheses_signal",
        "offensive_hypotheses",
        ["scan_job_id", "execution_context", "hypothesis_type", "target_ref", "source_signal"],
    )
    op.drop_constraint("uq_coverage_items_scan_target_test", "coverage_items", type_="unique")
    op.create_unique_constraint(
        "uq_coverage_items_scan_target_test",
        "coverage_items",
        ["scan_job_id", "execution_context", "coverage_type", "target_ref", "test_class"],
    )

    op.create_table(
        "endpoint_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("offensive_endpoints.id"), nullable=False),
        sa.Column("execution_context", sa.String(length=20), nullable=False, server_default="external"),
        sa.Column("auth_session_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("identity_key", sa.String(length=120), nullable=True),
        sa.Column("role_observed", sa.String(length=120), nullable=True),
        sa.Column("method", sa.String(length=12), nullable=False, server_default="GET"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=160), nullable=True),
        sa.Column("body_fingerprint", sa.String(length=80), nullable=True),
        sa.Column("redirect_location", sa.Text(), nullable=True),
        sa.Column("source_tool", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("source_artifact_id", sa.Integer(), sa.ForeignKey("evidence_artifacts.id"), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "endpoint_id", "execution_context", "method", "source_tool",
            name="uq_endpoint_observations_endpoint_context_method_tool",
        ),
    )
    for column in ("scan_job_id", "endpoint_id", "execution_context", "auth_session_revision", "identity_key", "role_observed", "method", "status_code", "body_fingerprint", "source_tool", "source_artifact_id", "first_seen", "last_seen"):
        op.create_index(f"ix_endpoint_observations_{column}", "endpoint_observations", [column], unique=False)

    op.create_table(
        "processor_checkpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("execution_context", sa.String(length=20), nullable=False, server_default="external"),
        sa.Column("processor_name", sa.String(length=120), nullable=False),
        sa.Column("processor_version", sa.String(length=80), nullable=False, server_default="v1"),
        sa.Column("input_fingerprint", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="pending"),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "scan_job_id", "execution_context", "processor_name", "processor_version", "input_fingerprint",
            name="uq_processor_checkpoints_context_input",
        ),
    )
    for column in ("scan_job_id", "execution_context", "processor_name", "processor_version", "input_fingerprint", "status", "created_at", "updated_at"):
        op.create_index(f"ix_processor_checkpoints_{column}", "processor_checkpoints", [column], unique=False)

    op.execute(
        """
        INSERT INTO scan_execution_contexts
            (scan_job_id, context_type, session_revision, status, metadata, started_at, created_at, updated_at)
        SELECT id, 'external', 0,
               CASE WHEN status IN ('completed', 'completed_with_gaps') THEN 'completed' ELSE 'running' END,
               '{"backfilled": true}'::jsonb, created_at, NOW(), NOW()
        FROM scan_jobs
        ON CONFLICT (scan_job_id, context_type) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_table("processor_checkpoints")
    op.drop_table("endpoint_observations")

    op.drop_constraint("uq_coverage_items_scan_target_test", "coverage_items", type_="unique")
    op.create_unique_constraint(
        "uq_coverage_items_scan_target_test", "coverage_items",
        ["scan_job_id", "coverage_type", "target_ref", "test_class"],
    )
    op.drop_constraint("uq_offensive_hypotheses_signal", "offensive_hypotheses", type_="unique")
    op.create_unique_constraint(
        "uq_offensive_hypotheses_signal", "offensive_hypotheses",
        ["scan_job_id", "hypothesis_type", "target_ref", "source_signal"],
    )
    op.drop_constraint("uq_scan_work_items_scan_phase_tool_target", "scan_work_items", type_="unique")
    op.create_unique_constraint(
        "uq_scan_work_items_scan_phase_tool_target", "scan_work_items",
        ["scan_job_id", "phase_id", "tool_name", "target"],
    )

    op.drop_index("ix_scan_work_items_auth_session_revision", table_name="scan_work_items")
    op.drop_column("scan_work_items", "auth_session_revision")
    for table in reversed((
        "evidence_artifacts", "offensive_hypotheses", "validation_runs",
        "coverage_items", "executed_tool_runs", "scan_work_items",
    )):
        op.drop_index(f"ix_{table}_execution_context", table_name=table)
        op.drop_column(table, "execution_context")
    op.drop_table("scan_execution_contexts")
