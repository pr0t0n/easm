from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0042_runtime_support_tables"
down_revision = "0041_work_item_contract"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())

    if "worker_heartbeats" not in existing_tables:
        op.create_table(
            "worker_heartbeats",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("worker_name", sa.String(length=120), nullable=False),
            sa.Column("mode", sa.String(length=20), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("current_scan_id", sa.Integer(), nullable=True),
            sa.Column("last_task_name", sa.String(length=120), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["current_scan_id"], ["scan_jobs.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_worker_heartbeats_id", "worker_heartbeats", ["id"])
        op.create_index("ix_worker_heartbeats_worker_name", "worker_heartbeats", ["worker_name"], unique=True)
        op.create_index("ix_worker_heartbeats_mode", "worker_heartbeats", ["mode"])
        op.create_index("ix_worker_heartbeats_status", "worker_heartbeats", ["status"])
        op.create_index("ix_worker_heartbeats_current_scan_id", "worker_heartbeats", ["current_scan_id"])
        op.create_index("ix_worker_heartbeats_last_seen_at", "worker_heartbeats", ["last_seen_at"])

    if "skill_library" not in existing_tables:
        op.create_table(
            "skill_library",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("skill_name", sa.String(length=120), nullable=False),
            sa.Column("skill_category", sa.String(length=80), nullable=False),
            sa.Column("activity_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("kill_chain_phases", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("objective", sa.Text(), nullable=False),
            sa.Column("quality_criteria", sa.Text(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_skill_library_id", "skill_library", ["id"])
        op.create_index("ix_skill_library_skill_name", "skill_library", ["skill_name"], unique=True)
        op.create_index("ix_skill_library_skill_category", "skill_library", ["skill_category"])

    if "skill_tool_mappings" not in existing_tables:
        op.create_table(
            "skill_tool_mappings",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("skill_id", sa.Integer(), nullable=False),
            sa.Column("tool_name", sa.String(length=120), nullable=False),
            sa.Column("score", sa.Float(), nullable=False),
            sa.Column("usage_guide", sa.Text(), nullable=False),
            sa.Column("evidence_type", sa.String(length=120), nullable=False),
            sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["skill_id"], ["skill_library.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_skill_tool_mappings_id", "skill_tool_mappings", ["id"])
        op.create_index("ix_skill_tool_mappings_skill_id", "skill_tool_mappings", ["skill_id"])
        op.create_index("ix_skill_tool_mappings_tool_name", "skill_tool_mappings", ["tool_name"])

    if "agent_activity_logs" not in existing_tables:
        op.create_table(
            "agent_activity_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("scan_job_id", sa.Integer(), nullable=False),
            sa.Column("iteration", sa.Integer(), nullable=False),
            sa.Column("activity_demand", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("skill_found", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("skill_lookup_source", sa.String(length=60), nullable=False),
            sa.Column("tool_selected", sa.String(length=120), nullable=False),
            sa.Column("tool_score", sa.Float(), nullable=True),
            sa.Column("tool_usage_guide", sa.Text(), nullable=False),
            sa.Column("execution_result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("agent_report", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("supervisor_evaluation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("approved", sa.Boolean(), nullable=True),
            sa.Column("status", sa.String(length=40), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_agent_activity_logs_id", "agent_activity_logs", ["id"])
        op.create_index("ix_agent_activity_logs_scan_job_id", "agent_activity_logs", ["scan_job_id"])
        op.create_index("ix_agent_activity_logs_iteration", "agent_activity_logs", ["iteration"])
        op.create_index("ix_agent_activity_logs_status", "agent_activity_logs", ["status"])
        op.create_index("ix_agent_activity_logs_created_at", "agent_activity_logs", ["created_at"])


def downgrade():
    op.drop_table("agent_activity_logs")
    op.drop_table("skill_tool_mappings")
    op.drop_table("skill_library")
    op.drop_table("worker_heartbeats")
