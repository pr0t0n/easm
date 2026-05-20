"""add agent_trace_events and skill_scores tables

Revision ID: 0011_agent_trace_events
Revises: 36258e602bd7
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011_agent_trace_events"
down_revision = "36258e602bd7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_trace_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("from_node", sa.String(length=60), nullable=False),
        sa.Column("to_node", sa.String(length=60), nullable=False),
        sa.Column("skill_id", sa.String(length=120), nullable=True),
        sa.Column("tool_name", sa.String(length=100), nullable=True),
        sa.Column("capability", sa.String(length=60), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="success"),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_trace_events_id", "agent_trace_events", ["id"])
    op.create_index("ix_agent_trace_events_scan_id", "agent_trace_events", ["scan_id"])
    op.create_index("ix_agent_trace_events_event_type", "agent_trace_events", ["event_type"])
    op.create_index("ix_agent_trace_events_created_at", "agent_trace_events", ["created_at"])

    op.create_table(
        "skill_scores",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skill_id", sa.String(length=120), nullable=False),
        sa.Column("capability", sa.String(length=60), nullable=False, server_default=""),
        sa.Column("library_hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_successes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_raw", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_promoted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("efficiency_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("productivity_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_skill_scores_id", "skill_scores", ["id"])
    op.create_index("ix_skill_scores_scan_id", "skill_scores", ["scan_id"])
    op.create_index("ix_skill_scores_skill_id", "skill_scores", ["skill_id"])
    op.create_index("ix_skill_scores_created_at", "skill_scores", ["created_at"])


def downgrade():
    op.drop_index("ix_skill_scores_created_at", table_name="skill_scores")
    op.drop_index("ix_skill_scores_skill_id", table_name="skill_scores")
    op.drop_index("ix_skill_scores_scan_id", table_name="skill_scores")
    op.drop_index("ix_skill_scores_id", table_name="skill_scores")
    op.drop_table("skill_scores")
    op.drop_index("ix_agent_trace_events_created_at", table_name="agent_trace_events")
    op.drop_index("ix_agent_trace_events_event_type", table_name="agent_trace_events")
    op.drop_index("ix_agent_trace_events_scan_id", table_name="agent_trace_events")
    op.drop_index("ix_agent_trace_events_id", table_name="agent_trace_events")
    op.drop_table("agent_trace_events")
