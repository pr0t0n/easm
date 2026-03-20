"""initial schema

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-03-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "access_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_access_groups_id", "access_groups", ["id"])
    op.create_index("ix_access_groups_name", "access_groups", ["name"], unique=True)

    op.create_table(
        "user_access_groups",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), primary_key=True),
    )

    op.create_table(
        "scan_authorizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("requester_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("authorization_code", sa.String(length=64), nullable=False),
        sa.Column("target_query", sa.String(length=500), nullable=False),
        sa.Column("ownership_proof", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_authorizations_id", "scan_authorizations", ["id"])
    op.create_index("ix_scan_authorizations_authorization_code", "scan_authorizations", ["authorization_code"], unique=True)

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("target_query", sa.String(length=500), nullable=False),
        sa.Column("authorization_code", sa.String(length=64), nullable=True),
        sa.Column("mode", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("compliance_status", sa.String(length=50), nullable=False),
        sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("scan_authorizations.id"), nullable=True),
        sa.Column("current_step", sa.String(length=255), nullable=False),
        sa.Column("mission_progress", sa.Integer(), nullable=False),
        sa.Column("state_data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_jobs_id", "scan_jobs", ["id"])

    op.create_table(
        "scan_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_logs_id", "scan_logs", ["id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cve", sa.String(length=50), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_findings_id", "findings", ["id"])

    op.create_table(
        "false_positive_memory",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("signature", sa.String(length=500), nullable=False),
        sa.Column("embedding_ref", sa.String(length=255), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_false_positive_memory_id", "false_positive_memory", ["id"])

    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("authorization_code", sa.String(length=64), nullable=True),
        sa.Column("targets_text", sa.Text(), nullable=False),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column("frequency", sa.String(length=20), nullable=False),
        sa.Column("run_time", sa.String(length=5), nullable=False),
        sa.Column("day_of_week", sa.String(length=10), nullable=True),
        sa.Column("day_of_month", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scheduled_scans_id", "scheduled_scans", ["id"])

    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_app_settings_id", "app_settings", ["id"])

    op.create_table(
        "operation_lines",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_operation_lines_id", "operation_lines", ["id"])

    op.create_table(
        "client_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_client_policies_id", "client_policies", ["id"])

    op.create_table(
        "policy_allowlist_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("client_policies.id"), nullable=False),
        sa.Column("target_pattern", sa.String(length=500), nullable=False),
        sa.Column("tool_group", sa.String(length=50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_policy_allowlist_entries_id", "policy_allowlist_entries", ["id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("event_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_audit_events_id", "audit_events", ["id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("policy_allowlist_entries")
    op.drop_table("client_policies")
    op.drop_table("operation_lines")
    op.drop_table("app_settings")
    op.drop_table("scheduled_scans")
    op.drop_table("false_positive_memory")
    op.drop_table("findings")
    op.drop_table("scan_logs")
    op.drop_table("scan_jobs")
    op.drop_table("scan_authorizations")
    op.drop_table("user_access_groups")
    op.drop_table("access_groups")
    op.drop_table("users")
