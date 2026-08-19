"""BAS (Breach & Attack Simulation) module: enrollment tokens, agents, schedules, jobs

Revision ID: 0027
Revises: 0026
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


JSONB = postgresql.JSONB(astext_type=sa.Text())


def _index(table: str, *columns: str) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column], unique=False)


def upgrade() -> None:
    op.create_table(
        "bas_enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("issued_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("secret_hash", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("used_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("code", name="uq_bas_enrollment_tokens_code"),
    )
    _index("bas_enrollment_tokens", "owner_id", "access_group_id", "issued_by_id", "username", "code", "status")

    op.create_table(
        "bas_agents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("enrollment_token_id", sa.Integer(), sa.ForeignKey("bas_enrollment_tokens.id"), nullable=True),
        sa.Column("label", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("hostname", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("os", sa.String(length=20), nullable=False, server_default=""),
        sa.Column("os_version", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("arch", sa.String(length=20), nullable=False, server_default=""),
        sa.Column("agent_version", sa.String(length=40), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("tunnel_host", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("tunnel_port", sa.Integer(), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_ip", sa.String(length=64), nullable=True),
        sa.Column("enrolled_via_host", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("enrolled_via_port", sa.Integer(), nullable=True),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    _index("bas_agents", "owner_id", "access_group_id", "enrollment_token_id", "os", "status", "last_heartbeat_at")

    op.create_table(
        "bas_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("bas_agents.id"), nullable=False),
        sa.Column("target_hint", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("technique_keys", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("frequency", sa.String(length=20), nullable=False, server_default="daily"),
        sa.Column("run_time", sa.String(length=5), nullable=False, server_default="00:00"),
        sa.Column("day_of_week", sa.String(length=10), nullable=True),
        sa.Column("day_of_month", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("max_authorized_risk_tier", sa.String(length=20), nullable=False, server_default="safe"),
        sa.Column("authorization_attested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("authorization_attested_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("authorization_attested_at", sa.DateTime(), nullable=True),
        sa.Column("authorization_code", sa.String(length=64), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    _index("bas_schedules", "owner_id", "access_group_id", "agent_id", "enabled", "authorization_code")

    op.create_table(
        "bas_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("bas_schedules.id"), nullable=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("bas_agents.id"), nullable=False),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("access_group_id", sa.Integer(), sa.ForeignKey("access_groups.id"), nullable=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("technique_key", sa.String(length=120), nullable=False),
        sa.Column("risk_tier", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
        sa.Column("kali_job_id", sa.String(length=120), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("dispatched_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("result", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    _index(
        "bas_jobs", "schedule_id", "agent_id", "owner_id", "access_group_id", "scan_job_id",
        "technique_key", "risk_tier", "status", "kali_job_id", "finding_id", "created_at",
    )


def downgrade() -> None:
    op.drop_table("bas_jobs")
    op.drop_table("bas_schedules")
    op.drop_table("bas_agents")
    op.drop_table("bas_enrollment_tokens")
