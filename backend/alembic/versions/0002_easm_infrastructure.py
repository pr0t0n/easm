"""EASM enterprise infrastructure - assets, vulnerabilities, temporal tracking

Revision ID: 0002_easm_infrastructure
Revises: 0001_initial_schema
Create Date: 2026-03-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_easm_infrastructure"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ────────────────────────────────────────────────────────────────────────
    # Tabela: assets (memória de estado de superfície)
    # ────────────────────────────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("domain_or_ip", sa.String(500), nullable=False, index=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True, default="http"),
        sa.Column("asset_type", sa.String(50), nullable=True, default="web"),  # web, login, database, ssh, ftp, etc
        sa.Column("criticality_score", sa.Float(), nullable=False, default=50.0),  # 0-100
        sa.Column("status", sa.String(30), nullable=False, default="active"),  # active, inactive, archived
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("scan_count", sa.Integer(), nullable=False, default=0),
        sa.Column("last_scan_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, default="{}"),
        # fingerprints armazenados: {technology: "nginx/1.19", headers: {...}, etc}
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_assets_owner_status", "assets", ["owner_id", "status"])
    op.create_index("ix_assets_criticality", "assets", ["criticality_score"], postgresql_where=sa.text("status = 'active'"))

    # ────────────────────────────────────────────────────────────────────────
    # Tabela: vulnerabilities (histórico com AGE)
    # ────────────────────────────────────────────────────────────────────────
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False, index=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True, index=True),
        sa.Column("tool_source", sa.String(100), nullable=False),  # nuclei, sqlmap, nessus, shodan, etc
        sa.Column("cve_id", sa.String(50), nullable=True, index=True),
        sa.Column("severity", sa.String(20), nullable=False),  # critical, high, medium, low, info
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_detected", sa.DateTime(), nullable=False, index=True),
        sa.Column("last_detected", sa.DateTime(), nullable=False),
        sa.Column("remediated_at", sa.DateTime(), nullable=True),
        sa.Column("detection_count", sa.Integer(), nullable=False, default=1),
        # FAIR pillar classification: perimeter_resilience, patching_hygiene, osint_exposure
        sa.Column("fair_pillar", sa.String(50), nullable=False, default="perimeter_resilience"),
        # Fator AGE: 1 + log10(days_open + 1)
        sa.Column("age_factor", sa.Float(), nullable=False, default=1.0),
        sa.Column("ra_score", sa.Float(), nullable=False, default=0.0),  # Risk score EASM
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_fair_pillar", "vulnerabilities", ["fair_pillar"])
    op.create_index("ix_vulnerabilities_remediated_at", "vulnerabilities", ["remediated_at"], postgresql_where=sa.text("remediated_at IS NOT NULL"))

    # ────────────────────────────────────────────────────────────────────────
    # Tabela: asset_rating_history (curva temporal EASM)
    # ────────────────────────────────────────────────────────────────────────
    op.create_table(
        "asset_rating_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False, index=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("easm_rating", sa.Float(), nullable=False),  # 0-100 score
        sa.Column("easm_grade", sa.String(10), nullable=False),  # A, B, C, D, F
        sa.Column("open_critical_count", sa.Integer(), nullable=False, default=0),
        sa.Column("open_high_count", sa.Integer(), nullable=False, default=0),
        sa.Column("open_medium_count", sa.Integer(), nullable=False, default=0),
        sa.Column("remediated_this_period", sa.Integer(), nullable=False, default=0),
        sa.Column("velocity_score", sa.Float(), nullable=False, default=0.0),  # % remediação por semana
        sa.Column("pillar_scores", postgresql.JSONB(astext_type=sa.Text()), nullable=False, default="{}"),  # {perimeter_resilience: 85, ...}
        sa.Column("recorded_at", sa.DateTime(), nullable=False, index=True),
    )
    op.create_index("ix_asset_rating_history_asset_recorded_at", "asset_rating_history", ["asset_id", "recorded_at"])

    # ────────────────────────────────────────────────────────────────────────
    # Tabela: easm_alerts (webhooks, desvio de postura)
    # ────────────────────────────────────────────────────────────────────────
    op.create_table(
        "easm_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("alert_type", sa.String(50), nullable=False),  # rating_drop, crown_jewel_age, critical_spike, etc
        sa.Column("severity", sa.String(20), nullable=False),  # critical, high, medium
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("trigger_value", sa.Float(), nullable=True),  # ex: rating caiu 10 pontos
        sa.Column("threshold_value", sa.Float(), nullable=True),  # ex: limite é 80
        sa.Column("is_resolved", sa.Boolean(), nullable=False, default=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_notes", sa.Text(), nullable=True),
        sa.Column("webhook_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True, default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False, index=True),
    )
    op.create_index("ix_easm_alerts_owner_resolved", "easm_alerts", ["owner_id", "is_resolved"])

    # ────────────────────────────────────────────────────────────────────────
    # Tabela: easm_alert_rules (configuração de gatilhos)
    # ────────────────────────────────────────────────────────────────────────
    op.create_table(
        "easm_alert_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(50), nullable=False),  # rating_drop, age_threshold, velocity, etc
        sa.Column("enabled", sa.Boolean(), nullable=False, default=True),
        sa.Column("condition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),  # {threshold: 10, period_hours: 24, ...}
        sa.Column("webhook_url", sa.String(500), nullable=True),
        sa.Column("notify_channels", postgresql.JSONB(astext_type=sa.Text()), nullable=False, default='["email"]'),  # ["email", "slack", "pagerduty"]
        sa.Column("asset_filter", postgresql.JSONB(astext_type=sa.Text()), nullable=False, default="{}"),  # {min_criticality: 70, types: [...]}
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_easm_alert_rules_owner_enabled", "easm_alert_rules", ["owner_id", "enabled"])


def downgrade() -> None:
    op.drop_table("easm_alert_rules")
    op.drop_table("easm_alerts")
    op.drop_table("asset_rating_history")
    op.drop_table("vulnerabilities")
    op.drop_table("assets")
