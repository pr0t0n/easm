"""finding adjudication cycles, validation wires and intelligence snapshots

Revision ID: 0026
Revises: 0025
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


JSONB = postgresql.JSONB(astext_type=sa.Text())


def _index(table: str, *columns: str) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column], unique=False)


def upgrade() -> None:
    op.create_table(
        "finding_adjudications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("cycle", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="reviewing"),
        sa.Column("dossier_hash", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("dossier", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("proposed_verdict", sa.String(length=40), nullable=True),
        sa.Column("final_verdict", sa.String(length=40), nullable=False, server_default="inconclusive"),
        sa.Column("reason_code", sa.String(length=120), nullable=False, server_default="insufficient_evidence"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("missing_evidence", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("contradictions", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("supporting_evidence_ids", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("model_name", sa.String(length=160), nullable=True),
        sa.Column("prompt_version", sa.String(length=80), nullable=False, server_default="finding-adjudication-v1"),
        sa.Column("prompt_hash", sa.String(length=80), nullable=True),
        sa.Column("model_response", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("finding_id", "cycle", name="uq_finding_adjudications_finding_cycle"),
    )
    _index(
        "finding_adjudications", "scan_job_id", "finding_id", "status", "dossier_hash",
        "proposed_verdict", "final_verdict", "reason_code", "created_at", "completed_at",
    )

    op.create_table(
        "validation_wires",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("adjudication_id", sa.Integer(), sa.ForeignKey("finding_adjudications.id"), nullable=True),
        sa.Column("parent_wire_id", sa.Integer(), sa.ForeignKey("validation_wires.id"), nullable=True),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("scan_work_items.id"), nullable=True),
        sa.Column("source_artifact_id", sa.Integer(), sa.ForeignKey("evidence_artifacts.id"), nullable=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("offensive_endpoints.id"), nullable=True),
        sa.Column("phase_id", sa.String(length=10), nullable=False, server_default="P21"),
        sa.Column("action_id", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="planned"),
        sa.Column("reason_code", sa.String(length=120), nullable=False, server_default="missing_evidence"),
        sa.Column("target_ref", sa.Text(), nullable=False, server_default=""),
        sa.Column("parameter_ref", sa.String(length=255), nullable=True),
        sa.Column("identity_key", sa.String(length=120), nullable=True),
        sa.Column("secondary_identity_key", sa.String(length=120), nullable=True),
        sa.Column("tool_name", sa.String(length=120), nullable=True),
        sa.Column("profile", sa.String(length=120), nullable=True),
        sa.Column("input_bindings", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("expected_signals", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("policy_decision", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("result_summary", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("idempotency_key", name="uq_validation_wires_idempotency_key"),
    )
    _index(
        "validation_wires", "scan_job_id", "finding_id", "adjudication_id", "parent_wire_id",
        "work_item_id", "source_artifact_id", "endpoint_id", "phase_id", "action_id", "status",
        "reason_code", "identity_key", "secondary_identity_key", "tool_name", "idempotency_key",
        "created_at", "updated_at",
    )

    op.create_table(
        "finding_intelligence_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("cve_id", sa.String(length=50), nullable=True),
        sa.Column("applicability", sa.String(length=40), nullable=False, server_default="unknown"),
        sa.Column("cvss_version", sa.String(length=20), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_source", sa.String(length=120), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=True),
        sa.Column("public_exploit_status", sa.String(length=40), nullable=False, server_default="unknown"),
        sa.Column("references", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    _index(
        "finding_intelligence_snapshots", "scan_job_id", "finding_id", "cve_id", "applicability",
        "public_exploit_status", "fetched_at",
    )


def downgrade() -> None:
    op.drop_table("finding_intelligence_snapshots")
    op.drop_table("validation_wires")
    op.drop_table("finding_adjudications")
