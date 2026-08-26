"""ObservedRequest: real captured HTTP request/response from browser_request_harvester

Revision ID: 0030
Revises: 0029
"""
from alembic import op


revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def _idx(table: str, column: str) -> None:
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})")


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS observed_requests (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            endpoint_id INTEGER REFERENCES offensive_endpoints(id),
            identity_key VARCHAR(120) NOT NULL DEFAULT '',
            source VARCHAR(60) NOT NULL DEFAULT 'browser_harvester',
            method VARCHAR(12) NOT NULL DEFAULT 'GET',
            url TEXT NOT NULL,
            normalized_url VARCHAR(1000) NOT NULL,
            request_headers JSONB NOT NULL DEFAULT '{}',
            request_body JSONB NOT NULL DEFAULT '{}',
            body_sha256 VARCHAR(64),
            request_content_type VARCHAR(160),
            status_code INTEGER,
            response_content_type VARCHAR(160),
            response_excerpt TEXT,
            is_mutating BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    for col in (
        "scan_job_id", "endpoint_id", "identity_key", "source", "method",
        "normalized_url", "body_sha256", "status_code", "is_mutating", "created_at",
    ):
        _idx("observed_requests", col)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS observed_requests")
