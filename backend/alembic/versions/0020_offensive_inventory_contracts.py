"""offensive inventory contracts

Revision ID: 0020
Revises: 0019
"""
from alembic import op


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_assets (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            asset_type VARCHAR(40) NOT NULL DEFAULT 'web',
            host VARCHAR(255) NOT NULL DEFAULT '',
            ip VARCHAR(80),
            url TEXT NOT NULL DEFAULT '',
            root_domain VARCHAR(255) NOT NULL DEFAULT '',
            in_scope BOOLEAN NOT NULL DEFAULT TRUE,
            source_tool VARCHAR(120),
            confidence INTEGER NOT NULL DEFAULT 60,
            metadata JSONB NOT NULL DEFAULT '{}',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_assets_scan_asset UNIQUE (scan_job_id, asset_type, host, url)
        )
        """
    )
    _idx("offensive_assets", "scan_job_id")
    _idx("offensive_assets", "asset_type")
    _idx("offensive_assets", "host")
    _idx("offensive_assets", "ip")
    _idx("offensive_assets", "root_domain")
    _idx("offensive_assets", "in_scope")
    _idx("offensive_assets", "source_tool")
    _idx("offensive_assets", "first_seen")
    _idx("offensive_assets", "last_seen")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_services (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            asset_id INTEGER REFERENCES offensive_assets(id),
            port INTEGER,
            protocol VARCHAR(30) NOT NULL DEFAULT 'tcp',
            service_name VARCHAR(120),
            product VARCHAR(160),
            version VARCHAR(120),
            tls BOOLEAN NOT NULL DEFAULT FALSE,
            banner TEXT,
            source_tool VARCHAR(120),
            metadata JSONB NOT NULL DEFAULT '{}',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_services_asset_port_proto UNIQUE (asset_id, port, protocol)
        )
        """
    )
    for col in ("scan_job_id", "asset_id", "port", "protocol", "service_name", "tls", "source_tool", "first_seen", "last_seen"):
        _idx("offensive_services", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_endpoints (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            asset_id INTEGER REFERENCES offensive_assets(id),
            url TEXT NOT NULL,
            normalized_url VARCHAR(1000) NOT NULL,
            method VARCHAR(12) NOT NULL DEFAULT 'GET',
            status_code INTEGER,
            content_type VARCHAR(160),
            auth_required BOOLEAN,
            auth_context VARCHAR(120) NOT NULL DEFAULT 'anonymous',
            role_observed VARCHAR(120),
            source_tool VARCHAR(120),
            source_artifact_id INTEGER REFERENCES evidence_artifacts(id),
            discovered_from TEXT,
            confidence INTEGER NOT NULL DEFAULT 60,
            tags JSONB NOT NULL DEFAULT '[]',
            metadata JSONB NOT NULL DEFAULT '{}',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_endpoints_scan_method_url_auth UNIQUE (scan_job_id, method, normalized_url, auth_context)
        )
        """
    )
    for col in ("scan_job_id", "asset_id", "normalized_url", "method", "status_code", "content_type", "auth_required", "auth_context", "role_observed", "source_tool", "source_artifact_id", "first_seen", "last_seen"):
        _idx("offensive_endpoints", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_js_assets (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            endpoint_id INTEGER REFERENCES offensive_endpoints(id),
            url TEXT NOT NULL,
            sha256 VARCHAR(80),
            size INTEGER,
            is_sourcemap BOOLEAN NOT NULL DEFAULT FALSE,
            bundle_name VARCHAR(255),
            framework_hint VARCHAR(120),
            download_status VARCHAR(40) NOT NULL DEFAULT 'pending',
            analysis_status VARCHAR(40) NOT NULL DEFAULT 'pending',
            metadata JSONB NOT NULL DEFAULT '{}',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_js_assets_scan_url UNIQUE (scan_job_id, url)
        )
        """
    )
    for col in ("scan_job_id", "endpoint_id", "sha256", "is_sourcemap", "bundle_name", "framework_hint", "download_status", "analysis_status", "first_seen", "last_seen"):
        _idx("offensive_js_assets", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_parameters (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            endpoint_id INTEGER NOT NULL REFERENCES offensive_endpoints(id),
            name VARCHAR(160) NOT NULL,
            location VARCHAR(40) NOT NULL DEFAULT 'query',
            type_hint VARCHAR(80),
            risk_hint VARCHAR(120),
            sample_value TEXT,
            source_tool VARCHAR(120),
            source_js_asset_id INTEGER REFERENCES offensive_js_assets(id),
            metadata JSONB NOT NULL DEFAULT '{}',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_parameters_endpoint_name_location UNIQUE (endpoint_id, name, location)
        )
        """
    )
    for col in ("scan_job_id", "endpoint_id", "name", "location", "type_hint", "risk_hint", "source_tool", "source_js_asset_id", "first_seen", "last_seen"):
        _idx("offensive_parameters", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_api_specs (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            url TEXT NOT NULL,
            spec_type VARCHAR(40) NOT NULL DEFAULT 'openapi',
            version VARCHAR(80),
            parsed_status VARCHAR(40) NOT NULL DEFAULT 'pending',
            endpoint_count INTEGER NOT NULL DEFAULT 0,
            metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_api_specs_scan_url_type UNIQUE (scan_job_id, url, spec_type)
        )
        """
    )
    for col in ("scan_job_id", "spec_type", "parsed_status", "created_at"):
        _idx("offensive_api_specs", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS offensive_hypotheses (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            hypothesis_type VARCHAR(120) NOT NULL,
            title VARCHAR(255) NOT NULL,
            target_ref VARCHAR(1000) NOT NULL DEFAULT '',
            source_signal TEXT NOT NULL DEFAULT '',
            confidence INTEGER NOT NULL DEFAULT 50,
            status VARCHAR(40) NOT NULL DEFAULT 'open',
            recommended_tools JSONB NOT NULL DEFAULT '[]',
            required_identities JSONB NOT NULL DEFAULT '[]',
            evidence_requirements JSONB NOT NULL DEFAULT '[]',
            metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_offensive_hypotheses_signal UNIQUE (scan_job_id, hypothesis_type, target_ref, source_signal)
        )
        """
    )
    for col in ("scan_job_id", "hypothesis_type", "target_ref", "confidence", "status", "created_at"):
        _idx("offensive_hypotheses", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS validation_runs (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            hypothesis_id INTEGER REFERENCES offensive_hypotheses(id),
            finding_id INTEGER REFERENCES findings(id),
            validator_name VARCHAR(120) NOT NULL,
            identity_key VARCHAR(120),
            baseline_artifact_id INTEGER REFERENCES evidence_artifacts(id),
            attempt_artifact_id INTEGER REFERENCES evidence_artifacts(id),
            negative_control_artifact_id INTEGER REFERENCES evidence_artifacts(id),
            result VARCHAR(40) NOT NULL DEFAULT 'candidate',
            reason TEXT,
            metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    for col in ("scan_job_id", "hypothesis_id", "finding_id", "validator_name", "identity_key", "baseline_artifact_id", "attempt_artifact_id", "negative_control_artifact_id", "result", "created_at"):
        _idx("validation_runs", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS coverage_items (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            coverage_type VARCHAR(80) NOT NULL,
            target_ref VARCHAR(1000) NOT NULL DEFAULT '',
            test_class VARCHAR(120) NOT NULL DEFAULT '',
            status VARCHAR(40) NOT NULL DEFAULT 'not_tested',
            endpoint_id INTEGER REFERENCES offensive_endpoints(id),
            hypothesis_id INTEGER REFERENCES offensive_hypotheses(id),
            finding_id INTEGER REFERENCES findings(id),
            blocking_reason TEXT,
            metadata JSONB NOT NULL DEFAULT '{}',
            updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_coverage_items_scan_target_test UNIQUE (scan_job_id, coverage_type, target_ref, test_class)
        )
        """
    )
    for col in ("scan_job_id", "coverage_type", "target_ref", "test_class", "status", "endpoint_id", "hypothesis_id", "finding_id", "updated_at"):
        _idx("coverage_items", col)

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS retest_runs (
            id SERIAL PRIMARY KEY,
            scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
            finding_id INTEGER NOT NULL REFERENCES findings(id),
            validation_run_id INTEGER REFERENCES validation_runs(id),
            status VARCHAR(40) NOT NULL DEFAULT 'queued',
            old_status VARCHAR(40),
            new_status VARCHAR(40),
            artifact_id INTEGER REFERENCES evidence_artifacts(id),
            summary TEXT,
            metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMP
        )
        """
    )
    for col in ("scan_job_id", "finding_id", "validation_run_id", "status", "artifact_id", "created_at"):
        _idx("retest_runs", col)


def downgrade() -> None:
    for table in (
        "retest_runs",
        "coverage_items",
        "validation_runs",
        "offensive_hypotheses",
        "offensive_api_specs",
        "offensive_parameters",
        "offensive_js_assets",
        "offensive_endpoints",
        "offensive_services",
        "offensive_assets",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table}")


def _idx(table: str, column: str) -> None:
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})")
