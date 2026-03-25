from datetime import datetime
import sqlalchemy as sa
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


user_access_groups = Table(
    "user_access_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("group_id", ForeignKey("access_groups.id"), primary_key=True),
)


class AccessGroup(Base):
    __tablename__ = "access_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    groups = relationship("AccessGroup", secondary=user_access_groups, lazy="joined")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    access_group_id: Mapped[int | None] = mapped_column(ForeignKey("access_groups.id"), nullable=True, index=True)
    target_query: Mapped[str] = mapped_column(String(500), index=True)
    authorization_code: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(50), default="single")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    compliance_status: Mapped[str] = mapped_column(String(50), default="pending")
    authorization_id: Mapped[int | None] = mapped_column(ForeignKey("scan_authorizations.id"), nullable=True, index=True)
    current_step: Mapped[str] = mapped_column(String(255), default="")
    mission_progress: Mapped[int] = mapped_column(Integer, default=0)
    retry_attempt: Mapped[int] = mapped_column(Integer, default=0)
    retry_max: Mapped[int] = mapped_column(Integer, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    state_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    logs = relationship("ScanLog", back_populates="scan_job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    source: Mapped[str] = mapped_column(String(100), default="manager")
    level: Mapped[str] = mapped_column(String(20), default="INFO")
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan_job = relationship("ScanJob", back_populates="logs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="low")
    # Mapeamento P1-P5 do Sn1per: P1=critical, P2=high, P3=medium, P4=low, P5=info
    sn1per_priority: Mapped[str | None] = mapped_column(String(10), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=1)
    # Confianca (0-100): derivada do CVSS/nuclei severity para reduzir FP noise
    confidence_score: Mapped[int] = mapped_column(Integer, default=50)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    # ── Falso Positivo ────────────────────────────────────────────────────────
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    fp_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    fp_reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    fp_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # ── Retest ────────────────────────────────────────────────────────────────
    # valores: None | "pending_retest" | "confirmed" | "refuted"
    retest_status: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_job = relationship("ScanJob", back_populates="findings")
    fp_reviewed_by = relationship("User", foreign_keys=[fp_reviewed_by_id])


class FalsePositiveMemory(Base):
    __tablename__ = "false_positive_memory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature: Mapped[str] = mapped_column(String(500), index=True)
    embedding_ref: Mapped[str] = mapped_column(String(255))
    memory_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    access_group_id: Mapped[int | None] = mapped_column(ForeignKey("access_groups.id"), nullable=True, index=True)
    authorization_code: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    targets_text: Mapped[str] = mapped_column(Text)
    scan_type: Mapped[str] = mapped_column(String(50), default="full")
    frequency: Mapped[str] = mapped_column(String(20), default="daily")
    run_time: Mapped[str] = mapped_column(String(5), default="00:00")
    day_of_week: Mapped[str | None] = mapped_column(String(10), nullable=True)
    day_of_month: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    key: Mapped[str] = mapped_column(String(100), index=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OperationLine(Base):
    __tablename__ = "operation_lines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(50), default="recon")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    definition: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    worker_name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    mode: Mapped[str] = mapped_column(String(20), default="unit", index=True)
    status: Mapped[str] = mapped_column(String(20), default="idle", index=True)
    current_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True, index=True)
    last_task_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScanAuthorization(Base):
    __tablename__ = "scan_authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    requester_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    authorization_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    target_query: Mapped[str] = mapped_column(String(500), index=True)
    ownership_proof: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="requested")
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    level: Mapped[str] = mapped_column(String(20), default="INFO")
    message: Mapped[str] = mapped_column(Text)
    event_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class ClientPolicy(Base):
    __tablename__ = "client_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), default="Default Policy")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PolicyAllowlistEntry(Base):
    __tablename__ = "policy_allowlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("client_policies.id"), index=True)
    target_pattern: Mapped[str] = mapped_column(String(500), index=True)
    tool_group: Mapped[str] = mapped_column(String(50), default="*")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ──────────────────────────────────────────────────────────────────────────────
# EASM ENTERPRISE INFRASTRUCTURE (Assets, Vulnerabilities, Temporal Tracking)
# ──────────────────────────────────────────────────────────────────────────────


class Asset(Base):
    """EASM Asset - memória de estado de superfície"""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    domain_or_ip: Mapped[str] = mapped_column(String(500), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), default="http", nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), default="web", nullable=True)  # web, login, database, ssh, ftp
    criticality_score: Mapped[float] = mapped_column(sa.Float, default=50.0)  # 0-100
    status: Mapped[str] = mapped_column(String(30), default="active", index=True)  # active, inactive, archived
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    rating_history = relationship("AssetRatingHistory", back_populates="asset", cascade="all, delete-orphan")


class Vulnerability(Base):
    """EASM Vulnerability - histórico com AGE factor"""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    tool_source: Mapped[str] = mapped_column(String(100))  # nuclei, sqlmap, nessus, shodan, etc
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20))  # critical, high, medium, low, info
    cvss_score: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_detected: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_detected: Mapped[datetime] = mapped_column(DateTime)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    detection_count: Mapped[int] = mapped_column(Integer, default=1)
    fair_pillar: Mapped[str] = mapped_column(String(50), default="perimeter_resilience")
    age_factor: Mapped[float] = mapped_column(sa.Float, default=1.0)  # 1 + log10(days_open + 1)
    ra_score: Mapped[float] = mapped_column(sa.Float, default=0.0)  # Risk score EASM
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", back_populates="vulnerabilities")
    finding = relationship("Finding", foreign_keys=[finding_id])


class AssetRatingHistory(Base):
    """EASM Temporal curve - rating history per asset per scan"""

    __tablename__ = "asset_rating_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    easm_rating: Mapped[float] = mapped_column(sa.Float)  # 0-100 score
    easm_grade: Mapped[str] = mapped_column(String(10))  # A, B, C, D, F
    open_critical_count: Mapped[int] = mapped_column(Integer, default=0)
    open_high_count: Mapped[int] = mapped_column(Integer, default=0)
    open_medium_count: Mapped[int] = mapped_column(Integer, default=0)
    remediated_this_period: Mapped[int] = mapped_column(Integer, default=0)
    velocity_score: Mapped[float] = mapped_column(sa.Float, default=0.0)  # % remediação por semana
    pillar_scores: Mapped[dict] = mapped_column(JSONB, default=dict)  # {perimeter_resilience: 85, ...}
    recorded_at: Mapped[datetime] = mapped_column(DateTime, index=True)

    asset = relationship("Asset", back_populates="rating_history")


class EASMAlert(Base):
    """EASM Alert - desvio de postura, webhooks"""

    __tablename__ = "easm_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(50))  # rating_drop, crown_jewel_age, critical_spike
    severity: Mapped[str] = mapped_column(String(20))  # critical, high, medium
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    trigger_value: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    threshold_value: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    webhook_payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class EASMAlertRule(Base):
    """EASM Alert Rule - configuração de gatilhos"""

    __tablename__ = "easm_alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(50))  # rating_drop, age_threshold, velocity
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    condition: Mapped[dict] = mapped_column(JSONB)  # {threshold: 10, period_hours: 24, ...}
    webhook_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notify_channels: Mapped[dict] = mapped_column(JSONB, default=dict)  # ["email", "slack", "pagerduty"]
    asset_filter: Mapped[dict] = mapped_column(JSONB, default=dict)  # {min_criticality: 70, types: [...]}
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
