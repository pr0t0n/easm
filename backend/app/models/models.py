from datetime import datetime
import sqlalchemy as sa
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text, Text as SAText
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
    target_query: Mapped[str] = mapped_column(Text, index=True)
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
    tech_stack: Mapped[list] = mapped_column(JSONB, default=list)
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
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    tool: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=1)
    # Confianca (0-100): derivada do CVSS/severidade da ferramenta para reduzir FP noise
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


class ExecutedToolRun(Base):
    """Rastreia execução de ferramentas para idempotência dentro de uma missão."""
    __tablename__ = "executed_tool_runs"
    __table_args__ = (
        sa.UniqueConstraint("scan_job_id", "tool_name", "target", name="uq_executed_tool_runs_scan_tool_target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(100), index=True)
    target: Mapped[str] = mapped_column(String(500), index=True)  # IP, domain, or URL scanned
    status: Mapped[str] = mapped_column(String(50), default="success")  # success, failed, skipped
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_time_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan_job = relationship("ScanJob")


class ScanAuditLog(Base):
    """Auditoria de memória operacional: notas, ações e observações do agente autônomo."""
    __tablename__ = "scan_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0, index=True)
    node_name: Mapped[str] = mapped_column(String(100), index=True)  # supervisor, strategic_planning, etc
    entry_type: Mapped[str] = mapped_column(String(50), index=True)  # note, todo, action, observation, error
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan_job = relationship("ScanJob")


class FalsePositiveMemory(Base):
    __tablename__ = "false_positive_memory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature: Mapped[str] = mapped_column(String(500), index=True)
    embedding_ref: Mapped[str] = mapped_column(String(255))
    memory_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class VulnerabilityLearning(Base):
    """Aprendizados revisáveis extraídos de reports públicos de vulnerabilidade."""
    __tablename__ = "vulnerability_learnings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending_review", index=True)
    source_kind: Mapped[str] = mapped_column(String(60), default="hackerone_report", index=True)
    source_urls: Mapped[list] = mapped_column(JSONB, default=list)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(255), default="")
    vulnerability_type: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps_to_reproduce: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    learned_mission: Mapped[str | None] = mapped_column(Text, nullable=True)
    learned_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    learned_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    technique_count: Mapped[int] = mapped_column(Integer, default=0)
    affected_phases: Mapped[list] = mapped_column(JSONB, default=list)
    affected_skills: Mapped[list] = mapped_column(JSONB, default=list)
    recommended_tools: Mapped[list] = mapped_column(JSONB, default=list)
    raw_extraction: Mapped[dict] = mapped_column(JSONB, default=dict)
    raw_llm_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    accepted_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", foreign_keys=[owner_id])
    accepted_by = relationship("User", foreign_keys=[accepted_by_id])


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
# ScriptKidd.o infrastructure (assets, vulnerabilities, temporal tracking)
# ──────────────────────────────────────────────────────────────────────────────


class Asset(Base):
    """Asset - memória de estado de superfície"""

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
    """Vulnerability - histórico com AGE factor"""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    tool_source: Mapped[str] = mapped_column(String(100))  # nmap-vulscan, nikto, shodan, etc
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
    ra_score: Mapped[float] = mapped_column(sa.Float, default=0.0)  # Risk score
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", back_populates="vulnerabilities")
    finding = relationship("Finding", foreign_keys=[finding_id])


class AssetRatingHistory(Base):
    """Temporal curve - rating history per asset per scan"""

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
    """Posture alert - desvio de postura, webhooks"""

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
    """Posture alert rule - configuração de gatilhos"""

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


# ──────────────────────────────────────────────────────────────────────────────
# Skill Library: catálogo de skills e ferramentas com scores para o agente
# ──────────────────────────────────────────────────────────────────────────────


class SkillLibrary(Base):
    """Biblioteca de skills disponíveis para o agente por fase do Kill Chain."""
    __tablename__ = "skill_library"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    skill_name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    skill_category: Mapped[str] = mapped_column(String(80), index=True)
    activity_types: Mapped[list] = mapped_column(JSONB, default=list)
    kill_chain_phases: Mapped[list] = mapped_column(JSONB, default=list)
    objective: Mapped[str] = mapped_column(Text, default="")
    quality_criteria: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tool_mappings = relationship("SkillToolMapping", back_populates="skill", cascade="all, delete-orphan")


class SkillToolMapping(Base):
    """Mapeamento de ferramentas por skill com score e guia de uso."""
    __tablename__ = "skill_tool_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    skill_id: Mapped[int] = mapped_column(ForeignKey("skill_library.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(120), index=True)
    score: Mapped[float] = mapped_column(Float, default=5.0)
    usage_guide: Mapped[str] = mapped_column(Text, default="")
    evidence_type: Mapped[str] = mapped_column(String(120), default="")
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    skill = relationship("SkillLibrary", back_populates="tool_mappings")


class AgentActivityLog(Base):
    """Rastreia o ciclo completo supervisor→agente→supervisor por atividade."""
    __tablename__ = "agent_activity_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0, index=True)

    activity_demand: Mapped[dict] = mapped_column(JSONB, default=dict)
    skill_found: Mapped[dict] = mapped_column(JSONB, default=dict)
    skill_lookup_source: Mapped[str] = mapped_column(String(60), default="library_db")
    tool_selected: Mapped[str] = mapped_column(String(120), default="")
    tool_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    tool_usage_guide: Mapped[str] = mapped_column(Text, default="")
    execution_result: Mapped[dict] = mapped_column(JSONB, default=dict)
    agent_report: Mapped[dict] = mapped_column(JSONB, default=dict)
    supervisor_evaluation: Mapped[dict] = mapped_column(JSONB, default=dict)
    approved: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_job = relationship("ScanJob")


class AgentTraceEvent(Base):
    """Low-level graph transition events emitted by the agent graph tracer."""
    __tablename__ = "agent_trace_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    from_node: Mapped[str] = mapped_column(String(120), default="")
    to_node: Mapped[str] = mapped_column(String(120), default="")
    skill_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    capability: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="ok", index=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan_job = relationship("ScanJob", foreign_keys=[scan_id])


class SkillScore(Base):
    """Efficiency and productivity metrics computed per skill execution."""
    __tablename__ = "skill_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0, index=True)
    skill_id: Mapped[str] = mapped_column(String(120), index=True)
    capability: Mapped[str] = mapped_column(String(60), default="")
    library_hits: Mapped[int] = mapped_column(Integer, default=0)
    tool_attempts: Mapped[int] = mapped_column(Integer, default=0)
    tool_successes: Mapped[int] = mapped_column(Integer, default=0)
    tool_failures: Mapped[int] = mapped_column(Integer, default=0)
    findings_raw: Mapped[int] = mapped_column(Integer, default=0)
    findings_promoted: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    efficiency_score: Mapped[float] = mapped_column(Float, default=0.0)
    productivity_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan_job = relationship("ScanJob", foreign_keys=[scan_id])
