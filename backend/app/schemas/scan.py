from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator

# SEC-003: state_data is echoed back to API callers (ScanResponse/ReportResponse),
# but it can carry raw credential material under these keys (auth_config's
# username/password/bearer_token/cookies/headers, llm_risk's password/auth_value)
# — see ScanJob.state_data's encryption-at-rest in StateDataJSON, which protects
# the DB column but not a decrypted-in-Python value handed back over HTTP.
_STATE_DATA_SENSITIVE_SUBTREES = ("auth_config", "llm_risk", "api_scan_config")
_STATE_DATA_SENSITIVE_LEAVES = {
    "password", "passwd", "bearer_token", "token", "cookie", "cookies",
    "headers", "header_value", "auth_value",
    "spec_payload",
}


def _redact_sensitive_leaves(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, sub in value.items():
            if key in _STATE_DATA_SENSITIVE_LEAVES and sub:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive_leaves(sub)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_leaves(item) for item in value]
    return value


def _redact_state_data(state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {}
    out = dict(state)
    for key in _STATE_DATA_SENSITIVE_SUBTREES:
        if key in out and isinstance(out[key], (dict, list)):
            out[key] = _redact_sensitive_leaves(out[key])
    return out


class ScanCreate(BaseModel):
    target_query: str
    mode: str = "single"
    execution_plan: str = "external_only"
    access_group_id: int | None = None
    access_group_name: str | None = None
    authorization_code: str | None = None
    scope_authorization_attested: bool = False
    schedule_at: datetime | None = None
    llm_risk_enabled: bool = False
    llm_risk_url: str | None = None
    llm_risk_auth_type: str = "none"
    llm_risk_auth_header: str | None = None
    llm_risk_auth_value: str | None = None
    llm_risk_auth_username: str | None = None
    llm_risk_auth_password: str | None = None
    llm_risk_strategy_profile: str | None = None
    llm_risk_request_template: str | None = None
    llm_risk_response_field: str | None = None
    # EASM scan level: 'full' (P01-P22) or 'asm' (passive recon only P01-P08+P18+P21-P22)
    scan_level: str = "full"
    # Target authentication for scanner (propagated to ffuf/curl/sqlmap)
    auth_config: dict[str, Any] | None = None
    # Optional source/repository input for SAST and secret scanners.
    source_config: dict[str, Any] | None = None
    api_scan_config: dict[str, Any] | None = None


class ScanResponse(BaseModel):
    id: int
    target_query: str
    mode: str
    access_group_id: int | None = None
    status: str
    compliance_status: str
    current_step: str
    mission_progress: int
    retry_attempt: int = 0
    retry_max: int = 0
    next_retry_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    # Derived timestamps (scan_jobs não tem colunas próprias): started=created,
    # finished=updated quando o status é terminal.
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # Contagem de achados ABERTOS (is_false_positive=false) por severidade —
    # o card/Centro Operacional leem estes campos; sem eles, mostravam 0.
    open_critical: int = 0
    open_high: int = 0
    open_medium: int = 0
    open_low: int = 0
    open_info: int = 0
    state_data: dict[str, Any] = {}

    @field_validator("state_data")
    @classmethod
    def _redact_credentials(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _redact_state_data(value)


class LogResponse(BaseModel):
    id: int
    source: str
    level: str
    message: str
    created_at: datetime


class AuditLogEntry(BaseModel):
    id: int
    iteration: int
    node_name: str
    entry_type: str  # note, todo, action, observation, error
    content: str
    created_at: datetime


class AutonomyResponse(BaseModel):
    scan_id: int
    autonomy_notes: list[str]
    autonomy_todos: list[str]
    autonomy_actions: list[str]
    autonomy_observations: list[str]
    autonomy_errors: list[str]
    delegated_tasks: list[dict[str, Any]]
    active_skills: list[dict[str, Any]]
    execution_control: dict[str, Any]
    audit_trail: list[AuditLogEntry]


class ReportResponse(BaseModel):
    scan_id: int
    status: str
    findings: list[dict[str, Any]]
    state_data: dict[str, Any]

    @field_validator("state_data")
    @classmethod
    def _redact_credentials(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _redact_state_data(value)


class ScanStatusResponse(BaseModel):
    id: int
    status: str
    compliance_status: str
    current_step: str
    mission_progress: int
    mission_index: int = 0
    mission_items: list[str] = []
    node_history: list[str] = []
    discovered_ports: list[int]
    pending_port_tests: list[int]
    retry_attempt: int = 0
    retry_max: int = 0
    next_retry_at: datetime | None = None
    last_error: str | None = None
