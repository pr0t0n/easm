from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ScanCreate(BaseModel):
    target_query: str
    mode: str = "single"
    access_group_id: int | None = None
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


class LogResponse(BaseModel):
    id: int
    source: str
    level: str
    message: str
    created_at: datetime


class ReportResponse(BaseModel):
    scan_id: int
    status: str
    findings: list[dict[str, Any]]
    state_data: dict[str, Any]


class ScanStatusResponse(BaseModel):
    id: int
    status: str
    compliance_status: str
    current_step: str
    mission_progress: int
    mission_index: int = 0
    mission_items: list[str] = []
    node_history: list[str] = []
    burp_status: str = "none"
    discovered_ports: list[int]
    pending_port_tests: list[int]
    retry_attempt: int = 0
    retry_max: int = 0
    next_retry_at: datetime | None = None
    last_error: str | None = None
