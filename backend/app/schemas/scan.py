from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ScanCreate(BaseModel):
    target_query: str
    authorization_code: str | None = None
    mode: str = "single"
    access_group_id: int | None = None
    schedule_at: datetime | None = None


class ScanResponse(BaseModel):
    id: int
    target_query: str
    authorization_code: str | None = None
    mode: str
    access_group_id: int | None = None
    status: str
    compliance_status: str
    current_step: str
    mission_progress: int
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
    discovered_ports: list[int]
    pending_port_tests: list[int]
