from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


AlertType = Literal[
    "multi_ip_access",
    "keypair_expiring",
    "keypair_expired",
    "admin_notify",
]


class UserSecurityAlertOut(BaseModel):
    id: str
    alert_type: str
    file_id: str | None = None
    file_name: str | None = None
    title_vi: str
    message_vi: str
    detail_json: dict[str, Any] | None = None
    is_read: bool
    created_at: datetime


class UserSecurityAlertsResponse(BaseModel):
    alerts: list[UserSecurityAlertOut]
    unread_count: int


class MarkAlertReadRequest(BaseModel):
    alert_ids: list[str] = Field(default_factory=list, max_length=50)
