"""Pydantic schemas for audit log operations."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..models.audit_log import AuditAction, AuditResult


class AuditLogResponse(BaseModel):
    """Schema for audit log response data."""

    id: int
    action: AuditAction
    result: AuditResult
    resource_type: str
    resource_id: Optional[int]
    resource_name: Optional[str]
    user_id: Optional[int]
    username: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    request_method: Optional[str]
    request_path: Optional[str]
    request_params: Optional[Dict[str, Any]]
    response_code: Optional[int]
    error_message: Optional[str]
    details: Optional[Dict[str, Any]]
    environment_name: Optional[str]
    secret_id: Optional[int]
    secret_version: Optional[int]
    created_at: datetime

    class Config:
        orm_mode = True
        use_enum_values = True


class AuditLogListResponse(BaseModel):
    """Schema for paginated audit log list responses."""

    logs: List[AuditLogResponse]
    total: int
    page: int
    per_page: int
    pages: int
    has_prev: bool
    has_next: bool
    prev_page: Optional[int]
    next_page: Optional[int]


class AuditLogFilterRequest(BaseModel):
    """Schema for audit log filtering requests."""

    action: Optional[AuditAction] = None
    result: Optional[AuditResult] = None
    resource_type: Optional[str] = Field(
        None, description="Resource type (secret, user, environment)"
    )
    user_id: Optional[int] = None
    environment_name: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ip_address: Optional[str] = None
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(50, ge=1, le=100, description="Items per page")

    class Config:
        schema_extra = {
            "example": {
                "action": "create",
                "result": "success",
                "resource_type": "secret",
                "user_id": 1,
                "environment_name": "production",
                "start_date": "2023-01-01T00:00:00",
                "end_date": "2023-12-31T23:59:59",
                "page": 1,
                "per_page": 50,
            }
        }


class AuditSummaryResponse(BaseModel):
    """Schema for audit activity summary."""

    total_actions: int
    successful_actions: int
    failed_actions: int
    unique_users: int
    unique_resources: int
    most_active_user: Optional[str]
    most_accessed_resource: Optional[str]
    actions_by_type: Dict[str, int]
    actions_by_result: Dict[str, int]
    recent_activity: List[AuditLogResponse]

    class Config:
        orm_mode = True


class SecurityEventResponse(BaseModel):
    """Schema for security-related events."""

    event_type: str = Field(..., description="Type of security event")
    severity: str = Field(
        ..., description="Severity level (low, medium, high, critical)"
    )
    description: str = Field(..., description="Event description")
    user_info: Optional[Dict[str, Any]] = None
    resource_info: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    occurred_at: datetime
    resolved: bool = Field(False, description="Whether the event has been resolved")

    class Config:
        schema_extra = {
            "example": {
                "event_type": "failed_login_attempts",
                "severity": "medium",
                "description": "Multiple failed login attempts from IP address",
                "user_info": {"username": "john.doe", "email": "john@company.com"},
                "resource_info": {"ip_address": "192.168.1.100"},
                "metadata": {"attempt_count": 5, "time_window": "5 minutes"},
                "occurred_at": "2023-01-01T12:00:00",
                "resolved": False,
            }
        }
