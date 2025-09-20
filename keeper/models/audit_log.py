"""Audit log model for tracking all secret operations."""

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import (
    Column,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import BaseModel


class AuditAction(Enum):
    """Enumeration of auditable actions."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    ROTATE = "rotate"
    SYNC = "sync"
    SYNC_AWS = "sync_aws"
    SYNC_VAULT = "sync_vault"
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS_DENIED = "access_denied"
    EXPORT = "export"
    IMPORT = "import"


class AuditResult(Enum):
    """Enumeration of audit results."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    ERROR = "error"


class AuditLog(BaseModel):
    """Audit log model for tracking all operations."""

    __tablename__ = "audit_logs"

    # Action information
    action = Column(SQLEnum(AuditAction), nullable=False, index=True)
    result = Column(SQLEnum(AuditResult), nullable=False, index=True)

    # Resource information
    resource_type = Column(
        String(50), nullable=False, index=True
    )  # secret, user, environment
    resource_id = Column(Integer, nullable=True, index=True)
    resource_name = Column(String(255), nullable=True, index=True)

    # User and session information
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String(100), nullable=True)  # For cases where user is deleted
    session_id = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)

    # Request information
    request_method = Column(String(10), nullable=True)
    request_path = Column(String(500), nullable=True)
    request_params = Column(Text, nullable=True)  # JSON string

    # Response information
    response_code = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    # Additional context
    details = Column(Text, nullable=True)  # JSON string for additional details
    environment_name = Column(String(100), nullable=True)

    # Secret-specific information (when applicable)
    secret_id = Column(Integer, ForeignKey("secrets.id"), nullable=True, index=True)
    secret_version = Column(Integer, nullable=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    secret = relationship("Secret", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action.value} {self.resource_type} by {self.username}>"

    def get_request_params_dict(self) -> Dict[str, Any]:
        """Get request parameters as a dictionary."""
        if not self.request_params:
            return {}
        try:
            import json

            return json.loads(self.request_params)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_request_params_dict(self, params: Dict[str, Any]) -> None:
        """Set request parameters from a dictionary."""
        import json

        self.request_params = json.dumps(params) if params else None

    def get_details_dict(self) -> Dict[str, Any]:
        """Get details as a dictionary."""
        if not self.details:
            return {}
        try:
            import json

            return json.loads(self.details)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_details_dict(self, details: Dict[str, Any]) -> None:
        """Set details from a dictionary."""
        import json

        self.details = json.dumps(details) if details else None

    @classmethod
    def log_action(
        cls,
        action: AuditAction,
        result: AuditResult,
        resource_type: str,
        resource_id: Optional[int] = None,
        resource_name: Optional[str] = None,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        secret_id: Optional[int] = None,
        secret_version: Optional[int] = None,
        environment_name: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        request_params: Optional[Dict[str, Any]] = None,
        response_code: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> "AuditLog":
        """Create and save an audit log entry."""
        audit_log = cls(
            action=action,
            result=result,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=error_message,
            secret_id=secret_id,
            secret_version=secret_version,
            environment_name=environment_name,
            request_method=request_method,
            request_path=request_path,
            response_code=response_code,
            session_id=session_id,
        )

        if details:
            audit_log.set_details_dict(details)

        if request_params:
            audit_log.set_request_params_dict(request_params)

        audit_log.save()
        return audit_log

    @classmethod
    def log_secret_action(
        cls,
        action: AuditAction,
        result: AuditResult,
        secret,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        secret_version: Optional[int] = None,
    ) -> "AuditLog":
        """Log an action performed on a secret."""
        return cls.log_action(
            action=action,
            result=result,
            resource_type="secret",
            resource_id=secret.id,
            resource_name=secret.name,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            error_message=error_message,
            details=details,
            secret_id=secret.id,
            secret_version=secret_version,
            environment_name=secret.environment.name,
        )

    @classmethod
    def log_user_action(
        cls,
        action: AuditAction,
        result: AuditResult,
        user,
        ip_address: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> "AuditLog":
        """Log an action performed by or on a user."""
        return cls.log_action(
            action=action,
            result=result,
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            error_message=error_message,
            details=details,
            session_id=session_id,
        )

    @classmethod
    def get_secret_history(cls, secret_id: int, limit: int = 50):
        """Get audit history for a specific secret."""
        return (
            cls.query.filter_by(secret_id=secret_id)
            .order_by(cls.created_at.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_user_activity(cls, user_id: int, limit: int = 50):
        """Get activity history for a specific user."""
        return (
            cls.query.filter_by(user_id=user_id)
            .order_by(cls.created_at.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_recent_activity(cls, limit: int = 100):
        """Get recent system activity."""
        return cls.query.order_by(cls.created_at.desc()).limit(limit).all()

    @classmethod
    def get_failed_actions(cls, hours: int = 24):
        """Get failed actions within the specified number of hours."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return (
            cls.query.filter(
                cls.result.in_([AuditResult.FAILURE, AuditResult.ERROR]),
                cls.created_at >= cutoff_time,
            )
            .order_by(cls.created_at.desc())
            .all()
        )

    @classmethod
    def get_environment_activity(cls, environment_name: str, limit: int = 50):
        """Get activity for a specific environment."""
        return (
            cls.query.filter_by(environment_name=environment_name)
            .order_by(cls.created_at.desc())
            .limit(limit)
            .all()
        )
