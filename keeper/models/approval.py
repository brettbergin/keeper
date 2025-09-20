"""Approval workflow model for managing secret operations that require approval."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from flask import current_app
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
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


class ApprovalStatus(Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalType(Enum):
    """Type of operation requiring approval."""

    SECRET_ROTATION = "secret_rotation"
    SECRET_CREATE = "secret_create"
    SECRET_UPDATE = "secret_update"
    SECRET_DELETE = "secret_delete"
    ENVIRONMENT_ACCESS = "environment_access"


class Approval(BaseModel):
    """Model for tracking approval requests."""

    __tablename__ = "approvals"

    # Request information
    approval_type = Column(SQLEnum(ApprovalType), nullable=False, index=True)
    status = Column(
        SQLEnum(ApprovalStatus),
        default=ApprovalStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Requester information
    requester_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    requester_username = Column(String(100), nullable=False)  # Cached for audit

    # Target resource information
    resource_type = Column(String(50), nullable=False)  # secret, environment, etc.
    resource_id = Column(Integer, nullable=True)
    resource_name = Column(String(255), nullable=False)
    environment_name = Column(String(100), nullable=False)

    # Request details
    request_reason = Column(Text, nullable=True)
    request_details = Column(JSON, nullable=True)  # Additional context

    # Approval information
    approver_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approver_username = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_comment = Column(Text, nullable=True)

    # Auto-expiration
    expires_at = Column(DateTime, nullable=True)

    # Execution tracking
    executed = Column(Boolean, default=False, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    execution_result = Column(Text, nullable=True)

    # Relationships
    requester = relationship(
        "User", foreign_keys=[requester_id], backref="approval_requests"
    )
    approver = relationship(
        "User", foreign_keys=[approver_id], backref="approvals_given"
    )

    def __repr__(self) -> str:
        return f"<Approval {self.approval_type.value} by {self.requester_username} - {self.status.value}>"

    @property
    def is_pending(self) -> bool:
        """Check if approval is still pending."""
        return self.status == ApprovalStatus.PENDING

    @property
    def is_approved(self) -> bool:
        """Check if approval has been approved."""
        return self.status == ApprovalStatus.APPROVED

    @property
    def is_expired(self) -> bool:
        """Check if approval has expired."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        return self.status == ApprovalStatus.EXPIRED

    @property
    def can_be_executed(self) -> bool:
        """Check if this approval can be executed."""
        return self.is_approved and not self.executed and not self.is_expired

    def approve(
        self, approver_id: int, approver_username: str, comment: Optional[str] = None
    ) -> None:
        """Approve this request."""
        if not self.is_pending:
            raise ValueError(f"Cannot approve request with status: {self.status.value}")

        self.status = ApprovalStatus.APPROVED
        self.approver_id = approver_id
        self.approver_username = approver_username
        self.approved_at = datetime.utcnow()
        self.approval_comment = comment

        current_app.logger.info(f"Approval {self.id} approved by {approver_username}")

    def reject(
        self, approver_id: int, approver_username: str, comment: Optional[str] = None
    ) -> None:
        """Reject this request."""
        if not self.is_pending:
            raise ValueError(f"Cannot reject request with status: {self.status.value}")

        self.status = ApprovalStatus.REJECTED
        self.approver_id = approver_id
        self.approver_username = approver_username
        self.approved_at = datetime.utcnow()
        self.approval_comment = comment

        current_app.logger.info(f"Approval {self.id} rejected by {approver_username}")

    def cancel(self) -> None:
        """Cancel this request."""
        if self.status not in [ApprovalStatus.PENDING]:
            raise ValueError(f"Cannot cancel request with status: {self.status.value}")

        self.status = ApprovalStatus.CANCELLED
        current_app.logger.info(f"Approval {self.id} cancelled")

    def mark_executed(self, result: Optional[str] = None) -> None:
        """Mark this approval as executed."""
        if not self.can_be_executed:
            raise ValueError(
                f"Cannot execute approval with status: {self.status.value}"
            )

        self.executed = True
        self.executed_at = datetime.utcnow()
        self.execution_result = result

        current_app.logger.info(f"Approval {self.id} executed successfully")

    def get_request_details(self) -> Dict[str, Any]:
        """Get request details as a dictionary."""
        return self.request_details or {}

    def set_request_details(self, details: Dict[str, Any]) -> None:
        """Set request details from a dictionary."""
        self.request_details = details

    @classmethod
    def create_rotation_approval(
        cls,
        requester_id: int,
        requester_username: str,
        secret_id: int,
        secret_name: str,
        environment_name: str,
        reason: Optional[str] = None,
        rotation_details: Optional[Dict[str, Any]] = None,
        expires_in_hours: int = 72,
    ) -> "Approval":
        """Create a secret rotation approval request."""

        approval = cls(
            approval_type=ApprovalType.SECRET_ROTATION,
            requester_id=requester_id,
            requester_username=requester_username,
            resource_type="secret",
            resource_id=secret_id,
            resource_name=secret_name,
            environment_name=environment_name,
            request_reason=reason,
            expires_at=datetime.utcnow() + datetime.timedelta(hours=expires_in_hours),
        )

        if rotation_details:
            approval.set_request_details(rotation_details)

        approval.save()
        return approval

    @classmethod
    def get_pending_approvals_for_manager(cls, manager_id: int) -> List["Approval"]:
        """Get pending approvals that a manager can approve."""
        from .user import User, UserRole

        manager = User.query.get(manager_id)
        if not manager or manager.role not in [UserRole.MANAGER, UserRole.ADMIN]:
            return []

        query = cls.query.filter_by(status=ApprovalStatus.PENDING)

        if manager.role == UserRole.MANAGER:
            # Managers can only approve for environments they manage
            managed_envs = manager.get_managed_environments()
            query = query.filter(cls.environment_name.in_(managed_envs))

        return query.order_by(cls.created_at.desc()).all()

    @classmethod
    def get_pending_approvals_for_environment(
        cls, environment: str
    ) -> List["Approval"]:
        """Get pending approvals for a specific environment."""
        return (
            cls.query.filter_by(
                status=ApprovalStatus.PENDING, environment_name=environment
            )
            .order_by(cls.created_at.desc())
            .all()
        )

    @classmethod
    def cleanup_expired_approvals(cls) -> int:
        """Mark expired approvals and return count."""
        expired_approvals = cls.query.filter(
            cls.status == ApprovalStatus.PENDING, cls.expires_at < datetime.utcnow()
        ).all()

        count = len(expired_approvals)
        for approval in expired_approvals:
            approval.status = ApprovalStatus.EXPIRED

        if count > 0:
            from .database import db

            db.session.commit()
            current_app.logger.info(f"Marked {count} approvals as expired")

        return count
