"""Service for managing approval workflows."""

from typing import Any, Dict, List, Optional

from flask import current_app

from ..models import Approval, ApprovalStatus, ApprovalType, Secret, User
from ..models.audit_log import AuditAction, AuditResult
from ..services.audit_logger import get_audit_logger


class ApprovalService:
    """Service for managing approval workflows."""

    def __init__(self):
        self.audit_logger = get_audit_logger()

    def request_rotation_approval(
        self,
        secret: Secret,
        requester: User,
        reason: Optional[str] = None,
        rotation_details: Optional[Dict[str, Any]] = None,
    ) -> Approval:
        """Request approval for secret rotation."""

        # Check if approval is actually needed
        if not requester.requires_approval_for_rotation(secret.environment.name):
            raise ValueError("Approval not required for this rotation")

        # Check if there's already a pending approval
        existing = Approval.query.filter_by(
            status=ApprovalStatus.PENDING,
            approval_type=ApprovalType.SECRET_ROTATION,
            resource_id=secret.id,
            requester_id=requester.id,
        ).first()

        if existing:
            raise ValueError(
                f"Pending approval already exists for this secret rotation (ID: {existing.id})"
            )

        # Create approval request
        approval = Approval.create_rotation_approval(
            requester_id=requester.id,
            requester_username=requester.username,
            secret_id=secret.id,
            secret_name=secret.name,
            environment_name=secret.environment.name,
            reason=reason,
            rotation_details=rotation_details,
        )

        # Log the approval request
        self.audit_logger.log_security_event(
            action=AuditAction.CREATE,
            result=AuditResult.SUCCESS,
            resource_type="approval_request",
            resource_id=approval.id,
            resource_name=f"rotation:{secret.name}",
            user_id=requester.id,
            username=requester.username,
            details={
                "approval_type": "secret_rotation",
                "secret_id": secret.id,
                "environment": secret.environment.name,
                "reason": reason,
            },
        )

        current_app.logger.info(
            f"Rotation approval requested by {requester.username} for secret {secret.name} "
            f"in {secret.environment.name} (approval ID: {approval.id})"
        )

        return approval

    def approve_request(
        self, approval_id: int, approver: User, comment: Optional[str] = None
    ) -> Approval:
        """Approve a pending request."""

        approval = Approval.query.get_or_404(approval_id)

        # Check if approver has permission
        if not approver.can_manage_environment(approval.environment_name):
            raise ValueError(
                f"User {approver.username} cannot approve requests for environment {approval.environment_name}"
            )

        # Approve the request
        approval.approve(approver.id, approver.username, comment)
        approval.save()

        # Log the approval
        self.audit_logger.log_security_event(
            action=AuditAction.UPDATE,
            result=AuditResult.SUCCESS,
            resource_type="approval",
            resource_id=approval.id,
            resource_name=f"{approval.approval_type.value}:{approval.resource_name}",
            user_id=approver.id,
            username=approver.username,
            details={
                "action": "approved",
                "original_requester": approval.requester_username,
                "comment": comment,
                "environment": approval.environment_name,
            },
        )

        current_app.logger.info(
            f"Approval {approval.id} approved by {approver.username} "
            f"for {approval.approval_type.value} of {approval.resource_name}"
        )

        return approval

    def reject_request(
        self, approval_id: int, approver: User, comment: Optional[str] = None
    ) -> Approval:
        """Reject a pending request."""

        approval = Approval.query.get_or_404(approval_id)

        # Check if approver has permission
        if not approver.can_manage_environment(approval.environment_name):
            raise ValueError(
                f"User {approver.username} cannot reject requests for environment {approval.environment_name}"
            )

        # Reject the request
        approval.reject(approver.id, approver.username, comment)
        approval.save()

        # Log the rejection
        self.audit_logger.log_security_event(
            action=AuditAction.UPDATE,
            result=AuditResult.FAILURE,
            resource_type="approval",
            resource_id=approval.id,
            resource_name=f"{approval.approval_type.value}:{approval.resource_name}",
            user_id=approver.id,
            username=approver.username,
            details={
                "action": "rejected",
                "original_requester": approval.requester_username,
                "comment": comment,
                "environment": approval.environment_name,
            },
        )

        current_app.logger.info(
            f"Approval {approval.id} rejected by {approver.username} "
            f"for {approval.approval_type.value} of {approval.resource_name}"
        )

        return approval

    def execute_approved_rotation(
        self, approval_id: int, executor: User
    ) -> Dict[str, Any]:
        """Execute an approved rotation request."""

        approval = Approval.query.get_or_404(approval_id)

        if not approval.can_be_executed:
            raise ValueError(
                f"Approval {approval_id} cannot be executed (status: {approval.status.value})"
            )

        try:
            # Get the secret and rotation details
            secret = Secret.query.get(approval.resource_id)
            if not secret:
                raise ValueError(f"Secret {approval.resource_id} not found")

            rotation_details = approval.get_request_details()

            # Execute the rotation based on stored details
            from ..models.secret_version import SecretVersion

            # Create new version with the approved parameters
            new_version = SecretVersion.create_version(
                secret_id=secret.id,
                value=rotation_details.get("new_value"),
                created_by_id=executor.id,
                generation_method=rotation_details.get("generation_method", "manual"),
                generation_params=rotation_details.get("generation_params"),
                make_current=True,
            )

            # Update secret rotation timestamp
            secret.mark_rotated()

            # Mark approval as executed
            approval.mark_executed(
                f"Rotation completed - new version {new_version.version_number}"
            )
            approval.save()

            # Log the execution
            self.audit_logger.log_security_event(
                action=AuditAction.ROTATE,
                result=AuditResult.SUCCESS,
                resource_type="secret",
                resource_id=secret.id,
                resource_name=secret.name,
                user_id=executor.id,
                username=executor.username,
                details={
                    "approval_id": approval.id,
                    "new_version": new_version.version_number,
                    "approved_by": approval.approver_username,
                    "environment": secret.environment.name,
                },
            )

            current_app.logger.info(
                f"Approved rotation executed for secret {secret.name} "
                f"(approval {approval.id}, new version {new_version.version_number})"
            )

            return {
                "success": True,
                "approval_id": approval.id,
                "secret_id": secret.id,
                "new_version": new_version.version_number,
                "message": "Rotation completed successfully",
            }

        except Exception as e:
            current_app.logger.error(
                f"Failed to execute approved rotation {approval_id}: {str(e)}"
            )

            # Log the failure
            self.audit_logger.log_security_event(
                action=AuditAction.ROTATE,
                result=AuditResult.ERROR,
                resource_type="secret",
                resource_id=approval.resource_id,
                resource_name=approval.resource_name,
                user_id=executor.id,
                username=executor.username,
                details={
                    "approval_id": approval.id,
                    "error": str(e),
                    "environment": approval.environment_name,
                },
                error_message=str(e),
            )

            return {"success": False, "approval_id": approval.id, "error": str(e)}

    def get_pending_approvals_for_user(self, user: User) -> List[Approval]:
        """Get pending approvals that a user can approve."""
        return Approval.get_pending_approvals_for_manager(user.id)

    def get_user_requests(self, user: User, limit: int = 50) -> List[Approval]:
        """Get approval requests made by a user."""
        return (
            Approval.query.filter_by(requester_id=user.id)
            .order_by(Approval.created_at.desc())
            .limit(limit)
            .all()
        )

    def cleanup_expired_approvals(self) -> int:
        """Clean up expired approvals."""
        return Approval.cleanup_expired_approvals()


# Global service instance
approval_service = ApprovalService()


def get_approval_service() -> ApprovalService:
    """Get the global approval service instance."""
    return approval_service
