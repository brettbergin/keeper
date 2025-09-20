"""Structured audit logging service for security and compliance."""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from flask import current_app, g, request

from ..models.audit_log import AuditAction, AuditLog, AuditResult


class StructuredAuditLogger:
    """Enhanced audit logger that writes to both database and log files."""

    def __init__(self):
        self.logger = logging.getLogger("keeper.audit")

    def log_security_event(
        self,
        action: AuditAction,
        result: AuditResult,
        resource_type: str,
        resource_id: Optional[int] = None,
        resource_name: Optional[str] = None,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        **kwargs,
    ) -> AuditLog:
        """Log a security event to both database and log files."""

        # Gather request context
        ip_address = None
        user_agent = None
        request_method = None
        request_path = None
        request_id = None

        if request:
            ip_address = request.remote_addr
            user_agent = request.headers.get("User-Agent", "")
            request_method = request.method
            request_path = request.path

        if hasattr(g, "request_id"):
            request_id = g.request_id

        # Create database audit log entry
        audit_log = AuditLog(
            action=action,
            result=result,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path,
            error_message=error_message,
        )

        if details:
            audit_log.set_details_dict(details)

        # Save to database
        try:
            audit_log.save()
        except Exception as e:
            current_app.logger.error(f"Failed to save audit log to database: {str(e)}")

        # Create structured log entry for file logging
        log_entry = {
            "event_type": "security_audit",
            "timestamp": datetime.utcnow().isoformat(),
            "action": action.value,
            "result": result.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_method": request_method,
            "request_path": request_path,
            "request_id": request_id,
            "details": details or {},
            "error_message": error_message,
        }

        # Add any additional kwargs
        log_entry.update(kwargs)

        # Log to file
        if result in [AuditResult.FAILURE, AuditResult.ERROR]:
            self.logger.error(
                f"SECURITY EVENT: {action.value} {resource_type}", extra=log_entry
            )
        elif result == AuditResult.PARTIAL:
            self.logger.warning(
                f"SECURITY EVENT: {action.value} {resource_type}", extra=log_entry
            )
        else:
            self.logger.info(
                f"SECURITY EVENT: {action.value} {resource_type}", extra=log_entry
            )

        return audit_log

    def log_secret_access(
        self,
        action: AuditAction,
        secret_id: int,
        secret_name: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        result: AuditResult = AuditResult.SUCCESS,
        secret_version: Optional[int] = None,
        **kwargs,
    ) -> AuditLog:
        """Log secret access events with additional secret-specific details."""

        details = {"secret_version": secret_version, **kwargs}

        return self.log_security_event(
            action=action,
            result=result,
            resource_type="secret",
            resource_id=secret_id,
            resource_name=secret_name,
            user_id=user_id,
            username=username,
            details=details,
        )

    def log_authentication_event(
        self,
        action: AuditAction,
        username: str,
        result: AuditResult,
        error_message: Optional[str] = None,
        **kwargs,
    ) -> AuditLog:
        """Log authentication events."""

        return self.log_security_event(
            action=action,
            result=result,
            resource_type="user",
            resource_name=username,
            username=username,
            error_message=error_message,
            **kwargs,
        )

    def log_sync_event(
        self,
        action: AuditAction,
        secret_id: int,
        secret_name: str,
        backend: str,
        result: AuditResult,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        sync_details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> AuditLog:
        """Log synchronization events."""

        details = {"backend": backend, "sync_details": sync_details or {}}

        return self.log_security_event(
            action=action,
            result=result,
            resource_type="secret",
            resource_id=secret_id,
            resource_name=secret_name,
            user_id=user_id,
            username=username,
            details=details,
            error_message=error_message,
        )

    def log_kms_event(
        self,
        action: str,
        result: AuditResult,
        key_id: Optional[str] = None,
        operation_details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Log KMS operations to audit trail."""

        log_entry = {
            "event_type": "kms_operation",
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "result": result.value,
            "key_id": key_id,
            "details": operation_details or {},
            "error_message": error_message,
        }

        if hasattr(g, "request_id"):
            log_entry["request_id"] = g.request_id

        if result in [AuditResult.FAILURE, AuditResult.ERROR]:
            self.logger.error(f"KMS OPERATION: {action}", extra=log_entry)
        else:
            self.logger.info(f"KMS OPERATION: {action}", extra=log_entry)


# Global audit logger instance
audit_logger = StructuredAuditLogger()


def get_audit_logger() -> StructuredAuditLogger:
    """Get the global audit logger instance."""
    return audit_logger
