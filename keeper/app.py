"""Flask application factory."""

import json
import logging
import logging.handlers
import os
import time
from pathlib import Path

from flask import Flask, g, request
from flask_wtf.csrf import CSRFProtect

from .config import config
from .models import db


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add request context if available
        if hasattr(g, "request_id"):
            log_entry["request_id"] = g.request_id

        # Add extra fields from the log record
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "getMessage",
                "exc_info",
                "exc_text",
                "stack_info",
                "message",
            ):
                log_entry[key] = value

        return json.dumps(log_entry)


def setup_logging(app):
    """Configure comprehensive logging for the application."""
    log_dir = Path(app.config["LOG_DIR"])
    log_dir.mkdir(exist_ok=True)

    # Clear existing handlers
    app.logger.handlers.clear()

    # Set logging level
    log_level = getattr(logging, app.config["LOG_LEVEL"].upper())
    app.logger.setLevel(log_level)

    # Choose formatter based on configuration
    if app.config.get("ENABLE_JSON_LOGGING", False):
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(app.config["LOG_FORMAT"])

    # Console handler (always enabled in development)
    if app.debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        app.logger.addHandler(console_handler)

    # Main application log file
    app_log_file = log_dir / app.config["LOG_FILE"]
    app_handler = logging.handlers.RotatingFileHandler(
        str(app_log_file),
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    app_handler.setLevel(log_level)
    app_handler.setFormatter(formatter)
    app.logger.addHandler(app_handler)

    # Error log file (for WARNING and above)
    error_log_file = log_dir / app.config["ERROR_LOG_FILE"]
    error_handler = logging.handlers.RotatingFileHandler(
        str(error_log_file),
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    app.logger.addHandler(error_handler)

    # Configure specific loggers for different modules
    setup_module_loggers(app, log_dir, formatter)

    # Configure request logging if enabled
    if app.config.get("ENABLE_REQUEST_LOGGING", False):
        setup_request_logging(app)

    app.logger.info(
        f"Logging configured - Level: {app.config['LOG_LEVEL']}, "
        f"JSON: {app.config.get('ENABLE_JSON_LOGGING', False)}"
    )


def setup_module_loggers(app, log_dir, formatter):
    """Set up specific loggers for different modules."""

    # Audit logger for security events
    audit_logger = logging.getLogger("keeper.audit")
    audit_log_file = log_dir / app.config["AUDIT_LOG_FILE"]
    audit_handler = logging.handlers.RotatingFileHandler(
        str(audit_log_file),
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(formatter)
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False  # Don't send to root logger

    # Sync logger for synchronization operations
    sync_logger = logging.getLogger("keeper.sync")
    sync_log_file = log_dir / app.config["SYNC_LOG_FILE"]
    sync_handler = logging.handlers.RotatingFileHandler(
        str(sync_log_file),
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    sync_handler.setLevel(logging.DEBUG)
    sync_handler.setFormatter(formatter)
    sync_logger.addHandler(sync_handler)
    sync_logger.setLevel(logging.DEBUG)
    sync_logger.propagate = True  # Also send to root logger

    # KMS logger for key management operations
    kms_logger = logging.getLogger("keeper.kms")
    kms_handler = logging.handlers.RotatingFileHandler(
        str(log_dir / "kms.log"),
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    kms_handler.setLevel(logging.DEBUG)
    kms_handler.setFormatter(formatter)
    kms_logger.addHandler(kms_handler)
    kms_logger.setLevel(logging.DEBUG)
    kms_logger.propagate = True


def setup_request_logging(app):
    """Set up request/response logging middleware."""
    import uuid

    @app.before_request
    def before_request():
        g.request_id = str(uuid.uuid4())[:8]
        g.start_time = time.time()

        # Log incoming request
        app.logger.info(
            f"Request started - {request.method} {request.path}",
            extra={
                "request_id": g.request_id,
                "method": request.method,
                "path": request.path,
                "remote_addr": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", ""),
            },
        )

    @app.after_request
    def after_request(response):
        if hasattr(g, "start_time"):
            duration = time.time() - g.start_time

            # Log response
            app.logger.info(
                f"Request completed - {response.status_code} ({duration:.3f}s)",
                extra={
                    "request_id": getattr(g, "request_id", "unknown"),
                    "status_code": response.status_code,
                    "duration": duration,
                    "content_length": response.content_length,
                },
            )

        return response


def create_app(config_name=None):
    """Create and configure Flask application."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Setup logging first, before any other operations
    setup_logging(app)

    # Initialize extensions
    db.init_app(app)
    CSRFProtect(app)

    # Register blueprints
    register_blueprints(app)

    # Initialize database
    with app.app_context():
        db.create_all()

        # Create default environments if they don't exist
        from .models import Environment

        Environment.create_default_environments()

        # Create default admin user if configured
        from .models import User

        User.ensure_default_admin()

    # Register error handlers
    register_error_handlers(app)

    # Register shell context
    register_shell_context(app)

    app.logger.info(f"Keeper application started in {config_name} mode")

    return app


def register_blueprints(app):
    """Register application blueprints."""
    from .views.admin import admin_bp
    from .views.api import api_bp
    from .views.approvals import approvals_bp
    from .views.auth import auth_bp
    from .views.environments import environments_bp
    from .views.main import main_bp
    from .views.secrets import secrets_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(secrets_bp, url_prefix="/secrets")
    app.register_blueprint(environments_bp, url_prefix="/environments")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(approvals_bp, url_prefix="/approvals")


def register_error_handlers(app):
    """Register application error handlers."""

    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template

        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template

        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template

        return render_template("errors/403.html"), 403


def register_shell_context(app):
    """Register shell context for Flask CLI."""

    @app.shell_context_processor
    def make_shell_context():
        from .models import (
            AuditAction,
            AuditLog,
            AuditResult,
            Environment,
            SecrecyLevel,
            Secret,
            SecretType,
            SecretVersion,
            SyncStatus,
            User,
            db,
        )

        return {
            "db": db,
            "User": User,
            "Environment": Environment,
            "Secret": Secret,
            "SecretVersion": SecretVersion,
            "AuditLog": AuditLog,
            "SecretType": SecretType,
            "SecrecyLevel": SecrecyLevel,
            "SyncStatus": SyncStatus,
            "AuditAction": AuditAction,
            "AuditResult": AuditResult,
        }
