"""Session management for authentication."""

import secrets
import string
from datetime import datetime, timedelta
from typing import Optional

from flask import current_app, session

from ..models import AuditAction, AuditLog, AuditResult, User


def generate_session_token() -> str:
    """Generate a secure session token."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def is_authenticated() -> bool:
    """Check if the current user is authenticated."""
    if "user_id" not in session or "session_token" not in session:
        return False

    user_id = session["user_id"]
    session_token = session["session_token"]

    user = User.query.get(user_id)
    if not user:
        return False

    if user.session_token != session_token:
        return False

    return user.is_authenticated()


def get_current_user() -> Optional[User]:
    """Get the current authenticated user."""
    if not is_authenticated():
        return None

    user_id = session["user_id"]
    return User.query.get(user_id)


def create_session(user: User, ip_address: Optional[str] = None) -> str:
    """Create a new session for the user."""
    session_token = generate_session_token()
    expires_at = datetime.utcnow() + timedelta(hours=8)

    # Set user session
    user.set_session(session_token, expires_at)
    user.update_last_login(ip_address)

    # Set Flask session
    session["user_id"] = user.id
    session["username"] = user.username
    session["user_role"] = user.role.value
    session["is_admin"] = user.role.value == "admin"
    session["session_token"] = session_token

    current_app.logger.info(
        f"Session created for user {user.username} (role: {user.role.value})"
    )

    return session_token


def destroy_session(user: Optional[User] = None, log_logout: bool = True) -> None:
    """Destroy the current session."""
    if not user:
        user = get_current_user()

    session_token = session.get("session_token")

    if user and log_logout:
        user.clear_session()

        # Log the logout
        AuditLog.log_user_action(
            action=AuditAction.LOGOUT,
            result=AuditResult.SUCCESS,
            user=user,
            session_id=session_token,
        )

    session.clear()
    current_app.logger.info(
        f"Session destroyed for user {user.username if user else 'unknown'}"
    )


def extend_session() -> None:
    """Extend the current session expiration."""
    user = get_current_user()
    if user:
        expires_at = datetime.utcnow() + timedelta(hours=8)
        user.session_expires_at = expires_at
        user.save()


def require_auth(f):
    """Decorator to require authentication for routes."""
    from functools import wraps

    from flask import flash, redirect, url_for

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            flash("Please log in to access this page", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function
