"""Role-based access control decorators and permission functions."""

from functools import wraps
from typing import Callable, List

from flask import abort, current_app, flash, redirect, request, url_for

from ..auth.session import get_current_user
from ..models.user import User, UserRole


class PermissionDenied(Exception):
    """Exception raised when a user lacks required permissions."""

    pass


def require_role(required_roles: List[UserRole]):
    """Decorator to require specific user roles."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()

            if not user:
                flash("Authentication required", "error")
                return redirect(url_for("auth.login"))

            if user.role not in required_roles:
                current_app.logger.warning(
                    f"Access denied: user {user.username} (role: {user.role.value}) "
                    f"attempted to access {request.endpoint} requiring roles: {[r.value for r in required_roles]}"
                )
                flash("Insufficient privileges", "error")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_admin(f: Callable) -> Callable:
    """Decorator to require admin role."""
    return require_role([UserRole.ADMIN])(f)


def require_manager_or_admin(f: Callable) -> Callable:
    """Decorator to require manager or admin role."""
    return require_role([UserRole.MANAGER, UserRole.ADMIN])(f)


def require_environment_access(environment_param: str = "environment"):
    """Decorator to require access to a specific environment."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()

            if not user:
                flash("Authentication required", "error")
                return redirect(url_for("auth.login"))

            # Get environment from URL parameters or kwargs
            environment = kwargs.get(environment_param) or request.view_args.get(
                environment_param
            )

            if not environment:
                current_app.logger.error(
                    f"Environment parameter '{environment_param}' not found in request"
                )
                abort(400)

            if not user.can_access_environment(environment):
                current_app.logger.warning(
                    f"Environment access denied: user {user.username} attempted to access {environment}"
                )
                flash(f"Access denied to environment: {environment}", "error")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_environment_management(environment_param: str = "environment"):
    """Decorator to require management access to a specific environment."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()

            if not user:
                flash("Authentication required", "error")
                return redirect(url_for("auth.login"))

            # Get environment from URL parameters or kwargs
            environment = kwargs.get(environment_param) or request.view_args.get(
                environment_param
            )

            if not environment:
                current_app.logger.error(
                    f"Environment parameter '{environment_param}' not found in request"
                )
                abort(400)

            if not user.can_manage_environment(environment):
                current_app.logger.warning(
                    f"Environment management access denied: user {user.username} attempted to manage {environment}"
                )
                flash(
                    f"Management access denied to environment: {environment}", "error"
                )
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_secret_access(secret_param: str = "secret_id"):
    """Decorator to require access to a specific secret based on its environment."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from ..models.secret import Secret

            user = get_current_user()

            if not user:
                flash("Authentication required", "error")
                return redirect(url_for("auth.login"))

            # Get secret ID from URL parameters or kwargs
            secret_id = kwargs.get(secret_param) or request.view_args.get(secret_param)

            if not secret_id:
                current_app.logger.error(
                    f"Secret parameter '{secret_param}' not found in request"
                )
                abort(400)

            secret = Secret.query.get(secret_id)
            if not secret:
                abort(404)

            environment = secret.environment.name

            if not user.can_access_environment(environment):
                current_app.logger.warning(
                    f"Secret access denied: user {user.username} attempted to access secret {secret_id} in {environment}"
                )
                flash(f"Access denied to secret in environment: {environment}", "error")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


class PermissionChecker:
    """Helper class for checking permissions programmatically."""

    @staticmethod
    def can_user_perform_action(user: User, action: str, environment: str) -> bool:
        """Check if user can perform a specific action in an environment."""
        if not user or not user.is_active:
            return False

        action_permissions = {
            "view_secrets": user.can_access_environment,
            "create_secret": user.can_create_secret,
            "edit_secret": user.can_edit_secret,
            "rotate_secret": user.can_rotate_secret,
            "manage_environment": user.can_manage_environment,
            "approve_requests": user.can_manage_environment,
        }

        permission_func = action_permissions.get(action)
        if not permission_func:
            return False

        return permission_func(environment)

    @staticmethod
    def get_accessible_environments(user: User) -> List[str]:
        """Get list of environments the user can access."""
        if not user or not user.is_active:
            return []

        from ..models.environment import Environment

        all_environments = Environment.query.filter_by(is_active=True).all()
        accessible = []

        for env in all_environments:
            if user.can_access_environment(env.name):
                accessible.append(env.name)

        return accessible

    @staticmethod
    def get_manageable_environments(user: User) -> List[str]:
        """Get list of environments the user can manage."""
        if not user or not user.is_active:
            return []

        from ..models.environment import Environment

        all_environments = Environment.query.filter_by(is_active=True).all()
        manageable = []

        for env in all_environments:
            if user.can_manage_environment(env.name):
                manageable.append(env.name)

        return manageable

    @staticmethod
    def requires_approval(user: User, action: str, environment: str) -> bool:
        """Check if an action requires approval."""
        if not user or not user.is_active:
            return True

        if action == "rotate_secret":
            return user.requires_approval_for_rotation(environment)

        # Other actions that might require approval
        if action in ["create_secret_in_prod", "delete_secret"]:
            return user.role == UserRole.USER and environment == "production"

        return False
