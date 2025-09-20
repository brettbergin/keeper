"""Admin blueprint for administrative functions."""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..auth import require_admin
from ..auth.session import get_current_user
from ..models import (
    Approval,
    AuditAction,
    AuditLog,
    AuditResult,
    AuthMethod,
    Environment,
    Secret,
    User,
    UserRole,
)

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/")
@require_admin
def index():
    """Admin dashboard."""
    # System statistics
    total_users = User.query.filter_by(is_active=True).count()
    total_secrets = Secret.query.filter_by(is_active=True).count()
    total_environments = Environment.query.filter_by(is_active=True).count()

    # User role statistics
    admin_count = User.query.filter_by(role=UserRole.ADMIN, is_active=True).count()
    manager_count = User.query.filter_by(role=UserRole.MANAGER, is_active=True).count()
    user_count = User.query.filter_by(role=UserRole.USER, is_active=True).count()

    # Pending approvals
    pending_approvals = Approval.query.filter_by(status="pending").count()

    # Recent activity
    recent_activity = AuditLog.get_recent_activity(limit=20)

    # Failed actions in the last 24 hours
    failed_actions = AuditLog.get_failed_actions(hours=24)

    # Secrets needing attention
    expiring_secrets = Secret.get_expiring_secrets(days=30)
    rotation_needed = Secret.get_secrets_needing_rotation()
    out_of_sync = Secret.get_out_of_sync_secrets()

    from datetime import datetime

    # Create system_stats object that the template expects
    system_stats = {
        "total_users": total_users,
        "total_secrets": total_secrets,
        "total_environments": total_environments,
        "admin_users": admin_count,
        "synced_secrets": total_secrets,  # Placeholder - could calculate actual synced count
        "active_environments": total_environments,  # Placeholder - could calculate actual active count
        "audit_logs_today": AuditLog.query.filter(
            AuditLog.created_at
            >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count(),
    }

    return render_template(
        "admin/index.html",
        total_users=total_users,
        total_secrets=total_secrets,
        total_environments=total_environments,
        admin_count=admin_count,
        manager_count=manager_count,
        user_count=user_count,
        pending_approvals=pending_approvals,
        recent_activity=recent_activity,
        recent_admin_activity=recent_activity,  # Add this for the template
        failed_actions=failed_actions,
        expiring_secrets=expiring_secrets,
        rotation_needed=rotation_needed,
        out_of_sync=out_of_sync,
        system_stats=system_stats,  # Add the system_stats object
        now=datetime.utcnow(),
    )


@admin_bp.route("/users")
@require_admin
def users():
    """Manage users."""
    page = request.args.get("page", 1, type=int)
    per_page = 20

    # Add filtering options
    role_filter = request.args.get("role")
    auth_method_filter = request.args.get("auth_method")
    active_filter = request.args.get("active")

    users_query = User.query

    if role_filter:
        try:
            role = UserRole(role_filter)
            users_query = users_query.filter_by(role=role)
        except ValueError:
            pass

    if auth_method_filter:
        try:
            auth_method = AuthMethod(auth_method_filter)
            users_query = users_query.filter_by(auth_method=auth_method)
        except ValueError:
            pass

    if active_filter == "true":
        users_query = users_query.filter_by(is_active=True)
    elif active_filter == "false":
        users_query = users_query.filter_by(is_active=False)

    users_query = users_query.order_by(User.username)
    users = users_query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "admin/users.html",
        users=users,
        user_roles=UserRole,
        auth_methods=AuthMethod,
        role_filter=role_filter,
        auth_method_filter=auth_method_filter,
        active_filter=active_filter,
    )


@admin_bp.route("/users/create", methods=["GET", "POST"])
@require_admin
def create_user():
    """Create a new user."""
    current_user = get_current_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        role_value = request.form.get("role")
        auth_method_value = request.form.get("auth_method")
        password = request.form.get("password", "").strip()

        # Validation
        if not username or not email or not full_name:
            flash("Username, email, and full name are required", "error")
            return render_template(
                "admin/create_user.html",
                user_roles=UserRole,
                auth_methods=AuthMethod,
                environments=Environment.query.filter_by(is_active=True).all(),
            )

        # Check if user already exists
        if User.find_by_username(username):
            flash("Username already exists", "error")
            return render_template(
                "admin/create_user.html",
                user_roles=UserRole,
                auth_methods=AuthMethod,
                environments=Environment.query.filter_by(is_active=True).all(),
            )

        if User.find_by_email(email):
            flash("Email already exists", "error")
            return render_template(
                "admin/create_user.html",
                user_roles=UserRole,
                auth_methods=AuthMethod,
                environments=Environment.query.filter_by(is_active=True).all(),
            )

        try:
            role = UserRole(role_value)
            auth_method = AuthMethod(auth_method_value)
        except ValueError:
            flash("Invalid role or authentication method", "error")
            return render_template(
                "admin/create_user.html",
                user_roles=UserRole,
                auth_methods=AuthMethod,
                environments=Environment.query.filter_by(is_active=True).all(),
            )

        # For database auth, password is required
        if auth_method == AuthMethod.DATABASE and not password:
            flash("Password is required for database authentication", "error")
            return render_template(
                "admin/create_user.html",
                user_roles=UserRole,
                auth_methods=AuthMethod,
                environments=Environment.query.filter_by(is_active=True).all(),
            )

        # Create user
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            auth_method=auth_method,
            is_active=True,
            email_verified=True if auth_method != AuthMethod.DATABASE else False,
        )

        if auth_method == AuthMethod.DATABASE and password:
            user.set_password(password)

        # Handle managed environments for managers
        if role == UserRole.MANAGER:
            managed_envs = request.form.getlist("managed_environments")
            user.set_managed_environments(managed_envs)

        user.save()

        # Log the action
        AuditLog.log_action(
            action=AuditAction.CREATE,
            result=AuditResult.SUCCESS,
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            user_id=current_user.id,
            username=current_user.username,
            ip_address=request.remote_addr,
            details={
                "action": "user_created",
                "role": role.value,
                "auth_method": auth_method.value,
                "managed_environments": user.get_managed_environments(),
            },
        )

        flash(f"User {username} created successfully", "success")
        return redirect(url_for("admin.user_detail", id=user.id))

    # GET request - show create form
    environments = Environment.query.filter_by(is_active=True).all()

    return render_template(
        "admin/create_user.html",
        user_roles=UserRole,
        auth_methods=AuthMethod,
        environments=environments,
    )


@admin_bp.route("/users/<int:id>")
@require_admin
def user_detail(id):
    """Show user details."""
    user = User.query.get_or_404(id)

    # Get user's activity
    activity = AuditLog.get_user_activity(user.id, limit=50)

    # Get user's secrets
    user_secrets = user.secrets.filter_by(is_active=True).all()

    # Get user's approval requests and approvals given
    approval_requests = (
        Approval.query.filter_by(requester_id=user.id)
        .order_by(Approval.created_at.desc())
        .limit(20)
        .all()
    )
    approvals_given = (
        Approval.query.filter_by(approver_id=user.id)
        .order_by(Approval.approved_at.desc())
        .limit(20)
        .all()
    )

    # Get environments user can access
    from ..auth.permissions import PermissionChecker

    accessible_envs = PermissionChecker.get_accessible_environments(user)
    manageable_envs = PermissionChecker.get_manageable_environments(user)

    return render_template(
        "admin/user_detail.html",
        user=user,
        activity=activity,
        user_secrets=user_secrets,
        approval_requests=approval_requests,
        approvals_given=approvals_given,
        accessible_envs=accessible_envs,
        manageable_envs=manageable_envs,
    )


@admin_bp.route("/users/<int:id>/edit-role", methods=["GET", "POST"])
@require_admin
def edit_user_role(id):
    """Edit user role and permissions."""
    user = User.query.get_or_404(id)
    current_user = get_current_user()

    if request.method == "POST":
        # Prevent users from modifying their own role
        if user.id == current_user.id:
            flash("You cannot modify your own role", "error")
            return redirect(url_for("admin.user_detail", id=id))

        old_role = user.role
        new_role_value = request.form.get("role")

        try:
            new_role = UserRole(new_role_value)
        except ValueError:
            flash("Invalid role selected", "error")
            return redirect(url_for("admin.edit_user_role", id=id))

        user.role = new_role

        # Handle managed environments for managers
        if new_role == UserRole.MANAGER:
            managed_envs = request.form.getlist("managed_environments")
            user.set_managed_environments(managed_envs)
        else:
            user.set_managed_environments([])

        user.save()

        flash(
            f"Role updated from {old_role.value} to {new_role.value} for {user.username}",
            "success",
        )

        # Log the action
        AuditLog.log_action(
            action=AuditAction.UPDATE,
            result=AuditResult.SUCCESS,
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            user_id=current_user.id,
            username=current_user.username,
            ip_address=request.remote_addr,
            details={
                "action": "role_change",
                "old_role": old_role.value,
                "new_role": new_role.value,
                "managed_environments": user.get_managed_environments(),
            },
        )

        return redirect(url_for("admin.user_detail", id=id))

    # GET request - show role edit form
    environments = Environment.query.filter_by(is_active=True).all()

    return render_template(
        "admin/edit_user_role.html",
        user=user,
        environments=environments,
        user_roles=UserRole,
        current_user=current_user,
    )


@admin_bp.route("/users/<int:id>/toggle-active", methods=["POST"])
@require_admin
def toggle_user_active(id):
    """Toggle user active status."""
    user = User.query.get_or_404(id)
    current_user = get_current_user()

    # Prevent users from deactivating themselves
    if user.id == current_user.id:
        flash("You cannot deactivate your own account", "error")
        return redirect(url_for("admin.user_detail", id=id))

    user.is_active = not user.is_active
    user.save()

    status = "activated" if user.is_active else "deactivated"
    flash(f"User {user.username} {status}", "success")

    # Log the action
    AuditLog.log_action(
        action=AuditAction.UPDATE,
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.username,
        user_id=current_user.id,
        username=current_user.username,
        ip_address=request.remote_addr,
        details={"action": "active_toggle", "new_status": user.is_active},
    )

    return redirect(url_for("admin.user_detail", id=id))


@admin_bp.route("/audit")
@require_admin
def audit_logs():
    """View audit logs."""
    page = request.args.get("page", 1, type=int)
    per_page = 50

    # Filtering
    action = request.args.get("action")
    result = request.args.get("result")
    resource_type = request.args.get("resource_type")
    user_id = request.args.get("user_id", type=int)

    query = AuditLog.query

    if action:
        query = query.filter_by(action=AuditAction(action))

    if result:
        query = query.filter_by(result=AuditResult(result))

    if resource_type:
        query = query.filter_by(resource_type=resource_type)

    if user_id:
        query = query.filter_by(user_id=user_id)

    audit_logs = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get filter options
    actions = list(AuditAction)
    results = list(AuditResult)
    resource_types = ["secret", "user", "environment"]
    users = User.get_active_users()

    return render_template(
        "admin/audit_logs.html",
        audit_logs=audit_logs,
        actions=actions,
        results=results,
        resource_types=resource_types,
        users=users,
        current_action=action,
        current_result=result,
        current_resource_type=resource_type,
        current_user_id=user_id,
    )


@admin_bp.route("/system")
@require_admin
def system_info():
    """System information page."""
    import platform
    import sys
    from datetime import datetime

    system_info = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "hostname": platform.node(),
        "current_time": datetime.utcnow().isoformat(),
        "flask_version": current_app.config.get("VERSION", "0.1.0"),
    }

    # Database statistics
    db_stats = {
        "total_users": User.query.count(),
        "active_users": User.query.filter_by(is_active=True).count(),
        "total_secrets": Secret.query.count(),
        "active_secrets": Secret.query.filter_by(is_active=True).count(),
        "total_environments": Environment.query.count(),
        "audit_log_entries": AuditLog.query.count(),
    }

    return render_template(
        "admin/system_info.html", system_info=system_info, db_stats=db_stats
    )
