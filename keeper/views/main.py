"""Main blueprint for home page and basic routes."""

from flask import Blueprint, current_app, render_template

from ..models import AuditLog, Environment, Secret, User

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Home page with dashboard overview."""
    # Get summary statistics
    total_secrets = Secret.query.filter_by(is_active=True).count()
    total_environments = Environment.query.filter_by(is_active=True).count()
    total_users = User.query.filter_by(is_active=True).count()

    # Get secrets by environment
    environments = Environment.get_active_environments()
    env_stats = []
    for env in environments:
        secret_count = env.secrets.filter_by(is_active=True).count()
        env_stats.append({"environment": env, "secret_count": secret_count})

    # Get recent activity
    recent_activity = AuditLog.get_recent_activity(limit=10)

    # Get secrets needing attention
    expiring_secrets = Secret.get_expiring_secrets(days=30)
    rotation_needed = Secret.get_secrets_needing_rotation()
    out_of_sync = Secret.get_out_of_sync_secrets()

    return render_template(
        "main/index.html",
        total_secrets=total_secrets,
        total_environments=total_environments,
        total_users=total_users,
        env_stats=env_stats,
        recent_activity=recent_activity,
        expiring_secrets=expiring_secrets[:5],
        rotation_needed=rotation_needed[:5],
        out_of_sync=out_of_sync[:5],
    )


@main_bp.route("/dashboard")
def dashboard():
    """Detailed dashboard page."""
    return render_template("main/dashboard.html")


@main_bp.route("/health")
def health():
    """Health check endpoint."""
    try:
        # Check database connectivity
        db_status = "ok"
        Secret.query.first()  # Simple query to test DB
    except Exception as e:
        current_app.logger.error(f"Database health check failed: {e}")
        db_status = "error"

    return {
        "status": "ok" if db_status == "ok" else "error",
        "database": db_status,
        "version": current_app.config.get("VERSION", "0.1.0"),
    }


@main_bp.route("/about")
def about():
    """About page."""
    return render_template("main/about.html")


@main_bp.route("/help")
def help():
    """Help page."""
    return render_template("main/help.html")
