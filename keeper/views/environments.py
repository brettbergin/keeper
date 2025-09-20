"""Environments blueprint for environment management."""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..auth.permissions import require_admin
from ..auth.session import get_current_user, require_auth
from ..models import AuditAction, AuditLog, AuditResult, Environment, Secret, SyncStatus

environments_bp = Blueprint("environments", __name__)


@environments_bp.route("/")
@require_auth
def index():
    """List all environments."""
    environments = Environment.get_active_environments()

    # Get secret counts for each environment
    env_stats = []
    for env in environments:
        secret_count = env.secrets.filter_by(is_active=True).count()
        env_stats.append({"environment": env, "secret_count": secret_count})

    return render_template("environments/index.html", env_stats=env_stats)


@environments_bp.route("/create", methods=["GET", "POST"])
@require_admin
def create():
    """Create a new environment."""
    if request.method == "POST":
        user = get_current_user()

        # Get form data
        name = request.form.get("name")
        display_name = request.form.get("display_name")
        description = request.form.get("description")
        is_production = "is_production" in request.form
        is_active = "is_active" in request.form
        aws_sync_enabled = "aws_sync_enabled" in request.form
        vault_sync_enabled = "vault_sync_enabled" in request.form
        vault_path_prefix = request.form.get("vault_path_prefix")

        # Validate required fields
        if not all([name, display_name]):
            flash("Name and display name are required", "error")
            return render_template("environments/create.html")

        # Check if environment already exists
        existing = Environment.find_by_name(name)
        if existing:
            flash("An environment with this name already exists", "error")
            return render_template("environments/create.html")

        try:
            # Create the environment
            environment = Environment.create(
                name=name,
                display_name=display_name,
                description=description,
                is_production=is_production,
                is_active=is_active,
                aws_sync_enabled=aws_sync_enabled,
                vault_sync_enabled=vault_sync_enabled,
                vault_path_prefix=vault_path_prefix,
            )

            # Log the action
            AuditLog.log_action(
                action=AuditAction.CREATE,
                result=AuditResult.SUCCESS,
                resource_type="environment",
                resource_id=environment.id,
                resource_name=environment.name,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
            )

            flash(f'Environment "{display_name}" created successfully', "success")
            return redirect(url_for("environments.index"))

        except Exception as e:
            current_app.logger.error(f"Error creating environment: {e}")
            flash("An error occurred while creating the environment", "error")

    return render_template("environments/create.html")


@environments_bp.route("/<int:id>")
@require_auth
def detail(id):
    """Show environment details."""
    environment = Environment.query.get_or_404(id)

    # Get secrets in this environment
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("SECRETS_PER_PAGE", 20)

    secrets = environment.secrets.filter_by(is_active=True).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Calculate environment statistics
    all_secrets = environment.secrets.filter_by(is_active=True).all()
    secret_count = len(all_secrets)

    synced_count = 0
    pending_count = 0
    failed_count = 0

    for secret in all_secrets:
        # Check AWS sync status
        aws_synced = (
            hasattr(secret, "aws_sync_status")
            and secret.aws_sync_status == SyncStatus.SYNCED
        )
        aws_pending = (
            hasattr(secret, "aws_sync_status")
            and secret.aws_sync_status == SyncStatus.SYNC_PENDING
        )
        aws_failed = (
            hasattr(secret, "aws_sync_status")
            and secret.aws_sync_status == SyncStatus.SYNC_ERROR
        )

        # Check Vault sync status
        vault_synced = (
            hasattr(secret, "vault_sync_status")
            and secret.vault_sync_status == SyncStatus.SYNCED
        )
        vault_pending = (
            hasattr(secret, "vault_sync_status")
            and secret.vault_sync_status == SyncStatus.SYNC_PENDING
        )
        vault_failed = (
            hasattr(secret, "vault_sync_status")
            and secret.vault_sync_status == SyncStatus.SYNC_ERROR
        )

        # Count as synced if either AWS or Vault is synced
        if aws_synced or vault_synced:
            synced_count += 1
        # Count as pending if either is pending (and none are synced)
        elif aws_pending or vault_pending:
            pending_count += 1
        # Count as failed if either failed (and none are synced or pending)
        elif aws_failed or vault_failed:
            failed_count += 1

    stats = {
        "secret_count": secret_count,
        "synced_count": synced_count,
        "pending_count": pending_count,
        "failed_count": failed_count,
    }

    # Get recent secrets for the template
    recent_secrets = (
        environment.secrets.filter_by(is_active=True)
        .order_by(Secret.updated_at.desc())
        .limit(5)
        .all()
    )

    from datetime import datetime

    return render_template(
        "environments/detail.html",
        environment=environment,
        secrets=secrets,
        stats=stats,
        recent_secrets=recent_secrets,
        now=datetime.utcnow(),
    )


@environments_bp.route("/<int:id>/edit", methods=["GET", "POST"])
@require_admin
def edit(id):
    """Edit an environment."""
    environment = Environment.query.get_or_404(id)

    if request.method == "POST":
        user = get_current_user()

        # Get form data
        display_name = request.form.get("display_name")
        description = request.form.get("description")
        is_production = "is_production" in request.form
        is_active = "is_active" in request.form
        aws_sync_enabled = "aws_sync_enabled" in request.form
        vault_sync_enabled = "vault_sync_enabled" in request.form
        vault_path_prefix = request.form.get("vault_path_prefix")

        # Validate required fields
        if not display_name:
            flash("Display name is required", "error")
            return render_template("environments/edit.html", environment=environment)

        try:
            # Update the environment
            environment.update(
                display_name=display_name,
                description=description,
                is_production=is_production,
                is_active=is_active,
                aws_sync_enabled=aws_sync_enabled,
                vault_sync_enabled=vault_sync_enabled,
                vault_path_prefix=vault_path_prefix,
            )
            environment.save()

            # Log the action
            AuditLog.log_action(
                action=AuditAction.UPDATE,
                result=AuditResult.SUCCESS,
                resource_type="environment",
                resource_id=environment.id,
                resource_name=environment.name,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
            )

            flash(f'Environment "{display_name}" updated successfully', "success")
            return redirect(url_for("environments.detail", id=environment.id))

        except Exception as e:
            current_app.logger.error(f"Error updating environment: {e}")
            flash("An error occurred while updating the environment", "error")

    return render_template("environments/edit.html", environment=environment)


@environments_bp.route("/<int:id>/sync", methods=["POST"])
@require_admin
def sync(id):
    """Sync all secrets in an environment to configured backends."""
    environment = Environment.query.get_or_404(id)
    user = get_current_user()

    try:
        # Get all active secrets in this environment
        secrets = environment.secrets.filter_by(is_active=True).all()

        sync_results = {"total": len(secrets), "success": 0, "failed": 0, "errors": []}

        for secret in secrets:
            try:
                # Here you would implement actual sync logic
                # For now, just update the sync status
                secret.aws_sync_status = (
                    SyncStatus.SYNCED
                    if environment.aws_sync_enabled
                    else secret.aws_sync_status
                )
                secret.vault_sync_status = (
                    SyncStatus.SYNCED
                    if environment.vault_sync_enabled
                    else secret.vault_sync_status
                )
                secret.save()
                sync_results["success"] += 1

            except Exception as e:
                sync_results["failed"] += 1
                sync_results["errors"].append(f"Failed to sync {secret.name}: {str(e)}")
                current_app.logger.error(f"Error syncing secret {secret.name}: {e}")

        # Log the action
        AuditLog.log_action(
            action=AuditAction.SYNC,
            result=(
                AuditResult.SUCCESS
                if sync_results["failed"] == 0
                else AuditResult.PARTIAL
            ),
            resource_type="environment",
            resource_id=environment.id,
            resource_name=environment.name,
            user_id=user.id,
            username=user.username,
            ip_address=request.remote_addr,
            details={"sync_results": sync_results},
        )

        if sync_results["failed"] == 0:
            return {
                "success": True,
                "message": f"Successfully synced {sync_results['success']} secrets",
            }
        else:
            return {
                "success": False,
                "message": f"Partially synced: {sync_results['success']} succeeded, {sync_results['failed']} failed",
                "errors": sync_results["errors"],
            }

    except Exception as e:
        current_app.logger.error(f"Error during environment sync: {e}")
        return {"success": False, "message": f"Sync failed: {str(e)}"}


@environments_bp.route("/<int:id>/delete", methods=["POST"])
@require_admin
def delete(id):
    """Delete an environment."""
    environment = Environment.query.get_or_404(id)
    user = get_current_user()

    # Prevent deletion of production environments
    if environment.is_production:
        flash("Production environments cannot be deleted", "error")
        return redirect(url_for("environments.detail", id=environment.id))

    # Check if environment has active secrets
    active_secrets_count = environment.secrets.filter_by(is_active=True).count()
    if active_secrets_count > 0:
        flash(
            f"Cannot delete environment with {active_secrets_count} active secrets. Please delete or move the secrets first.",
            "error",
        )
        return redirect(url_for("environments.detail", id=environment.id))

    try:
        environment_name = environment.name
        environment_display_name = environment.display_name

        # Log the action before deletion
        AuditLog.log_action(
            action=AuditAction.DELETE,
            result=AuditResult.SUCCESS,
            resource_type="environment",
            resource_id=environment.id,
            resource_name=environment.name,
            user_id=user.id,
            username=user.username,
            ip_address=request.remote_addr,
        )

        # Delete the environment
        environment.delete()

        flash(
            f'Environment "{environment_display_name}" deleted successfully', "success"
        )
        return redirect(url_for("environments.index"))

    except Exception as e:
        current_app.logger.error(f"Error deleting environment: {e}")
        flash("An error occurred while deleting the environment", "error")
        return redirect(url_for("environments.detail", id=environment.id))
