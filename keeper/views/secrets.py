"""Secrets blueprint for secret management operations."""

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ..auth.session import get_current_user, require_auth
from ..models import (
    AuditAction,
    AuditLog,
    AuditResult,
    Environment,
    SecrecyLevel,
    Secret,
    SecretType,
    SecretVersion,
    SyncStatus,
)

secrets_bp = Blueprint("secrets", __name__)


def _generate_secret_value(secret_type, length=32, complexity="complex"):
    """Generate a secret value based on type and parameters."""
    from ..utils.crypto import generate_api_key, generate_password, generate_ssh_key

    if secret_type == SecretType.PASSWORD:
        include_symbols = complexity == "complex"
        return generate_password(length, include_symbols=include_symbols)
    elif secret_type == SecretType.API_KEY:
        return generate_api_key(length)
    elif secret_type == SecretType.SSH_KEY:
        return generate_ssh_key()  # SSH keys have fixed format
    elif secret_type == SecretType.RSA_KEY:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return key.private_key_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    else:
        # Default to random string for other types
        import secrets
        import string

        if complexity == "alphanumeric":
            charset = string.ascii_letters + string.digits
        elif complexity == "complex":
            charset = string.ascii_letters + string.digits + "!@#$%^&*"
        else:  # standard
            charset = string.ascii_letters + string.digits

        return "".join(secrets.choice(charset) for _ in range(length))


@secrets_bp.route("/")
@require_auth
def index():
    """List all secrets with advanced filtering, search, and pagination."""
    from datetime import datetime

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get(
        "per_page", current_app.config.get("SECRETS_PER_PAGE", 20), type=int
    )

    # Limit per_page to reasonable bounds
    per_page = max(5, min(per_page, 100))

    # Filtering parameters
    environment_id = request.args.get("environment", type=int)
    secret_type = request.args.get("type")
    service = request.args.get("service")
    search = request.args.get("search")
    secrecy_level = request.args.get("secrecy_level")
    sync_status = request.args.get("sync_status")

    # Date filtering
    created_after = request.args.get("created_after")
    created_before = request.args.get("created_before")
    updated_after = request.args.get("updated_after")
    updated_before = request.args.get("updated_before")

    # Sorting
    sort_by = request.args.get("sort_by", "name")
    sort_order = request.args.get("sort_order", "asc")

    # Special filters
    show_expired = request.args.get("show_expired", type=bool)
    needs_rotation = request.args.get("needs_rotation", type=bool)

    # Build query
    query = Secret.query.filter_by(is_active=True)

    # Apply filters
    if environment_id:
        query = query.filter_by(environment_id=environment_id)

    if secret_type:
        try:
            query = query.filter_by(secret_type=SecretType(secret_type.upper()))
        except ValueError:
            pass  # Invalid secret type, ignore

    if service:
        query = query.filter_by(service_name=service)

    if secrecy_level:
        try:
            query = query.filter_by(secrecy_level=SecrecyLevel(secrecy_level.upper()))
        except ValueError:
            pass

    if sync_status:
        if sync_status == "synced":
            query = query.filter(
                (Secret.aws_sync_status == SyncStatus.SYNCED)
                | (Secret.vault_sync_status == SyncStatus.SYNCED)
            )
        elif sync_status == "out_of_sync":
            query = query.filter(
                (
                    Secret.aws_sync_status.in_(
                        [SyncStatus.SYNC_PENDING, SyncStatus.SYNC_FAILED]
                    )
                )
                | (
                    Secret.vault_sync_status.in_(
                        [SyncStatus.SYNC_PENDING, SyncStatus.SYNC_FAILED]
                    )
                )
            )
        elif sync_status == "error":
            query = query.filter(
                (Secret.aws_sync_status == SyncStatus.SYNC_FAILED)
                | (Secret.vault_sync_status == SyncStatus.SYNC_FAILED)
            )

    if search:
        search_filter = (
            Secret.name.contains(search)
            | Secret.display_name.contains(search)
            | Secret.description.contains(search)
            | Secret.service_name.contains(search)
            | Secret.tags.contains(search)
        )
        query = query.filter(search_filter)

    # Date filters
    if created_after:
        try:
            date = datetime.fromisoformat(created_after)
            query = query.filter(Secret.created_at >= date)
        except ValueError:
            pass

    if created_before:
        try:
            date = datetime.fromisoformat(created_before)
            query = query.filter(Secret.created_at <= date)
        except ValueError:
            pass

    if updated_after:
        try:
            date = datetime.fromisoformat(updated_after)
            query = query.filter(Secret.updated_at >= date)
        except ValueError:
            pass

    if updated_before:
        try:
            date = datetime.fromisoformat(updated_before)
            query = query.filter(Secret.updated_at <= date)
        except ValueError:
            pass

    # Special filters
    if show_expired and hasattr(Secret, "expires_at"):
        try:
            query = query.filter(Secret.expires_at <= datetime.utcnow())
        except Exception:
            pass

    if (
        needs_rotation
        and hasattr(Secret, "auto_rotate")
        and hasattr(Secret, "next_rotation_at")
    ):
        try:
            query = query.filter(
                (Secret.auto_rotate == True)
                & (Secret.next_rotation_at <= datetime.utcnow())
            )
        except Exception:
            pass

    # Apply sorting
    sort_column = getattr(Secret, sort_by, Secret.name)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Paginate with current filters
    secrets = query.paginate(page=page, per_page=per_page, error_out=False)

    # Get filter options
    environments = Environment.get_active_environments()
    secret_types = list(SecretType)
    secrecy_levels = list(SecrecyLevel)
    services = [
        row[0]
        for row in Secret.query.with_entities(Secret.service_name).distinct().all()
        if row[0]
    ]

    # Get statistics
    total_secrets = Secret.query.filter_by(is_active=True).count()

    # Check if Secret model has expires_at column
    expired_count = 0
    if hasattr(Secret, "expires_at"):
        try:
            expired_count = (
                Secret.query.filter_by(is_active=True)
                .filter(Secret.expires_at <= datetime.utcnow())
                .count()
            )
        except Exception:
            expired_count = 0

    # Check if Secret model has rotation columns
    rotation_due_count = 0
    if hasattr(Secret, "auto_rotate") and hasattr(Secret, "next_rotation_at"):
        try:
            rotation_due_count = (
                Secret.query.filter_by(is_active=True)
                .filter(
                    (Secret.auto_rotate == True)
                    & (Secret.next_rotation_at <= datetime.utcnow())
                )
                .count()
            )
        except Exception:
            rotation_due_count = 0

    return render_template(
        "secrets/index.html",
        secrets=secrets,
        environments=environments,
        secret_types=secret_types,
        secrecy_levels=secrecy_levels,
        services=services,
        current_environment=environment_id,
        current_type=secret_type,
        current_service=service,
        current_search=search,
        current_secrecy_level=secrecy_level,
        current_sync_status=sync_status,
        created_after=created_after,
        created_before=created_before,
        updated_after=updated_after,
        updated_before=updated_before,
        sort_by=sort_by,
        sort_order=sort_order,
        per_page=per_page,
        show_expired=show_expired,
        needs_rotation=needs_rotation,
        total_secrets=total_secrets,
        expired_count=expired_count,
        rotation_due_count=rotation_due_count,
    )


@secrets_bp.route("/create", methods=["GET", "POST"])
@require_auth
def create():
    """Create a new secret."""
    if request.method == "POST":
        user = get_current_user()

        # Get form data
        name = request.form.get("name")
        display_name = request.form.get("display_name")
        description = request.form.get("description")
        secret_type = request.form.get("secret_type")
        secrecy_level = request.form.get("secrecy_level")
        environment_id = request.form.get("environment_id", type=int)
        service_name = request.form.get("service_name")
        value = request.form.get("value")

        # Validate required fields
        if not all([name, display_name, environment_id, value]):
            flash("Name, display name, environment, and value are required", "error")
            return render_template(
                "secrets/create.html",
                environments=Environment.get_active_environments(),
                secret_types=list(SecretType),
                secrecy_levels=list(SecrecyLevel),
            )

        # Check if secret already exists
        existing = Secret.find_by_name_and_environment(name, environment_id)
        if existing:
            flash(
                "A secret with this name already exists in the selected environment",
                "error",
            )
            return render_template(
                "secrets/create.html",
                environments=Environment.get_active_environments(),
                secret_types=list(SecretType),
                secrecy_levels=list(SecrecyLevel),
            )

        try:
            # Convert form values to proper enum values
            secret_type_enum = SecretType.STRING
            if secret_type:
                try:
                    secret_type_enum = SecretType(secret_type.upper())
                except ValueError:
                    secret_type_enum = SecretType.STRING

            secrecy_level_enum = SecrecyLevel.MEDIUM
            if secrecy_level:
                try:
                    secrecy_level_enum = SecrecyLevel(secrecy_level.upper())
                except ValueError:
                    secrecy_level_enum = SecrecyLevel.MEDIUM

            # Create the secret
            secret = Secret.create(
                name=name,
                display_name=display_name,
                description=description,
                secret_type=secret_type_enum,
                secrecy_level=secrecy_level_enum,
                environment_id=environment_id,
                service_name=service_name,
                creator_id=user.id,
            )

            # Create the first version
            SecretVersion.create_version(
                secret_id=secret.id,
                value=value,
                created_by_id=user.id,
                generation_method="manual",
            )

            # Log the action
            AuditLog.log_secret_action(
                action=AuditAction.CREATE,
                result=AuditResult.SUCCESS,
                secret=secret,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
            )

            flash(f'Secret "{display_name}" created successfully', "success")
            return redirect(url_for("secrets.detail", id=secret.id))

        except Exception as e:
            current_app.logger.error(f"Error creating secret: {e}")
            flash("An error occurred while creating the secret", "error")

    return render_template(
        "secrets/create.html",
        environments=Environment.get_active_environments(),
        secret_types=list(SecretType),
        secrecy_levels=list(SecrecyLevel),
    )


@secrets_bp.route("/<int:id>")
@require_auth
def detail(id):
    """Show secret details."""
    secret = Secret.query.get_or_404(id)

    # Check if user can access this environment
    user = get_current_user()
    if not user.can_access_environment(secret.environment.name):
        flash(
            "You do not have permission to access secrets in this environment", "error"
        )
        return redirect(url_for("secrets.index"))

    # Get current version
    current_version = secret.current_version

    # Decrypt current value if available
    current_value = None
    if current_version:
        try:
            current_value = current_version.decrypt_value()
        except Exception as e:
            current_app.logger.error(f"Error decrypting secret value: {e}")
            current_value = "[Decryption Error]"

    # Get version history
    version_history = SecretVersion.get_version_history(secret.id, limit=10)

    # Get audit history
    audit_history = AuditLog.get_secret_history(secret.id, limit=20)

    # Log the read access
    AuditLog.log_secret_action(
        action=AuditAction.READ,
        result=AuditResult.SUCCESS,
        secret=secret,
        user_id=user.id,
        username=user.username,
        ip_address=request.remote_addr,
        secret_version=current_version.version_number if current_version else None,
    )

    return render_template(
        "secrets/detail.html",
        secret=secret,
        current_version=current_version,
        current_value=current_value,
        versions=version_history,
        audit_history=audit_history,
    )


@secrets_bp.route("/<int:id>/edit", methods=["GET", "POST"])
@require_auth
def edit(id):
    """Edit secret metadata."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash("You do not have permission to edit secrets in this environment", "error")
        return redirect(url_for("secrets.index"))

    if request.method == "POST":
        try:
            # Check if user wants to update the secret value
            update_value = "update_value" in request.form
            new_value = request.form.get("value", "").strip()

            if update_value and new_value:
                # Validate that the user provided a value
                if not new_value:
                    flash("New value is required when updating secret value", "error")
                    return render_template(
                        "secrets/edit.html",
                        secret=secret,
                        environments=Environment.get_active_environments(),
                        current_version=secret.current_version,
                        versions=SecretVersion.get_version_history(secret.id, limit=5),
                        secrecy_levels=list(SecrecyLevel),
                    )

                # Create new version with the updated value
                generation_method = request.form.get("generation_method", "manual")
                new_version = SecretVersion.create_version(
                    secret_id=secret.id,
                    value=new_value,
                    created_by_id=user.id,
                    generation_method=generation_method,
                    make_current=True,  # Make the new version current
                )

                # Mark sync statuses as pending since value changed
                secret.aws_sync_status = SyncStatus.SYNC_PENDING
                secret.vault_sync_status = SyncStatus.SYNC_PENDING

            # Update secret metadata
            secret.display_name = request.form.get("display_name", secret.display_name)
            secret.description = request.form.get("description", secret.description)
            secret.service_name = request.form.get("service_name", secret.service_name)

            # Handle secrecy level
            secrecy_level = request.form.get("secrecy_level")
            if secrecy_level:
                try:
                    secret.secrecy_level = SecrecyLevel(secrecy_level.upper())
                except ValueError:
                    pass  # Keep existing value if invalid

            # Handle expiration
            expires_at = request.form.get("expires_at")
            if expires_at:
                from datetime import datetime

                secret.expires_at = datetime.fromisoformat(expires_at)

            # Handle rotation settings
            secret.auto_rotate = "auto_rotate" in request.form
            rotation_interval = request.form.get("rotation_interval_days", type=int)
            if rotation_interval:
                secret.rotation_interval_days = rotation_interval

            secret.save()

            # Log the action
            action_details = {"action": "metadata_update"}
            if update_value and new_value:
                action_details.update(
                    {
                        "action": "value_and_metadata_update",
                        "new_version": (
                            new_version.version_number
                            if "new_version" in locals()
                            else None
                        ),
                        "generation_method": (
                            generation_method
                            if "generation_method" in locals()
                            else None
                        ),
                    }
                )

            AuditLog.log_secret_action(
                action=AuditAction.UPDATE,
                result=AuditResult.SUCCESS,
                secret=secret,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
                secret_version=(
                    new_version.version_number if "new_version" in locals() else None
                ),
                details=action_details,
            )

            success_message = "Secret updated successfully"
            if update_value and new_value:
                success_message = f"Secret updated successfully (new version {new_version.version_number} created)"

            flash(success_message, "success")
            return redirect(url_for("secrets.detail", id=secret.id))

        except Exception as e:
            current_app.logger.error(f"Error updating secret {id}: {e}")
            flash("An error occurred while updating the secret", "error")

    # Get required data for the template
    environments = Environment.get_active_environments()
    current_version = secret.current_version
    versions = SecretVersion.get_version_history(secret.id, limit=5)

    return render_template(
        "secrets/edit.html",
        secret=secret,
        environments=environments,
        current_version=current_version,
        versions=versions,
        secrecy_levels=list(SecrecyLevel),
    )


@secrets_bp.route("/<int:id>/rotate", methods=["GET", "POST"])
@require_auth
def rotate(id):
    """Rotate a secret (AB rotation)."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash(
            "You do not have permission to rotate secrets in this environment", "error"
        )
        return redirect(url_for("secrets.index"))

    if request.method == "POST":
        generation_method = request.form.get("generation_method", "manual")
        new_value = request.form.get("new_value")
        immediate_activate = "immediate_activate" in request.form
        auto_sync = "auto_sync" in request.form
        schedule_rotation = "schedule_rotation" in request.form

        # Handle different generation methods
        if generation_method == "auto":
            # Auto-generate based on secret type and parameters
            length = int(request.form.get("length", 32))
            complexity = request.form.get("complexity", "complex")
            new_value = _generate_secret_value(secret.secret_type, length, complexity)

        elif generation_method == "manual":
            if not new_value:
                flash("New value is required for manual rotation", "error")
                return render_template(
                    "secrets/rotate.html",
                    secret=secret,
                    current_version=secret.current_version,
                    versions=SecretVersion.get_version_history(secret.id, limit=5),
                )

        elif generation_method == "imported":
            import_source = request.form.get("import_source")
            import_path = request.form.get("import_path")
            if not import_source or not import_path:
                flash(
                    "Import source and path are required for imported rotation", "error"
                )
                return render_template(
                    "secrets/rotate.html",
                    secret=secret,
                    current_version=secret.current_version,
                    versions=SecretVersion.get_version_history(secret.id, limit=5),
                )
            # TODO: Implement import functionality
            flash("Import functionality not yet implemented", "warning")
            return render_template(
                "secrets/rotate.html",
                secret=secret,
                current_version=secret.current_version,
                versions=SecretVersion.get_version_history(secret.id, limit=5),
            )

        try:
            # Create new version
            new_version = SecretVersion.create_version(
                secret_id=secret.id,
                value=new_value,
                created_by_id=user.id,
                generation_method=generation_method,
                make_current=immediate_activate,
            )

            # Update secret rotation timestamp
            secret.mark_rotated()

            # Handle scheduled rotation
            if schedule_rotation:
                rotation_interval = int(request.form.get("rotation_interval", 90))
                next_rotation = request.form.get("next_rotation")
                secret.auto_rotate = True
                secret.rotation_interval_days = rotation_interval
                if next_rotation:
                    from datetime import datetime

                    secret.next_rotation_at = datetime.fromisoformat(next_rotation)

            # Mark sync statuses as pending if auto_sync is enabled
            if auto_sync:
                secret.aws_sync_status = SyncStatus.SYNC_PENDING
                secret.vault_sync_status = SyncStatus.SYNC_PENDING

            secret.save()

            # Log the action
            AuditLog.log_secret_action(
                action=AuditAction.ROTATE,
                result=AuditResult.SUCCESS,
                secret=secret,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
                secret_version=new_version.version_number,
                details={"generation_method": generation_method},
            )

            flash("Secret rotated successfully", "success")
            return redirect(url_for("secrets.detail", id=secret.id))

        except Exception as e:
            current_app.logger.error(f"Error rotating secret {id}: {e}")
            flash("An error occurred while rotating the secret", "error")

    # Get data for GET request
    current_version = secret.current_version
    versions = SecretVersion.get_version_history(secret.id, limit=5)

    return render_template(
        "secrets/rotate.html",
        secret=secret,
        current_version=current_version,
        versions=versions,
    )


@secrets_bp.route("/<int:id>/delete", methods=["POST"])
@require_auth
def delete(id):
    """Delete a secret."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash(
            "You do not have permission to delete secrets in this environment", "error"
        )
        return redirect(url_for("secrets.index"))

    try:
        secret_name = secret.display_name

        # Soft delete - mark as inactive
        secret.is_active = False
        secret.save()

        # Log the action
        AuditLog.log_secret_action(
            action=AuditAction.DELETE,
            result=AuditResult.SUCCESS,
            secret=secret,
            user_id=user.id,
            username=user.username,
            ip_address=request.remote_addr,
        )

        flash(f'Secret "{secret_name}" deleted successfully', "success")

    except Exception as e:
        current_app.logger.error(f"Error deleting secret {id}: {e}")
        flash("An error occurred while deleting the secret", "error")

    return redirect(url_for("secrets.index"))


@secrets_bp.route("/<int:id>/versions/<int:version_id>/activate", methods=["POST"])
@require_auth
def activate_version(id, version_id):
    """Activate a specific version of a secret (AB rotation)."""
    secret = Secret.query.get_or_404(id)
    version = SecretVersion.query.get_or_404(version_id)
    user = get_current_user()

    # Check permissions and version belongs to secret
    if (
        not user.can_access_environment(secret.environment.name)
        or version.secret_id != secret.id
    ):
        flash("You do not have permission to activate this version", "error")
        return redirect(url_for("secrets.detail", id=id))

    try:
        # Activate the version (deactivates others)
        version.activate()

        # Mark sync as pending since active version changed
        secret.aws_sync_status = SyncStatus.SYNC_PENDING
        secret.vault_sync_status = SyncStatus.SYNC_PENDING
        secret.save()

        # Log the action
        AuditLog.log_secret_action(
            action=AuditAction.UPDATE,
            result=AuditResult.SUCCESS,
            secret=secret,
            user_id=user.id,
            username=user.username,
            ip_address=request.remote_addr,
            secret_version=version.version_number,
            details={"action": "version_activation"},
        )

        flash(f"Version {version.version_number} activated successfully", "success")

    except Exception as e:
        current_app.logger.error(f"Error activating version {version_id}: {e}")
        flash("An error occurred while activating the version", "error")

    return redirect(url_for("secrets.detail", id=id))


@secrets_bp.route("/<int:id>/sync", methods=["POST"])
@require_auth
def sync(id):
    """Manually sync a secret to external backends."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash("You do not have permission to sync secrets in this environment", "error")
        return redirect(url_for("secrets.detail", id=id))

    try:
        # Mark as pending sync
        secret.aws_sync_status = SyncStatus.SYNC_PENDING
        secret.vault_sync_status = SyncStatus.SYNC_PENDING
        secret.save()

        # Log the sync request
        AuditLog.log_secret_action(
            action=AuditAction.UPDATE,
            result=AuditResult.SUCCESS,
            secret=secret,
            user_id=user.id,
            username=user.username,
            ip_address=request.remote_addr,
            details={"action": "sync_requested"},
        )

        flash(
            "Sync requested successfully. Synchronization will occur in the background.",
            "success",
        )

    except Exception as e:
        current_app.logger.error(f"Error requesting sync for secret {id}: {e}")
        flash("An error occurred while requesting sync", "error")

    return redirect(url_for("secrets.detail", id=id))


@secrets_bp.route("/<int:id>/sync-status")
@require_auth
def sync_status(id):
    """Get sync status for a secret."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        return jsonify({"error": "Permission denied"}), 403

    return jsonify(
        {
            "aws_sync_status": secret.aws_sync_status.value,
            "vault_sync_status": secret.vault_sync_status.value,
            "aws_last_sync": (
                secret.aws_last_sync.isoformat() if secret.aws_last_sync else None
            ),
            "vault_last_sync": (
                secret.vault_last_sync.isoformat() if secret.vault_last_sync else None
            ),
            "overall_status": secret.sync_status,
        }
    )
