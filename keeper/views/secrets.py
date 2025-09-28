"""Secrets blueprint for secret management operations."""

import uuid

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
    environment_id = request.args.get("environment")
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
        try:
            # Convert string UUID to UUID object
            env_uuid = uuid.UUID(environment_id)
            query = query.filter_by(environment_id=env_uuid)
        except ValueError:
            # Invalid UUID format, ignore the filter
            pass

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
        environment_id = request.form.get("environment_id")
        service_name = request.form.get("service_name")
        value = request.form.get("value")
        generation_method = request.form.get("generation_method", "manual")

        # RBAC: Check if user can manually enter secrets
        if generation_method == "manual" and not user.can_manually_enter_secrets():
            flash(
                "Only administrators can manually enter secret values. Please use the auto-generate feature.",
                "error",
            )
            return render_template(
                "secrets/create.html",
                environments=Environment.get_active_environments(),
                secret_types=list(SecretType),
                secrecy_levels=list(SecrecyLevel),
                current_user=user,
            )

        # Convert environment_id to UUID if provided
        if environment_id:
            try:
                environment_id = uuid.UUID(environment_id)
            except ValueError:
                flash("Invalid environment ID", "error")
                return render_template(
                    "secrets/create.html",
                    environments=Environment.get_active_environments(),
                    secret_types=list(SecretType),
                    secrecy_levels=list(SecrecyLevel),
                    current_user=user,
                )

        # RBAC: Check if user can create secrets in the selected environment
        if environment_id:
            # Get the environment to check permissions
            environment = Environment.query.get(environment_id)
            if not environment:
                flash("Environment not found", "error")
                return render_template(
                    "secrets/create.html",
                    environments=Environment.get_active_environments(),
                    secret_types=list(SecretType),
                    secrecy_levels=list(SecrecyLevel),
                    current_user=user,
                )

            # Check if user has permission to create secrets in this environment
            if not user.can_create_secret(environment.name):
                flash(
                    f"You do not have permission to create secrets in the {environment.display_name} environment",
                    "error",
                )
                return render_template(
                    "secrets/create.html",
                    environments=Environment.get_active_environments(),
                    secret_types=list(SecretType),
                    secrecy_levels=list(SecrecyLevel),
                    current_user=user,
                )

        # Validate required fields
        if not all([name, display_name, environment_id, value]):
            flash("Name, display name, environment, and value are required", "error")
            return render_template(
                "secrets/create.html",
                environments=Environment.get_active_environments(),
                secret_types=list(SecretType),
                secrecy_levels=list(SecrecyLevel),
                current_user=user,
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
                current_user=user,
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

            # Create the first version with proper generation method
            SecretVersion.create_version(
                secret_id=secret.id,
                value=value,
                created_by_id=user.id,
                generation_method=generation_method,
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

    # GET request - show create form
    user = get_current_user()
    return render_template(
        "secrets/create.html",
        environments=Environment.get_active_environments(),
        secret_types=list(SecretType),
        secrecy_levels=list(SecrecyLevel),
        current_user=user,
    )


@secrets_bp.route("/<uuid:id>")
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


@secrets_bp.route("/<uuid:id>/edit", methods=["GET", "POST"])
@require_auth
def edit(id):
    """Edit secret metadata."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_edit_secret(secret.environment.name):
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


@secrets_bp.route("/<uuid:id>/rotate", methods=["GET", "POST"])
@require_auth
def rotate(id):
    """Rotate a secret (AB rotation)."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_rotate_secret(secret.environment.name):
        flash(
            "You do not have permission to rotate secrets in this environment", "error"
        )
        return redirect(url_for("secrets.index"))

    # Check if approval is required for this rotation
    if user.requires_approval_for_rotation(secret.environment.name):
        flash(
            "This rotation requires manager approval. Redirecting to approval request.",
            "info",
        )
        return redirect(url_for("approvals.request_rotation", secret_id=secret.id))

    if request.method == "POST":
        generation_method = request.form.get("generation_method", "manual")
        new_value = request.form.get("new_value")
        immediate_activate = "immediate_activate" in request.form
        auto_sync = "auto_sync" in request.form
        schedule_rotation = "schedule_rotation" in request.form

        # RBAC: Check if user can manually enter secrets for rotation
        if (
            generation_method in ["manual", "imported"]
            and not user.can_manually_enter_secrets()
        ):
            flash(
                "Only administrators can manually enter or import secret values. Please use auto-generation.",
                "error",
            )
            return render_template(
                "secrets/rotate.html",
                secret=secret,
                current_version=secret.current_version,
                versions=SecretVersion.get_version_history(secret.id, limit=5),
                current_user=user,
            )

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
                    current_user=user,
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
                    current_user=user,
                )
            # TODO: Implement import functionality
            flash("Import functionality not yet implemented", "warning")
            return render_template(
                "secrets/rotate.html",
                secret=secret,
                current_version=secret.current_version,
                versions=SecretVersion.get_version_history(secret.id, limit=5),
                current_user=user,
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
        current_user=user,
    )


@secrets_bp.route("/<uuid:id>/delete", methods=["POST"])
@require_auth
def delete(id):
    """Delete a secret completely from all storage locations."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_edit_secret(secret.environment.name):
        flash(
            "You do not have permission to delete secrets in this environment", "error"
        )
        return redirect(url_for("secrets.index"))

    secret_name = secret.display_name
    deletion_results = {"local": False, "aws": False, "vault": False, "errors": []}

    try:
        from ..services.aws_secrets import AWSSecretsManager, AWSSecretsManagerError
        from ..services.vault_client import VaultClient, VaultClientError

        current_app.logger.info(
            f"Starting complete deletion of secret {id} from all backends"
        )

        # Delete from AWS Secrets Manager if synced
        if secret.aws_sync_status == SyncStatus.SYNCED and secret.aws_secret_arn:
            try:
                aws_client = AWSSecretsManager()
                aws_result = aws_client.delete_secret(
                    secret, user.id, force_delete=True
                )
                deletion_results["aws"] = True
                current_app.logger.info(
                    f"Successfully deleted secret from AWS: {aws_result}"
                )
            except AWSSecretsManagerError as e:
                deletion_results["errors"].append(f"AWS deletion failed: {str(e)}")
                current_app.logger.error(f"Failed to delete secret from AWS: {e}")
            except Exception as e:
                deletion_results["errors"].append(f"AWS deletion error: {str(e)}")
                current_app.logger.error(f"Unexpected error deleting from AWS: {e}")

        # Delete from HashiCorp Vault if synced
        if secret.vault_sync_status == SyncStatus.SYNCED and secret.vault_path:
            try:
                vault_client = VaultClient()
                vault_result = vault_client.delete_secret(secret, user.id)
                deletion_results["vault"] = True
                current_app.logger.info(
                    f"Successfully deleted secret from Vault: {vault_result}"
                )
            except VaultClientError as e:
                deletion_results["errors"].append(f"Vault deletion failed: {str(e)}")
                current_app.logger.error(f"Failed to delete secret from Vault: {e}")
            except Exception as e:
                deletion_results["errors"].append(f"Vault deletion error: {str(e)}")
                current_app.logger.error(f"Unexpected error deleting from Vault: {e}")

        # Delete from local database (hard delete all versions)
        try:
            # Delete all secret versions first
            SecretVersion.query.filter_by(secret_id=secret.id).delete()

            # Delete the secret itself
            secret.delete()
            deletion_results["local"] = True
            current_app.logger.info(f"Successfully deleted secret from local database")
        except Exception as e:
            deletion_results["errors"].append(f"Database deletion failed: {str(e)}")
            current_app.logger.error(f"Failed to delete secret from database: {e}")

        # Log the complete deletion action if local deletion succeeded
        if deletion_results["local"]:
            AuditLog.log_action(
                action=AuditAction.DELETE,
                result=AuditResult.SUCCESS,
                resource_type="secret",
                resource_id=str(secret.id),
                resource_name=secret.name,
                user_id=user.id,
                username=user.username,
                ip_address=request.remote_addr,
                details={
                    "action": "complete_deletion",
                    "aws_deleted": deletion_results["aws"],
                    "vault_deleted": deletion_results["vault"],
                    "local_deleted": deletion_results["local"],
                    "errors": deletion_results["errors"],
                },
            )

        # Provide feedback based on results
        if deletion_results["local"] and not deletion_results["errors"]:
            flash(
                f'Secret "{secret_name}" completely deleted from all storage locations',
                "success",
            )
        elif deletion_results["local"] and deletion_results["errors"]:
            error_summary = "; ".join(deletion_results["errors"])
            flash(
                f'Secret "{secret_name}" deleted from database, but some backend deletions failed: {error_summary}',
                "warning",
            )
        else:
            error_summary = "; ".join(deletion_results["errors"])
            flash(f'Failed to delete secret "{secret_name}": {error_summary}', "error")

    except Exception as e:
        current_app.logger.error(f"Critical error during secret deletion {id}: {e}")
        flash("A critical error occurred while deleting the secret", "error")

    return redirect(url_for("secrets.index"))


@secrets_bp.route("/<uuid:id>/remove-aws", methods=["POST"])
@require_auth
def remove_aws_immediate(id):
    """Remove a secret from AWS Secrets Manager only."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash(
            "You do not have permission to modify secrets in this environment", "error"
        )
        return redirect(url_for("secrets.detail", id=id))

    # Check if secret is actually synced to AWS
    if secret.aws_sync_status != SyncStatus.SYNCED or not secret.aws_secret_arn:
        flash("Secret is not synced to AWS Secrets Manager", "warning")
        return redirect(url_for("secrets.detail", id=id))

    try:
        from ..services.aws_secrets import AWSSecretsManager, AWSSecretsManagerError

        current_app.logger.info(f"Removing secret {id} from AWS Secrets Manager")

        # Remove from AWS
        aws_client = AWSSecretsManager()
        result = aws_client.delete_secret(secret, user.id, force_delete=True)

        if result.get("status") == "success":
            # Update local status to reflect removal
            secret.aws_sync_status = SyncStatus.NOT_SYNCED
            secret.aws_secret_arn = None
            secret.aws_version_id = None
            secret.aws_last_sync = None
            secret.save()

            flash("Successfully removed from AWS Secrets Manager", "success")
            current_app.logger.info(f"Successfully removed secret {id} from AWS")
        else:
            error_msg = result.get("message", "Unknown error")
            flash(f"Failed to remove from AWS: {error_msg}", "error")

    except AWSSecretsManagerError as e:
        current_app.logger.error(f"AWS error removing secret {id}: {e}")
        flash(f"AWS removal failed: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(f"Unexpected error removing secret {id} from AWS: {e}")
        flash("An unexpected error occurred while removing from AWS", "error")

    return redirect(url_for("secrets.detail", id=id))


@secrets_bp.route("/<uuid:id>/remove-vault", methods=["POST"])
@require_auth
def remove_vault_immediate(id):
    """Remove a secret from HashiCorp Vault only."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash(
            "You do not have permission to modify secrets in this environment", "error"
        )
        return redirect(url_for("secrets.detail", id=id))

    # Check if secret is actually synced to Vault
    if secret.vault_sync_status != SyncStatus.SYNCED or not secret.vault_path:
        flash("Secret is not synced to HashiCorp Vault", "warning")
        return redirect(url_for("secrets.detail", id=id))

    try:
        from ..services.vault_client import VaultClient, VaultClientError

        current_app.logger.info(f"Removing secret {id} from HashiCorp Vault")

        # Remove from Vault
        vault_client = VaultClient()
        result = vault_client.delete_secret(secret, user.id)

        if result.get("status") == "success":
            # Update local status to reflect removal
            secret.vault_sync_status = SyncStatus.NOT_SYNCED
            secret.vault_path = None
            secret.vault_version = None
            secret.vault_last_sync = None
            secret.save()

            flash("Successfully removed from HashiCorp Vault", "success")
            current_app.logger.info(f"Successfully removed secret {id} from Vault")
        else:
            error_msg = result.get("message", "Unknown error")
            flash(f"Failed to remove from Vault: {error_msg}", "error")

    except VaultClientError as e:
        current_app.logger.error(f"Vault error removing secret {id}: {e}")
        flash(f"Vault removal failed: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(
            f"Unexpected error removing secret {id} from Vault: {e}"
        )
        flash("An unexpected error occurred while removing from Vault", "error")

    return redirect(url_for("secrets.detail", id=id))


@secrets_bp.route("/<uuid:id>/versions/<uuid:version_id>/activate", methods=["POST"])
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


@secrets_bp.route("/<uuid:id>/sync", methods=["POST"])
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


@secrets_bp.route("/<uuid:id>/sync-status")
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


@secrets_bp.route("/<uuid:id>/sync-aws", methods=["POST"])
@require_auth
def sync_aws_immediate(id):
    """Immediately sync a secret to AWS Secrets Manager."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash("You do not have permission to sync secrets in this environment", "error")
        return redirect(url_for("secrets.detail", id=id))

    try:
        from ..services.sync_service import SyncError, SyncService

        current_app.logger.info(f"Starting immediate AWS sync for secret {id}")

        # Perform immediate sync to AWS only
        sync_service = SyncService()
        result = sync_service.sync_secret_to_backends(secret, user.id, backends=["aws"])

        if result["overall_success"]:
            flash("Successfully synced to AWS Secrets Manager", "success")
            current_app.logger.info(f"AWS sync successful for secret {id}")
        else:
            error_msg = result.get("aws", {}).get("message", "Unknown error")
            flash(f"AWS sync failed: {error_msg}", "error")
            current_app.logger.error(f"AWS sync failed for secret {id}: {error_msg}")

    except SyncError as e:
        current_app.logger.error(f"Sync error for secret {id}: {e}")
        flash(f"Sync failed: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(f"Unexpected error syncing secret {id}: {e}")
        flash("An unexpected error occurred during sync", "error")

    return redirect(url_for("secrets.detail", id=id))


@secrets_bp.route("/<uuid:id>/sync-vault", methods=["POST"])
@require_auth
def sync_vault_immediate(id):
    """Immediately sync a secret to HashiCorp Vault."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        flash("You do not have permission to sync secrets in this environment", "error")
        return redirect(url_for("secrets.detail", id=id))

    try:
        from ..services.sync_service import SyncError, SyncService

        current_app.logger.info(f"Starting immediate Vault sync for secret {id}")

        # Perform immediate sync to Vault only
        sync_service = SyncService()
        result = sync_service.sync_secret_to_backends(
            secret, user.id, backends=["vault"]
        )

        if result["overall_success"]:
            flash("Successfully synced to HashiCorp Vault", "success")
            current_app.logger.info(f"Vault sync successful for secret {id}")
        else:
            error_msg = result.get("vault", {}).get("message", "Unknown error")
            flash(f"Vault sync failed: {error_msg}", "error")
            current_app.logger.error(f"Vault sync failed for secret {id}: {error_msg}")

    except SyncError as e:
        current_app.logger.error(f"Sync error for secret {id}: {e}")
        flash(f"Sync failed: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(f"Unexpected error syncing secret {id}: {e}")
        flash("An unexpected error occurred during sync", "error")

    return redirect(url_for("secrets.detail", id=id))
