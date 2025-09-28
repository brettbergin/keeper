"""API blueprint for REST endpoints."""

from flask import Blueprint, current_app, jsonify, request

from ..auth.session import get_current_user, require_auth
from ..models import Environment, SecrecyLevel, Secret, SecretType, SecretVersion

api_bp = Blueprint("api", __name__)


@api_bp.route("/health")
def health():
    """API health check."""
    return jsonify({"status": "ok", "version": "1.0.0"})


@api_bp.route("/environments")
@require_auth
def list_environments():
    """List all environments."""
    environments = Environment.get_active_environments()
    return jsonify(
        [
            {
                "id": env.id,
                "name": env.name,
                "display_name": env.display_name,
                "description": env.description,
                "is_production": env.is_production,
            }
            for env in environments
        ]
    )


@api_bp.route("/secrets")
@require_auth
def list_secrets():
    """List secrets with filtering."""
    environment_id = request.args.get("environment")
    service = request.args.get("service")
    secret_type = request.args.get("type")

    query = Secret.query.filter_by(is_active=True)

    if environment_id:
        query = query.filter_by(environment_id=environment_id)

    if service:
        query = query.filter_by(service_name=service)

    if secret_type:
        query = query.filter_by(secret_type=SecretType(secret_type))

    secrets = query.all()

    return jsonify(
        [
            {
                "id": secret.id,
                "name": secret.name,
                "display_name": secret.display_name,
                "environment": secret.environment.name,
                "service_name": secret.service_name,
                "secret_type": secret.secret_type.value,
                "secrecy_level": secret.secrecy_level.value,
                "sync_status": secret.sync_status,
                "created_at": secret.created_at.isoformat(),
                "updated_at": secret.updated_at.isoformat(),
            }
            for secret in secrets
        ]
    )


@api_bp.route("/secrets/<uuid:id>")
@require_auth
def get_secret(id):
    """Get secret details."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        return jsonify({"error": "Permission denied"}), 403

    current_version = secret.current_version

    return jsonify(
        {
            "id": secret.id,
            "name": secret.name,
            "display_name": secret.display_name,
            "description": secret.description,
            "environment": {
                "id": secret.environment.id,
                "name": secret.environment.name,
                "display_name": secret.environment.display_name,
            },
            "service_name": secret.service_name,
            "secret_type": secret.secret_type.value,
            "secrecy_level": secret.secrecy_level.value,
            "aws_sync_status": secret.aws_sync_status.value,
            "vault_sync_status": secret.vault_sync_status.value,
            "sync_status": secret.sync_status,
            "current_version": (
                current_version.version_number if current_version else None
            ),
            "expires_at": secret.expires_at.isoformat() if secret.expires_at else None,
            "auto_rotate": secret.auto_rotate,
            "rotation_interval_days": secret.rotation_interval_days,
            "last_rotated_at": (
                secret.last_rotated_at.isoformat() if secret.last_rotated_at else None
            ),
            "created_at": secret.created_at.isoformat(),
            "updated_at": secret.updated_at.isoformat(),
        }
    )


@api_bp.route("/secrets/<uuid:id>/value")
@require_auth
def get_secret_value(id):
    """Get secret value (current version)."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        return jsonify({"error": "Permission denied"}), 403

    current_version = secret.current_version
    if not current_version:
        return jsonify({"error": "No current version found"}), 404

    try:
        value = current_version.decrypt_value()
        return jsonify(
            {
                "value": value,
                "version": current_version.version_number,
                "created_at": current_version.created_at.isoformat(),
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error decrypting secret {id}: {e}")
        return jsonify({"error": "Failed to decrypt secret"}), 500


@api_bp.route("/secrets", methods=["POST"])
@require_auth
def create_secret():
    """Create a new secret."""
    user = get_current_user()
    data = request.get_json()

    # Validate required fields
    required_fields = ["name", "display_name", "environment_id", "value"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Check if secret already exists
    existing = Secret.find_by_name_and_environment(data["name"], data["environment_id"])
    if existing:
        return (
            jsonify({"error": "Secret with this name already exists in environment"}),
            409,
        )

    try:
        # Create the secret
        secret = Secret.create(
            name=data["name"],
            display_name=data["display_name"],
            description=data.get("description"),
            secret_type=SecretType(data.get("secret_type", "string")),
            secrecy_level=SecrecyLevel(data.get("secrecy_level", "medium")),
            environment_id=data["environment_id"],
            service_name=data.get("service_name"),
            creator_id=user.id,
        )

        # Create the first version
        SecretVersion.create_version(
            secret_id=secret.id,
            value=data["value"],
            created_by_id=user.id,
            generation_method="api",
        )

        return (
            jsonify(
                {
                    "id": secret.id,
                    "name": secret.name,
                    "display_name": secret.display_name,
                    "environment": secret.environment.name,
                    "created_at": secret.created_at.isoformat(),
                }
            ),
            201,
        )

    except Exception as e:
        current_app.logger.error(f"Error creating secret via API: {e}")
        return jsonify({"error": "Failed to create secret"}), 500


@api_bp.route("/secrets/<uuid:id>/rotate", methods=["POST"])
@require_auth
def rotate_secret(id):
    """Rotate a secret."""
    secret = Secret.query.get_or_404(id)
    user = get_current_user()
    data = request.get_json()

    # Check permissions
    if not user.can_access_environment(secret.environment.name):
        return jsonify({"error": "Permission denied"}), 403

    if "value" not in data:
        return jsonify({"error": "Missing required field: value"}), 400

    try:
        # Create new version
        new_version = SecretVersion.create_version(
            secret_id=secret.id,
            value=data["value"],
            created_by_id=user.id,
            generation_method="api",
            make_current=True,
        )

        # Update secret rotation timestamp
        secret.mark_rotated()

        return jsonify(
            {
                "version": new_version.version_number,
                "created_at": new_version.created_at.isoformat(),
                "message": "Secret rotated successfully",
            }
        )

    except Exception as e:
        current_app.logger.error(f"Error rotating secret {id} via API: {e}")
        return jsonify({"error": "Failed to rotate secret"}), 500
