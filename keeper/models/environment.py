"""Environment model for multi-environment secret management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.orm import relationship

from .base import BaseModel


class Environment(BaseModel):
    """Environment model for organizing secrets by deployment environment."""

    __tablename__ = "environments"

    # Basic environment information
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Environment configuration
    is_active = Column(Boolean, default=True, nullable=False)
    is_production = Column(Boolean, default=False, nullable=False)
    sort_order = Column(String(10), default="999", nullable=False)

    # AWS configuration for this environment
    aws_region = Column(String(50), nullable=True)
    aws_secrets_prefix = Column(String(255), nullable=True)

    # Vault configuration for this environment
    vault_mount_point = Column(String(255), nullable=True)
    vault_path_prefix = Column(String(255), nullable=True)

    # Environment metadata
    color_code = Column(String(7), nullable=True)  # Hex color for UI
    icon = Column(String(50), nullable=True)

    # KMS Configuration (per-environment keys)
    kms_key_id = Column(String(2048), nullable=True)  # Environment-specific KMS key
    kms_key_alias = Column(
        String(256), nullable=True
    )  # Environment-specific KMS key alias
    key_rotation_enabled = Column(Boolean, default=True, nullable=False)
    last_key_rotation = Column(DateTime, nullable=True)

    # Sync configuration
    aws_sync_enabled = Column(Boolean, default=True, nullable=False)
    vault_sync_enabled = Column(Boolean, default=True, nullable=False)

    # Relationships
    secrets = relationship("Secret", back_populates="environment", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Environment {self.name} ({self.display_name})>"

    @property
    def full_aws_prefix(self) -> str:
        """Get the full AWS Secrets Manager prefix for this environment."""
        return f"{self.aws_secrets_prefix or self.name}/"

    @property
    def full_vault_prefix(self) -> str:
        """Get the full Vault path prefix for this environment."""
        mount = self.vault_mount_point or "secret"
        prefix = self.vault_path_prefix or self.name
        return f"{mount}/{prefix}/"

    def get_aws_secret_name(self, secret_name: str) -> str:
        """Generate AWS secret name for this environment."""
        return f"{self.full_aws_prefix}{secret_name}"

    def get_vault_path(self, secret_name: str) -> str:
        """Generate Vault path for this environment."""
        return f"{self.full_vault_prefix}{secret_name}"

    @classmethod
    def get_active_environments(cls) -> List["Environment"]:
        """Get all active environments ordered by sort_order."""
        return (
            cls.query.filter_by(is_active=True).order_by(cls.sort_order, cls.name).all()
        )

    @classmethod
    def get_production_environments(cls) -> List["Environment"]:
        """Get all production environments."""
        return cls.query.filter_by(is_production=True, is_active=True).all()

    @classmethod
    def find_by_name(cls, name: str) -> Optional["Environment"]:
        """Find environment by name."""
        return cls.query.filter_by(name=name).first()

    @classmethod
    def get_default_environment(cls) -> Optional["Environment"]:
        """Get the default environment (usually development)."""
        # First try to find 'development' environment
        env = cls.query.filter_by(name="development", is_active=True).first()
        if env:
            return env

        # If not found, return the first active non-production environment
        env = (
            cls.query.filter_by(is_production=False, is_active=True)
            .order_by(cls.sort_order)
            .first()
        )
        if env:
            return env

        # If no non-production environment, return any active environment
        return cls.query.filter_by(is_active=True).order_by(cls.sort_order).first()

    def get_kms_key_spec(self) -> Optional[str]:
        """Get the KMS key specification for this environment."""
        return self.kms_key_id or self.kms_key_alias

    def get_encryption_context(self) -> Dict[str, str]:
        """Get the encryption context for this environment."""
        return {
            "application": "keeper",
            "environment": self.name,
            "environment_id": str(self.id),
        }

    def can_use_kms(self) -> bool:
        """Check if this environment is configured to use KMS."""
        return bool(self.kms_key_id or self.kms_key_alias)

    def initiate_key_rotation(self) -> Dict[str, Any]:
        """Initiate key rotation for this environment."""
        try:
            from ..services.key_management import get_key_management_service

            km_service = get_key_management_service()

            if self.can_use_kms():
                result = km_service.rotate_keys(self.get_kms_key_spec())
                self.last_key_rotation = datetime.utcnow()
                self.save()
                return result
            else:
                return {
                    "success": False,
                    "message": "No KMS key configured for this environment",
                }

        except Exception as e:
            return {"success": False, "message": f"Key rotation failed: {str(e)}"}

    def get_key_info(self) -> Dict[str, Any]:
        """Get information about this environment's KMS key."""
        try:
            from ..services.key_management import get_key_management_service

            km_service = get_key_management_service()

            if self.can_use_kms():
                return km_service.get_key_info(self.get_kms_key_spec())
            else:
                return {
                    "key_id": "local-development-key",
                    "description": "Local development key (not secure for production)",
                    "warning": "Configure KMS_KEY_ID or KMS_KEY_ALIAS for production use",
                }

        except Exception as e:
            return {"error": f"Failed to get key info: {str(e)}"}

    @classmethod
    def create_default_environments(cls) -> None:
        """Create default environments if they don't exist."""
        default_envs = [
            {
                "name": "development",
                "display_name": "Development",
                "description": "Development environment for testing",
                "sort_order": "010",
                "color_code": "#28a745",
                "icon": "fas fa-code",
                "kms_key_alias": "alias/keeper-development",
                "key_rotation_enabled": False,  # Disable for dev
            },
            {
                "name": "staging",
                "display_name": "Staging",
                "description": "Staging environment for pre-production testing",
                "sort_order": "020",
                "color_code": "#ffc107",
                "icon": "fas fa-vial",
                "kms_key_alias": "alias/keeper-staging",
                "key_rotation_enabled": True,
            },
            {
                "name": "production",
                "display_name": "Production",
                "description": "Production environment",
                "is_production": True,
                "sort_order": "030",
                "color_code": "#dc3545",
                "icon": "fas fa-server",
                "kms_key_alias": "alias/keeper-production",
                "key_rotation_enabled": True,
            },
        ]

        for env_data in default_envs:
            if not cls.find_by_name(env_data["name"]):
                cls.create(**env_data)
