"""Secret model for managing secrets across backends."""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import BaseModel


class SecretType(Enum):
    """Enumeration of supported secret types."""

    STRING = "string"
    PASSWORD = "password"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    RSA_KEY = "rsa_key"
    CERTIFICATE = "certificate"
    DATABASE_CREDENTIALS = "database_credentials"
    JSON = "json"
    YAML = "yaml"


class SecrecyLevel(Enum):
    """Enumeration of secrecy levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SyncStatus(Enum):
    """Enumeration of synchronization statuses."""

    SYNCED = "synced"
    OUT_OF_SYNC = "out_of_sync"
    SYNC_PENDING = "sync_pending"
    SYNC_ERROR = "sync_error"
    NOT_SYNCED = "not_synced"


class Secret(BaseModel):
    """Main secret model."""

    __tablename__ = "secrets"

    # Basic secret information
    name = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Secret classification
    secret_type = Column(SQLEnum(SecretType), nullable=False, default=SecretType.STRING)
    secrecy_level = Column(
        SQLEnum(SecrecyLevel), nullable=False, default=SecrecyLevel.MEDIUM
    )

    # Service and environment association
    service_name = Column(String(255), nullable=True, index=True)
    environment_id = Column(Integer, ForeignKey("environments.id"), nullable=False)

    # Secret lifecycle
    expires_at = Column(DateTime, nullable=True)
    auto_rotate = Column(Boolean, default=False, nullable=False)
    rotation_interval_days = Column(Integer, nullable=True)
    last_rotated_at = Column(DateTime, nullable=True)

    # Backend synchronization status
    aws_sync_status = Column(
        SQLEnum(SyncStatus), default=SyncStatus.NOT_SYNCED, nullable=False
    )
    vault_sync_status = Column(
        SQLEnum(SyncStatus), default=SyncStatus.NOT_SYNCED, nullable=False
    )
    aws_last_sync = Column(DateTime, nullable=True)
    vault_last_sync = Column(DateTime, nullable=True)

    # AWS Secrets Manager specific
    aws_secret_arn = Column(String(512), nullable=True)
    aws_version_id = Column(String(64), nullable=True)

    # Vault specific
    vault_path = Column(String(512), nullable=True)
    vault_version = Column(Integer, nullable=True)

    # Metadata
    tags = Column(Text, nullable=True)  # JSON string of tags
    is_active = Column(Boolean, default=True, nullable=False)

    # Foreign keys
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    environment = relationship("Environment", back_populates="secrets")
    creator = relationship("User", back_populates="secrets")
    versions = relationship(
        "SecretVersion",
        back_populates="secret",
        lazy="dynamic",
        order_by="desc(SecretVersion.version_number)",
    )
    audit_logs = relationship("AuditLog", back_populates="secret", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Secret {self.name} in {self.environment.name}>"

    @property
    def current_version(self) -> Optional["SecretVersion"]:
        """Get the current (latest) version of the secret."""
        return self.versions.filter_by(is_current=True).first()

    @property
    def previous_version(self) -> Optional["SecretVersion"]:
        """Get the previous version of the secret (for AB rotation)."""
        return (
            self.versions.filter_by(is_current=False)
            .order_by("version_number desc")
            .first()
        )

    @property
    def is_expired(self) -> bool:
        """Check if the secret has expired."""
        return self.expires_at is not None and datetime.utcnow() > self.expires_at

    @property
    def needs_rotation(self) -> bool:
        """Check if the secret needs rotation based on rotation interval."""
        if not self.auto_rotate or not self.rotation_interval_days:
            return False

        if not self.last_rotated_at:
            return True

        rotation_due = self.last_rotated_at + timedelta(
            days=self.rotation_interval_days
        )
        return datetime.utcnow() > rotation_due

    @property
    def sync_status(self) -> str:
        """Get overall sync status across all backends."""
        if (
            self.aws_sync_status == SyncStatus.SYNC_ERROR
            or self.vault_sync_status == SyncStatus.SYNC_ERROR
        ):
            return "error"
        if (
            self.aws_sync_status == SyncStatus.OUT_OF_SYNC
            or self.vault_sync_status == SyncStatus.OUT_OF_SYNC
        ):
            return "out_of_sync"
        if (
            self.aws_sync_status == SyncStatus.SYNC_PENDING
            or self.vault_sync_status == SyncStatus.SYNC_PENDING
        ):
            return "pending"
        if (
            self.aws_sync_status == SyncStatus.SYNCED
            and self.vault_sync_status == SyncStatus.SYNCED
        ):
            return "synced"
        return "partial"

    @property
    def full_name(self) -> str:
        """Get the full name including environment."""
        return f"{self.environment.name}/{self.name}"

    def get_aws_secret_name(self) -> str:
        """Get the AWS Secrets Manager secret name."""
        return self.environment.get_aws_secret_name(self.name)

    def get_vault_path(self) -> str:
        """Get the Vault path for this secret."""
        return self.environment.get_vault_path(self.name)

    def update_aws_sync_status(
        self,
        status: SyncStatus,
        arn: Optional[str] = None,
        version_id: Optional[str] = None,
    ) -> None:
        """Update AWS synchronization status."""
        self.aws_sync_status = status
        self.aws_last_sync = datetime.utcnow()
        if arn:
            self.aws_secret_arn = arn
        if version_id:
            self.aws_version_id = version_id
        self.save()

    def update_vault_sync_status(
        self,
        status: SyncStatus,
        path: Optional[str] = None,
        version: Optional[int] = None,
    ) -> None:
        """Update Vault synchronization status."""
        self.vault_sync_status = status
        self.vault_last_sync = datetime.utcnow()
        if path:
            self.vault_path = path
        if version:
            self.vault_version = version
        self.save()

    def mark_rotated(self) -> None:
        """Mark the secret as rotated."""
        self.last_rotated_at = datetime.utcnow()
        self.save()

    def get_tags_dict(self) -> Dict[str, str]:
        """Get tags as a dictionary."""
        if not self.tags:
            return {}
        try:
            import json

            return json.loads(self.tags)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_tags_dict(self, tags: Dict[str, str]) -> None:
        """Set tags from a dictionary."""
        import json

        self.tags = json.dumps(tags) if tags else None

    @classmethod
    def find_by_name_and_environment(
        cls, name: str, environment_id: int
    ) -> Optional["Secret"]:
        """Find secret by name and environment."""
        return cls.query.filter_by(name=name, environment_id=environment_id).first()

    @classmethod
    def find_by_service(
        cls, service_name: str, environment_id: Optional[int] = None
    ) -> List["Secret"]:
        """Find secrets by service name."""
        query = cls.query.filter_by(service_name=service_name, is_active=True)
        if environment_id:
            query = query.filter_by(environment_id=environment_id)
        return query.all()

    @classmethod
    def get_expiring_secrets(cls, days: int = 30) -> List["Secret"]:
        """Get secrets expiring within the specified number of days."""
        cutoff_date = datetime.utcnow() + timedelta(days=days)
        return cls.query.filter(
            cls.expires_at.isnot(None),
            cls.expires_at <= cutoff_date,
            cls.is_active == True,
        ).all()

    @classmethod
    def get_secrets_needing_rotation(cls) -> List["Secret"]:
        """Get secrets that need rotation."""
        secrets = cls.query.filter_by(auto_rotate=True, is_active=True).all()
        return [secret for secret in secrets if secret.needs_rotation]

    @classmethod
    def get_out_of_sync_secrets(cls) -> List["Secret"]:
        """Get secrets that are out of sync with backends."""
        return (
            cls.query.filter(
                (cls.aws_sync_status == SyncStatus.OUT_OF_SYNC)
                | (cls.vault_sync_status == SyncStatus.OUT_OF_SYNC)
                | (cls.aws_sync_status == SyncStatus.SYNC_ERROR)
                | (cls.vault_sync_status == SyncStatus.SYNC_ERROR)
            )
            .filter_by(is_active=True)
            .all()
        )
