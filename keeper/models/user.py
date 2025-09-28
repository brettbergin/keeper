"""User model for authentication and authorization."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

import bcrypt
from flask import current_app
from sqlalchemy import JSON, Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import String, Text
from sqlalchemy.orm import relationship

from .base import BaseModel


class UserRole(Enum):
    """Enumeration of user roles with hierarchical permissions."""

    USER = "user"  # Basic user - can create/edit secrets in dev/staging
    MANAGER = "manager"  # Manager - can approve secrets in assigned environments
    ADMIN = "admin"  # Administrator - full access to all environments


class AuthMethod(Enum):
    """Enumeration of authentication methods."""

    SAML = "saml"  # SAML/Okta authentication
    DATABASE = "database"  # Database authentication with username/password
    DEMO = "demo"  # Demo authentication (for development)


class User(BaseModel):
    """User model for authentication via Okta SAML."""

    __tablename__ = "users"

    # Basic user information
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)

    # SAML attributes
    saml_subject_id = Column(String(255), unique=True, nullable=True, index=True)
    saml_session_index = Column(String(255), nullable=True)

    # Authentication
    auth_method = Column(SQLEnum(AuthMethod), default=AuthMethod.SAML, nullable=False)
    password_hash = Column(String(255), nullable=True)  # For database auth
    email_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(255), nullable=True)
    email_verification_expires = Column(DateTime, nullable=True)
    must_change_password = Column(Boolean, default=False, nullable=False)

    # Role-based access control
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    managed_environments = Column(
        JSON, nullable=True
    )  # List of environment names for managers

    # User status and metadata
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 compatible

    # User preferences
    preferred_environment = Column(String(50), default="development", nullable=False)
    timezone = Column(String(50), default="UTC", nullable=False)

    # Session management
    session_token = Column(Text, nullable=True)
    session_expires_at = Column(DateTime, nullable=True)

    # Relationships
    secrets = relationship("Secret", back_populates="creator", lazy="dynamic")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.email})>"

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if not self.is_active:
            return False

        # For database auth, check email verification
        if self.auth_method == AuthMethod.DATABASE and not self.email_verified:
            return False

        if not self.session_token or not self.session_expires_at:
            return False
        return datetime.utcnow() < self.session_expires_at

    def can_access_environment(self, environment: str) -> bool:
        """Check if user can access a specific environment based on role."""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.MANAGER:
            managed_envs = self.get_managed_environments()
            return environment in managed_envs or environment == "development"
        else:  # USER role
            return environment in ["development", "staging"]

    def can_manage_environment(self, environment: str) -> bool:
        """Check if user can manage (approve) secrets in an environment."""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.MANAGER:
            managed_envs = self.get_managed_environments()
            return environment in managed_envs
        return False

    def can_create_secret(self, environment: str) -> bool:
        """Check if user can create secrets in an environment."""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.MANAGER:
            return self.can_access_environment(environment)
        else:  # USER role
            return environment in ["development", "staging"]

    def can_manually_enter_secrets(self) -> bool:
        """Check if user can manually enter secret values (vs only auto-generate)."""
        return self.role == UserRole.ADMIN

    def can_edit_secret(self, environment: str) -> bool:
        """Check if user can edit secrets in an environment."""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.MANAGER:
            return self.can_access_environment(environment)
        else:  # USER role
            return environment in ["development", "staging"]

    def can_rotate_secret(self, environment: str) -> bool:
        """Check if user can rotate secrets in an environment."""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.MANAGER:
            return self.can_access_environment(environment)
        else:  # USER role
            # Users can only rotate in dev/staging without approval
            return environment in ["development"]

    def requires_approval_for_rotation(self, environment: str) -> bool:
        """Check if secret rotation requires manager approval."""
        if self.role == UserRole.ADMIN:
            return False
        elif self.role == UserRole.MANAGER:
            return False  # Managers don't need approval
        else:  # USER role
            return environment not in ["development"]  # Staging and prod need approval

    def get_managed_environments(self) -> List[str]:
        """Get list of environments this user manages."""
        if not self.managed_environments:
            return []
        return (
            self.managed_environments
            if isinstance(self.managed_environments, list)
            else []
        )

    def set_managed_environments(self, environments: List[str]) -> None:
        """Set the environments this user manages."""
        self.managed_environments = environments if environments else None

    def set_password(self, password: str) -> None:
        """Set user password with bcrypt hashing."""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
            "utf-8"
        )
        self.must_change_password = False

    def check_password(self, password: str) -> bool:
        """Check if provided password matches the stored hash."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def generate_email_verification_token(self) -> str:
        """Generate email verification token."""
        import datetime
        import secrets

        token = secrets.token_urlsafe(32)
        self.email_verification_token = token
        self.email_verification_expires = (
            datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        )
        return token

    def verify_email_token(self, token: str) -> bool:
        """Verify email verification token."""
        if not self.email_verification_token or not self.email_verification_expires:
            return False

        if datetime.utcnow() > self.email_verification_expires:
            return False

        if self.email_verification_token == token:
            self.email_verified = True
            self.email_verification_token = None
            self.email_verification_expires = None
            return True

        return False

    @property
    def is_admin(self) -> bool:
        """Backward compatibility property for admin check."""
        return self.role == UserRole.ADMIN

    @property
    def role_display_name(self) -> str:
        """Get human-readable role name."""
        role_names = {
            UserRole.USER: "User",
            UserRole.MANAGER: "Manager",
            UserRole.ADMIN: "Administrator",
        }
        return role_names.get(self.role, "Unknown")

    def update_last_login(self, ip_address: Optional[str] = None) -> None:
        """Update last login timestamp and IP."""
        self.last_login = datetime.utcnow()
        if ip_address:
            self.last_login_ip = ip_address
        self.save()

    def set_session(self, token: str, expires_at: datetime) -> None:
        """Set user session token and expiration."""
        self.session_token = token
        self.session_expires_at = expires_at
        self.save()

    def clear_session(self) -> None:
        """Clear user session."""
        self.session_token = None
        self.session_expires_at = None
        self.save()

    @classmethod
    def find_by_email(cls, email: str) -> Optional["User"]:
        """Find user by email address."""
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_username(cls, username: str) -> Optional["User"]:
        """Find user by username."""
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_saml_subject_id(cls, subject_id: str) -> Optional["User"]:
        """Find user by SAML subject ID."""
        return cls.query.filter_by(saml_subject_id=subject_id).first()

    @classmethod
    def get_active_users(cls) -> List["User"]:
        """Get all active users."""
        return cls.query.filter_by(is_active=True).all()

    @classmethod
    def get_admins(cls) -> List["User"]:
        """Get all admin users."""
        return cls.query.filter_by(role=UserRole.ADMIN, is_active=True).all()

    @classmethod
    def get_managers(cls) -> List["User"]:
        """Get all manager users."""
        return cls.query.filter_by(role=UserRole.MANAGER, is_active=True).all()

    @classmethod
    def get_managers_for_environment(cls, environment: str) -> List["User"]:
        """Get managers who can approve actions in a specific environment."""
        managers = cls.query.filter_by(role=UserRole.MANAGER, is_active=True).all()
        return [m for m in managers if environment in m.get_managed_environments()]

    @classmethod
    def create_admin_user(
        cls,
        username: str = "admin",
        password: str = "admin",
        email: str = "admin@keeper.local",
    ) -> "User":
        """Create default admin user."""
        admin = cls(
            username=username,
            email=email,
            full_name="Default Administrator",
            role=UserRole.ADMIN,
            auth_method=AuthMethod.DATABASE,
            is_active=True,
            email_verified=True,
            must_change_password=True,  # Force password change on first login
        )
        admin.set_password(password)
        admin.save()
        return admin

    @classmethod
    def ensure_default_admin(cls) -> Optional["User"]:
        """Ensure default admin user exists if configured."""

        if not current_app.config.get("CREATE_DEFAULT_ADMIN", True):
            return None

        username = current_app.config.get("DEFAULT_ADMIN_USERNAME", "admin")
        password = current_app.config.get("DEFAULT_ADMIN_PASSWORD", "admin")
        email = current_app.config.get("DEFAULT_ADMIN_EMAIL", "admin@localhost")

        # Check if admin user already exists
        existing_admin = cls.find_by_username(username)
        if existing_admin:
            return existing_admin

        # Create admin user
        admin = cls.create_admin_user(username=username, password=password, email=email)
        current_app.logger.info(f"Default admin user created: {username}")
        return admin

    @staticmethod
    def verify_email_token(token: str) -> Optional["User"]:
        """Verify email verification token and return user."""
        user = User.query.filter_by(email_verification_token=token).first()
        if not user:
            return None

        if (
            user.email_verification_expires
            and datetime.utcnow() > user.email_verification_expires
        ):
            return None

        return user
