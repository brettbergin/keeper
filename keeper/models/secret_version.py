"""Secret version model for managing secret history and rotation."""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional

from flask import current_app
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import BaseModel


class SecretVersion(BaseModel):
    """Model for storing different versions of secrets for rotation and history."""

    __tablename__ = "secret_versions"

    # Version information
    secret_id = Column(Integer, ForeignKey("secrets.id"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    is_current = Column(Boolean, default=False, nullable=False, index=True)

    # Secret value (encrypted)
    encrypted_value = Column(LargeBinary, nullable=False)
    value_hash = Column(String(64), nullable=False)  # SHA-256 hash for integrity

    # Envelope encryption metadata (KMS/Local)
    encrypted_dek = Column(
        LargeBinary, nullable=True
    )  # Encrypted Data Encryption Key (empty for local)
    kms_key_id = Column(
        String(2048), nullable=True
    )  # ARN of KMS key used (or 'local' for dev)
    encryption_context = Column(JSON, nullable=True)  # Additional authenticated data
    encryption_algorithm = Column(String(50), default="aes-256-gcm-kms", nullable=False)
    nonce = Column(LargeBinary, nullable=False)  # 12-byte nonce for GCM
    auth_tag = Column(LargeBinary, nullable=False)  # 16-byte authentication tag

    # Legacy encryption support (for migration)
    encryption_key_id = Column(String(64), nullable=True)  # Legacy key identifier

    # Generation metadata
    generation_method = Column(String(50), nullable=True)  # manual, auto, imported
    generation_params = Column(
        Text, nullable=True
    )  # JSON string of generation parameters

    # Lifecycle
    activated_at = Column(DateTime, nullable=True)
    deactivated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    # Foreign keys
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    secret = relationship("Secret", back_populates="versions")
    created_by = relationship("User")

    def __repr__(self) -> str:
        return f"<SecretVersion {self.secret.name} v{self.version_number}>"

    @property
    def is_active(self) -> bool:
        """Check if this version is currently active."""
        if not self.is_current:
            return False
        if self.deactivated_at and datetime.utcnow() > self.deactivated_at:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def decrypt_value(self) -> str:
        """Decrypt and return the secret value using envelope encryption."""
        try:
            from ..services.key_management import (
                DecryptionError,
                KeyManagementError,
                get_key_management_service,
            )

            current_app.logger.debug(
                f"Starting decryption for secret version {self.id} using algorithm {self.encryption_algorithm}"
            )

            # Validate required fields before attempting decryption
            if not self.encrypted_value:
                current_app.logger.error(
                    f"Secret version {self.id} has no encrypted value"
                )
                raise ValueError("No encrypted value found for secret version")

            # Handle legacy encryption methods
            if self.encryption_algorithm in ["aes-256-gcm", "fernet"]:
                current_app.logger.debug(
                    f"Using legacy decryption for algorithm: {self.encryption_algorithm}"
                )
                return self._decrypt_legacy()

            # Use new envelope encryption
            km_service = get_key_management_service()

            # Validate all required KMS fields
            required_fields = ["nonce", "auth_tag"]
            missing_fields = [
                field for field in required_fields if getattr(self, field) is None
            ]
            if missing_fields:
                current_app.logger.error(
                    f"Secret version {self.id} missing required fields: {missing_fields}"
                )
                raise ValueError(
                    f"Missing required encryption fields: {missing_fields}"
                )

            encrypted_data = {
                "encrypted_value": self.encrypted_value,
                "encrypted_dek": self.encrypted_dek or b"",
                "nonce": self.nonce,
                "auth_tag": self.auth_tag,
                "kms_key_id": self.kms_key_id,
                "encryption_context": self.encryption_context,
                "algorithm": self.encryption_algorithm,
            }

            plaintext = km_service.decrypt_secret(encrypted_data)

            # Verify integrity if hash exists
            if self.value_hash:
                if not self.verify_integrity(plaintext):
                    current_app.logger.error(
                        f"Integrity check failed for secret version {self.id}"
                    )
                    raise ValueError("Secret integrity verification failed")
                else:
                    current_app.logger.debug(
                        f"Integrity check passed for secret version {self.id}"
                    )

            current_app.logger.debug(f"Successfully decrypted secret version {self.id}")
            return plaintext

        except DecryptionError as e:
            current_app.logger.error(
                f"Decryption error for secret version {self.id}: {e.error_code} - {str(e)}"
            )
            raise
        except KeyManagementError as e:
            current_app.logger.error(
                f"Key management error for secret version {self.id}: {e.error_code} - {str(e)}"
            )
            raise
        except ValueError as e:
            current_app.logger.error(
                f"Validation error for secret version {self.id}: {str(e)}"
            )
            raise
        except Exception as e:
            current_app.logger.error(
                f"Unexpected error decrypting secret version {self.id}: {str(e)}"
            )
            raise ValueError(f"Failed to decrypt secret version: {str(e)}") from e

    def encrypt_value(
        self, value: str, encryption_context: Optional[Dict[str, str]] = None
    ) -> None:
        """Encrypt and store the secret value using envelope encryption."""
        try:
            from ..services.key_management import (
                EncryptionError,
                KeyManagementError,
                get_key_management_service,
            )

            # Validate input
            if not value:
                raise ValueError("Cannot encrypt empty or None value")

            if not isinstance(value, str):
                raise ValueError(f"Value must be a string, got {type(value)}")

            current_app.logger.debug(
                f"Starting encryption for secret version {self.id or 'new'}"
            )

            km_service = get_key_management_service()

            # Add environment context if available and not provided
            if not encryption_context:
                try:
                    encryption_context = self._get_encryption_context()
                    current_app.logger.debug(
                        f"Generated encryption context: {encryption_context}"
                    )
                except Exception as e:
                    current_app.logger.warning(
                        f"Failed to get encryption context, using default: {str(e)}"
                    )
                    encryption_context = {"application": "keeper"}

            encrypted_data = km_service.encrypt_secret(value, encryption_context)

            # Validate encrypted data structure
            required_fields = ["encrypted_value", "algorithm"]
            missing_fields = [
                field for field in required_fields if field not in encrypted_data
            ]
            if missing_fields:
                raise ValueError(
                    f"Encryption service returned incomplete data, missing: {missing_fields}"
                )

            # Store encrypted data and metadata
            self.encrypted_value = encrypted_data["encrypted_value"]
            self.encrypted_dek = encrypted_data.get("encrypted_dek")
            self.nonce = encrypted_data.get("nonce")
            self.auth_tag = encrypted_data.get("auth_tag")
            self.kms_key_id = encrypted_data.get("kms_key_id")
            self.encryption_context = encrypted_data.get("encryption_context")
            self.encryption_algorithm = encrypted_data["algorithm"]

            # Generate hash for integrity checking
            self.value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()

            current_app.logger.info(
                f"Successfully encrypted secret version {self.id or 'new'} using {self.encryption_algorithm}"
            )

        except EncryptionError as e:
            current_app.logger.error(
                f"Encryption error for secret version {self.id or 'new'}: {e.error_code} - {str(e)}"
            )
            raise
        except KeyManagementError as e:
            current_app.logger.error(
                f"Key management error for secret version {self.id or 'new'}: {e.error_code} - {str(e)}"
            )
            raise
        except ValueError as e:
            current_app.logger.error(
                f"Validation error for secret version {self.id or 'new'}: {str(e)}"
            )
            raise
        except Exception as e:
            current_app.logger.error(
                f"Unexpected error encrypting secret version {self.id or 'new'}: {str(e)}"
            )
            raise ValueError(f"Failed to encrypt secret version: {str(e)}") from e

    def _get_encryption_context(self) -> Optional[Dict[str, str]]:
        """Get encryption context for this secret version."""
        try:
            # Try to use the loaded relationship first
            if hasattr(self, "secret") and self.secret and self.secret.environment:
                return {
                    "environment": self.secret.environment.name,
                    "secret_name": self.secret.name,
                }

            # If relationship not loaded, query the database
            if self.secret_id:
                from sqlalchemy import text

                from .database import db

                result = db.session.execute(
                    text(
                        """
                        SELECT s.name, e.name as env_name 
                        FROM secrets s 
                        JOIN environments e ON s.environment_id = e.id 
                        WHERE s.id = :secret_id
                    """
                    ),
                    {"secret_id": self.secret_id},
                ).fetchone()

                if result:
                    return {"environment": result.env_name, "secret_name": result.name}

            # Fallback to basic context
            return {
                "application": "keeper",
                "secret_id": str(self.secret_id) if self.secret_id else "unknown",
            }

        except Exception as e:
            current_app.logger.warning(
                f"Could not determine encryption context: {str(e)}"
            )
            return {
                "application": "keeper",
                "secret_id": str(self.secret_id) if self.secret_id else "unknown",
            }

    def _decrypt_legacy(self) -> str:
        """Decrypt using legacy encryption methods (for backward compatibility)."""
        try:
            current_app.logger.debug(
                f"Using legacy decryption for algorithm: {self.encryption_algorithm}"
            )

            # Validate required fields for legacy decryption
            if not self.encrypted_value:
                raise ValueError("No encrypted value found for legacy decryption")

            if self.encryption_algorithm == "aes-256-gcm":
                # Legacy AES-256-GCM decryption
                import base64

                # Validate required fields for AES-GCM
                if not self.nonce or not self.auth_tag:
                    raise ValueError(
                        "Missing nonce or auth_tag for AES-256-GCM decryption"
                    )

                try:
                    encryption_key = self._get_legacy_encryption_key()
                    key = base64.b64decode(encryption_key.encode())
                except Exception as e:
                    current_app.logger.error(
                        f"Failed to decode legacy encryption key: {str(e)}"
                    )
                    raise ValueError(f"Invalid legacy encryption key: {str(e)}")

                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )

                try:
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(self.nonce, self.auth_tag),
                        backend=default_backend(),
                    )
                    decryptor = cipher.decryptor()

                    plaintext = (
                        decryptor.update(self.encrypted_value) + decryptor.finalize()
                    )
                    return plaintext.decode("utf-8")
                except Exception as e:
                    current_app.logger.error(f"AES-256-GCM decryption failed: {str(e)}")
                    raise ValueError(f"AES-256-GCM decryption failed: {str(e)}")

            elif self.encryption_algorithm == "fernet":
                # Legacy Fernet decryption
                try:
                    encryption_key = self._get_legacy_encryption_key()
                    from cryptography.fernet import Fernet

                    fernet = Fernet(encryption_key.encode())
                    return fernet.decrypt(self.encrypted_value).decode("utf-8")
                except Exception as e:
                    current_app.logger.error(f"Fernet decryption failed: {str(e)}")
                    raise ValueError(f"Fernet decryption failed: {str(e)}")

            else:
                raise ValueError(
                    f"Unsupported legacy encryption algorithm: {self.encryption_algorithm}"
                )

        except ValueError:
            # Re-raise validation errors as-is
            raise
        except Exception as e:
            current_app.logger.error(f"Unexpected error in legacy decryption: {str(e)}")
            raise ValueError(f"Legacy decryption failed: {str(e)}") from e

    def verify_integrity(self, decrypted_value: str) -> bool:
        """Verify the integrity of the decrypted value."""
        import hashlib

        expected_hash = hashlib.sha256(decrypted_value.encode("utf-8")).hexdigest()
        return expected_hash == self.value_hash

    def activate(self) -> None:
        """Activate this version and deactivate others with transaction safety."""
        from flask import current_app

        with self.safe_transaction():
            current_app.logger.debug(f"Activating secret version {self.id}")

            # Deactivate other versions in a safe way
            other_versions = (
                SecretVersion.query.filter_by(secret_id=self.secret_id, is_current=True)
                .filter(SecretVersion.id != self.id)
                .all()
            )

            deactivated_count = 0
            for version in other_versions:
                version.is_current = False
                version.deactivated_at = datetime.utcnow()
                deactivated_count += 1

            # Activate this version
            self.is_current = True
            self.activated_at = datetime.utcnow()
            self.deactivated_at = None

            current_app.logger.info(
                f"Activated version {self.id} and deactivated {deactivated_count} other versions"
            )

    def deactivate(self) -> None:
        """Deactivate this version with transaction safety."""
        from flask import current_app

        with self.safe_transaction():
            current_app.logger.debug(f"Deactivating secret version {self.id}")

            self.is_current = False
            self.deactivated_at = datetime.utcnow()

            current_app.logger.info(f"Deactivated secret version {self.id}")

    def get_generation_params_dict(self) -> Dict[str, Any]:
        """Get generation parameters as a dictionary."""
        if not self.generation_params:
            return {}
        try:
            import json

            return json.loads(self.generation_params)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_generation_params_dict(self, params: Dict[str, Any]) -> None:
        """Set generation parameters from a dictionary."""

        self.generation_params = json.dumps(params) if params else None

    def _get_legacy_encryption_key(self) -> str:
        """Get the encryption key for legacy encryption methods."""
        current_app.logger.warning(
            "Using legacy encryption key retrieval - consider migrating to KMS"
        )

        if self.encryption_key_id:
            # Try to get key from environment variable first
            import os

            key_env_var = f"KEEPER_ENCRYPTION_KEY_{self.encryption_key_id}"
            key = os.environ.get(key_env_var)
            if key:
                return key

            # Try to get key from database storage (simple approach for development)
            from sqlalchemy import text

            from .database import db

            try:
                result = db.session.execute(
                    text(
                        "SELECT encryption_key FROM encryption_keys WHERE key_id = :key_id"
                    ),
                    {"key_id": self.encryption_key_id},
                ).fetchone()
                if result:
                    return result[0]
            except:
                pass  # Table might not exist, fall through to default

        # Fallback to a default key (NOT recommended for production)
        import os

        default_key = os.environ.get("KEEPER_DEFAULT_ENCRYPTION_KEY")
        if default_key:
            return default_key

        # Use a fixed development key based on key_id to ensure consistency
        if self.encryption_key_id:
            # Create a deterministic key from the key_id for development
            hash_input = f"keeper_dev_key_{self.encryption_key_id}".encode()
            key_hash = hashlib.sha256(hash_input).digest()
            import base64

            return base64.b64encode(key_hash).decode("utf-8")

        # Final fallback - fixed development key
        import base64

        return base64.b64encode(b"keeper_development_key_32_bytes!").decode("utf-8")

    @classmethod
    def create_version(
        cls,
        secret_id: int,
        value: str,
        created_by_id: int,
        generation_method: str = "manual",
        generation_params: Optional[Dict[str, Any]] = None,
        make_current: bool = True,
    ) -> "SecretVersion":
        """Create a new secret version with transaction safety."""
        from flask import current_app

        # Use safe transaction to prevent data loss
        with cls.safe_transaction() as session:
            # Get the next version number
            latest_version = (
                cls.query.filter_by(secret_id=secret_id)
                .order_by(cls.version_number.desc())
                .first()
            )
            version_number = (
                (latest_version.version_number + 1) if latest_version else 1
            )

            current_app.logger.debug(
                f"Creating version {version_number} for secret {secret_id}"
            )

            # Create the version
            version = cls(
                secret_id=secret_id,
                version_number=version_number,
                created_by_id=created_by_id,
                generation_method=generation_method,
            )

            if generation_params:
                version.set_generation_params_dict(generation_params)

            # Encrypt the value - this is where errors could occur
            try:
                version.encrypt_value(value)
            except Exception as e:
                current_app.logger.error(
                    f"Failed to encrypt value for new version: {str(e)}"
                )
                raise ValueError(f"Failed to encrypt secret value: {str(e)}") from e

            # Add to session but don't commit yet
            session.add(version)

            # Make it current if requested - this involves updating other versions
            if make_current:
                try:
                    # Deactivate other versions in the same transaction
                    other_versions = cls.query.filter_by(
                        secret_id=secret_id, is_current=True
                    ).all()

                    for other_version in other_versions:
                        other_version.is_current = False
                        other_version.deactivated_at = datetime.utcnow()

                    # Activate this version
                    version.is_current = True
                    version.activated_at = datetime.utcnow()

                    current_app.logger.debug(
                        f"Activated version {version_number} and deactivated {len(other_versions)} other versions"
                    )

                except Exception as e:
                    current_app.logger.error(
                        f"Failed to activate new version: {str(e)}"
                    )
                    raise ValueError(
                        f"Failed to activate secret version: {str(e)}"
                    ) from e

            # Transaction will be committed by the context manager
            current_app.logger.info(
                f"Successfully created secret version {version_number} for secret {secret_id}"
            )
            return version

    @classmethod
    def get_current_version(cls, secret_id: int) -> Optional["SecretVersion"]:
        """Get the current version of a secret."""
        return cls.query.filter_by(secret_id=secret_id, is_current=True).first()

    @classmethod
    def get_version_history(cls, secret_id: int, limit: int = 10) -> list:
        """Get version history for a secret."""
        return (
            cls.query.filter_by(secret_id=secret_id)
            .order_by(cls.version_number.desc())
            .limit(limit)
            .all()
        )
