"""Key management abstraction layer with multiple backend support."""

import secrets
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import current_app

from .kms_service import KMSService, KMSServiceError


class KeyManagementError(Exception):
    """Base exception for key management errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.original_error = original_error
        self.timestamp = datetime.utcnow()


class DecryptionError(KeyManagementError):
    """Specific exception for decryption failures."""

    pass


class EncryptionError(KeyManagementError):
    """Specific exception for encryption failures."""

    pass


class KeyNotFoundError(KeyManagementError):
    """Specific exception for missing encryption keys."""

    pass


class KeyManagementService(ABC):
    """Abstract base class for key management backends."""

    @abstractmethod
    def encrypt_secret(
        self, value: str, encryption_context: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Encrypt a secret value.

        Args:
            value: The plaintext secret to encrypt
            encryption_context: Additional authenticated data

        Returns:
            Dictionary containing encrypted data and metadata

        Raises:
            KeyManagementError: If encryption fails
        """
        pass

    @abstractmethod
    def decrypt_secret(
        self,
        encrypted_data: Dict[str, Any],
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Decrypt a secret value.

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            encryption_context: Additional authenticated data

        Returns:
            Plaintext secret value

        Raises:
            KeyManagementError: If decryption fails
        """
        pass

    @abstractmethod
    def rotate_keys(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Rotate encryption keys.

        Args:
            key_id: Specific key to rotate (optional)

        Returns:
            Dictionary with rotation status

        Raises:
            KeyManagementError: If rotation fails
        """
        pass

    @abstractmethod
    def get_key_info(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about encryption keys.

        Args:
            key_id: Specific key to get info for (optional)

        Returns:
            Dictionary with key information

        Raises:
            KeyManagementError: If info retrieval fails
        """
        pass


class KMSKeyManagement(KeyManagementService):
    """AWS KMS-based key management implementation."""

    def __init__(self):
        self.kms_service = KMSService()

    def encrypt_secret(
        self, value: str, encryption_context: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Encrypt a secret using KMS envelope encryption.

        Process:
        1. Generate data encryption key (DEK) using KMS
        2. Encrypt secret with DEK using AES-256-GCM
        3. Return encrypted secret + encrypted DEK

        Args:
            value: The plaintext secret to encrypt
            encryption_context: Additional authenticated data for KMS

        Returns:
            Dictionary containing:
            - encrypted_value: AES-256-GCM encrypted secret
            - encrypted_dek: KMS-encrypted data key
            - nonce: GCM nonce
            - auth_tag: GCM authentication tag
            - kms_key_id: KMS key used
            - encryption_context: Context used
            - algorithm: Encryption algorithm used

        Raises:
            KeyManagementError: If encryption fails
        """
        try:
            current_app.logger.debug("Starting KMS envelope encryption")

            # Generate data encryption key via KMS
            dek = self.kms_service.generate_data_key(
                encryption_context=encryption_context
            )

            # Encrypt the secret value using the plaintext DEK
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

            cipher = Cipher(
                algorithms.AES(dek.plaintext_key),
                modes.GCM(nonce),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()

            # Encrypt the value
            ciphertext = encryptor.update(value.encode("utf-8")) + encryptor.finalize()

            # Get authentication tag
            auth_tag = encryptor.tag

            current_app.logger.info(
                "Successfully encrypted secret using KMS envelope encryption"
            )

            return {
                "encrypted_value": ciphertext,
                "encrypted_dek": dek.encrypted_key,
                "nonce": nonce,
                "auth_tag": auth_tag,
                "kms_key_id": dek.key_id,
                "encryption_context": encryption_context
                or current_app.config.get("kms_encryption_context"),
                "algorithm": "aes-256-gcm-kms",
                "encrypted_at": datetime.utcnow().isoformat(),
            }

        except KMSServiceError as e:
            current_app.logger.error(f"KMS error during encryption: {str(e)}")
            raise EncryptionError(
                f"KMS encryption failed: {str(e)}",
                error_code="KMS_ERROR",
                original_error=e,
            ) from e
        except ValueError as e:
            current_app.logger.error(f"Invalid encryption parameters: {str(e)}")
            raise EncryptionError(
                f"Invalid encryption parameters: {str(e)}",
                error_code="INVALID_PARAMS",
                original_error=e,
            ) from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error during encryption: {str(e)}")
            raise EncryptionError(
                f"Encryption failed: {str(e)}",
                error_code="UNKNOWN_ERROR",
                original_error=e,
            ) from e

    def decrypt_secret(
        self,
        encrypted_data: Dict[str, Any],
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Decrypt a secret using KMS envelope encryption.

        Process:
        1. Decrypt the DEK using KMS
        2. Use DEK to decrypt the secret with AES-256-GCM
        3. Verify authentication tag

        Args:
            encrypted_data: Dictionary from encrypt_secret()
            encryption_context: Additional authenticated data for KMS

        Returns:
            Plaintext secret value

        Raises:
            KeyManagementError: If decryption fails
        """
        try:
            current_app.logger.debug("Starting KMS envelope decryption")

            # Decrypt the data encryption key using KMS
            context = encryption_context or encrypted_data.get("encryption_context")
            plaintext_dek = self.kms_service.decrypt_data_key(
                encrypted_data["encrypted_dek"], encryption_context=context
            )

            # Decrypt the secret value using the plaintext DEK
            cipher = Cipher(
                algorithms.AES(plaintext_dek),
                modes.GCM(encrypted_data["nonce"], encrypted_data["auth_tag"]),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()

            # Decrypt and verify
            plaintext = (
                decryptor.update(encrypted_data["encrypted_value"])
                + decryptor.finalize()
            )

            current_app.logger.debug(
                "Successfully decrypted secret using KMS envelope encryption"
            )

            return plaintext.decode("utf-8")

        except KMSServiceError as e:
            current_app.logger.error(f"KMS error during decryption: {str(e)}")
            raise DecryptionError(
                f"KMS decryption failed: {str(e)}",
                error_code="KMS_ERROR",
                original_error=e,
            ) from e
        except KeyError as e:
            current_app.logger.error(
                f"Missing required encryption data field: {str(e)}"
            )
            raise DecryptionError(
                f"Missing required encryption data: {str(e)}",
                error_code="MISSING_DATA",
                original_error=e,
            ) from e
        except ValueError as e:
            current_app.logger.error(f"Invalid encryption data format: {str(e)}")
            raise DecryptionError(
                f"Invalid encryption data: {str(e)}",
                error_code="INVALID_DATA",
                original_error=e,
            ) from e
        except UnicodeDecodeError as e:
            current_app.logger.error(f"Failed to decode decrypted value: {str(e)}")
            raise DecryptionError(
                f"Failed to decode decrypted value: {str(e)}",
                error_code="DECODE_ERROR",
                original_error=e,
            ) from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error during decryption: {str(e)}")
            raise DecryptionError(
                f"Decryption failed: {str(e)}",
                error_code="UNKNOWN_ERROR",
                original_error=e,
            ) from e

    def rotate_keys(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Rotate KMS Customer Master Key.

        Args:
            key_id: KMS key to rotate

        Returns:
            Dictionary with rotation status

        Raises:
            KeyManagementError: If rotation fails
        """
        try:
            return self.kms_service.rotate_key(key_id)
        except KMSServiceError as e:
            raise KeyManagementError(f"Key rotation failed: {str(e)}") from e

    def get_key_info(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get KMS key information.

        Args:
            key_id: KMS key to get info for

        Returns:
            Dictionary with key information

        Raises:
            KeyManagementError: If info retrieval fails
        """
        try:
            return self.kms_service.get_key_info(key_id)
        except KMSServiceError as e:
            raise KeyManagementError(f"Failed to get key info: {str(e)}") from e

    def cleanup_cache(self) -> None:
        """Clean up cached data encryption keys."""
        self.kms_service.cleanup_cache()


class LocalKeyManagement(KeyManagementService):
    """Local key management for development and testing."""

    def __init__(self):
        self._warned = False

    def _warn_insecure(self):
        """Issue a security warning for local key management."""
        if not self._warned:
            current_app.logger.warning(
                "⚠️  WARNING: Using local key management - NOT SECURE FOR PRODUCTION! "
                "Configure KMS_KEY_ID or KMS_KEY_ALIAS for production use."
            )
            self._warned = True

    def _get_local_key(self) -> bytes:
        """Get a deterministic local encryption key."""
        # Use a deterministic key derived from config for consistency
        key_material = current_app.config.get("SECRET_KEY", "default-dev-key")
        # Create a 32-byte key for AES-256
        import hashlib

        return hashlib.sha256(f"keeper-local-{key_material}".encode()).digest()

    def encrypt_secret(
        self, value: str, encryption_context: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Encrypt a secret using local AES-256-GCM.

        Args:
            value: The plaintext secret to encrypt
            encryption_context: Ignored in local implementation

        Returns:
            Dictionary containing encrypted data

        Raises:
            KeyManagementError: If encryption fails
        """
        self._warn_insecure()

        try:
            current_app.logger.debug("Encrypting secret using local key management")

            key = self._get_local_key()
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # Encrypt the value
            ciphertext = encryptor.update(value.encode("utf-8")) + encryptor.finalize()

            # Get authentication tag
            auth_tag = encryptor.tag

            return {
                "encrypted_value": ciphertext,
                "encrypted_dek": b"",  # No separate DEK in local mode
                "nonce": nonce,
                "auth_tag": auth_tag,
                "kms_key_id": "local-development-key",
                "encryption_context": {},
                "algorithm": "aes-256-gcm-local",
                "encrypted_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            current_app.logger.error(f"Local encryption error: {str(e)}")
            raise KeyManagementError(f"Local encryption failed: {str(e)}") from e

    def decrypt_secret(
        self,
        encrypted_data: Dict[str, Any],
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Decrypt a secret using local AES-256-GCM.

        Args:
            encrypted_data: Dictionary from encrypt_secret()
            encryption_context: Ignored in local implementation

        Returns:
            Plaintext secret value

        Raises:
            KeyManagementError: If decryption fails
        """
        self._warn_insecure()

        try:
            current_app.logger.debug("Decrypting secret using local key management")

            key = self._get_local_key()

            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(encrypted_data["nonce"], encrypted_data["auth_tag"]),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()

            # Decrypt and verify
            plaintext = (
                decryptor.update(encrypted_data["encrypted_value"])
                + decryptor.finalize()
            )

            return plaintext.decode("utf-8")

        except Exception as e:
            current_app.logger.error(f"Local decryption error: {str(e)}")
            raise KeyManagementError(f"Local decryption failed: {str(e)}") from e

    def rotate_keys(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Local key rotation (no-op).

        Args:
            key_id: Ignored in local implementation

        Returns:
            Dictionary with rotation status
        """
        self._warn_insecure()

        current_app.logger.warning("Key rotation not supported in local mode")
        return {
            "key_id": "local-development-key",
            "rotation_enabled": False,
            "message": "Key rotation not supported in local development mode",
        }

    def get_key_info(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get local key information.

        Args:
            key_id: Ignored in local implementation

        Returns:
            Dictionary with key information
        """
        self._warn_insecure()

        return {
            "key_id": "local-development-key",
            "arn": "local://development-key",
            "description": "Local development encryption key",
            "key_usage": "ENCRYPT_DECRYPT",
            "key_state": "Enabled",
            "creation_date": "2024-01-01T00:00:00Z",
            "rotation_enabled": False,
            "multi_region": False,
            "warning": "This is a local development key - NOT SECURE FOR PRODUCTION",
        }


def get_key_management_service() -> KeyManagementService:
    """
    Factory function to get the appropriate key management service.

    Returns:
        KeyManagementService instance based on configuration
    """
    backend = current_app.config.get("KEY_MANAGEMENT_BACKEND", "local")

    if backend == "kms":
        # Validate KMS configuration
        if not (
            current_app.config.get("KMS_KEY_ID")
            or current_app.config.get("KMS_KEY_ALIAS")
        ):
            current_app.logger.warning(
                "KMS backend selected but no KMS_KEY_ID or KMS_KEY_ALIAS configured. "
                "Falling back to local key management."
            )
            return LocalKeyManagement()

        try:
            return KMSKeyManagement()
        except Exception as e:
            current_app.logger.error(
                f"Failed to initialize KMS key management: {str(e)}. "
                "Falling back to local key management."
            )
            return LocalKeyManagement()

    else:
        return LocalKeyManagement()
