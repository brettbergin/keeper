"""AWS KMS service for envelope encryption."""

import base64
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import current_app


class KMSDataKey:
    """Represents a data encryption key from KMS."""

    def __init__(self, plaintext_key: bytes, encrypted_key: bytes, key_id: str):
        self.plaintext_key = plaintext_key
        self.encrypted_key = encrypted_key
        self.key_id = key_id
        self.created_at = datetime.utcnow()

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if the key has exceeded its TTL."""
        return datetime.utcnow() - self.created_at > timedelta(seconds=ttl_seconds)


class DEKCache:
    """In-memory cache for Data Encryption Keys with TTL."""

    def __init__(self):
        self._cache: Dict[str, KMSDataKey] = {}
        self._lock = Lock()

    def get(self, cache_key: str, ttl_seconds: int) -> Optional[KMSDataKey]:
        """Get a cached DEK if it exists and hasn't expired."""
        with self._lock:
            if cache_key in self._cache:
                dek = self._cache[cache_key]
                if not dek.is_expired(ttl_seconds):
                    return dek
                else:
                    del self._cache[cache_key]
            return None

    def put(self, cache_key: str, dek: KMSDataKey) -> None:
        """Cache a DEK."""
        with self._lock:
            self._cache[cache_key] = dek

    def clear(self) -> None:
        """Clear all cached keys."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self, ttl_seconds: int) -> None:
        """Remove expired keys from cache."""
        with self._lock:
            expired_keys = [
                key for key, dek in self._cache.items() if dek.is_expired(ttl_seconds)
            ]
            for key in expired_keys:
                del self._cache[key]


class KMSService:
    """AWS Key Management Service wrapper for envelope encryption."""

    def __init__(self):
        self._client = None
        self._dek_cache = DEKCache()

    @property
    def client(self):
        """Lazy initialization of KMS client."""
        if self._client is None:
            self._client = boto3.client(
                "kms",
                region_name=current_app.config.get("KMS_REGION"),
                aws_access_key_id=current_app.config.get("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=current_app.config.get("AWS_SECRET_ACCESS_KEY"),
            )
        return self._client

    def generate_data_key(
        self,
        key_id: Optional[str] = None,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> KMSDataKey:
        """
        Generate a new data encryption key using KMS.

        Args:
            key_id: KMS key ID or alias to use
            encryption_context: Additional authenticated data

        Returns:
            KMSDataKey containing plaintext and encrypted key

        Raises:
            KMSServiceError: If key generation fails
        """
        try:
            key_spec = key_id or current_app.config.get("kms_key_spec")
            context = encryption_context or current_app.config.get(
                "kms_encryption_context"
            )

            current_app.logger.info(f"Generating data key using KMS key: {key_spec}")

            # Generate 256-bit (32 byte) data key for AES-256
            response = self.client.generate_data_key(
                KeyId=key_spec, KeySpec="AES_256", EncryptionContext=context
            )

            dek = KMSDataKey(
                plaintext_key=response["Plaintext"],
                encrypted_key=response["CiphertextBlob"],
                key_id=response["KeyId"],
            )

            current_app.logger.info(
                f"Successfully generated data key with KMS key ID: {dek.key_id}"
            )

            return dek

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError generating data key: {error_code} - {error_message}"
            )
            raise KMSServiceError(
                f"Failed to generate data key: {error_message}"
            ) from e
        except BotoCoreError as e:
            current_app.logger.error(f"BotoCore error generating data key: {str(e)}")
            raise KMSServiceError(f"KMS service unavailable: {str(e)}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error generating data key: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def decrypt_data_key(
        self, encrypted_key: bytes, encryption_context: Optional[Dict[str, str]] = None
    ) -> bytes:
        """
        Decrypt a data encryption key using KMS.

        Args:
            encrypted_key: The encrypted data key blob
            encryption_context: Additional authenticated data used during encryption

        Returns:
            Plaintext data key bytes

        Raises:
            KMSServiceError: If decryption fails
        """
        try:
            # Check cache first
            cache_key = base64.b64encode(encrypted_key).decode("utf-8")
            ttl = current_app.config.get("KMS_DEK_CACHE_TTL", 3600)

            cached_dek = self._dek_cache.get(cache_key, ttl)
            if cached_dek:
                current_app.logger.debug("Using cached data key")
                return cached_dek.plaintext_key

            context = encryption_context or current_app.config.get(
                "kms_encryption_context"
            )

            current_app.logger.debug("Decrypting data key via KMS")

            response = self.client.decrypt(
                CiphertextBlob=encrypted_key, EncryptionContext=context
            )

            plaintext_key = response["Plaintext"]

            # Cache the decrypted key
            dek = KMSDataKey(
                plaintext_key=plaintext_key,
                encrypted_key=encrypted_key,
                key_id=response["KeyId"],
            )
            self._dek_cache.put(cache_key, dek)

            current_app.logger.debug("Successfully decrypted data key")
            return plaintext_key

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError decrypting data key: {error_code} - {error_message}"
            )
            raise KMSServiceError(f"Failed to decrypt data key: {error_message}") from e
        except BotoCoreError as e:
            current_app.logger.error(f"BotoCore error decrypting data key: {str(e)}")
            raise KMSServiceError(f"KMS service unavailable: {str(e)}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error decrypting data key: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def rotate_key(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Initiate rotation of a KMS Customer Master Key.

        Args:
            key_id: KMS key ID or alias to rotate

        Returns:
            Dictionary with rotation status information

        Raises:
            KMSServiceError: If rotation fails
        """
        try:
            key_spec = key_id or current_app.config.get("kms_key_spec")

            current_app.logger.info(f"Initiating key rotation for: {key_spec}")

            # Enable automatic key rotation
            self.client.enable_key_rotation(KeyId=key_spec)

            # Get rotation status
            rotation_response = self.client.get_key_rotation_status(KeyId=key_spec)

            current_app.logger.info(f"Key rotation initiated for: {key_spec}")

            return {
                "key_id": key_spec,
                "rotation_enabled": rotation_response["KeyRotationEnabled"],
                "initiated_at": datetime.utcnow().isoformat(),
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError rotating key: {error_code} - {error_message}"
            )
            raise KMSServiceError(f"Failed to rotate key: {error_message}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error rotating key: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def get_key_info(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about a KMS key.

        Args:
            key_id: KMS key ID or alias

        Returns:
            Dictionary with key information

        Raises:
            KMSServiceError: If key info retrieval fails
        """
        try:
            key_spec = key_id or current_app.config.get("kms_key_spec")

            response = self.client.describe_key(KeyId=key_spec)
            key_metadata = response["KeyMetadata"]

            # Get rotation status if applicable
            rotation_enabled = False
            try:
                rotation_response = self.client.get_key_rotation_status(KeyId=key_spec)
                rotation_enabled = rotation_response["KeyRotationEnabled"]
            except ClientError:
                pass  # Key might not support rotation

            return {
                "key_id": key_metadata["KeyId"],
                "arn": key_metadata["Arn"],
                "description": key_metadata.get("Description", ""),
                "key_usage": key_metadata["KeyUsage"],
                "key_state": key_metadata["KeyState"],
                "creation_date": key_metadata["CreationDate"].isoformat(),
                "rotation_enabled": rotation_enabled,
                "multi_region": key_metadata.get("MultiRegion", False),
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError getting key info: {error_code} - {error_message}"
            )
            raise KMSServiceError(f"Failed to get key info: {error_message}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error getting key info: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def create_grant(
        self,
        key_id: str,
        grantee_principal: str,
        operations: list,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Create a grant for a KMS key.

        Args:
            key_id: KMS key ID or alias
            grantee_principal: Principal to grant access to
            operations: List of allowed operations
            encryption_context: Encryption context constraints

        Returns:
            Grant token

        Raises:
            KMSServiceError: If grant creation fails
        """
        try:
            grant_params = {
                "KeyId": key_id,
                "GranteePrincipal": grantee_principal,
                "Operations": operations,
            }

            if encryption_context:
                grant_params["Constraints"] = {
                    "EncryptionContextSubset": encryption_context
                }

            response = self.client.create_grant(**grant_params)

            current_app.logger.info(
                f"Created grant {response['GrantId']} for principal {grantee_principal}"
            )

            return response["GrantToken"]

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError creating grant: {error_code} - {error_message}"
            )
            raise KMSServiceError(f"Failed to create grant: {error_message}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error creating grant: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def retire_grant(self, grant_token: str, key_id: Optional[str] = None) -> None:
        """
        Retire a KMS grant.

        Args:
            grant_token: Grant token to retire
            key_id: KMS key ID (optional if grant token is sufficient)

        Raises:
            KMSServiceError: If grant retirement fails
        """
        try:
            params = {"GrantToken": grant_token}
            if key_id:
                params["KeyId"] = key_id

            self.client.retire_grant(**params)

            current_app.logger.info(f"Retired grant with token: {grant_token}")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            current_app.logger.error(
                f"KMS ClientError retiring grant: {error_code} - {error_message}"
            )
            raise KMSServiceError(f"Failed to retire grant: {error_message}") from e
        except Exception as e:
            current_app.logger.error(f"Unexpected error retiring grant: {str(e)}")
            raise KMSServiceError(f"Unexpected error: {str(e)}") from e

    def cleanup_cache(self) -> None:
        """Clean up expired DEKs from cache."""
        ttl = current_app.config.get("KMS_DEK_CACHE_TTL", 3600)
        self._dek_cache.cleanup_expired(ttl)

    def clear_cache(self) -> None:
        """Clear all cached DEKs."""
        self._dek_cache.clear()


class KMSServiceError(Exception):
    """Exception raised for KMS service errors."""

    pass
