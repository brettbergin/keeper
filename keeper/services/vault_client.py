"""HashiCorp Vault integration service."""

import json
from typing import Any, Dict, List, Optional

import hvac
from flask import current_app

from ..models.audit_log import AuditAction, AuditLog, AuditResult
from ..models.secret import Secret, SyncStatus


class VaultClientError(Exception):
    """Custom exception for Vault operations."""

    pass


class VaultClient:
    """Service class for HashiCorp Vault operations."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None):
        """Initialize Vault client."""
        self.url = url or current_app.config.get("VAULT_URL", "http://localhost:8200")
        self.token = token or current_app.config.get("VAULT_TOKEN")
        self.mount_point = current_app.config.get("VAULT_MOUNT_POINT", "secret")
        self._client = None

    @property
    def client(self):
        """Lazy initialization of hvac client."""
        if self._client is None:
            self._client = hvac.Client(url=self.url, token=self.token)
            if not self._client.is_authenticated():
                raise VaultClientError("Failed to authenticate with Vault")
        return self._client

    def test_connection(self) -> Dict[str, Any]:
        """Test Vault connectivity and authentication."""
        try:
            client = hvac.Client(url=self.url, token=self.token)

            if not client.is_authenticated():
                return {
                    "status": "error",
                    "message": "Authentication failed - invalid token",
                }

            # Test read capability
            try:
                client.secrets.kv.v2.list_secrets(mount_point=self.mount_point, path="")
            except hvac.exceptions.Forbidden:
                return {
                    "status": "warning",
                    "message": "Connected but limited permissions",
                }
            except hvac.exceptions.InvalidPath:
                # Mount point might not exist or be empty
                pass

            return {
                "status": "success",
                "url": self.url,
                "mount_point": self.mount_point,
                "message": "Successfully connected to Vault",
            }

        except hvac.exceptions.VaultError as e:
            return {"status": "error", "message": f"Vault error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Connection failed: {str(e)}"}

    def create_secret(
        self, secret: Secret, value: str, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Create a secret in Vault."""
        secret_path = secret.get_vault_path()

        try:
            # Prepare secret data
            if secret.secret_type.value in ["json", "yaml"]:
                try:
                    secret_data = (
                        json.loads(value)
                        if secret.secret_type.value == "json"
                        else {"data": value}
                    )
                except json.JSONDecodeError:
                    secret_data = {"data": value}
            else:
                secret_data = {"data": value}

            # Add metadata
            secret_data.update(
                {
                    "keeper_secret_id": str(secret.id),
                    "secret_type": secret.secret_type.value,
                    "secrecy_level": secret.secrecy_level.value,
                    "environment": secret.environment.name,
                    "service_name": secret.service_name,
                    "display_name": secret.display_name,
                }
            )

            # Create the secret using KV v2
            response = self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.mount_point, path=secret_path, secret=secret_data
            )

            # Update secret with Vault information
            secret.update_vault_sync_status(
                status=SyncStatus.SYNCED,
                path=secret_path,
                version=response["data"]["version"],
            )

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "create",
                        "vault_path": secret_path,
                        "version": response["data"]["version"],
                    },
                )

            return {
                "status": "success",
                "path": secret_path,
                "version": response["data"]["version"],
                "message": f"Secret '{secret_path}' created successfully in Vault",
            }

        except hvac.exceptions.InvalidPath:
            error_msg = f"Invalid path: {secret_path}"
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=error_msg,
                    details={"operation": "create"},
                )

            raise VaultClientError(error_msg)

        except hvac.exceptions.Forbidden:
            error_msg = "Insufficient permissions to create secret in Vault"
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=error_msg,
                    details={"operation": "create"},
                )

            raise VaultClientError(error_msg)

        except Exception as e:
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "create"},
                )

            raise VaultClientError(f"Failed to create secret: {str(e)}")

    def get_secret(
        self, secret: Secret, version: Optional[int] = None
    ) -> Dict[str, Any]:
        """Retrieve a secret from Vault."""
        secret_path = secret.get_vault_path()

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                mount_point=self.mount_point, path=secret_path, version=version
            )

            secret_data = response["data"]["data"]
            metadata = response["data"]["metadata"]

            return {
                "status": "success",
                "data": secret_data,
                "version": metadata["version"],
                "created_time": metadata["created_time"],
                "deletion_time": metadata.get("deletion_time"),
                "destroyed": metadata.get("destroyed", False),
            }

        except hvac.exceptions.InvalidPath:
            return {
                "status": "not_found",
                "message": f"Secret '{secret_path}' not found in Vault",
            }

        except hvac.exceptions.Forbidden:
            raise VaultClientError("Insufficient permissions to read secret from Vault")

        except Exception as e:
            raise VaultClientError(f"Failed to retrieve secret: {str(e)}")

    def update_secret(
        self, secret: Secret, value: str, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Update a secret in Vault."""
        secret_path = secret.get_vault_path()

        try:
            # Prepare secret data
            if secret.secret_type.value in ["json", "yaml"]:
                try:
                    secret_data = (
                        json.loads(value)
                        if secret.secret_type.value == "json"
                        else {"data": value}
                    )
                except json.JSONDecodeError:
                    secret_data = {"data": value}
            else:
                secret_data = {"data": value}

            # Add metadata
            secret_data.update(
                {
                    "keeper_secret_id": str(secret.id),
                    "secret_type": secret.secret_type.value,
                    "secrecy_level": secret.secrecy_level.value,
                    "environment": secret.environment.name,
                    "service_name": secret.service_name,
                    "display_name": secret.display_name,
                }
            )

            # Update the secret
            response = self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.mount_point, path=secret_path, secret=secret_data
            )

            # Update secret with new Vault information
            secret.update_vault_sync_status(
                status=SyncStatus.SYNCED,
                path=secret_path,
                version=response["data"]["version"],
            )

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "update",
                        "vault_path": secret_path,
                        "version": response["data"]["version"],
                    },
                )

            return {
                "status": "success",
                "path": secret_path,
                "version": response["data"]["version"],
                "message": f"Secret '{secret_path}' updated successfully in Vault",
            }

        except hvac.exceptions.InvalidPath:
            error_msg = f"Invalid path: {secret_path}"
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=error_msg,
                    details={"operation": "update"},
                )

            raise VaultClientError(error_msg)

        except hvac.exceptions.Forbidden:
            error_msg = "Insufficient permissions to update secret in Vault"
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=error_msg,
                    details={"operation": "update"},
                )

            raise VaultClientError(error_msg)

        except Exception as e:
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "update"},
                )

            raise VaultClientError(f"Failed to update secret: {str(e)}")

    def delete_secret(
        self, secret: Secret, user_id: Optional[int] = None, destroy: bool = False
    ) -> Dict[str, Any]:
        """Delete a secret from Vault."""
        secret_path = secret.get_vault_path()

        try:
            if destroy:
                # Permanently destroy all versions
                # First get all versions
                metadata = self.client.secrets.kv.v2.read_secret_metadata(
                    mount_point=self.mount_point, path=secret_path
                )
                versions = list(metadata["data"]["versions"].keys())

                # Destroy all versions
                response = self.client.secrets.kv.v2.destroy_secret_versions(
                    mount_point=self.mount_point, path=secret_path, versions=versions
                )
                message = f"Secret '{secret_path}' permanently destroyed in Vault"
            else:
                # Soft delete (mark for deletion)
                response = self.client.secrets.kv.v2.delete_latest_version_of_secret(
                    mount_point=self.mount_point, path=secret_path
                )
                message = f"Secret '{secret_path}' deleted in Vault (can be undeleted)"

            # Update sync status
            secret.update_vault_sync_status(status=SyncStatus.NOT_SYNCED)

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "delete",
                        "vault_path": secret_path,
                        "destroy": destroy,
                    },
                )

            return {"status": "success", "path": secret_path, "message": message}

        except hvac.exceptions.InvalidPath:
            return {
                "status": "not_found",
                "message": f"Secret '{secret_path}' not found in Vault",
            }

        except hvac.exceptions.Forbidden:
            error_msg = "Insufficient permissions to delete secret from Vault"

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=error_msg,
                    details={"operation": "delete"},
                )

            raise VaultClientError(error_msg)

        except Exception as e:
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_VAULT,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "delete"},
                )

            raise VaultClientError(f"Failed to delete secret: {str(e)}")

    def sync_secret(
        self, secret: Secret, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Synchronize a secret with Vault."""
        current_version = secret.current_version
        if not current_version:
            raise VaultClientError("No current version found for secret")

        try:
            # Get current value
            value = current_version.decrypt_value()

            # Check if secret exists in Vault
            vault_secret = self.get_secret(secret)

            if vault_secret["status"] == "not_found":
                # Create new secret
                return self.create_secret(secret, value, user_id)
            else:
                # Update existing secret
                return self.update_secret(secret, value, user_id)

        except Exception as e:
            secret.update_vault_sync_status(status=SyncStatus.SYNC_ERROR)
            raise VaultClientError(f"Failed to sync secret: {str(e)}")

    def list_secrets(self, path: str = "") -> List[Dict[str, Any]]:
        """List secrets in Vault."""
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                mount_point=self.mount_point, path=path
            )

            secrets = []
            if "keys" in response["data"]:
                for key in response["data"]["keys"]:
                    full_path = f"{path}/{key}".strip("/")
                    try:
                        # Get metadata
                        metadata = self.client.secrets.kv.v2.read_secret_metadata(
                            mount_point=self.mount_point, path=full_path
                        )

                        secrets.append(
                            {
                                "path": full_path,
                                "created_time": metadata["data"]["created_time"],
                                "updated_time": metadata["data"]["updated_time"],
                                "current_version": metadata["data"]["current_version"],
                                "oldest_version": metadata["data"]["oldest_version"],
                                "versions": list(metadata["data"]["versions"].keys()),
                            }
                        )
                    except Exception:
                        # If we can't get metadata, still include the path
                        secrets.append(
                            {"path": full_path, "error": "Could not retrieve metadata"}
                        )

            return secrets

        except hvac.exceptions.InvalidPath:
            return []
        except hvac.exceptions.Forbidden:
            raise VaultClientError("Insufficient permissions to list secrets")
        except Exception as e:
            raise VaultClientError(f"Failed to list secrets: {str(e)}")

    def get_secret_metadata(self, secret_path: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a secret without retrieving the value."""
        try:
            response = self.client.secrets.kv.v2.read_secret_metadata(
                mount_point=self.mount_point, path=secret_path
            )

            return {
                "path": secret_path,
                "created_time": response["data"]["created_time"],
                "updated_time": response["data"]["updated_time"],
                "current_version": response["data"]["current_version"],
                "oldest_version": response["data"]["oldest_version"],
                "max_versions": response["data"]["max_versions"],
                "cas_required": response["data"]["cas_required"],
                "delete_version_after": response["data"]["delete_version_after"],
                "versions": response["data"]["versions"],
            }

        except hvac.exceptions.InvalidPath:
            return None
        except Exception as e:
            raise VaultClientError(f"Failed to get secret metadata: {str(e)}")

    def get_secret_versions(self, secret_path: str) -> List[Dict[str, Any]]:
        """Get all versions of a secret."""
        try:
            metadata = self.get_secret_metadata(secret_path)
            if not metadata:
                return []

            versions = []
            for version_num, version_info in metadata["versions"].items():
                versions.append(
                    {
                        "version": int(version_num),
                        "created_time": version_info["created_time"],
                        "deletion_time": version_info.get("deletion_time"),
                        "destroyed": version_info.get("destroyed", False),
                    }
                )

            # Sort by version number descending
            return sorted(versions, key=lambda x: x["version"], reverse=True)

        except Exception as e:
            raise VaultClientError(f"Failed to get secret versions: {str(e)}")
