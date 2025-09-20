"""Synchronization service for managing secrets across backends."""

from typing import Any, Dict, List, Optional

from flask import current_app

from ..models.audit_log import AuditAction, AuditLog, AuditResult
from ..models.base import BaseModel
from ..models.secret import Secret, SyncStatus
from .aws_secrets import AWSSecretsManager, AWSSecretsManagerError
from .vault_client import VaultClient, VaultClientError


class SyncError(Exception):
    """Custom exception for sync operations."""

    pass


class SyncService:
    """Service for synchronizing secrets between backends."""

    def __init__(self):
        """Initialize sync service with backend clients."""
        self.aws_client = AWSSecretsManager()
        self.vault_client = VaultClient()

    def test_backends(self) -> Dict[str, Any]:
        """Test connectivity to all backends."""
        results = {
            "aws": self.aws_client.test_connection(),
            "vault": self.vault_client.test_connection(),
        }

        overall_status = "success"
        if any(r["status"] == "error" for r in results.values()):
            overall_status = "error"
        elif any(r["status"] == "warning" for r in results.values()):
            overall_status = "warning"

        results["overall_status"] = overall_status
        return results

    def sync_secret_to_backends(
        self,
        secret: Secret,
        user_id: Optional[int] = None,
        backends: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Sync a secret to specified backends with transaction safety."""
        if backends is None:
            backends = ["aws", "vault"]

        results = {}
        overall_success = True

        # Use transaction safety to prevent database corruption during sync
        with BaseModel.safe_transaction():
            current_app.logger.debug(
                f"Starting sync for secret {secret.id} to backends: {backends}"
            )

            # Validate secret state before sync
            current_version = secret.current_version
            if not current_version:
                raise SyncError("No current version found for secret")

            # Test decryption before attempting sync to prevent data loss
            try:
                value = current_version.decrypt_value()
                current_app.logger.debug(
                    f"Successfully decrypted secret {secret.id} for sync"
                )
            except Exception as e:
                current_app.logger.error(
                    f"Failed to decrypt secret {secret.id} before sync: {str(e)}"
                )
                raise SyncError(
                    f"Cannot sync secret: decryption failed - {str(e)}"
                ) from e

            # Store original sync statuses for rollback if needed
            original_aws_status = secret.aws_sync_status
            original_vault_status = secret.vault_sync_status

            try:
                # Sync to AWS
                if "aws" in backends:
                    try:
                        current_app.logger.debug(f"Syncing secret {secret.id} to AWS")
                        results["aws"] = self.aws_client.sync_secret(secret, user_id)
                        if results["aws"]["status"] != "success":
                            overall_success = False
                            current_app.logger.warning(
                                f"AWS sync failed for secret {secret.id}: {results['aws']}"
                            )
                    except AWSSecretsManagerError as e:
                        current_app.logger.error(
                            f"AWS sync error for secret {secret.id}: {str(e)}"
                        )
                        results["aws"] = {"status": "error", "message": str(e)}
                        overall_success = False

                # Sync to Vault
                if "vault" in backends:
                    try:
                        current_app.logger.debug(f"Syncing secret {secret.id} to Vault")
                        results["vault"] = self.vault_client.sync_secret(
                            secret, user_id
                        )
                        if results["vault"]["status"] != "success":
                            overall_success = False
                            current_app.logger.warning(
                                f"Vault sync failed for secret {secret.id}: {results['vault']}"
                            )
                    except VaultClientError as e:
                        current_app.logger.error(
                            f"Vault sync error for secret {secret.id}: {str(e)}"
                        )
                        results["vault"] = {"status": "error", "message": str(e)}
                        overall_success = False

                # If any sync failed, consider rollback
                if not overall_success:
                    current_app.logger.warning(
                        f"Some backend syncs failed for secret {secret.id}, maintaining original sync statuses"
                    )
                    # Note: We don't rollback backend sync statuses here as they may have partially succeeded
                    # The sync status should reflect the actual state in each backend

                results["overall_success"] = overall_success
                current_app.logger.info(
                    f"Sync completed for secret {secret.id}: overall_success={overall_success}"
                )
                return results

            except Exception as e:
                # If there's a critical error, restore original sync statuses
                current_app.logger.error(
                    f"Critical error during sync for secret {secret.id}: {str(e)}"
                )
                secret.aws_sync_status = original_aws_status
                secret.vault_sync_status = original_vault_status
                raise SyncError(f"Sync failed with critical error: {str(e)}") from e

    def check_sync_status(self, secret: Secret) -> Dict[str, Any]:
        """Check if a secret is in sync across all backends."""
        status = {
            "secret_id": secret.id,
            "secret_name": secret.name,
            "environment": secret.environment.name,
            "aws_status": secret.aws_sync_status.value,
            "vault_status": secret.vault_sync_status.value,
            "overall_status": secret.sync_status,
            "needs_sync": False,
            "issues": [],
        }

        # Check if sync is needed
        if secret.aws_sync_status in [
            SyncStatus.OUT_OF_SYNC,
            SyncStatus.SYNC_PENDING,
            SyncStatus.SYNC_ERROR,
        ]:
            status["needs_sync"] = True
            status["issues"].append(f"AWS: {secret.aws_sync_status.value}")

        if secret.vault_sync_status in [
            SyncStatus.OUT_OF_SYNC,
            SyncStatus.SYNC_PENDING,
            SyncStatus.SYNC_ERROR,
        ]:
            status["needs_sync"] = True
            status["issues"].append(f"Vault: {secret.vault_sync_status.value}")

        return status

    def compare_secret_values(self, secret: Secret) -> Dict[str, Any]:
        """Compare secret values across backends."""
        comparison = {
            "secret_id": secret.id,
            "keeper_value_hash": None,
            "aws_value_hash": None,
            "vault_value_hash": None,
            "values_match": False,
            "errors": [],
        }

        try:
            # Get Keeper value
            current_version = secret.current_version
            if current_version:
                keeper_value = current_version.decrypt_value()
                comparison["keeper_value_hash"] = current_version.value_hash
            else:
                comparison["errors"].append("No current version in Keeper")
                return comparison

            # Get AWS value
            try:
                aws_result = self.aws_client.get_secret(secret)
                if aws_result["status"] == "success":
                    import hashlib

                    aws_hash = hashlib.sha256(
                        aws_result["value"].encode("utf-8")
                    ).hexdigest()
                    comparison["aws_value_hash"] = aws_hash
                else:
                    comparison["errors"].append(f"AWS: {aws_result['message']}")
            except Exception as e:
                comparison["errors"].append(f"AWS error: {str(e)}")

            # Get Vault value
            try:
                vault_result = self.vault_client.get_secret(secret)
                if vault_result["status"] == "success":
                    vault_value = vault_result["data"].get("data", "")
                    import hashlib

                    vault_hash = hashlib.sha256(
                        str(vault_value).encode("utf-8")
                    ).hexdigest()
                    comparison["vault_value_hash"] = vault_hash
                else:
                    comparison["errors"].append(f"Vault: {vault_result['message']}")
            except Exception as e:
                comparison["errors"].append(f"Vault error: {str(e)}")

            # Check if all values match
            hashes = [
                h
                for h in [
                    comparison["keeper_value_hash"],
                    comparison["aws_value_hash"],
                    comparison["vault_value_hash"],
                ]
                if h is not None
            ]

            comparison["values_match"] = len(set(hashes)) <= 1 and len(hashes) > 0

        except Exception as e:
            comparison["errors"].append(f"Comparison error: {str(e)}")

        return comparison

    def bulk_sync_secrets(
        self,
        secrets: List[Secret],
        user_id: Optional[int] = None,
        backends: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Sync multiple secrets to backends."""
        results = {
            "total_secrets": len(secrets),
            "successful": 0,
            "failed": 0,
            "results": [],
            "errors": [],
        }

        for secret in secrets:
            try:
                sync_result = self.sync_secret_to_backends(secret, user_id, backends)
                results["results"].append(
                    {
                        "secret_id": secret.id,
                        "secret_name": secret.name,
                        "result": sync_result,
                    }
                )

                if sync_result["overall_success"]:
                    results["successful"] += 1
                else:
                    results["failed"] += 1

            except Exception as e:
                results["failed"] += 1
                results["errors"].append(
                    {
                        "secret_id": secret.id,
                        "secret_name": secret.name,
                        "error": str(e),
                    }
                )

        return results

    def sync_environment_secrets(
        self,
        environment_id: int,
        user_id: Optional[int] = None,
        backends: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Sync all secrets in an environment."""
        from ..models.environment import Environment

        environment = Environment.query.get(environment_id)
        if not environment:
            raise SyncError(f"Environment {environment_id} not found")

        secrets = environment.secrets.filter_by(is_active=True).all()
        return self.bulk_sync_secrets(secrets, user_id, backends)

    def get_out_of_sync_secrets(
        self, environment_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get all secrets that are out of sync."""
        query = Secret.query.filter(
            (Secret.aws_sync_status == SyncStatus.OUT_OF_SYNC)
            | (Secret.vault_sync_status == SyncStatus.OUT_OF_SYNC)
            | (Secret.aws_sync_status == SyncStatus.SYNC_ERROR)
            | (Secret.vault_sync_status == SyncStatus.SYNC_ERROR)
        ).filter_by(is_active=True)

        if environment_id:
            query = query.filter_by(environment_id=environment_id)

        secrets = query.all()

        return [self.check_sync_status(secret) for secret in secrets]

    def repair_sync_status(
        self, secret: Secret, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Attempt to repair sync status by checking actual backend states."""
        repair_results = {
            "secret_id": secret.id,
            "secret_name": secret.name,
            "aws_repaired": False,
            "vault_repaired": False,
            "errors": [],
        }

        # Check AWS
        try:
            aws_result = self.aws_client.get_secret(secret)
            if aws_result["status"] == "success":
                secret.update_aws_sync_status(
                    status=SyncStatus.SYNCED,
                    arn=aws_result.get("arn"),
                    version_id=aws_result.get("version_id"),
                )
                repair_results["aws_repaired"] = True
            elif aws_result["status"] == "not_found":
                secret.update_aws_sync_status(status=SyncStatus.NOT_SYNCED)
                repair_results["aws_repaired"] = True
        except Exception as e:
            repair_results["errors"].append(f"AWS repair failed: {str(e)}")

        # Check Vault
        try:
            vault_result = self.vault_client.get_secret(secret)
            if vault_result["status"] == "success":
                secret.update_vault_sync_status(
                    status=SyncStatus.SYNCED,
                    path=secret.get_vault_path(),
                    version=vault_result.get("version"),
                )
                repair_results["vault_repaired"] = True
            elif vault_result["status"] == "not_found":
                secret.update_vault_sync_status(status=SyncStatus.NOT_SYNCED)
                repair_results["vault_repaired"] = True
        except Exception as e:
            repair_results["errors"].append(f"Vault repair failed: {str(e)}")

        # Log the repair operation
        if user_id:
            AuditLog.log_secret_action(
                action=AuditAction.UPDATE,
                result=(
                    AuditResult.SUCCESS
                    if repair_results["aws_repaired"]
                    or repair_results["vault_repaired"]
                    else AuditResult.PARTIAL
                ),
                secret=secret,
                user_id=user_id,
                details={
                    "operation": "sync_repair",
                    "aws_repaired": repair_results["aws_repaired"],
                    "vault_repaired": repair_results["vault_repaired"],
                    "errors": repair_results["errors"],
                },
            )

        return repair_results

    def delete_from_backends(
        self,
        secret: Secret,
        user_id: Optional[int] = None,
        backends: Optional[List[str]] = None,
        force_delete: bool = False,
    ) -> Dict[str, Any]:
        """Delete a secret from specified backends."""
        if backends is None:
            backends = ["aws", "vault"]

        results = {}
        overall_success = True

        # Delete from AWS
        if "aws" in backends:
            try:
                results["aws"] = self.aws_client.delete_secret(
                    secret, user_id, force_delete
                )
                if results["aws"]["status"] != "success":
                    overall_success = False
            except Exception as e:
                results["aws"] = {"status": "error", "message": str(e)}
                overall_success = False

        # Delete from Vault
        if "vault" in backends:
            try:
                results["vault"] = self.vault_client.delete_secret(
                    secret, user_id, force_delete
                )
                if results["vault"]["status"] != "success":
                    overall_success = False
            except Exception as e:
                results["vault"] = {"status": "error", "message": str(e)}
                overall_success = False

        results["overall_success"] = overall_success
        return results
