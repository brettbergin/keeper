"""Migration script to move existing secrets from legacy encryption to KMS envelope encryption."""

import json
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ..models.database import db
from ..models.secret import Secret
from ..models.secret_version import SecretVersion
from ..services.key_management import KeyManagementError, get_key_management_service


class KMSMigrationError(Exception):
    """Exception raised during KMS migration."""

    pass


class KMSMigration:
    """Handles migration of secrets from legacy encryption to KMS envelope encryption."""

    def __init__(self, dry_run: bool = False, batch_size: int = 100):
        self.dry_run = dry_run
        self.batch_size = batch_size
        self.logger = logging.getLogger(__name__)
        self.migration_stats = {
            "total_secrets": 0,
            "migrated_secrets": 0,
            "failed_secrets": 0,
            "skipped_secrets": 0,
            "migration_errors": [],
        }

    def run_migration(self, environment_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Run the complete KMS migration process.

        Args:
            environment_id: Migrate only secrets in specific environment (optional)

        Returns:
            Dictionary with migration results and statistics
        """
        self.logger.info(f"Starting KMS migration (dry_run={self.dry_run})")

        try:
            # Validate prerequisites
            self._validate_prerequisites()

            # Get secrets to migrate
            secrets_to_migrate = self._get_secrets_to_migrate(environment_id)
            self.migration_stats["total_secrets"] = len(secrets_to_migrate)

            if not secrets_to_migrate:
                self.logger.info("No secrets found for migration")
                return self._build_results()

            self.logger.info(f"Found {len(secrets_to_migrate)} secrets to migrate")

            # Create backup if not dry run
            if not self.dry_run:
                backup_file = self._create_backup()
                self.migration_stats["backup_file"] = backup_file

            # Migrate secrets in batches
            self._migrate_secrets_in_batches(secrets_to_migrate)

            # Verify migration if not dry run
            if not self.dry_run:
                self._verify_migration(secrets_to_migrate)

            return self._build_results()

        except Exception as e:
            self.logger.error(f"Migration failed with error: {str(e)}")
            self.migration_stats["migration_errors"].append(f"Fatal error: {str(e)}")
            raise KMSMigrationError(f"Migration failed: {str(e)}") from e

    def _validate_prerequisites(self) -> None:
        """Validate that prerequisites for KMS migration are met."""
        self.logger.info("Validating migration prerequisites")

        # Check if KMS is properly configured
        try:
            km_service = get_key_management_service()
            key_info = km_service.get_key_info()

            if "error" in key_info:
                raise KMSMigrationError(f"KMS configuration error: {key_info['error']}")

            self.logger.info(
                f"KMS key validation successful: {key_info.get('key_id', 'unknown')}"
            )

        except KeyManagementError as e:
            raise KMSMigrationError(f"KMS service error: {str(e)}") from e
        except Exception as e:
            raise KMSMigrationError(f"Failed to validate KMS setup: {str(e)}") from e

        # Check database connectivity
        try:
            db.session.execute(text("SELECT 1")).fetchone()
        except SQLAlchemyError as e:
            raise KMSMigrationError(f"Database connectivity error: {str(e)}") from e

        self.logger.info("Prerequisites validation completed successfully")

    def _get_secrets_to_migrate(
        self, environment_id: Optional[int] = None
    ) -> List[SecretVersion]:
        """Get list of secret versions that need migration to KMS."""
        self.logger.info("Identifying secrets for migration")

        query = db.session.query(SecretVersion).filter(
            # Legacy encryption algorithms that need migration
            SecretVersion.encryption_algorithm.in_(["aes-256-gcm", "fernet"]),
            # Only migrate current versions initially
            SecretVersion.is_current == True,
        )

        if environment_id:
            query = query.join(Secret).filter(Secret.environment_id == environment_id)

        secret_versions = query.all()

        self.logger.info(f"Found {len(secret_versions)} secret versions for migration")

        return secret_versions

    def _create_backup(self) -> str:
        """Create a backup of existing secret data before migration."""
        backup_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = f"keeper_secrets_backup_{backup_timestamp}.json"

        self.logger.info(f"Creating backup: {backup_file}")

        try:
            # Export all secret metadata (not values for security)
            backup_data = {
                "backup_timestamp": backup_timestamp,
                "migration_type": "kms_envelope_encryption",
                "secrets": [],
            }

            secret_versions = (
                db.session.query(SecretVersion)
                .filter(
                    SecretVersion.encryption_algorithm.in_(["aes-256-gcm", "fernet"])
                )
                .all()
            )

            for version in secret_versions:
                backup_data["secrets"].append(
                    {
                        "secret_version_id": version.id,
                        "secret_id": version.secret_id,
                        "version_number": version.version_number,
                        "is_current": version.is_current,
                        "encryption_algorithm": version.encryption_algorithm,
                        "encryption_key_id": version.encryption_key_id,
                        "created_at": (
                            version.created_at.isoformat()
                            if version.created_at
                            else None
                        ),
                        "secret_name": version.secret.name if version.secret else None,
                        "environment_name": (
                            version.secret.environment.name
                            if version.secret and version.secret.environment
                            else None
                        ),
                    }
                )

            # Write backup to file
            with open(backup_file, "w") as f:
                json.dump(backup_data, f, indent=2)

            self.logger.info(f"Backup created successfully: {backup_file}")
            return backup_file

        except Exception as e:
            raise KMSMigrationError(f"Failed to create backup: {str(e)}") from e

    def _migrate_secrets_in_batches(
        self, secrets_to_migrate: List[SecretVersion]
    ) -> None:
        """Migrate secrets in batches to avoid memory issues."""
        self.logger.info(f"Migrating secrets in batches of {self.batch_size}")

        total_batches = (
            len(secrets_to_migrate) + self.batch_size - 1
        ) // self.batch_size

        for batch_num in range(total_batches):
            start_idx = batch_num * self.batch_size
            end_idx = min(start_idx + self.batch_size, len(secrets_to_migrate))
            batch = secrets_to_migrate[start_idx:end_idx]

            self.logger.info(
                f"Processing batch {batch_num + 1}/{total_batches} ({len(batch)} secrets)"
            )

            with self._database_transaction():
                for secret_version in batch:
                    try:
                        self._migrate_single_secret(secret_version)
                        self.migration_stats["migrated_secrets"] += 1
                    except Exception as e:
                        self.migration_stats["failed_secrets"] += 1
                        error_msg = f"Failed to migrate secret version {secret_version.id}: {str(e)}"
                        self.logger.error(error_msg)
                        self.migration_stats["migration_errors"].append(error_msg)

                        # Continue with other secrets unless it's a critical error
                        if "KMS service unavailable" in str(e):
                            raise KMSMigrationError(
                                "KMS service unavailable - stopping migration"
                            )

            # Log progress
            progress = ((batch_num + 1) / total_batches) * 100
            self.logger.info(f"Migration progress: {progress:.1f}% complete")

    def _migrate_single_secret(self, secret_version: SecretVersion) -> None:
        """Migrate a single secret version to KMS envelope encryption."""
        self.logger.debug(f"Migrating secret version {secret_version.id}")

        # Skip if already using KMS envelope encryption
        if secret_version.encryption_algorithm.endswith("-kms"):
            self.migration_stats["skipped_secrets"] += 1
            self.logger.debug(
                f"Skipping secret version {secret_version.id} - already using KMS"
            )
            return

        try:
            # Decrypt using legacy method
            plaintext_value = secret_version._decrypt_legacy()

            if not self.dry_run:
                # Get environment-specific encryption context
                encryption_context = None
                if secret_version.secret and secret_version.secret.environment:
                    encryption_context = (
                        secret_version.secret.environment.get_encryption_context()
                    )

                # Re-encrypt using KMS envelope encryption
                secret_version.encrypt_value(plaintext_value, encryption_context)

                # Save the updated version
                db.session.flush()

                self.logger.debug(
                    f"Successfully migrated secret version {secret_version.id}"
                )
            else:
                self.logger.debug(
                    f"DRY RUN: Would migrate secret version {secret_version.id}"
                )

        except Exception as e:
            self.logger.error(
                f"Failed to migrate secret version {secret_version.id}: {str(e)}"
            )
            raise

    def _verify_migration(self, migrated_secrets: List[SecretVersion]) -> None:
        """Verify that migrated secrets can be decrypted successfully."""
        self.logger.info("Verifying migration success")

        verification_errors = []
        verified_count = 0

        for secret_version in migrated_secrets:
            try:
                # Refresh from database
                db.session.refresh(secret_version)

                # Skip if it was skipped during migration
                if not secret_version.encryption_algorithm.endswith("-kms"):
                    continue

                # Try to decrypt the secret
                decrypted_value = secret_version.decrypt_value()

                # Verify integrity if hash exists
                if secret_version.value_hash and not secret_version.verify_integrity(
                    decrypted_value
                ):
                    verification_errors.append(
                        f"Integrity check failed for secret version {secret_version.id}"
                    )
                else:
                    verified_count += 1

            except Exception as e:
                verification_errors.append(
                    f"Failed to verify secret version {secret_version.id}: {str(e)}"
                )

        self.migration_stats["verified_secrets"] = verified_count
        self.migration_stats["verification_errors"] = verification_errors

        if verification_errors:
            self.logger.error(
                f"Verification failed for {len(verification_errors)} secrets"
            )
            for error in verification_errors[:10]:  # Log first 10 errors
                self.logger.error(f"Verification error: {error}")

            if len(verification_errors) > 10:
                self.logger.error(
                    f"... and {len(verification_errors) - 10} more verification errors"
                )
        else:
            self.logger.info(
                f"Migration verification successful for {verified_count} secrets"
            )

    @contextmanager
    def _database_transaction(self):
        """Context manager for database transactions with rollback on error."""
        if self.dry_run:
            # In dry run mode, always rollback
            try:
                yield
            finally:
                db.session.rollback()
        else:
            # In real mode, commit on success, rollback on error
            try:
                yield
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise

    def _build_results(self) -> Dict[str, Any]:
        """Build migration results dictionary."""
        return {
            "success": self.migration_stats["failed_secrets"] == 0,
            "dry_run": self.dry_run,
            "statistics": self.migration_stats,
            "summary": {
                "total_secrets": self.migration_stats["total_secrets"],
                "migrated_secrets": self.migration_stats["migrated_secrets"],
                "failed_secrets": self.migration_stats["failed_secrets"],
                "skipped_secrets": self.migration_stats["skipped_secrets"],
                "success_rate": (
                    (
                        self.migration_stats["migrated_secrets"]
                        / self.migration_stats["total_secrets"]
                        * 100
                    )
                    if self.migration_stats["total_secrets"] > 0
                    else 0
                ),
            },
        }


def run_kms_migration(
    environment_id: Optional[int] = None, dry_run: bool = True, batch_size: int = 100
) -> Dict[str, Any]:
    """
    Convenience function to run KMS migration.

    Args:
        environment_id: Migrate only secrets in specific environment
        dry_run: If True, don't make actual changes
        batch_size: Number of secrets to process in each batch

    Returns:
        Dictionary with migration results
    """
    migration = KMSMigration(dry_run=dry_run, batch_size=batch_size)
    return migration.run_migration(environment_id)


def rollback_kms_migration(backup_file: str) -> Dict[str, Any]:
    """
    Rollback KMS migration using a backup file.

    Args:
        backup_file: Path to the backup file created during migration

    Returns:
        Dictionary with rollback results
    """
    # This is a complex operation that would require careful implementation
    # For now, return a placeholder
    return {
        "success": False,
        "message": "Rollback functionality not yet implemented. Please restore from database backup.",
    }
