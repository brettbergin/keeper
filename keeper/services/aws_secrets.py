"""AWS Secrets Manager integration service."""

import json
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from flask import current_app

from ..models.audit_log import AuditAction, AuditLog, AuditResult
from ..models.secret import Secret, SyncStatus


class AWSSecretsManagerError(Exception):
    """Custom exception for AWS Secrets Manager operations."""

    pass


class AWSSecretsManager:
    """Service class for AWS Secrets Manager operations."""

    def __init__(self, region_name: Optional[str] = None):
        """Initialize AWS Secrets Manager client."""
        self.region_name = region_name or current_app.config.get(
            "AWS_REGION", "us-east-1"
        )
        self._client = None

    @property
    def client(self):
        """Lazy initialization of boto3 client."""
        if self._client is None:
            try:
                self._client = boto3.client(
                    "secretsmanager",
                    region_name=self.region_name,
                    aws_access_key_id=current_app.config.get("AWS_ACCESS_KEY_ID"),
                    aws_secret_access_key=current_app.config.get(
                        "AWS_SECRET_ACCESS_KEY"
                    ),
                )
            except NoCredentialsError:
                raise AWSSecretsManagerError("AWS credentials not configured")
        return self._client

    def test_connection(self) -> Dict[str, Any]:
        """Test AWS Secrets Manager connectivity."""
        try:
            # List secrets with limit to test connection
            response = self.client.list_secrets(MaxResults=1)
            return {
                "status": "success",
                "region": self.region_name,
                "message": "Successfully connected to AWS Secrets Manager",
            }
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            return {
                "status": "error",
                "error_code": error_code,
                "message": f"AWS error: {e.response['Error']['Message']}",
            }
        except Exception as e:
            return {"status": "error", "message": f"Connection failed: {str(e)}"}

    def create_secret(
        self, secret: Secret, value: str, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Create a secret in AWS Secrets Manager."""
        secret_name = secret.get_aws_secret_name()

        try:
            # Prepare secret data
            if secret.secret_type.value in ["json", "yaml"]:
                # Store structured data as JSON
                try:
                    secret_value = (
                        json.loads(value)
                        if secret.secret_type.value == "json"
                        else value
                    )
                except json.JSONDecodeError:
                    secret_value = value
            else:
                secret_value = value

            # Create tags
            tags = [
                {"Key": "Environment", "Value": secret.environment.name},
                {"Key": "SecretType", "Value": secret.secret_type.value},
                {"Key": "SecrecyLevel", "Value": secret.secrecy_level.value},
                {"Key": "ManagedBy", "Value": "Keeper"},
                {"Key": "KeeperSecretId", "Value": str(secret.id)},
            ]

            if secret.service_name:
                tags.append({"Key": "Service", "Value": secret.service_name})

            # Create the secret
            response = self.client.create_secret(
                Name=secret_name,
                Description=f"Keeper managed secret: {secret.display_name}",
                SecretString=(
                    json.dumps(secret_value)
                    if isinstance(secret_value, dict)
                    else str(secret_value)
                ),
                Tags=tags,
            )

            # Update secret with AWS information
            secret.update_aws_sync_status(
                status=SyncStatus.SYNCED,
                arn=response["ARN"],
                version_id=response["VersionId"],
            )

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "create",
                        "aws_arn": response["ARN"],
                        "version_id": response["VersionId"],
                    },
                )

            return {
                "status": "success",
                "arn": response["ARN"],
                "version_id": response["VersionId"],
                "message": f"Secret '{secret_name}' created successfully in AWS",
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            # Update sync status to error
            secret.update_aws_sync_status(status=SyncStatus.SYNC_ERROR)

            # Log the error
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=f"AWS error: {error_message}",
                    details={"operation": "create", "error_code": error_code},
                )

            if error_code == "ResourceExistsException":
                return {
                    "status": "error",
                    "error_code": error_code,
                    "message": f"Secret '{secret_name}' already exists in AWS",
                }

            raise AWSSecretsManagerError(f"Failed to create secret: {error_message}")

        except Exception as e:
            secret.update_aws_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "create"},
                )

            raise AWSSecretsManagerError(f"Failed to create secret: {str(e)}")

    def get_secret(self, secret: Secret) -> Dict[str, Any]:
        """Retrieve a secret from AWS Secrets Manager."""
        secret_name = secret.get_aws_secret_name()

        try:
            response = self.client.get_secret_value(SecretId=secret_name)

            return {
                "status": "success",
                "value": response["SecretString"],
                "arn": response["ARN"],
                "version_id": response["VersionId"],
                "created_date": response["CreatedDate"].isoformat(),
                "version_stages": response.get("VersionStages", []),
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            if error_code == "ResourceNotFoundException":
                return {
                    "status": "not_found",
                    "message": f"Secret '{secret_name}' not found in AWS",
                }

            raise AWSSecretsManagerError(f"Failed to retrieve secret: {error_message}")

    def update_secret(
        self, secret: Secret, value: str, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Update a secret in AWS Secrets Manager."""
        secret_name = secret.get_aws_secret_name()

        try:
            # Prepare secret data
            if secret.secret_type.value in ["json", "yaml"]:
                try:
                    secret_value = (
                        json.loads(value)
                        if secret.secret_type.value == "json"
                        else value
                    )
                except json.JSONDecodeError:
                    secret_value = value
            else:
                secret_value = value

            # Update the secret
            response = self.client.update_secret(
                SecretId=secret_name,
                Description=f"Keeper managed secret: {secret.display_name}",
                SecretString=(
                    json.dumps(secret_value)
                    if isinstance(secret_value, dict)
                    else str(secret_value)
                ),
            )

            # Update secret with new AWS information
            secret.update_aws_sync_status(
                status=SyncStatus.SYNCED,
                arn=response["ARN"],
                version_id=response["VersionId"],
            )

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "update",
                        "aws_arn": response["ARN"],
                        "version_id": response["VersionId"],
                    },
                )

            return {
                "status": "success",
                "arn": response["ARN"],
                "version_id": response["VersionId"],
                "message": f"Secret '{secret_name}' updated successfully in AWS",
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            secret.update_aws_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=f"AWS error: {error_message}",
                    details={"operation": "update", "error_code": error_code},
                )

            if error_code == "ResourceNotFoundException":
                return {
                    "status": "not_found",
                    "message": f"Secret '{secret_name}' not found in AWS",
                }

            raise AWSSecretsManagerError(f"Failed to update secret: {error_message}")

        except Exception as e:
            secret.update_aws_sync_status(status=SyncStatus.SYNC_ERROR)

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "update"},
                )

            raise AWSSecretsManagerError(f"Failed to update secret: {str(e)}")

    def delete_secret(
        self, secret: Secret, user_id: Optional[int] = None, force_delete: bool = False
    ) -> Dict[str, Any]:
        """Delete a secret from AWS Secrets Manager."""
        secret_name = secret.get_aws_secret_name()

        try:
            if force_delete:
                # Immediate deletion (cannot be undone)
                response = self.client.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )
                message = f"Secret '{secret_name}' permanently deleted from AWS"
            else:
                # Schedule for deletion (can be restored within recovery window)
                response = self.client.delete_secret(
                    SecretId=secret_name,
                    RecoveryWindowInDays=7,  # Default 7 days recovery window
                )
                message = f"Secret '{secret_name}' scheduled for deletion from AWS (7 day recovery window)"

            # Update sync status
            secret.update_aws_sync_status(status=SyncStatus.NOT_SYNCED)

            # Log the operation
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.SUCCESS,
                    secret=secret,
                    user_id=user_id,
                    details={
                        "operation": "delete",
                        "force_delete": force_delete,
                        "deletion_date": (
                            response.get("DeletionDate", "").isoformat()
                            if response.get("DeletionDate")
                            else None
                        ),
                    },
                )

            return {
                "status": "success",
                "arn": response["ARN"],
                "deletion_date": (
                    response.get("DeletionDate", "").isoformat()
                    if response.get("DeletionDate")
                    else None
                ),
                "message": message,
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=f"AWS error: {error_message}",
                    details={"operation": "delete", "error_code": error_code},
                )

            if error_code == "ResourceNotFoundException":
                return {
                    "status": "not_found",
                    "message": f"Secret '{secret_name}' not found in AWS",
                }

            raise AWSSecretsManagerError(f"Failed to delete secret: {error_message}")

        except Exception as e:
            if user_id:
                AuditLog.log_secret_action(
                    action=AuditAction.SYNC_AWS,
                    result=AuditResult.ERROR,
                    secret=secret,
                    user_id=user_id,
                    error_message=str(e),
                    details={"operation": "delete"},
                )

            raise AWSSecretsManagerError(f"Failed to delete secret: {str(e)}")

    def sync_secret(
        self, secret: Secret, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Synchronize a secret with AWS Secrets Manager."""
        current_version = secret.current_version
        if not current_version:
            raise AWSSecretsManagerError("No current version found for secret")

        try:
            # Get current value
            value = current_version.decrypt_value()

            # Check if secret exists in AWS
            aws_secret = self.get_secret(secret)

            if aws_secret["status"] == "not_found":
                # Create new secret
                return self.create_secret(secret, value, user_id)
            else:
                # Update existing secret
                return self.update_secret(secret, value, user_id)

        except Exception as e:
            secret.update_aws_sync_status(status=SyncStatus.SYNC_ERROR)
            raise AWSSecretsManagerError(f"Failed to sync secret: {str(e)}")

    def list_secrets(
        self, environment_prefix: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List secrets in AWS Secrets Manager."""
        try:
            filters = []
            if environment_prefix:
                filters.append({"Key": "name", "Values": [f"{environment_prefix}/"]})

            paginator = self.client.get_paginator("list_secrets")
            secrets = []

            for page in paginator.paginate(Filters=filters):
                for secret in page["SecretList"]:
                    secrets.append(
                        {
                            "name": secret["Name"],
                            "arn": secret["ARN"],
                            "description": secret.get("Description", ""),
                            "created_date": secret["CreatedDate"].isoformat(),
                            "last_changed_date": (
                                secret.get("LastChangedDate", "").isoformat()
                                if secret.get("LastChangedDate")
                                else None
                            ),
                            "tags": secret.get("Tags", []),
                        }
                    )

            return secrets

        except ClientError as e:
            raise AWSSecretsManagerError(
                f"Failed to list secrets: {e.response['Error']['Message']}"
            )

    def get_secret_metadata(self, secret_name: str) -> Dict[str, Any]:
        """Get metadata for a secret without retrieving the value."""
        try:
            response = self.client.describe_secret(SecretId=secret_name)

            return {
                "name": response["Name"],
                "arn": response["ARN"],
                "description": response.get("Description", ""),
                "created_date": response["CreatedDate"].isoformat(),
                "last_changed_date": (
                    response.get("LastChangedDate", "").isoformat()
                    if response.get("LastChangedDate")
                    else None
                ),
                "last_accessed_date": (
                    response.get("LastAccessedDate", "").isoformat()
                    if response.get("LastAccessedDate")
                    else None
                ),
                "deleted_date": (
                    response.get("DeletedDate", "").isoformat()
                    if response.get("DeletedDate")
                    else None
                ),
                "tags": response.get("Tags", []),
                "version_ids_to_stages": response.get("VersionIdsToStages", {}),
                "replication_status": response.get("ReplicationStatus", []),
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                return None
            raise AWSSecretsManagerError(
                f"Failed to get secret metadata: {e.response['Error']['Message']}"
            )
