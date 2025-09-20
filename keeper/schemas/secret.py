"""Pydantic schemas for secret-related operations."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from ..models.secret import SecrecyLevel, SecretType, SyncStatus


class SecretBase(BaseModel):
    """Base schema for secret data."""

    name: str = Field(..., min_length=1, max_length=255, description="Secret name")
    display_name: str = Field(
        ..., min_length=1, max_length=255, description="Display name"
    )
    description: Optional[str] = Field(
        None, max_length=1000, description="Secret description"
    )
    secret_type: SecretType = Field(SecretType.STRING, description="Type of secret")
    secrecy_level: SecrecyLevel = Field(
        SecrecyLevel.MEDIUM, description="Secrecy level"
    )
    service_name: Optional[str] = Field(
        None, max_length=255, description="Associated service"
    )
    expires_at: Optional[datetime] = Field(None, description="Expiration date")
    auto_rotate: bool = Field(False, description="Enable automatic rotation")
    rotation_interval_days: Optional[int] = Field(
        None, ge=1, le=365, description="Rotation interval in days"
    )

    @validator("name")
    def validate_name(cls, v):
        """Validate secret name format."""
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(
                "Name can only contain letters, numbers, hyphens, underscores, and dots"
            )
        return v.lower()

    @validator("rotation_interval_days")
    def validate_rotation_interval(cls, v, values):
        """Validate rotation interval is set when auto_rotate is True."""
        if values.get("auto_rotate") and not v:
            raise ValueError(
                "Rotation interval is required when auto_rotate is enabled"
            )
        return v


class SecretCreate(SecretBase):
    """Schema for creating a new secret."""

    environment_id: int = Field(..., gt=0, description="Environment ID")
    value: str = Field(..., min_length=1, description="Secret value")

    class Config:
        schema_extra = {
            "example": {
                "name": "database-password",
                "display_name": "Database Password",
                "description": "Main database connection password",
                "secret_type": "password",
                "secrecy_level": "high",
                "environment_id": 1,
                "service_name": "postgresql",
                "value": "super-secret-password",
                "auto_rotate": True,
                "rotation_interval_days": 90,
            }
        }


class SecretUpdate(BaseModel):
    """Schema for updating secret metadata."""

    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    service_name: Optional[str] = Field(None, max_length=255)
    secrecy_level: Optional[SecrecyLevel] = None
    expires_at: Optional[datetime] = None
    auto_rotate: Optional[bool] = None
    rotation_interval_days: Optional[int] = Field(None, ge=1, le=365)

    @validator("rotation_interval_days")
    def validate_rotation_interval(cls, v, values):
        """Validate rotation interval is set when auto_rotate is True."""
        if values.get("auto_rotate") and not v:
            raise ValueError(
                "Rotation interval is required when auto_rotate is enabled"
            )
        return v


class SecretRotateRequest(BaseModel):
    """Schema for rotating a secret."""

    new_value: str = Field(..., min_length=1, description="New secret value")
    generation_method: str = Field("manual", description="How the value was generated")
    generation_params: Optional[Dict[str, Any]] = Field(
        None, description="Parameters used for generation"
    )

    class Config:
        schema_extra = {
            "example": {
                "new_value": "new-super-secret-password",
                "generation_method": "auto",
                "generation_params": {
                    "length": 32,
                    "include_symbols": True,
                    "include_numbers": True,
                },
            }
        }


class EnvironmentInfo(BaseModel):
    """Schema for environment information in responses."""

    id: int
    name: str
    display_name: str
    is_production: bool


class SecretResponse(BaseModel):
    """Schema for secret response data."""

    id: int
    name: str
    display_name: str
    description: Optional[str]
    secret_type: SecretType
    secrecy_level: SecrecyLevel
    environment: EnvironmentInfo
    service_name: Optional[str]
    aws_sync_status: SyncStatus
    vault_sync_status: SyncStatus
    sync_status: str
    current_version: Optional[int]
    expires_at: Optional[datetime]
    auto_rotate: bool
    rotation_interval_days: Optional[int]
    last_rotated_at: Optional[datetime]
    is_expired: bool
    needs_rotation: bool
    created_at: datetime
    updated_at: datetime
    creator_username: str

    class Config:
        orm_mode = True


class SecretListResponse(BaseModel):
    """Schema for paginated secret list responses."""

    secrets: List[SecretResponse]
    total: int
    page: int
    per_page: int
    pages: int
    has_prev: bool
    has_next: bool
    prev_page: Optional[int]
    next_page: Optional[int]


class SecretValueResponse(BaseModel):
    """Schema for secret value responses."""

    value: str
    version: int
    created_at: datetime
    generation_method: Optional[str]

    class Config:
        schema_extra = {
            "example": {
                "value": "super-secret-password",
                "version": 1,
                "created_at": "2023-01-01T00:00:00",
                "generation_method": "manual",
            }
        }


class SecretVersionResponse(BaseModel):
    """Schema for secret version information."""

    version_number: int
    is_current: bool
    generation_method: Optional[str]
    generation_params: Optional[Dict[str, Any]]
    activated_at: Optional[datetime]
    deactivated_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    created_by_username: str

    class Config:
        orm_mode = True


class SecretHistoryResponse(BaseModel):
    """Schema for secret version history."""

    secret_id: int
    versions: List[SecretVersionResponse]

    class Config:
        orm_mode = True
