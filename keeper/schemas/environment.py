"""Pydantic schemas for environment-related operations."""

import uuid
from typing import List, Optional

from pydantic import BaseModel, Field, validator


class EnvironmentBase(BaseModel):
    """Base schema for environment data."""

    name: str = Field(..., min_length=1, max_length=100, description="Environment name")
    display_name: str = Field(
        ..., min_length=1, max_length=255, description="Display name"
    )
    description: Optional[str] = Field(
        None, max_length=1000, description="Environment description"
    )
    is_production: bool = Field(False, description="Is production environment")
    sort_order: str = Field("999", max_length=10, description="Sort order")
    color_code: Optional[str] = Field(
        None, max_length=7, description="Color code for UI"
    )
    icon: Optional[str] = Field(None, max_length=50, description="Icon class")

    @validator("name")
    def validate_name(cls, v):
        """Validate environment name format."""
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "Name can only contain letters, numbers, hyphens, and underscores"
            )
        return v.lower()

    @validator("color_code")
    def validate_color_code(cls, v):
        """Validate color code format."""
        if v and not (v.startswith("#") and len(v) == 7):
            raise ValueError("Color code must be in hex format (#RRGGBB)")
        return v


class EnvironmentCreate(EnvironmentBase):
    """Schema for creating a new environment."""

    aws_region: Optional[str] = Field(None, max_length=50, description="AWS region")
    aws_secrets_prefix: Optional[str] = Field(
        None, max_length=255, description="AWS secrets prefix"
    )
    vault_mount_point: Optional[str] = Field(
        None, max_length=255, description="Vault mount point"
    )
    vault_path_prefix: Optional[str] = Field(
        None, max_length=255, description="Vault path prefix"
    )

    class Config:
        schema_extra = {
            "example": {
                "name": "staging",
                "display_name": "Staging Environment",
                "description": "Pre-production testing environment",
                "is_production": False,
                "sort_order": "020",
                "color_code": "#ffc107",
                "icon": "fas fa-vial",
                "aws_region": "us-east-1",
                "aws_secrets_prefix": "staging",
                "vault_mount_point": "secret",
                "vault_path_prefix": "staging",
            }
        }


class EnvironmentUpdate(BaseModel):
    """Schema for updating environment information."""

    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    is_production: Optional[bool] = None
    is_active: Optional[bool] = None
    sort_order: Optional[str] = Field(None, max_length=10)
    color_code: Optional[str] = Field(None, max_length=7)
    icon: Optional[str] = Field(None, max_length=50)
    aws_region: Optional[str] = Field(None, max_length=50)
    aws_secrets_prefix: Optional[str] = Field(None, max_length=255)
    vault_mount_point: Optional[str] = Field(None, max_length=255)
    vault_path_prefix: Optional[str] = Field(None, max_length=255)

    @validator("color_code")
    def validate_color_code(cls, v):
        """Validate color code format."""
        if v and not (v.startswith("#") and len(v) == 7):
            raise ValueError("Color code must be in hex format (#RRGGBB)")
        return v


class EnvironmentResponse(BaseModel):
    """Schema for environment response data."""

    id: uuid.UUID
    name: str
    display_name: str
    description: Optional[str]
    is_active: bool
    is_production: bool
    sort_order: str
    color_code: Optional[str]
    icon: Optional[str]
    aws_region: Optional[str]
    aws_secrets_prefix: Optional[str]
    vault_mount_point: Optional[str]
    vault_path_prefix: Optional[str]
    full_aws_prefix: str
    full_vault_prefix: str
    created_at: str
    updated_at: str

    class Config:
        orm_mode = True


class EnvironmentListResponse(BaseModel):
    """Schema for environment list responses."""

    environments: List[EnvironmentResponse]
    total: int


class EnvironmentStatsResponse(BaseModel):
    """Schema for environment statistics."""

    environment: EnvironmentResponse
    secret_count: int
    active_secrets: int
    expired_secrets: int
    secrets_needing_rotation: int
    out_of_sync_secrets: int

    class Config:
        orm_mode = True


class EnvironmentSecretsResponse(BaseModel):
    """Schema for environment with its secrets."""

    environment: EnvironmentResponse
    secrets: List[dict]  # SecretResponse would create circular import
    total_secrets: int

    class Config:
        orm_mode = True
