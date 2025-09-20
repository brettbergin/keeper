"""Pydantic schemas for user-related operations."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator


class UserBase(BaseModel):
    """Base schema for user data."""

    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=100, description="Username")
    full_name: str = Field(..., min_length=1, max_length=255, description="Full name")
    preferred_environment: str = Field(
        "development", max_length=50, description="Preferred environment"
    )
    timezone: str = Field("UTC", max_length=50, description="User timezone")

    @validator("username")
    def validate_username(cls, v):
        """Validate username format."""
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(
                "Username can only contain letters, numbers, hyphens, underscores, and dots"
            )
        return v.lower()


class UserCreate(UserBase):
    """Schema for creating a new user."""

    is_admin: bool = Field(False, description="Admin privileges")
    saml_subject_id: Optional[str] = Field(
        None, max_length=255, description="SAML subject ID"
    )

    class Config:
        schema_extra = {
            "example": {
                "email": "john.doe@company.com",
                "username": "john.doe",
                "full_name": "John Doe",
                "preferred_environment": "development",
                "timezone": "America/New_York",
                "is_admin": False,
                "saml_subject_id": "john.doe@company.com",
            }
        }


class UserUpdate(BaseModel):
    """Schema for updating user information."""

    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    preferred_environment: Optional[str] = Field(None, max_length=50)
    timezone: Optional[str] = Field(None, max_length=50)
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None

    class Config:
        schema_extra = {
            "example": {
                "full_name": "John Smith",
                "preferred_environment": "staging",
                "timezone": "America/Los_Angeles",
            }
        }


class UserResponse(BaseModel):
    """Schema for user response data."""

    id: int
    email: str
    username: str
    full_name: str
    is_active: bool
    is_admin: bool
    preferred_environment: str
    timezone: str
    last_login: Optional[datetime]
    last_login_ip: Optional[str]
    saml_subject_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class UserListResponse(BaseModel):
    """Schema for paginated user list responses."""

    users: List[UserResponse]
    total: int
    page: int
    per_page: int
    pages: int
    has_prev: bool
    has_next: bool
    prev_page: Optional[int]
    next_page: Optional[int]


class UserProfileResponse(UserResponse):
    """Extended user response for profile pages."""

    secrets_created: int
    last_activity: Optional[datetime]
    session_expires_at: Optional[datetime]

    class Config:
        orm_mode = True


class UserLoginRequest(BaseModel):
    """Schema for demo login requests."""

    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., min_length=3, max_length=100, description="Username")
    full_name: Optional[str] = Field(None, max_length=255, description="Full name")

    class Config:
        schema_extra = {
            "example": {
                "email": "demo@company.com",
                "username": "demo.user",
                "full_name": "Demo User",
            }
        }


class UserSessionResponse(BaseModel):
    """Schema for user session information."""

    user_id: int
    username: str
    full_name: str
    is_admin: bool
    session_expires_at: Optional[datetime]
    last_login: Optional[datetime]

    class Config:
        orm_mode = True
