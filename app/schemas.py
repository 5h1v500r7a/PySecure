import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------- Auth ----------
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- Users ----------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user")

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in ("user", "analyst", "admin"):
            raise ValueError("role must be one of: user, analyst, admin")
        return v


class UserUpdateSelf(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


class UserRoleUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in ("user", "analyst", "admin"):
            raise ValueError("role must be one of: user, analyst, admin")
        return v


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ---------- Audit ----------
class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime.datetime
    username: Optional[str]
    role: Optional[str]
    method: str
    endpoint: str
    status_code: int
    ip_address: Optional[str]
    detail: Optional[str]

    class Config:
        from_attributes = True


class AuditStats(BaseModel):
    total_requests: int
    total_failed_logins: int
    requests_by_role: dict
    requests_by_status: dict
