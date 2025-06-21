from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
from enum import Enum
import re
from database.validators.accounts import validate_password_strength


class UserGroupEnum(str, Enum):
    USER = "user"
    ADMIN = "admin"


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserLoginSchema(UserBase):
    password: str


class PasswordResetCompletionRequest(UserRegistrationRequestSchema):
    token: str


class UserActivationToken(UserBase):
    token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserRead(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class UserSimpleRead(UserBase):
    """Схема для скороченої відповіді після реєстрації"""

    id: int

    class Config:
        orm_mode = True
