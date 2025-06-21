from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from exceptions.security import InvalidTokenError, TokenExpiredError
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserLoginSchema,
    UserRegistrationRequestSchema,
    UserSimpleRead,
    UserActivationToken,
    UserBase,
    PasswordResetCompletionRequest,
    RefreshTokenRequest,
)
from security.passwords import hash_password, verify_password


router = APIRouter()


@router.post("/register/", status_code=201)
async def user_register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    res = await db.execute(select(UserModel).where(UserModel.email == user.email))
    result = res.scalar_one_or_none()

    if result:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        group = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        user_group = group.scalar_one_or_none()
        if user_group is None:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.commit()
            await db.refresh(user_group)

        hashed_password = hash_password(user.password)
        new_user = UserModel(
            email=user.email, _hashed_password=hashed_password, group_id=user_group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        await db.refresh(activation_token)

        return {
            "id": new_user.id,
            "email": new_user.email,
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=200)
async def activate_token(data: UserActivationToken, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = res.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=400, detail=f"User with email {data.email} does not exist"
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True

    now = datetime.now(timezone.utc)

    activation_token_result = await db.execute(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    activation_token = activation_token_result.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token_expires_at = activation_token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if data.token != activation_token.token or token_expires_at < now:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    await db.delete(activation_token)
    db.add(user)

    await db.commit()
    await db.refresh(user)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
async def password_reset(data: UserBase, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = res.scalar_one_or_none()

    if user and user.is_active:

        all_tokens = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        result = all_tokens.scalars().all()
        for token in result:
            await db.delete(token)

        new_token = PasswordResetTokenModel(user_id=user.id)

        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
    data: PasswordResetCompletionRequest, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    now = datetime.now(timezone.utc)

    reset_token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    reset_token = reset_token_result.scalar_one_or_none()

    if not reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_expires_at = reset_token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if reset_token.token != data.token or token_expires_at < now:
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        new_password = hash_password(data.password)
        user._hashed_password = new_password
        await db.delete(reset_token)
        db.add(user)

        await db.commit()
        await db.refresh(user)

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=201)
async def generate_jwt_token(
    data: UserLoginSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    token_data = {"user_id": user.id, "email": user.email}

    try:
        access_token = jwt_manager.create_access_token(token_data)
        refresh_token = jwt_manager.create_refresh_token(token_data)
        refresh = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(refresh)
        await db.commit()
        await db.refresh(refresh)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/", status_code=200)
async def refresh_access_token(
    refresh_token: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    jwt_encode: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        payload = jwt_encode.decode_refresh_token(refresh_token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    res = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token.refresh_token
        )
    )
    token_ref = res.scalar_one_or_none()

    if not token_ref:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=404, detail="User not found.")

    if token_ref.user_id != user_id:
        raise HTTPException(status_code=401, detail="Refresh token user mismatch.")

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    token_data = {"user_id": user.id, "email": user.email}
    new_access_token = jwt_encode.create_access_token(token_data)
    return {"access_token": new_access_token}
