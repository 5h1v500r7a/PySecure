import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.config import MAX_FAILED_LOGIN_ATTEMPTS, LOCKOUT_MINUTES
from app.database import get_db
from app.models import User, RefreshToken
from app.rbac import get_current_user
from app.schemas import Token, TokenRefreshRequest, AccessTokenResponse, UserOut
from app.security import (
    verify_password, create_access_token,
    generate_refresh_token, refresh_token_expiry,
)
from app.audit import log_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    user = db.query(User).filter(User.username == form_data.username).first()

    # --- account lockout check (brute-force protection) ---
    if user and user.locked_until and user.locked_until > datetime.datetime.utcnow():
        log_event(db, username=form_data.username, role=None, method="POST",
                   endpoint="/auth/login", status_code=423, ip_address=ip,
                   detail="Login attempt on locked account")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked. Try again after {user.locked_until.isoformat()} UTC",
        )

    valid = user is not None and verify_password(form_data.password, user.hashed_password)

    if not valid or not user.is_active:
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(
                    minutes=LOCKOUT_MINUTES
                )
            db.commit()
        log_event(db, username=form_data.username, role=None, method="POST",
                   endpoint="/auth/login", status_code=401, ip_address=ip,
                   detail="Invalid credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # --- success: reset lockout state, issue tokens ---
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    access_token = create_access_token(user.username, user.role, user.id)
    refresh_token_str = generate_refresh_token()
    db.add(RefreshToken(
        token=refresh_token_str,
        user_id=user.id,
        expires_at=refresh_token_expiry(),
    ))
    db.commit()

    log_event(db, username=user.username, role=user.role, method="POST",
              endpoint="/auth/login", status_code=200, ip_address=ip,
              detail="Login successful")

    return Token(access_token=access_token, refresh_token=refresh_token_str)


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh_access_token(payload: TokenRefreshRequest, db: Session = Depends(get_db)):
    token_row = db.query(RefreshToken).filter(
        RefreshToken.token == payload.refresh_token
    ).first()

    if (
        token_row is None
        or token_row.revoked
        or token_row.expires_at < datetime.datetime.utcnow()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid or expired",
        )

    user = db.query(User).filter(User.id == token_row.user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    new_access_token = create_access_token(user.username, user.role, user.id)
    return AccessTokenResponse(access_token=new_access_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: TokenRefreshRequest, db: Session = Depends(get_db)):
    token_row = db.query(RefreshToken).filter(
        RefreshToken.token == payload.refresh_token
    ).first()
    if token_row:
        token_row.revoked = True
        db.commit()
    return None


@router.get("/me", response_model=UserOut)
def read_own_identity(current_user: User = Depends(get_current_user)):
    return current_user
