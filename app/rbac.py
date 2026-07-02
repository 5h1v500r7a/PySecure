"""
Role-Based Access Control.

`get_current_user` authenticates the JWT and loads the user.
`require_roles(*roles)` is a dependency factory that enforces the
principle of least privilege: each endpoint declares exactly the
roles allowed to call it, nothing more.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        raise credentials_error

    username = payload.get("sub")
    user_id = payload.get("uid")
    if username is None or user_id is None:
        raise credentials_error

    user = db.query(User).filter(User.id == user_id, User.username == username).first()
    if user is None:
        raise credentials_error
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    return user


def require_roles(*allowed_roles: str):
    """
    Usage: Depends(require_roles("admin", "analyst"))
    Rejects any authenticated user whose role isn't in allowed_roles,
    enforcing least-privilege access per endpoint.
    """
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted to access this resource",
            )
        return current_user

    return dependency
