from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import ROLE_ADMIN, ROLE_ANALYST, ROLE_USER
from app.database import get_db
from app.models import User
from app.rbac import require_roles, get_current_user
from app.schemas import UserOut, UserUpdateSelf
from app.security import hash_password

router = APIRouter(
    prefix="/user",
    tags=["user"],
    # Any authenticated role can reach their own profile/dashboard.
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_USER))],
)


@router.get("/profile", response_model=UserOut)
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.put("/profile", response_model=UserOut)
def update_profile(
    payload: UserUpdateSelf,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.email:
        current_user.email = payload.email
    if payload.password:
        current_user.hashed_password = hash_password(payload.password)
    db.commit()
    db.refresh(current_user)
    return current_user


@router.get("/dashboard")
def user_dashboard(current_user: User = Depends(get_current_user)):
    return {
        "welcome": f"Hello, {current_user.username}",
        "role": current_user.role,
        "account_created": current_user.created_at,
    }
