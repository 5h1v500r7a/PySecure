from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import ROLE_ADMIN
from app.database import get_db
from app.models import User, AuditLog
from app.rbac import require_roles
from app.schemas import UserCreate, UserOut, UserRoleUpdate, AuditLogOut, AuditStats
from app.security import hash_password

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_roles(ROLE_ADMIN))],  # every route here: admin-only
)


@router.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id).all()


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=409, detail="Email already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.put("/users/{user_id}/role", response_model=UserOut)
def update_user_role(user_id: int, payload: UserRoleUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return None


@router.get("/audit-logs", response_model=List[AuditLogOut])
def get_all_audit_logs(
    limit: int = Query(default=100, le=1000),
    username: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog)
    if username:
        q = q.filter(AuditLog.username == username)
    return q.order_by(AuditLog.timestamp.desc()).limit(limit).all()


@router.get("/audit-logs/stats", response_model=AuditStats)
def get_audit_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(AuditLog.id)).scalar()
    failed_logins = db.query(func.count(AuditLog.id)).filter(
        AuditLog.endpoint == "/auth/login", AuditLog.status_code != 200
    ).scalar()

    by_role_rows = db.query(AuditLog.role, func.count(AuditLog.id)).group_by(AuditLog.role).all()
    by_status_rows = db.query(AuditLog.status_code, func.count(AuditLog.id)).group_by(
        AuditLog.status_code
    ).all()

    return AuditStats(
        total_requests=total or 0,
        total_failed_logins=failed_logins or 0,
        requests_by_role={(r or "anonymous"): c for r, c in by_role_rows},
        requests_by_status={str(s): c for s, c in by_status_rows},
    )
