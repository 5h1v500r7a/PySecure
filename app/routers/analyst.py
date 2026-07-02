from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import ROLE_ADMIN, ROLE_ANALYST
from app.database import get_db
from app.models import AuditLog, User
from app.rbac import require_roles
from app.schemas import AuditLogOut

router = APIRouter(
    prefix="/analyst",
    tags=["analyst"],
    # Least privilege: analysts get read-only visibility; admins can too.
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST))],
)


@router.get("/audit-logs", response_model=List[AuditLogOut])
def read_audit_logs(limit: int = Query(default=50, le=200), db: Session = Depends(get_db)):
    """Read-only view of recent audit activity. No create/update/delete here."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()


@router.get("/dashboard")
def analyst_dashboard(db: Session = Depends(get_db)):
    user_counts = dict(
        db.query(User.role, func.count(User.id)).group_by(User.role).all()
    )
    recent_failed_logins = db.query(func.count(AuditLog.id)).filter(
        AuditLog.endpoint == "/auth/login", AuditLog.status_code != 200
    ).scalar()

    return {
        "users_by_role": user_counts,
        "recent_failed_logins": recent_failed_logins or 0,
    }


@router.get("/reports/security-summary")
def security_summary(db: Session = Depends(get_db)):
    top_endpoints = (
        db.query(AuditLog.endpoint, func.count(AuditLog.id).label("hits"))
        .group_by(AuditLog.endpoint)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
        .all()
    )
    forbidden_attempts = db.query(func.count(AuditLog.id)).filter(
        AuditLog.status_code == 403
    ).scalar()

    return {
        "top_endpoints": [{"endpoint": e, "hits": h} for e, h in top_endpoints],
        "forbidden_access_attempts": forbidden_attempts or 0,
    }
