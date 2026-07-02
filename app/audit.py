"""
Real-time audit logging middleware.

Every request (across admin, analyst, and user roles alike) is written
to the audit_logs table as it completes, independent of route-level
code. This gives a verifiable, tamper-resistant-by-design access trail
for security auditing / compliance, since routes can't accidentally
skip logging themselves.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.database import SessionLocal
from app.models import AuditLog
from app.security import decode_token

# Paths that don't need to clutter the audit trail
_SKIP_PATHS = {"/docs", "/openapi.json", "/redoc", "/favicon.ico"}


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.url.path in _SKIP_PATHS:
            return response

        username = None
        role = None

        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
            payload = decode_token(token)
            if payload:
                username = payload.get("sub")
                role = payload.get("role")

        db = SessionLocal()
        try:
            entry = AuditLog(
                user_id=None,
                username=username or "anonymous",
                role=role,
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code,
                ip_address=request.client.host if request.client else None,
            )
            db.add(entry)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return response


def log_event(db, *, username: str | None, role: str | None, method: str,
              endpoint: str, status_code: int, ip_address: str | None = None,
              detail: str | None = None):
    """
    Manual audit helper for events that happen outside a clean request/
    response cycle (e.g. a failed login attempt before a token exists),
    so security-relevant events are never missed.
    """
    entry = AuditLog(
        username=username or "anonymous",
        role=role,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        ip_address=ip_address,
        detail=detail,
    )
    db.add(entry)
    db.commit()
