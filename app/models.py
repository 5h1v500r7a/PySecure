import datetime

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.datetime.utcnow()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # user | analyst | admin
    is_active = Column(Boolean, default=True, nullable=False)

    # --- brute-force protection ---
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(512), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")


class AuditLog(Base):
    """
    Real-time audit trail. Written by AuditMiddleware on every request so
    that access is verifiable for security review / compliance purposes,
    independent of whether the endpoint itself does any logging.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)

    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True, index=True)
    role = Column(String(20), nullable=True, index=True)

    method = Column(String(10), nullable=False)
    endpoint = Column(String(255), nullable=False, index=True)
    status_code = Column(Integer, nullable=False)
    ip_address = Column(String(64), nullable=True)
    detail = Column(Text, nullable=True)
