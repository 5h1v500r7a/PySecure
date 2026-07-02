import datetime
import secrets

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import (
    SECRET_KEY, ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- Password hashing ----------
def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ---------- JWT access tokens ----------
def create_access_token(subject: str, role: str, user_id: int) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": subject,
        "role": role,
        "uid": user_id,
        "type": "access",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Returns the decoded payload, or None if invalid/expired."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ---------- Opaque refresh tokens ----------
def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def refresh_token_expiry() -> datetime.datetime:
    return datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
