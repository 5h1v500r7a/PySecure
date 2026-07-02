"""
Central configuration for PySecure.

All secrets should be supplied via environment variables in a real
deployment. Defaults below are for local/demo use only.
"""
import os

# --- JWT settings -----------------------------------------------------
SECRET_KEY = os.getenv("PYSECURE_SECRET_KEY", "dev-secret-change-me-in-prod-3f9a1c")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("PYSECURE_ACCESS_EXPIRE_MIN", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("PYSECURE_REFRESH_EXPIRE_DAYS", "7"))

# --- Account lockout (brute-force protection) --------------------------
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# --- Database -----------------------------------------------------------
DATABASE_URL = os.getenv("PYSECURE_DATABASE_URL", "sqlite:///./pysecure.db")

# --- Roles (principle of least privilege, lowest -> highest) -----------
ROLE_USER = "user"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ALL_ROLES = [ROLE_USER, ROLE_ANALYST, ROLE_ADMIN]
