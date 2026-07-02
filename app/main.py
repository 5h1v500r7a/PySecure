from fastapi import FastAPI

from app.database import Base, engine
from app.audit import AuditMiddleware
from app.routers import auth, admin, analyst, user

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PySecure",
    description="Role-Based Authentication Framework — JWT auth, bcrypt hashing, "
                "RBAC middleware, and real-time audit logging.",
    version="1.0.0",
)

# Real-time audit logging across every request, for every role.
app.add_middleware(AuditMiddleware)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(analyst.router)
app.include_router(user.router)


@app.get("/", tags=["health"])
def health_check():
    return {"status": "ok", "service": "PySecure"}
