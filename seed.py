"""
Seeds the database with 5 demo users spanning all three roles.
Run once before starting the server: `python seed.py`

    username        password        role
    ------------    ------------    -------
    root_admin      Admin#2026      admin
    sec_lead        Admin#2026      admin
    data_analyst    Analyst#2026    analyst
    audit_analyst   Analyst#2026    analyst
    jane_doe        User#2026       user
"""
from app.database import Base, engine, SessionLocal
from app.models import User
from app.security import hash_password

Base.metadata.create_all(bind=engine)

DEMO_USERS = [
    {"username": "root_admin",    "email": "root_admin@pysecure-corp.com",    "password": "Admin#2026",   "role": "admin"},
    {"username": "sec_lead",      "email": "sec_lead@pysecure-corp.com",      "password": "Admin#2026",   "role": "admin"},
    {"username": "data_analyst",  "email": "data_analyst@pysecure-corp.com",  "password": "Analyst#2026", "role": "analyst"},
    {"username": "audit_analyst", "email": "audit_analyst@pysecure-corp.com", "password": "Analyst#2026", "role": "analyst"},
    {"username": "jane_doe",      "email": "jane_doe@pysecure-corp.com",      "password": "User#2026",    "role": "user"},
]


def seed():
    db = SessionLocal()
    try:
        created = 0
        for u in DEMO_USERS:
            if db.query(User).filter(User.username == u["username"]).first():
                continue
            db.add(User(
                username=u["username"],
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                role=u["role"],
            ))
            created += 1
        db.commit()
        print(f"Seed complete. {created} new user(s) created (of {len(DEMO_USERS)} total).")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
