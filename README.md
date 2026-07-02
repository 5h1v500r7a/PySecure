
# PySecure — Role-Based Authentication Framework

A production-style RBAC server built with **FastAPI**, implementing JWT-based
authentication, bcrypt password hashing, multi-tier role access control, and
real-time audit logging for security auditing / compliance purposes.

## Features

- **JWT authentication** — short-lived access tokens (30 min) + long-lived
  opaque refresh tokens (7 days), with logout/revocation support.
- **Bcrypt password hashing** via `passlib`, with password-strength
  validation on account creation.
- **Role-Based Access Control** across three tiers — `admin`, `analyst`,
  `user` — each endpoint declares the *minimum* roles allowed
  (principle of least privilege).
- **Real-time audit logging middleware** — every request, from every role,
  is written to an `audit_logs` table as it completes, independent of
  route-level code, giving a verifiable access trail.
- **Account lockout** — 5 failed logins locks an account for 15 minutes
  (brute-force protection).
- **17 API endpoints** across authentication, admin, analyst, and user
  routers.
- **5 seeded demo users** spanning all three roles.

## Architecture

```
pysecure/
├── app/
│   ├── main.py          # app factory, middleware & router wiring
│   ├── config.py         # settings (JWT secret, expirations, lockout policy)
│   ├── database.py        # SQLAlchemy engine/session
│   ├── models.py          # User, RefreshToken, AuditLog
│   ├── schemas.py         # Pydantic request/response models
│   ├── security.py        # password hashing + JWT create/verify
│   ├── rbac.py             # get_current_user + require_roles() dependency
│   ├── audit.py            # AuditMiddleware (logs every request)
│   └── routers/
│       ├── auth.py         # login, refresh, logout, /me
│       ├── admin.py        # user management + full audit access
│       ├── analyst.py      # read-only audit/reporting access
│       └── user.py         # self-service profile & dashboard
├── seed.py                 # creates 5 demo users
└── requirements.txt
```

**RBAC design:** `require_roles(*roles)` is a dependency factory. Each
router declares the roles allowed to touch it — `admin.py` is admin-only,
`analyst.py` allows `admin`+`analyst` (read-only endpoints, no writes),
and `user.py` allows all three roles for self-service actions. This keeps
authorization logic declarative and centralized rather than scattered
through business logic.

**Audit design:** `AuditMiddleware` wraps every request/response cycle,
decodes the JWT (if present) to attach username/role, and writes a row to
`audit_logs` — so logging can't be accidentally skipped by a route, and
admins get a tamper-resistant-by-design activity trail.

## Setup

```bash
pip install -r requirements.txt
python seed.py                 # creates pysecure.db with 5 demo users
uvicorn app.main:app --reload  # http://127.0.0.1:8000
```

Interactive API docs: `http://127.0.0.1:8000/docs`

### Demo accounts (username / password / role)

| Username        | Password       | Role    |
|-----------------|----------------|---------|
| `root_admin`    | `Admin#2026`   | admin   |
| `sec_lead`       | `Admin#2026`   | admin   |
| `data_analyst`  | `Analyst#2026` | analyst |
| `audit_analyst` | `Analyst#2026` | analyst |
| `jane_doe`      | `User#2026`    | user    |

> These are demo credentials for local testing only — rotate/replace them
> before any real deployment, and set `PYSECURE_SECRET_KEY` via env var.

## API Reference

### Auth (`/auth`) — public / self
| Method | Path             | Access        | Description |
|--------|------------------|---------------|-------------|
| POST   | `/auth/login`    | public        | Returns access + refresh token |
| POST   | `/auth/refresh`  | public        | Exchange refresh token for new access token |
| POST   | `/auth/logout`   | public        | Revoke a refresh token |
| GET    | `/auth/me`       | any authed    | Current user's identity |

### Admin (`/admin`) — `admin` only
| Method | Path                        | Description |
|--------|-----------------------------|-------------|
| GET    | `/admin/users`              | List all users |
| GET    | `/admin/users/{id}`         | Get a single user |
| POST   | `/admin/users`              | Create a user (any role) |
| PUT    | `/admin/users/{id}/role`    | Change a user's role |
| DELETE | `/admin/users/{id}`         | Delete a user |
| GET    | `/admin/audit-logs`         | Full audit trail (filterable) |
| GET    | `/admin/audit-logs/stats`   | Aggregate audit statistics |

### Analyst (`/analyst`) — `admin`, `analyst` (read-only)
| Method | Path                              | Description |
|--------|-----------------------------------|-------------|
| GET    | `/analyst/audit-logs`            | Recent audit entries (read-only) |
| GET    | `/analyst/dashboard`             | User counts + failed-login summary |
| GET    | `/analyst/reports/security-summary` | Top endpoints, forbidden-attempt counts |

### User (`/user`) — `admin`, `analyst`, `user`
| Method | Path             | Description |
|--------|------------------|-------------|
| GET    | `/user/profile`  | Own profile |
| PUT    | `/user/profile`  | Update own email/password |
| GET    | `/user/dashboard`| Basic welcome dashboard |

## Example: login + call a protected endpoint

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -d "username=root_admin&password=Admin#2026" \
  -H "Content-Type: application/x-www-form-urlencoded"
# => {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}

curl http://127.0.0.1:8000/admin/users \
  -H "Authorization: Bearer <access_token>"
```

## Security notes

- Passwords are never stored or logged in plaintext; only bcrypt hashes
  are persisted.
- Access tokens are short-lived; refresh tokens are opaque (not JWTs) and
  stored server-side so they can be revoked on logout.
- All 403s and failed logins land in the audit trail (`/admin/audit-logs`,
  `/admin/audit-logs/stats`) for review.
- For production: move `SECRET_KEY` to a secrets manager, switch SQLite
  to Postgres (`PYSECURE_DATABASE_URL`), and put the app behind HTTPS.
==
