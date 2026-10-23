# TrueSite — Local Development Setup

## Project Structure

```
truesite/
├── truesite-backend/       ← FastAPI Python backend
│   ├── main.py             ← App entry point
│   ├── database.py         ← PostgreSQL models (Users table)
│   ├── security.py         ← All 5 security controls
│   ├── analyzer.py         ← URL analysis / ML logic
│   ├── schemas.py          ← Pydantic request/response models
│   ├── routers/
│   │   ├── auth.py         ← Register, Login, Change password
│   │   ├── analysis.py     ← Analyze URL, History, Usage
│   │   └── admin.py        ← Admin: list users, roles, lockout reset
│   ├── requirements.txt
│   └── .env                ← Database URL, JWT secret
│
└── truesite-frontend/      ← React + TypeScript frontend
    ├── src/
    │   ├── App.tsx
    │   ├── context/AuthContext.tsx
    │   ├── pages/SignIn.tsx
    │   ├── pages/Register.tsx
    │   └── components/
    ├── .env.local          ← VITE_API_URL=http://localhost:8000
    └── package.json
```

---

## Requirements

- **Python** 3.11 or higher
- **Node.js** 18 or higher
- **PostgreSQL** 15 or higher

---

## Step-by-Step Setup

### Step 1 — Install PostgreSQL

Download and install from: https://www.postgresql.org/download/

During installation, set a password for the `postgres` user. Remember it.

### Step 2 — Create the database

Open a terminal and run:

```bash
psql -U postgres
```

Then inside psql:

```sql
CREATE DATABASE truesite;
\q
```

### Step 3 — Configure the backend

Open `truesite-backend/.env` and update:

```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/truesite
SECRET_KEY=pick-any-long-random-string-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
FRONTEND_URL=http://localhost:5173
```

Replace `YOUR_PASSWORD` with your PostgreSQL password.

### Step 4 — Install backend dependencies

```bash
cd truesite-backend
pip install -r requirements.txt
```

### Step 5 — Run the backend

```bash
uvicorn main:app --reload --port 8000
```

You should see:
```
✅ Database tables created.
🚀 TrueSite backend running
INFO: Uvicorn running on http://0.0.0.0:8000
```

The database tables are created automatically on first run.

### Step 6 — Install frontend dependencies

Open a **new terminal**:

```bash
cd truesite-frontend
npm install
```

### Step 7 — Run the frontend

```bash
npm run dev
```

Open your browser at: **http://localhost:5173**

---

## API Documentation

Once the backend is running, visit:

- **Interactive docs:** http://localhost:8000/docs
- **Alternative docs:** http://localhost:8000/redoc

---

## Create an Admin User

After registering a normal user via the UI, you can promote them to Admin via psql:

```sql
psql -U postgres -d truesite
UPDATE users SET "Role" = 'Admin' WHERE "Email" = 'your@email.com';
\q
```

---

## Security Controls Implemented

| # | Control | Location |
|---|---------|----------|
| 1 | User login with JWT session management | `security.py` → `create_access_token()` |
| 2 | Role-Based Access Control (User/Admin) | `security.py` → `require_admin()` |
| 3 | Strong password + HaveIBeenPwned breach check | `security.py` → `check_password_strength()` + `is_password_breached()` |
| 4 | bcrypt password hashing | `security.py` → `hash_password()` |
| 5 | Account lockout (5 failures / 15 min) | `security.py` → `record_failed_attempt()` |

---

## Database Schema

### users table

| Column | Type | Description |
|--------|------|-------------|
| User_ID | Integer (PK) | Auto-increment primary key |
| full_name | Text | User's full name |
| Email | Text (Unique) | User's email address |
| password_hash | Text | bcrypt hashed password |
| Role | Text | User or Admin |
| Account_type | Text | Free |
| created_at | DateTime | Account creation date |
| failed_attempts | Integer | Lockout counter |
| locked_until | DateTime | Lockout expiry timestamp |
| last_login | DateTime | Last successful login |

### analysis_results table

Stores every URL analysis with result, confidence, risk score, and timestamp.

### daily_counts table

Tracks per-user daily analysis count for the 5/day limit enforcement.

---

## Useful Commands

```bash
# Check all users in DB
psql -U postgres -d truesite -c 'SELECT "User_ID", "Email", "Role", "Account_type", "failed_attempts", "locked_until" FROM users;'

# Manually unlock a user
psql -U postgres -d truesite -c 'UPDATE users SET failed_attempts=0, locked_until=NULL WHERE "Email"=\'user@example.com\';'

# View analysis history
psql -U postgres -d truesite -c 'SELECT * FROM analysis_results ORDER BY analyzed_at DESC LIMIT 10;'
```
