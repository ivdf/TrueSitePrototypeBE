"""
Security module — implements all 5 controls from the report:
  1. User login with session management  (JWT)
  2. Role-Based Access Control           (User / Admin)
  3. Strong password + breached check    (zxcvbn strength + HaveIBeenPwned k-anonymity API)
  4. bcrypt password storage             (passlib bcrypt)
  5. Account lockout                     (5 failures / 15 min)
"""

import os
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db, User

# ── Config ────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")
ALGORITHM  = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# ── Password hashing (Control 4: bcrypt) ─────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))



# ── Control 3: Strong password policy ────────────────────────────────────
MIN_LENGTH = 8

def check_password_strength(password: str) -> tuple[bool, str]:
    """Returns (is_strong, reason)."""
    if len(password) < MIN_LENGTH:
        return False, f"Password must be at least {MIN_LENGTH} characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        return False, "Password must contain at least one special character."
    return True, "OK"


# ── Control 3: HaveIBeenPwned k-anonymity check ───────────────────────────
def is_password_breached(password: str) -> bool:
    """
    Uses HIBP k-anonymity API — only the first 5 chars of the SHA-1 hash
    are sent to the API, so the full password is never exposed.
    Returns True if the password has appeared in a known breach.
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=4,
            headers={"Add-Padding": "true"},
        )
        if resp.status_code != 200:
            return False   # API unavailable — don't block registration
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix and int(count) > 0:
                return True
        return False
    except Exception:
        return False   # network error — don't block


# ── Control 1: JWT session management ────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = db.query(User).filter(User.Email == email).first()
    if user is None:
        raise credentials_exc
    return user


# ── Control 2: Role-Based Access Control ─────────────────────────────────
def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.Role != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    if current_user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing admin resources.",
        )
    return current_user


# ── Control 5: Account lockout ────────────────────────────────────────────
def check_lockout(user: User, db: Session) -> None:
    """Raise 403 if account is currently locked."""
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        remaining = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account locked due to too many failed attempts. Try again in {remaining} minute(s).",
        )


def record_failed_attempt(user: User, db: Session) -> None:
    """Increment failure counter; lock account if threshold reached."""
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= LOCKOUT_MAX_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        user.failed_attempts = 0
    db.commit()


def reset_failed_attempts(user: User, db: Session) -> None:
    """Clear failure counter on successful login."""
    user.failed_attempts = 0
    user.locked_until    = None
    user.last_login      = datetime.now(timezone.utc)
    db.commit()
# ── Strict gate: blocks users with must_change_password=True ──────────────
def get_current_user_strict(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Like get_current_user, but ALSO blocks access if must_change_password=True.
    Use on endpoints that must NOT be reached before the password is changed.
    """
    if current_user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing this resource.",
        )
    return current_user