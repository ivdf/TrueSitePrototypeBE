from sqlalchemy import (
    create_engine, Column, Integer, String,
    DateTime, Text, ForeignKey, Boolean
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/truesite"
)

DB_ENCRYPTION_KEY = os.getenv("DB_ENCRYPTION_KEY")
if not DB_ENCRYPTION_KEY:
    raise RuntimeError("DB_ENCRYPTION_KEY is missing from .env")

engine       = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()


# ── Table 1: users ────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    User_ID       = Column(Integer, primary_key=True, autoincrement=True)

    # Encrypted at the column level (AES-256)
    full_name     = Column(
        EncryptedType(String, DB_ENCRYPTION_KEY, AesEngine, "pkcs5"),
        nullable=False
    )

    # Email NOT encrypted — used for login lookup + unique index
    Email         = Column(String(255), unique=True, index=True, nullable=False)

    # bcrypt-hashed
    password_hash = Column(Text, nullable=False)

    Role          = Column(String(20), nullable=False, default="User")
    Account_type  = Column(String(20), nullable=False, default="Free")
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Security fields
    failed_attempts = Column(Integer, default=0)
    locked_until    = Column(DateTime(timezone=True), nullable=True)
    last_login      = Column(DateTime(timezone=True), nullable=True)

    # NEW — Force admin to change default password
    must_change_password = Column(Boolean, default=False, nullable=False)

    # NEW — Email verification
    is_email_verified          = Column(Boolean, default=False, nullable=False)
    verification_token         = Column(String(64), nullable=True, index=True)
    verification_token_expires = Column(DateTime(timezone=True), nullable=True)

    # Password reset
    reset_token          = Column(String(64), nullable=True, index=True)
    reset_token_expires  = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    scans = relationship("UserScan", back_populates="user", cascade="all, delete-orphan")


# ── Table 2: analysis_results ─────────────────────────────────────────────
# Matches Table 9 in the report exactly:
#   ID, URL, certificate_age_days, certificate_type (DV=0/OV=1/EV=2),
#   san_count, key_length, wildcard (0=No/1=Yes), result
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    url                  = Column(Text, unique=False, nullable=False)
    certificate_age_days = Column(Integer, nullable=False)
    certificate_type     = Column(Integer, nullable=False)   # DV=0, OV=1, EV=2
    san_count            = Column(Integer, nullable=False)
    key_length           = Column(Integer, nullable=False)
    wildcard             = Column(Integer, nullable=False)   # 0=No, 1=Yes
    result               = Column(String(20), nullable=False)  # Legitimate / Suspicious / Phishing Alert

    # Relationships
    scans = relationship("UserScan", back_populates="analysis", cascade="all, delete-orphan")


# ── Table 3: user_scans ───────────────────────────────────────────────────
# Matches Table 10 in the report exactly:
#   ID, User_ID (FK → users), analysis_id (FK → analysis_results), scanned_at
class UserScan(Base):
    __tablename__ = "user_scans"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    User_ID     = Column(Integer, ForeignKey("users.User_ID", ondelete="CASCADE"), nullable=False, index=True)
    analysis_id = Column(Integer, ForeignKey("analysis_results.id", ondelete="CASCADE"), nullable=False, index=True)
    scanned_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    user     = relationship("User",           back_populates="scans")
    analysis = relationship("AnalysisResult", back_populates="scans")


# ── Table 4: daily_counts ─────────────────────────────────────────────────
# Internal table — tracks 5/day limit per user
class DailyCount(Base):
    __tablename__ = "daily_counts"

    id      = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    date    = Column(String(10), nullable=False)   # YYYY-MM-DD
    count   = Column(Integer, default=0)


def init_db():
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created.")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
