from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


# ── Auth ──────────────────────────────────────────────────────────────────
import re
from pydantic import BaseModel, EmailStr, Field, field_validator

class RegisterRequest(BaseModel):
    full_name: str   = Field(..., min_length=2, max_length=100)
    email:     EmailStr
    password:  str   = Field(..., min_length=8)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        # Allow letters (including accented), spaces, hyphens, apostrophes
        if not re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ\s'-]+$", v):
            raise ValueError("Name cannot contain numbers or special characters.")
        if len(v) < 2:
            raise ValueError("Name must be at least 2 characters.")
        return v

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         "UserPublic"
    force_password_change: bool = False   # NEW — forces admin password change

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=8)


# ── User ──────────────────────────────────────────────────────────────────
class UserPublic(BaseModel):
    User_ID:      int
    full_name:    str
    Email:        str
    Role:         str
    Account_type: str
    created_at:   datetime
    model_config = {"from_attributes": True}


# ── Analysis result (matches Table 9) ────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3)

class AnalysisResponse(BaseModel):
    url:        str
    result:     str
    confidence: float
    risk_score: float
    details:    dict

# What gets stored in analysis_results table
class AnalysisResultDB(BaseModel):
    id:                   int
    url:                  str
    certificate_age_days: int
    certificate_type:     int   # 0=DV, 1=OV, 2=EV
    san_count:            int
    key_length:           int
    wildcard:             int   # 0=No, 1=Yes
    result:               str
    model_config = {"from_attributes": True}


# ── User scan (matches Table 10) ──────────────────────────────────────────
class UserScanItem(BaseModel):
    id:          int
    User_ID:     int
    analysis_id: int
    scanned_at:  datetime
    # Joined fields from analysis_results
    url:         Optional[str] = None
    result:      Optional[str] = None
    model_config = {"from_attributes": True}


# ── Admin ─────────────────────────────────────────────────────────────────
class UserAdminView(BaseModel):
    User_ID:              int
    full_name:            str
    Email:                str
    Role:                 str
    Account_type:         str
    created_at:           datetime
    failed_attempts:      int
    locked_until:         Optional[datetime]
    last_login:           Optional[datetime]
    must_change_password: bool = False   # NEW — visible in admin dashboard
    model_config = {"from_attributes": True}

class RoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(User|Admin)$")

# ── Password reset ────────────────────────────────────────────────────────
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordPayload(BaseModel):
    email: EmailStr
    token: str
    new_password: str = Field(..., min_length=8)

TokenResponse.model_rebuild()
