from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import secrets

from database import get_db, User
from schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserPublic, 
    PasswordChangeRequest, ForgotPasswordRequest, ResetPasswordPayload
)
from security import (
    hash_password, verify_password,
    check_password_strength, is_password_breached,
    create_access_token,
    get_current_user,
    check_lockout, record_failed_attempt, reset_failed_attempts,
)
from email_service import EmailService

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOCKOUT_MAX_ATTEMPTS = 5


# ── Register ──────────────────────────────────────────────────────────────
@router.post("/register", status_code=201)
def register(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,  # Added for non-blocking email
    db: Session = Depends(get_db)
):
    print("\n" + "="*60)
    print(f"📝 REGISTRATION ATTEMPT: {payload.email}")
    print("="*60)

    # 1. Check email uniqueness
    existing_user = db.query(User).filter(User.Email == payload.email.lower().strip()).first()
    if existing_user:
        print(f"❌ Email already exists: {payload.email}")
        raise HTTPException(status_code=409, detail="Email already registered.")

    # 2. Password strength check (Control 3)
    strong, reason = check_password_strength(payload.password)
    if not strong:
        print(f"❌ Password too weak: {reason}")
        raise HTTPException(status_code=422, detail=reason)

    # 3. Breached password check — HIBP k-anonymity (Control 3)
    if is_password_breached(payload.password):
        print(f"❌ Password found in data breach")
        raise HTTPException(
            status_code=422,
            detail="This password has appeared in a known data breach. Please choose a different password.",
        )

    # 4. Generate email verification token (24-hour expiry)
    verification_token = secrets.token_urlsafe(32)
    verification_expires = datetime.now(timezone.utc) + timedelta(hours=24)

    # 5. Create the user (unverified by default)
    user = User(
        full_name                   = payload.full_name.strip(),
        Email                       = payload.email.lower().strip(),
        password_hash               = hash_password(payload.password),
        Role                        = "User",
        Account_type                = "Free",
        is_email_verified           = False,
        verification_token          = verification_token,
        verification_token_expires  = verification_expires,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
        print(f"✅ User created in database: {user.Email} (ID: {user.User_ID})")
    except Exception as e:
        db.rollback()
        print(f"❌ Database error: {e}")
        raise HTTPException(status_code=409, detail="Email already registered.")

    # 6. Print link to console for debugging
    verify_link = f"https://truesiteprototypefe.pages.dev/verify-email?token={verification_token}"
    print(f"🔗 Verification link: {verify_link}")

    # 7. Send the verification email in the BACKGROUND (non-blocking)
    background_tasks.add_task(
        EmailService.send_verification_email,
        user_email=user.Email,
        full_name=user.full_name,
        verification_token=verification_token
    )
    
    print(f"✅ Registration complete for {user.Email}. Email sending in background.")
    print("="*60 + "\n")

    return {
        "message": "Registration successful. Please check your email to verify your account.",
        "email":   user.Email,
    }

# ── Login ─────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    print(f"\n🔐 LOGIN ATTEMPT: {payload.email}")
    
    user = db.query(User).filter(User.Email == payload.email.lower().strip()).first()

    # Don't reveal whether the email exists
    if not user:
        print(f"❌ Login failed: User not found - {payload.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # Control 5: lockout check before any password verification
    check_lockout(user, db)

    # Verify password
    if not verify_password(payload.password, user.password_hash):
        record_failed_attempt(user, db)   # Control 5: increment counter
        remaining = LOCKOUT_MAX_ATTEMPTS - (user.failed_attempts or 0)
        print(f"❌ Login failed: Invalid password for {payload.email} ({remaining} attempts remaining)")
        raise HTTPException(
            status_code=401,
            detail=f"Invalid email or password. {max(0, remaining)} attempt(s) remaining before lockout.",
        )

    # ── Email verification gate ───────────────────────────────────────────
    if not user.is_email_verified:
        print(f"❌ Login blocked: Email not verified for {user.Email}")
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please check your inbox for the verification link.",
        )

    # Successful login — reset counter (Control 5) and issue token (Control 1)
    reset_failed_attempts(user, db)
    token = create_access_token({"sub": user.Email, "role": user.Role})
    print(f"✅ Login successful: {user.Email}")
    
    return TokenResponse(
        access_token=token,
        user=UserPublic.model_validate(user),
        force_password_change=bool(user.must_change_password),
    )

# ── OAuth2-compatible login ───────────────────────────────────────────────
@router.post("/token")
def login_oauth2(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    payload = LoginRequest(email=form_data.username, password=form_data.password)
    result = login(payload, db)
    return {
        "access_token": result.access_token,
        "token_type":   result.token_type,
    }

# ── Get current user ──────────────────────────────────────────────────────
@router.get("/me", response_model=UserPublic)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── Change password ───────────────────────────────────────────────────────
@router.put("/change-password", status_code=200)
def change_password(
    payload: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    print(f"\n🔒 PASSWORD CHANGE for: {current_user.Email}")
    
    if not verify_password(payload.current_password, current_user.password_hash):
        print(f"❌ Password change failed: Incorrect current password")
        raise HTTPException(status_code=401, detail="Current password is incorrect.")

    strong, reason = check_password_strength(payload.new_password)
    if not strong:
        print(f"❌ Password change failed: New password too weak")
        raise HTTPException(status_code=422, detail=reason)

    if is_password_breached(payload.new_password):
        print(f"❌ Password change failed: New password found in breach")
        raise HTTPException(
            status_code=422,
            detail="This password has appeared in a known data breach. Please choose a different password.",
        )

    current_user.password_hash = hash_password(payload.new_password)
    current_user.must_change_password = False
    db.commit()
    
    print(f"✅ Password changed successfully for {current_user.Email}")
    
    try:
        EmailService.send_password_change_confirmation(
            user_email=current_user.Email,
            full_name=current_user.full_name
        )
        print(f"✅ Password change confirmation email sent")
    except Exception as e:
        print(f"⚠️ Could not send confirmation email: {e}")
    
    return {"message": "Password updated successfully."}


# ── Forgot Password ───────────────────────────────────────────────────────
@router.post("/forgot-password", status_code=200)
def forgot_password(
    payload: ForgotPasswordRequest, 
    db: Session = Depends(get_db)
):
    print(f"\n🔑 FORGOT PASSWORD request for: {payload.email}")
    
    user = db.query(User).filter(User.Email == payload.email.lower().strip()).first()
    
    success_msg = {"message": "If that email exists in our records, a reset link has been sent."}
    
    if not user:
        print(f"⚠️ Password reset requested for non-existent email: {payload.email}")
        return success_msg

    reset_token = secrets.token_urlsafe(32)
    user.reset_token = reset_token
    user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()
    
    print(f"📧 Sending password reset email to: {user.Email}")

    try:
        result = EmailService.send_password_reset_email(
            user_email=user.Email,
            full_name=user.full_name,
            reset_token=reset_token
        )
        if result:
            print(f"✅ Password reset email sent to {user.Email}")
        else:
            print(f"⚠️ Failed to send password reset email")
    except Exception as e:
        print(f"❌ Error sending password reset email: {e}")

    return success_msg


# ── Reset Password ────────────────────────────────────────────────────────
@router.post("/reset-password", status_code=200)
def reset_password(payload: ResetPasswordPayload, db: Session = Depends(get_db)):
    print(f"\n🔄 RESET PASSWORD for email: {payload.email}")
    
    user = db.query(User).filter(User.Email == payload.email.lower().strip()).first()
    
    # Validate token existence
    if not user or not user.reset_token:
        raise HTTPException(status_code=400, detail="Invalid token or email association.")
        
    # Constant-time token comparison
    if not secrets.compare_digest(user.reset_token, payload.token):
        print(f"❌ Reset password failed: Invalid token for {payload.email}")
        raise HTTPException(status_code=400, detail="Invalid token or email association.")
        
    # Check expiry window
    if user.reset_token_expires:
        expires = user.reset_token_expires
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            print(f"❌ Reset password failed: Token expired for {payload.email}")
            raise HTTPException(status_code=400, detail="The password reset link has expired.")

    strong, reason = check_password_strength(payload.new_password)
    if not strong:
        print(f"❌ Reset password failed: New password too weak")
        raise HTTPException(status_code=422, detail=reason)

    if is_password_breached(payload.new_password):
        print(f"❌ Reset password failed: New password found in breach")
        raise HTTPException(
            status_code=422,
            detail="This password has appeared in a known data breach. Please choose a different password.",
        )

    user.password_hash = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    reset_failed_attempts(user, db)
    
    db.commit()
    print(f"✅ Password reset successful for {user.Email}")
    
    return {"message": "Password updated successfully. You can now log in."}


# ── Test Email Endpoint ───────────────────────────────────────────────────
@router.post("/test-email")
def test_email(email: str):
    print(f"\n🧪 TEST EMAIL endpoint called for: {email}")
    try:
        result = EmailService.send_welcome_email(
            user_email=email,
            full_name="Test User"
        )
        if result:
            return {"success": True, "message": f"Test email sent to {email}"}
        else:
            return {"success": False, "message": "Email sending failed - check credentials"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}


# ── Verify Email (FIXED) ──────────────────────────────────────────────────
@router.get("/verify-email", status_code=200)
def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    """
    Called when the user clicks the verification link.
    Sets is_email_verified = TRUE and clears the token.
    """
    print(f"\n📧 VERIFY EMAIL attempt with token: {token[:12]}...")

    # 1. Fetch the user from the database
    user = db.query(User).filter(User.verification_token == token).first()

    # 2. If no user is found, the token is invalid or already used
    if not user:
        print("❌ Verification failed: Token not found (or already used)")
        raise HTTPException(
            status_code=400,
            detail="Invalid verification link. It may have already been used.",
        )

    # 3. Check expiry
    if user.verification_token_expires:
        expires = user.verification_token_expires
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            print(f"❌ Verification failed: Token expired for {user.Email}")
            raise HTTPException(
                status_code=400,
                detail="Verification link has expired. Please register again or request a new link.",
            )

    # 4. Mark verified + clear token
    user.is_email_verified          = True
    user.verification_token         = None
    user.verification_token_expires = None
    db.commit()

    print(f"✅ Email verified successfully for {user.Email}")
    return {
        "message": "Email verified successfully. You can now log in.",
        "email":   user.Email,
    }
