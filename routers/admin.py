from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from database import get_db, User, AnalysisResult, UserScan
from schemas  import UserAdminView, RoleUpdateRequest
from security import get_current_user, require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users", response_model=list[UserAdminView])
def list_users(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.get("/users/{user_id}", response_model=UserAdminView)
def get_user(user_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.User_ID == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.put("/users/{user_id}/role")
def update_role(
    user_id: int, payload: RoleUpdateRequest,
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.User_ID == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.User_ID == admin.User_ID:
        raise HTTPException(status_code=400, detail="You cannot change your own role.")
    user.Role = payload.role
    db.commit()
    return {"message": f"Role updated to {payload.role} for {user.Email}."}


@router.post("/users/{user_id}/reset-lockout")
def reset_lockout(user_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.User_ID == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.failed_attempts = 0
    user.locked_until    = None
    db.commit()
    return {"message": f"Lockout cleared for {user.Email}."}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == admin.User_ID:
        raise HTTPException(status_code=400, detail="Cannot delete your own account.")
    user = db.query(User).filter(User.User_ID == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    db.delete(user)
    db.commit()
    return {"message": f"User {user.Email} deleted."}


@router.get("/stats")
def get_stats(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    total_users     = db.query(User).count()
    admin_count     = db.query(User).filter(User.Role == "Admin").count()
    locked          = db.query(User).filter(User.locked_until > datetime.now(timezone.utc)).count()
    total_analyses  = db.query(AnalysisResult).count()
    total_scans     = db.query(UserScan).count()

    # Result breakdown from analysis_results
    legitimate = db.query(AnalysisResult).filter(AnalysisResult.result == "Legitimate").count()
    suspicious = db.query(AnalysisResult).filter(AnalysisResult.result == "Suspicious").count()
    phishing   = db.query(AnalysisResult).filter(AnalysisResult.result == "Phishing Alert").count()

    return {
        "total_users":       total_users,
        "admin_count":       admin_count,
        "regular_users":     total_users - admin_count,
        "currently_locked":  locked,
        "total_analyses":    total_analyses,
        "total_scans":       total_scans,
        "results_breakdown": {
            "legitimate": legitimate,
            "suspicious": suspicious,
            "phishing":   phishing,
        },
    }
