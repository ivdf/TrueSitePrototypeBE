# routers/analysis.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from database import get_db, User, AnalysisResult, UserScan, DailyCount
from schemas import AnalyzeRequest, AnalysisResponse
from security import get_current_user
from analyzer import analyze_url
from email_service import EmailService

router = APIRouter(prefix="/api/analysis", tags=["analysis"])

# ── Daily limit configuration ─────────────────────────────────────────────
DAILY_LIMIT = 5
UNLIMITED_ROLES = {"Admin"}


def effective_limit(user: User) -> int:
    """Return the daily analysis limit for the given user (0 = unlimited)."""
    return 0 if user.Role in UNLIMITED_ROLES else DAILY_LIMIT


# ── Validation type normalization (DV=0, OV=1, EV=2) ──────────────────────
def _vtype_to_int(v) -> int:
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v if v in (0, 1, 2) else 0
    return {"DV": 0, "OV": 1, "EV": 2}.get(str(v), 0)


def normalize_result(result: str) -> str:
    mapping = {
        "legitimate": "Legitimate",
        "suspicious": "Suspicious",
        "scam":       "Phishing Alert",
    }
    return mapping.get(result.lower(), result)


def get_today_count(user_id: int, db: Session) -> DailyCount:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    record = db.query(DailyCount).filter(
        DailyCount.user_id == user_id,
        DailyCount.date    == today,
    ).first()
    if not record:
        record = DailyCount(user_id=user_id, date=today, count=0)
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(
    payload: AnalyzeRequest,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    daily = get_today_count(current_user.User_ID, db)
    limit = effective_limit(current_user)
    if limit > 0 and daily.count >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit of {limit} analyses reached. Resets at midnight UTC.",
        )

    analysis = analyze_url(payload.url)
    features = analysis["details"]["features"]

    ar = AnalysisResult(
        url                  = payload.url,
        certificate_age_days = features["cert_age_days"],
        certificate_type     = _vtype_to_int(features["validation_type"]),
        san_count            = features["san_count"],
        key_length           = features["key_length"],
        wildcard             = 1 if features["is_wildcard"] else 0,
        result               = normalize_result(analysis["result"]),
    )
    db.add(ar)
    db.flush()

    scan = UserScan(User_ID=current_user.User_ID, analysis_id=ar.id)
    db.add(scan)
    daily.count += 1
    db.commit()

    EmailService.send_analysis_alert(
        user_email  = current_user.Email,
        full_name   = current_user.full_name,
        url         = payload.url,
        result      = analysis["result"],
        confidence  = analysis["confidence"],
        risk_score  = analysis["risk_score"],
    )

    return AnalysisResponse(
        url        = payload.url,
        result     = analysis["result"],
        confidence = analysis["confidence"],
        risk_score = analysis["risk_score"],
        details    = analysis["details"],
    )


@router.get("/usage")
def get_usage(
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    daily = get_today_count(current_user.User_ID, db)
    limit = effective_limit(current_user)
    if limit == 0:
        return {"used": daily.count, "limit": 0, "remaining": -1, "unlimited": True}
    return {
        "used":      daily.count,
        "limit":     limit,
        "remaining": max(0, limit - daily.count),
        "unlimited": False,
    }


@router.get("/history")
def get_history(
    limit:        int     = 20,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    scans = (
        db.query(UserScan)
        .filter(UserScan.User_ID == current_user.User_ID)
        .order_by(UserScan.scanned_at.desc())
        .limit(min(limit, 50))
        .all()
    )
    result = []
    for scan in scans:
        ar = scan.analysis
        result.append({
            "id":          scan.id,
            "url":         ar.url         if ar else "",
            "result":      ar.result      if ar else "",
            "confidence":  "",
            "risk_score":  "",
            "analyzed_at": scan.scanned_at.isoformat(),
            "certificate_age_days": ar.certificate_age_days if ar else 0,
            "certificate_type":     ar.certificate_type     if ar else 0,
            "san_count":            ar.san_count             if ar else 0,
            "key_length":           ar.key_length            if ar else 0,
            "wildcard":             ar.wildcard              if ar else 0,
        })
    return result