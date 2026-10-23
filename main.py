"""
TrueSite — FastAPI Backend
Run with: uvicorn main:app --reload --port 8000
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from database import init_db
from routers import auth, analysis, admin

load_dotenv()

app = FastAPI(
    title="TrueSite API",
    description="ML-powered phishing detection backend",
    version="1.0.0",
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ── No-cache middleware for authenticated responses ─────────────────────
class NoCacheMiddleware(BaseHTTPMiddleware):
    """
    Tells the browser not to cache API responses so that pressing the
    Back button after logout does not show stale authenticated data.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Only apply to API endpoints — static assets can still be cached
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"]        = "no-cache"
            response.headers["Expires"]       = "0"
        return response

# ── CORS ──────────────────────────────────────────────────────────────────
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(NoCacheMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(analysis.router)
app.include_router(admin.router)


# ── Startup ───────────────────────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    init_db()
    print("🚀 TrueSite backend running")


# ── Health check ──────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "service": "TrueSite API", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}
