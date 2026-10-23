#!/bin/bash
# TrueSite Local Setup Script
# Run this once to set everything up

set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║       TrueSite Local Setup           ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Check PostgreSQL ────────────────────────────────────────────────────
echo "[ 1/5 ] Checking PostgreSQL..."
if ! command -v psql &> /dev/null; then
  echo "  ❌ PostgreSQL not found."
  echo "  Install it from: https://www.postgresql.org/download/"
  echo "  Then re-run this script."
  exit 1
fi
echo "  ✅ PostgreSQL found."

# ── 2. Create database ─────────────────────────────────────────────────────
echo ""
echo "[ 2/5 ] Creating database..."
echo "  Enter your PostgreSQL password when prompted."
psql -U postgres -c "CREATE DATABASE truesite;" 2>/dev/null || echo "  ℹ️  Database already exists — skipping."
echo "  ✅ Database ready."

# ── 3. Backend dependencies ────────────────────────────────────────────────
echo ""
echo "[ 3/5 ] Installing Python dependencies..."
cd truesite-backend
pip install -r requirements.txt
echo "  ✅ Python packages installed."

# ── 4. Frontend dependencies ───────────────────────────────────────────────
echo ""
echo "[ 4/5 ] Installing frontend dependencies..."
cd ../truesite-frontend
npm install
echo "  ✅ Node packages installed."

# ── 5. Done ────────────────────────────────────────────────────────────────
echo ""
echo "[ 5/5 ] Setup complete!"
echo ""
echo "══════════════════════════════════════════"
echo " HOW TO RUN:"
echo ""
echo " Terminal 1 — Backend:"
echo "   cd truesite-backend"
echo "   uvicorn main:app --reload --port 8000"
echo ""
echo " Terminal 2 — Frontend:"
echo "   cd truesite-frontend"
echo "   npm run dev"
echo ""
echo " Then open: http://localhost:5173"
echo "══════════════════════════════════════════"
echo ""
echo " API Docs: http://localhost:8000/docs"
echo ""
