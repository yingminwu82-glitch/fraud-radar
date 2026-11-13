"""Vercel entry point for the existing FastAPI application."""

from pathlib import Path
import os
import sys

backend_path = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(backend_path))

# Vercel serverless functions may not expose a writable filesystem for SQLite.
# Keep the SQLite demo available unless a hosted DATABASE_URL is configured.
os.environ.setdefault("DATABASE_URL", "sqlite://")

from app.main import app  # noqa: E402
