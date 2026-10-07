"""Vercel entry point: serves the demo console page and its /api/* endpoints."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo_app"))
sys.path.insert(0, ROOT)

from app import Handler  # noqa: E402


class handler(Handler):
    pass
