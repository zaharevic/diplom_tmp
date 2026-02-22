"""
Simple session-based authentication for admin panel.
Uses secure cookies to manage login state.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

# Admin credentials from environment
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Session storage (in-memory; in production use Redis or similar)
active_sessions = {}


def create_session(session_id: Optional[str] = None) -> str:
    """Create new admin session."""
    if session_id is None:
        session_id = secrets.token_hex(32)
    
    active_sessions[session_id] = {
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=12),
    }
    
    return session_id


def is_session_valid(session_id: Optional[str]) -> bool:
    """Check if session is valid and not expired."""
    if not session_id:
        return False
    
    session = active_sessions.get(session_id)
    if not session:
        return False
    
    if datetime.now(timezone.utc) > session["expires_at"]:
        # Session expired
        del active_sessions[session_id]
        return False
    
    return True


def invalidate_session(session_id: str):
    """Logout/invalidate session."""
    if session_id in active_sessions:
        del active_sessions[session_id]


def verify_password(password: str) -> bool:
    """Verify admin password."""
    return password == ADMIN_PASSWORD
