import os
import sys


def find_script(script_name: str) -> str | None:
    """Locate a helper script in common candidate directories."""
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidates = [
        os.path.join(base, "scripts", script_name),
        os.path.join(os.getcwd(), "scripts", script_name),
        os.path.join("/app", "scripts", script_name),
        os.path.join(base, script_name),
    ]
    for p in candidates:
        try:
            if os.path.exists(p):
                return p
        except Exception:
            continue
    return None
