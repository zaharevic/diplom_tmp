import sqlite3
import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/reports/vuln_collector.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        c = conn.cursor()
        _create_tables(c)
        _run_migrations(c)
        conn.commit()


def _create_tables(c):
    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            ip TEXT,
            os TEXT,
            collected_at TEXT,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP,
            raw_json TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            hostname TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_software_hostname ON software(hostname)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_software_name ON software(name)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS software_management (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL UNIQUE,
            normalized_for_nvd TEXT NOT NULL,
            status TEXT DEFAULT 'new',
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_software_management_status ON software_management(status)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            report_id INTEGER,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            total_packages INTEGER DEFAULT 0,
            checked_packages INTEGER DEFAULT 0,
            vulnerable_count INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE SET NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_queue_hostname ON scan_queue(hostname)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_queue_status ON scan_queue(status)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS vuln_risk (
            cve_id TEXT PRIMARY KEY,
            ep_ss REAL DEFAULT 0,
            in_kev INTEGER DEFAULT 0,
            base_risk REAL DEFAULT 0,
            computed_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS vuln_risk_host (
            host TEXT,
            cve_id TEXT,
            risk_score REAL DEFAULT 0,
            computed_at TEXT,
            PRIMARY KEY (host, cve_id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_risk_base_risk ON vuln_risk(base_risk)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_risk_host_host ON vuln_risk_host(host)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            host TEXT PRIMARY KEY,
            criticality INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_hosts_criticality ON hosts(criticality)")


def _run_migrations(c):
    """Idempotent ALTER TABLE migrations."""
    _safe_alter(c, "ALTER TABLE software_management ADD COLUMN ep_ss REAL DEFAULT 0")
    _safe_alter(c, "ALTER TABLE software_management ADD COLUMN in_kev INTEGER DEFAULT 0")
    _safe_alter(c, "ALTER TABLE software_management ADD COLUMN last_checked TEXT")
    _safe_alter(c, "ALTER TABLE software ADD COLUMN family TEXT DEFAULT ''")
    c.execute("CREATE INDEX IF NOT EXISTS idx_software_family ON software(family)")

    # Fix any legacy invalid status values
    c.execute("UPDATE software_management SET status = 'new' WHERE status IS NULL OR status = ''")
    c.execute("UPDATE software_management SET status = 'new' WHERE status NOT IN ('new', 'in_task', 'ignore')")


def _safe_alter(c, sql: str):
    try:
        c.execute(sql)
    except Exception:
        pass  # column already exists
