from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
import uvicorn
import os
import json
import sqlite3
import logging
import time
import sys
from datetime import datetime, timezone
from contextlib import contextmanager
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import NVD module
from nvd import NVDClient, print_nvd_log_summary, normalize_for_nvd
from auth import create_session, is_session_valid, invalidate_session, verify_password
from pages import (
    get_login_page, get_dashboard_page, get_hosts_page, 
    get_packages_page, get_software_management_page
)

# Check for -nvd-log flag
NVD_LOG = "-nvd-log" in sys.argv or os.environ.get("NVD_LOG") == "true"
if NVD_LOG:
    logger.info("NVD API logging enabled - detailed statistics will be printed")

app = FastAPI()

# List of public routes (no authentication required)
PUBLIC_ROUTES = {"/login", "/api/collect"}

def get_session_id(request: Request) -> str:
    """Extract session ID from cookie."""
    return request.cookies.get("admin_session", "")

def is_admin_authenticated(request: Request) -> bool:
    """Check if user is authenticated admin."""
    session_id = get_session_id(request)
    return is_session_valid(session_id)

# Middleware for logging and authentication
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Log requests and enforce authentication."""
    start_time = time.time()
    method = request.method
    path = request.url.path
    
    # Check if route requires authentication
    is_public = path in PUBLIC_ROUTES or path.startswith("/api/collect")
    is_admin_page = path.startswith(("/dashboard", "/hosts", "/packages", "/logout"))
    is_api_call = path.startswith("/api/") and path not in PUBLIC_ROUTES
    
    # Redirect to login if accessing admin pages without auth
    if is_admin_page and not is_admin_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    
    # For API calls (except collection), check X-API-KEY or session
    if is_api_call and API_KEY:
        provided_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
        if provided_key != API_KEY and not is_admin_authenticated(request):
            return JSONResponse({"error": "Invalid or missing API key"}, status_code=401)
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        status_code = response.status_code
        logger.info(f"{method} {path} -> {status_code} (took {process_time:.2f}s)")
        return response
    except Exception as e:
        logger.error(f"{method} {path} -> ERROR: {e}")
        raise

DATA_DIR = os.environ.get("DATA_DIR", "/data/reports")
os.makedirs(DATA_DIR, exist_ok=True)

# SQLite database for storing reports and packages
DB_PATH = os.environ.get("DB_PATH", "/data/reports/vuln_collector.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Optional API key enforcement
API_KEY = os.environ.get("API_KEY")
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # Optional NVD API key for higher rate limits

if API_KEY:
    logger.info(f"API_KEY configured; enforcing X-API-KEY header")

# Initialize NVD client
nvd_client = NVDClient(DB_PATH, api_key=NVD_API_KEY)
if NVD_API_KEY:
    logger.info(f"NVD_API_KEY configured for higher rate limits")
else:
    logger.warning(f"NVD_API_KEY not set; using public NVD API (limited rate)")


# ==================== AUTHENTICATION ROUTES ====================

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Render login page."""
    return get_login_page().replace("{error_html}", "")


@app.post("/login")
async def login(request: Request, response: Response):
    """Handle login form submission."""
    try:
        form_data = await request.form()
        password = form_data.get("password", "")
        
        if verify_password(password):
            session_id = create_session()
            resp = RedirectResponse(url="/dashboard", status_code=302)
            resp.set_cookie("admin_session", session_id, max_age=12*3600, httponly=True)
            logger.info(f"Admin login successful")
            return resp
        else:
            logger.warning(f"Failed login attempt with incorrect password")
            error_html = '<div class="error">Incorrect password</div>'
            return HTMLResponse(
                get_login_page().replace("{error_html}", error_html),
                status_code=401
            )
    except Exception as e:
        logger.error(f"Login error: {e}")
        return HTMLResponse(
            get_login_page().replace("{error_html}", '<div class="error">Login error</div>'),
            status_code=500
        )


@app.post("/logout")
async def logout(request: Request):
    """Handle logout."""
    session_id = get_session_id(request)
    if session_id:
        invalidate_session(session_id)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("admin_session")
    logger.info(f"Admin logout")
    return response


# ==================== ADMIN PAGES ====================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect root to dashboard."""
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Render dashboard page."""
    return get_dashboard_page()


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page():
    """Render hosts management page."""
    return get_hosts_page()


@app.get("/packages", response_class=HTMLResponse)
async def packages_page():
    """Render package selection page."""
    return get_packages_page()


@app.get("/software-management", response_class=HTMLResponse)
async def software_management_page():
    """Render software management page."""
    return get_software_management_page()



def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        c = conn.cursor()
        # Table for reports (raw JSON)
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
        # Table for software (packages) from reports
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
        
        # Table for software management (status, normalized names for NVD)
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
        
        # Table for scan queue tracking
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
        
        conn.commit()


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# Initialize database on startup
init_db()


@app.post("/api/collect")
async def collect(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Check API key if configured
    if API_KEY:
        provided_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
        if provided_key != API_KEY:
            logger.warning(f"Invalid or missing API key from {request.client.host}")
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        logger.debug(f"API key verified for {request.client.host}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = payload.get("hostname", "unknown")
    safe_host = ''.join(c for c in host if c.isalnum() or c in ('-', '_')).rstrip()
    filename = f"report_{safe_host}_{ts}.json"
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Save report to database
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO reports (hostname, ip, os, collected_at, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.get("hostname", "unknown"),
                payload.get("ip", ""),
                payload.get("os", ""),
                payload.get("collected_at", ""),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        report_id = c.lastrowid

        # Insert software packages
        software_list = payload.get("software", [])
        for app_info in software_list:
            c.execute(
                """
                INSERT INTO software (report_id, hostname, name, version)
                VALUES (?, ?, ?, ?)
                """,
                (
                    report_id,
                    payload.get("hostname", "unknown"),
                    app_info.get("name", ""),
                    app_info.get("version", ""),
                ),
            )
        conn.commit()

    logger.info(f"Report received from {host}: id={report_id}, software_count={len(software_list)}, saved to {path}")
    return JSONResponse({"status": "ok", "saved_to": path, "report_id": report_id})


@app.get("/api/hosts/ping")
async def ping_host(hostname: str):
    """
    Ping a host to check if it's online.
    Returns online status based on ICMP/TCP ping.
    """
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname required")
    
    try:
        # Try to resolve hostname and connect on port 22 (SSH) or 445 (SMB)
        # If no response in 2 seconds, consider offline
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        # Try SSH first (port 22)
        try:
            result = sock.connect_ex((hostname, 22))
            sock.close()
            is_online = (result == 0)
        except socket.gaierror:
            # Hostname resolution failed
            is_online = False
        except Exception:
            is_online = False
        
        logger.debug(f"Ping check for {hostname}: {'online' if is_online else 'offline'}")
        return JSONResponse({"hostname": hostname, "online": is_online})
    
    except Exception as e:
        logger.error(f"Error pinging {hostname}: {e}")
        return JSONResponse({"hostname": hostname, "online": False})


@app.get("/api/reports")
async def get_reports(hostname: str = None, limit: int = 100):
    """Get reports, optionally filtered by hostname."""
    with get_db() as conn:
        c = conn.cursor()
        if hostname:
            c.execute(
                "SELECT id, hostname, ip, os, collected_at, received_at FROM reports WHERE hostname = ? ORDER BY received_at DESC LIMIT ?",
                (hostname, limit),
            )
        else:
            c.execute(
                "SELECT id, hostname, ip, os, collected_at, received_at FROM reports ORDER BY received_at DESC LIMIT ?",
                (limit,),
            )
        reports = [dict(row) for row in c.fetchall()]
    logger.debug(f"Retrieved {len(reports)} reports (hostname={hostname})")
    return JSONResponse({"reports": reports})


@app.get("/api/software")
async def get_software(hostname: str = None, name: str = None, limit: int = 1000):
    """Get software packages, optionally filtered by hostname or name."""
    logger.debug(f"Fetching software: hostname={hostname}, name={name}, limit={limit}")
    
    with get_db() as conn:
        c = conn.cursor()
        # Use DISTINCT to avoid duplicates from multiple reports
        query = "SELECT DISTINCT hostname, name, version FROM software WHERE 1=1"
        params = []
        if hostname:
            query += " AND hostname = ?"
            params.append(hostname)
        if name:
            query += " AND name LIKE ?"
            params.append(f"%{name}%")
        query += " ORDER BY hostname, name LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        software = [dict(row) for row in c.fetchall()]
    
    logger.info(f"Retrieved {len(software)} unique software records (hostname={hostname}, name={name})")
    return JSONResponse({"software": software})


@app.get("/api/hosts")
async def get_hosts():
    """Get list of unique hostnames that reported."""
    logger.debug("Fetching list of hosts")
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT hostname FROM reports ORDER BY hostname")
        hosts = [row[0] for row in c.fetchall()]
    
    logger.info(f"Retrieved {len(hosts)} hosts")
    return JSONResponse({"hosts": hosts})


@app.get("/api/check-cves")
async def check_cves(package_name: str, version: str = None):
    """
    Check package for CVEs using NVD API with smart caching.
    Uses 24-hour cache TTL to minimize API calls.
    """
    if not package_name:
        raise HTTPException(status_code=400, detail="package_name required")
    
    logger.info(f"CVE check requested: package={package_name}, version={version}")
    result = nvd_client.check_package(package_name, version)
    
    logger.info(
        f"CVE check result: package={package_name}, version={version}, "
        f"cves_found={result['cves_found']}, cvss_max={result['cvss_max']}, "
        f"cached={result['cached']}, vulnerable={result['vulnerable']}"
    )
    return JSONResponse(result)


@app.get("/api/scan-host")
async def scan_host(hostname: str):
    """
    Scan all software on a host for CVEs.
    Returns summary of vulnerable packages.
    """
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname required")
    
    logger.info(f"Host scan requested: hostname={hostname}")
    # Instead of performing an immediate NVD scan (which can be long-running),
    # return the list of available packages for the host so the user can
    # select which ones to scan via the UI. Scanning is performed by
    # POST /api/scan-packages with a list of package names.
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT name, version FROM software WHERE hostname = ? ORDER BY name", (hostname,))
        rows = c.fetchall()

    software_list = [{"name": r[0], "version": r[1]} for r in rows]
    logger.info(f"Returning {len(software_list)} unique software packages for {hostname} (no NVD queries performed)")

    return JSONResponse({
        "hostname": hostname,
        "total_software": len(software_list),
        "software": software_list,
    })


@app.post("/api/scan-packages")
async def scan_packages(request: Request):
    """
    Scan selected packages for a host. Expects JSON:
    {
      "hostname": "DESKTOP-...",
      "packages": [ {"name": "pkg1", "version": "1.2"}, {"name": "pkg2"} ]
    }
    Returns CVE results for selected packages.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    hostname = payload.get("hostname")
    packages = payload.get("packages")
    if not hostname or not packages or not isinstance(packages, list):
        raise HTTPException(status_code=400, detail="hostname and packages[] required")

    logger.info(f"Selected scan requested for host={hostname}, packages={len(packages)}")

    vulnerable = []
    checked = 0

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version") if pkg.get("version") else None
        if not name:
            continue
        checked += 1
        result = nvd_client.check_package(name, version)

        if result["vulnerable"]:
            vulnerable.append({
                "name": name,
                "version": version,
                "cves_found": result["cves_found"],
                "cvss_max": result["cvss_max"],
                "cves": result["cves"][:10],
            })
            logger.warning(
                f"Vulnerability found on {hostname}: {name} v{version} ({result['cves_found']} CVEs, CVSS max={result['cvss_max']})"
            )

    logger.info(f"Selected scan complete for {hostname}: checked={checked}, vulnerable={len(vulnerable)}")

    if NVD_LOG:
        print_nvd_log_summary()

    return JSONResponse({
        "hostname": hostname,
        "checked": checked,
        "vulnerable_count": len(vulnerable),
        "vulnerable_packages": vulnerable,
    })


@app.get("/api/packages")
async def get_packages():
    """
    Get all unique packages with their normalized names and CVE counts.
    Used for package management UI.
    """
    with get_db() as conn:
        c = conn.cursor()
        # Get unique packages with count and CVE status
        c.execute("""
            SELECT DISTINCT name
            FROM software
            ORDER BY name
        """)
        packages = c.fetchall()
    
    result = []
    for (pkg_name,) in packages:
        normalized = normalize_for_nvd(pkg_name)

        # Use cached results only to avoid triggering live NVD API queries
        cached = nvd_client.cache.get_cached_result(pkg_name)
        if cached:
            cves_found = cached.get("cves_found", 0)
            cvss_max = cached.get("cvss_max", 0)
            vulnerable = cves_found > 0
            was_cached = True
        else:
            cves_found = 0
            cvss_max = 0
            vulnerable = False
            was_cached = False

        result.append({
            "original_name": pkg_name,
            "normalized_name": normalized,
            "cves_found": cves_found,
            "cvss_max": cvss_max,
            "cached": was_cached,
            "vulnerable": vulnerable,
        })
    
    logger.debug(f"Retrieved {len(result)} packages for management UI")
    return JSONResponse(result)


@app.post("/api/packages/rescan")
async def rescan_package(request: Request):
    """
    Update package name and rescan NVD with new name.
    Used when user corrects a package name.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    original_name = payload.get("original_name")
    new_name = payload.get("new_name")
    
    if not original_name or not new_name:
        raise HTTPException(status_code=400, detail="original_name and new_name required")
    
    logger.info(f"Package rename requested: {original_name} -> {new_name}")
    
    # Update all references to this package in database
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE software SET name = ? WHERE name = ?", (new_name, original_name))
        conn.commit()
        updated_count = c.rowcount
    
    logger.info(f"Updated {updated_count} software records from {original_name} to {new_name}")
    
    # Clear cache for this package and rescan
    with nvd_client.cache._get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM cve_cache WHERE package_name = ?", (original_name,))
        conn.commit()
    
    # Perform fresh NVD query with new name
    result = nvd_client.check_package(new_name)
    
    logger.info(
        f"Rescan complete for {new_name}: cves_found={result['cves_found']}, "
        f"cvss_max={result['cvss_max']}"
    )
    
    return JSONResponse({
        "success": True,
        "original_name": original_name,
        "new_name": new_name,
        "updated_records": updated_count,
        "cve_result": result,
    })


# ==================== SOFTWARE MANAGEMENT API ====================

@app.get("/api/software-management")
async def get_software_management():
    """Get all unique software with their management status and normalized NVD names."""
    with get_db() as conn:
        c = conn.cursor()
        
        # Get all unique software names from reports
        c.execute("""
            SELECT DISTINCT name FROM software ORDER BY name
        """)
        packages = [row[0] for row in c.fetchall()]
        
        result = []
        for pkg_name in packages:
            # Check if this package has management settings
            c.execute("""
                SELECT normalized_for_nvd, status, comment FROM software_management 
                WHERE original_name = ?
            """, (pkg_name,))
            mgmt_row = c.fetchone()
            
            # Get cached CVE status
            cached = nvd_client.cache.get_cached_result(pkg_name)
            
            if mgmt_row:
                normalized = mgmt_row[0]
                status = mgmt_row[1]
                comment = mgmt_row[2]
            else:
                normalized = normalize_for_nvd(pkg_name)
                status = "new"
                comment = None
            
            cves_found = cached.get("cves_found", 0) if cached else 0
            
            result.append({
                "original_name": pkg_name,
                "normalized_for_nvd": normalized,
                "status": status,
                "comment": comment,
                "cves_found": cves_found,
                "cached": cached is not None,
            })
    
    logger.debug(f"Retrieved {len(result)} software packages for management")
    return JSONResponse(result)


@app.post("/api/software-management/update")
async def update_software_management(request: Request):
    """Update software management settings (status, normalized name)."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    original_name = payload.get("original_name")
    normalized_for_nvd = payload.get("normalized_for_nvd")
    status = payload.get("status")  # new, in_task, ignore
    comment = payload.get("comment", "")
    
    if not original_name:
        raise HTTPException(status_code=400, detail="original_name required")
    
    if status not in ("new", "in_task", "ignore"):
        raise HTTPException(status_code=400, detail="status must be: new, in_task, or ignore")
    
    logger.info(f"Software management update: {original_name} -> status={status}, normalized={normalized_for_nvd}")
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Insert or update management record
        if not normalized_for_nvd:
            normalized_for_nvd = normalize_for_nvd(original_name)
        
        c.execute("""
            INSERT INTO software_management (original_name, normalized_for_nvd, status, comment, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(original_name) DO UPDATE SET
                normalized_for_nvd = ?,
                status = ?,
                comment = ?,
                updated_at = CURRENT_TIMESTAMP
        """, (original_name, normalized_for_nvd, status, comment, normalized_for_nvd, status, comment))
        
        conn.commit()
    
    return JSONResponse({
        "success": True,
        "original_name": original_name,
        "status": status,
        "normalized_for_nvd": normalized_for_nvd,
    })


@app.post("/api/force-check")
async def force_check_package(request: Request):
    """Force check a package against NVD API, ignoring cache."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    package_name = payload.get("package_name")
    version = payload.get("version")
    
    if not package_name:
        raise HTTPException(status_code=400, detail="package_name required")
    
    logger.info(f"Force check requested for: {package_name} v{version}")
    
    # Clear cache entry
    with nvd_client.cache._get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM cve_cache WHERE package_name = ? AND version = ?", 
                  (package_name, version or ""))
        conn.commit()
    
    # Perform fresh NVD query
    result = nvd_client.check_package(package_name, version)
    
    logger.info(
        f"Force check complete for {package_name}: cves_found={result['cves_found']}, "
        f"cvss_max={result['cvss_max']}"
    )
    
    return JSONResponse(result)


@app.get("/api/scan-queue")
async def get_scan_queue():
    """Get current scan queue status."""
    with get_db() as conn:
        c = conn.cursor()
        
        # Get pending and in-progress scans
        c.execute("""
            SELECT id, hostname, status, started_at, total_packages, checked_packages, 
                   vulnerable_count, created_at
            FROM scan_queue
            WHERE status IN ('pending', 'processing')
            ORDER BY created_at DESC
            LIMIT 50
        """)
        queue_items = [dict(row) for row in c.fetchall()]
        
        # Get recent completed scans
        c.execute("""
            SELECT id, hostname, status, completed_at, total_packages, checked_packages, 
                   vulnerable_count, created_at
            FROM scan_queue
            WHERE status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 10
        """)
        completed_items = [dict(row) for row in c.fetchall()]
    
    logger.debug(f"Retrieved scan queue: {len(queue_items)} active, {len(completed_items)} recent")
    
    return JSONResponse({
        "active": queue_items,
        "recent_completed": completed_items,
    })


@app.post("/api/scan-queue/add")
async def add_to_scan_queue(request: Request):
    """Add a host scan to the queue."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    hostname = payload.get("hostname")
    report_id = payload.get("report_id")
    
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname required")
    
    logger.info(f"Adding to scan queue: {hostname} (report_id={report_id})")
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO scan_queue (hostname, report_id, status, created_at)
            VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
        """, (hostname, report_id))
        conn.commit()
        queue_id = c.lastrowid
    
    return JSONResponse({
        "success": True,
        "queue_id": queue_id,
        "hostname": hostname,
        "status": "pending",
    })


@app.post("/api/scan-queue/update")
async def update_scan_queue(request: Request):
    """Update scan queue item status."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    queue_id = payload.get("queue_id")
    status = payload.get("status")  # pending, processing, completed, failed
    checked = payload.get("checked_packages", 0)
    vulnerable = payload.get("vulnerable_count", 0)
    total = payload.get("total_packages", 0)
    error = payload.get("error_message")
    
    if not queue_id or not status:
        raise HTTPException(status_code=400, detail="queue_id and status required")
    
    logger.debug(f"Updating scan queue {queue_id}: status={status}")
    
    with get_db() as conn:
        c = conn.cursor()
        
        if status == "processing":
            c.execute("""
                UPDATE scan_queue 
                SET status = ?, started_at = CURRENT_TIMESTAMP, total_packages = ?
                WHERE id = ?
            """, (status, total, queue_id))
        elif status == "completed":
            c.execute("""
                UPDATE scan_queue 
                SET status = ?, completed_at = CURRENT_TIMESTAMP, 
                    checked_packages = ?, vulnerable_count = ?
                WHERE id = ?
            """, (status, checked, vulnerable, queue_id))
        elif status == "failed":
            c.execute("""
                UPDATE scan_queue 
                SET status = ?, completed_at = CURRENT_TIMESTAMP, error_message = ?
                WHERE id = ?
            """, (status, error, queue_id))
        else:
            c.execute("UPDATE scan_queue SET status = ? WHERE id = ?", (status, queue_id))
        
        conn.commit()
    
    return JSONResponse({"success": True, "queue_id": queue_id, "status": status})


if __name__ == "__main__":
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=False)
