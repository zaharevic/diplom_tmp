from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import os
import json
import sqlite3
import logging
import time
import sys
from datetime import datetime, timezone
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import NVD module
from nvd import NVDClient, print_nvd_log_summary, normalize_for_nvd
from dashboard import create_dashboard_route

# Check for -nvd-log flag
NVD_LOG = "-nvd-log" in sys.argv or os.environ.get("NVD_LOG") == "true"
if NVD_LOG:
    logger.info("NVD API logging enabled - detailed statistics will be printed")

app = FastAPI()

# Middleware for logging all HTTP requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming HTTP requests with response status."""
    start_time = time.time()
    method = request.method
    path = request.url.path
    
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


# Initialize dashboard routes
create_dashboard_route(app)


if __name__ == "__main__":
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=False)
