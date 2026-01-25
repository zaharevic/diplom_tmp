from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import os
import json
import sqlite3
import logging
import time
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
from nvd import NVDClient

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
        query = "SELECT id, report_id, hostname, name, version FROM software WHERE 1=1"
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
    
    logger.info(f"Retrieved {len(software)} software records (hostname={hostname}, name={name})")
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
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT name, version FROM software WHERE hostname = ? ORDER BY name", (hostname,))
        software_list = c.fetchall()
    
    logger.info(f"Found {len(software_list)} unique software packages on {hostname}")
    
    vulnerable = []
    checked = 0
    
    for name, version in software_list:
        checked += 1
        result = nvd_client.check_package(name, version)
        
        if result["vulnerable"]:
            vulnerable.append({
                "name": name,
                "version": version,
                "cves_found": result["cves_found"],
                "cvss_max": result["cvss_max"],
                "cves": result["cves"][:5],  # Top 5 CVEs
            })
            logger.warning(
                f"Vulnerability found on {hostname}: {name} v{version} "
                f"({result['cves_found']} CVEs, CVSS max={result['cvss_max']})"
            )
    
    logger.info(
        f"Scan complete for {hostname}: checked={checked}, vulnerable={len(vulnerable)}"
    )
    return JSONResponse({
        "hostname": hostname,
        "total_software": checked,
        "vulnerable_count": len(vulnerable),
        "vulnerable_packages": vulnerable,
    })


if __name__ == "__main__":
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=False)
