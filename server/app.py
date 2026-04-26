from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, StreamingResponse
import csv
import io
from fastapi.templating import Jinja2Templates
import uvicorn
import os
import json
import sqlite3
import logging
import time
import sys
from datetime import datetime, timezone, date, timedelta
import socket
import threading
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import NVD module
from nvd import (
    NVDClient,
    print_nvd_log_summary,
    normalize_for_nvd,
    init_local_nvd_db,
    get_cpe_keywords,
)
from auth import create_session, is_session_valid, invalidate_session, verify_password
from pages import get_login_page
from core.database import get_db, init_db, DB_PATH
from core.utils import find_script
from services.matcher import match_package_to_cves
from services.risk import import_epss, import_kev, recompute_base_risk, compute_risk

# Check for -nvd-log flag
NVD_LOG = "-nvd-log" in sys.argv or os.environ.get("NVD_LOG") == "true"
if NVD_LOG:
    logger.info("NVD API logging enabled - detailed statistics will be printed")

app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

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

# Optional API key enforcement
API_KEY = os.environ.get("API_KEY")
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # Optional NVD API key for higher rate limits

if API_KEY:
    logger.info(f"API_KEY настроен; требуется заголовок X-API-KEY")

# Инициализировать локальную БД NVD (создаёт nvd_local.db если его нет)
init_local_nvd_db()
# Инициализировать NVD клиент
nvd_client = NVDClient(DB_PATH, api_key=NVD_API_KEY)
if NVD_API_KEY:
    logger.info(f"NVD_API_KEY настроен для более высоких лимитов запросов")
else:
    logger.warning(f"NVD_API_KEY не установлен; используется открытый NVD API (ограниченный лимит)")

# Import status tracker for background NVD import
import_status = {
    'running': False,
    'start_time': None,
    'current_year': None,
    'total_years': None,
    'last_message': None,
    'finished': False,
    'error': None,
}
import_status_lock = threading.Lock()

# Status tracker for background "scan all software" job
scan_all_state      = {"running": False, "done": 0, "total": 0, "errors": 0}
scan_all_state_lock = threading.Lock()


# ==================== AUTHENTICATION ROUTES ====================


@app.on_event("startup")
def auto_daily_snapshot():
    """Take a snapshot on startup if one hasn't been taken today."""
    try:
        taken = take_snapshot()
        if taken:
            logger.info("Daily snapshot created on startup")
    except Exception as e:
        logger.warning(f"auto_daily_snapshot failed: {e}")


@app.on_event("startup")
def ensure_nvd_populated():
    """On startup, if the local NVD DB exists but has no CVE rows,
    run a background import of all NVD yearly feeds + modified feed.

    This runs in a background thread so the FastAPI server can start
    immediately and the import proceeds asynchronously.
    """
    try:
        # Determine path to local NVD DB used by init_local_nvd_db (default)
        local_db = os.environ.get("LOCAL_NVD_DB", "nvd_local.db")
        # If init_local_nvd_db created file at /app/nvd_local.db or project root, try common locations
        possible_paths = [local_db, os.path.join(os.getcwd(), local_db), os.path.join(os.path.dirname(__file__), '..', local_db)]
        found = None
        for p in possible_paths:
            if os.path.exists(p):
                found = os.path.abspath(p)
                break
        if not found:
            logger.info(f"Local NVD DB not found at expected paths; skipping automatic import: {possible_paths}")
            return

        conn = sqlite3.connect(found)
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM cve")
            cnt = cur.fetchone()[0]
        except Exception:
            cnt = 0
        conn.close()

        if cnt > 0:
            logger.info(f"Local NVD DB at {found} already populated ({cnt} CVE rows)")
            return

        # Start background thread to import all NVD years + modified feed
        def importer_thread(db_path):
            try:
                start_year = 2002
                end_year = datetime.now().year
                logger.info(f"Starting background NVD import into {db_path} (years {start_year}-{end_year})")
                # mark status
                try:
                    with import_status_lock:
                        import_status['running'] = True
                        import_status['start_time'] = datetime.now().isoformat()
                        import_status['current_year'] = None
                        import_status['total_years'] = end_year - start_year + 1
                        import_status['last_message'] = 'Started background import'
                        import_status['finished'] = False
                        import_status['error'] = None
                except Exception:
                    pass

                # Prefer running the provided batch import script if present (simpler and tested)
                batch_script = find_script('import_all_nvd_years.sh') or find_script('Import-All-NVD-Years.ps1')
                if batch_script:
                    try:
                        with import_status_lock:
                            import_status['last_message'] = f'Running batch script {batch_script}'
                        logger.info(f"Running batch import script: {batch_script}")
                        if batch_script.endswith('.sh'):
                            logger.info(f"Running batch import script: {batch_script}")
                            subprocess.run(['bash', batch_script, str(start_year), str(end_year), db_path], check=False)
                        else:
                            # PowerShell script - invoke with powershell if available
                            logger.info(f"Running PowerShell batch import script: {batch_script}")
                            subprocess.run(['pwsh', '-File', batch_script, str(start_year), str(end_year), db_path], check=False)
                    except Exception as e:
                        logger.warning(f"Failed to run batch import script {batch_script}: {e}")
                        with import_status_lock:
                            import_status['error'] = str(e)
                else:
                    # Fallback: call per-year importer script if available
                    for year in range(start_year, end_year + 1):
                        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
                        logger.info(f"Importing NVD year {year} from {url}")
                        with import_status_lock:
                            import_status['current_year'] = year
                            import_status['last_message'] = f'Importing year {year}'
                        script_path = find_script('nvd_import_full.py')
                        if script_path:
                            try:
                                subprocess.run([sys.executable, script_path, '--feed-url', url, '--db', db_path], check=False)
                            except Exception as e:
                                logger.warning(f"Failed to run importer {script_path}: {e}")
                                with import_status_lock:
                                    import_status['last_message'] = f'Failed to run importer for year {year}: {e}'
                        else:
                            logger.error(f"Importer script nvd_import_full.py not found in any candidate paths; skipping year {year}")
                            with import_status_lock:
                                import_status['last_message'] = f'nvd_import_full.py not found; skipped year {year}'

                    # Import modified feed using nvd_update_modified.py if present
                    modurl = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
                    script_path = find_script('nvd_update_modified.py')
                    if script_path:
                        try:
                            with import_status_lock:
                                import_status['last_message'] = 'Importing modified feed'
                            subprocess.run([sys.executable, script_path, '--url', modurl, '--db', db_path], check=False)
                        except Exception as e:
                            logger.warning(f"Failed to run modified-feed importer {script_path}: {e}")
                            with import_status_lock:
                                import_status['error'] = str(e)
                    else:
                        logger.error("Modified-feed importer nvd_update_modified.py not found; modified feed not imported")
                        with import_status_lock:
                            import_status['last_message'] = 'modified importer not found'

                logger.info(f"Background NVD import finished (target DB: {db_path})")
                try:
                    with import_status_lock:
                        import_status['running'] = False
                        import_status['finished'] = True
                        import_status['last_message'] = 'Import finished'
                        import_status['current_year'] = None
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"Background NVD import failed: {e}")
                try:
                    with import_status_lock:
                        import_status['running'] = False
                        import_status['finished'] = True
                        import_status['error'] = str(e)
                        import_status['last_message'] = 'Import failed'
                except Exception:
                    pass

        t = threading.Thread(target=importer_thread, args=(found,), daemon=True)
        t.start()
        logger.info("Triggered background NVD import thread; import will run asynchronously.")

    except Exception as e:
        logger.error(f"Error while checking/starting NVD import: {e}")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Render login page."""
    return get_login_page().replace("{error_html}", "")


@app.get("/api/nvd-import/status")
async def nvd_import_status():
    """Return status of background NVD import."""
    try:
        with import_status_lock:
            status_copy = dict(import_status)
    except Exception:
        status_copy = {'running': False, 'finished': False, 'error': 'status unavailable'}
    return JSONResponse(status_copy)


# Vulnerability risk updater status tracker (EPSS + CISA KEV)
vuln_risk_status = {
    'running': False,
    'start_time': None,
    'last_message': None,
    'finished': False,
    'error': None,
}
vuln_risk_status_lock = threading.Lock()


@app.post("/api/vuln-risk/update")
async def trigger_vuln_risk_update(background: bool = True):
    """Trigger an update of vuln_risk (fetch EPSS + CISA KEV and update DB).

    If `background` is true (default), the update runs in a background thread
    and this endpoint returns immediately with status started. If false, it
    runs synchronously.
    """
    try:
        with vuln_risk_status_lock:
            if vuln_risk_status.get('running'):
                return JSONResponse({'status': 'already_running'}, status_code=409)

        def run_update():
            try:
                with vuln_risk_status_lock:
                    vuln_risk_status['running'] = True
                    vuln_risk_status['start_time'] = datetime.now().isoformat()
                    vuln_risk_status['last_message'] = 'Importing EPSS scores'
                    vuln_risk_status['finished'] = False
                    vuln_risk_status['error'] = None

                epss_count = import_epss(DB_PATH)

                with vuln_risk_status_lock:
                    vuln_risk_status['last_message'] = f'EPSS done ({epss_count} rows), importing KEV'

                kev_count = import_kev(DB_PATH)

                with vuln_risk_status_lock:
                    vuln_risk_status['last_message'] = f'KEV done ({kev_count} entries), recomputing risk scores'

                updated = recompute_base_risk(DB_PATH)

                with vuln_risk_status_lock:
                    vuln_risk_status['last_message'] = f'Done: EPSS={epss_count}, KEV={kev_count}, risk recomputed={updated}'
                    vuln_risk_status['running'] = False
                    vuln_risk_status['finished'] = True

            except Exception as e:
                logger.error(f"vuln_risk update failed: {e}")
                with vuln_risk_status_lock:
                    vuln_risk_status['running'] = False
                    vuln_risk_status['finished'] = True
                    vuln_risk_status['error'] = str(e)
                    vuln_risk_status['last_message'] = 'Update failed'

        if background:
            t = threading.Thread(target=run_update, daemon=True)
            t.start()
            return JSONResponse({'status': 'started'})
        else:
            run_update()
            return JSONResponse({'status': 'completed'})
    except Exception as e:
        logger.error(f"trigger_vuln_risk_update error: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get("/api/vuln-risk/status")
async def vuln_risk_update_status():
    """Return status of the EPSS/KEV vuln_risk updater."""
    try:
        with vuln_risk_status_lock:
            status_copy = dict(vuln_risk_status)
    except Exception:
        status_copy = {'running': False, 'finished': False, 'error': 'status unavailable'}
    return JSONResponse(status_copy)


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
            logger.info(f"Успешный вход администратора")
            return resp
        else:
            logger.warning(f"Неудачная попытка входа с неверным паролем")
            error_html = '<div class="error">Неверный пароль</div>'
            return HTMLResponse(
                get_login_page().replace("{error_html}", error_html),
                status_code=401
            )
    except Exception as e:
        logger.error(f"Ошибка при входе: {e}")
        return HTMLResponse(
            get_login_page().replace("{error_html}", '<div class="error">Ошибка входа</div>'),
            status_code=500
        )


@app.post("/logout")
async def logout(request: Request):
    """Обработать выход из системы."""
    session_id = get_session_id(request)
    if session_id:
        invalidate_session(session_id)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("admin_session")
    logger.info(f"Выход администратора")
    return response


# ==================== ADMIN PAGES ====================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Перенаправить корень на панель."""
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard")
async def dashboard(request: Request):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM reports")
        reports_count = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT hostname || '|' || name || '|' || version) FROM software")
        software_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cve_cache WHERE cves_found > 0")
        vulnerable_count = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT hostname) FROM reports")
        hosts_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'new'")
        new_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'in_task'")
        in_task_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'ignore'")
        ignore_count = c.fetchone()[0]
        c.execute("""SELECT COUNT(*) FROM software_management
                     WHERE status = 'in_task' AND due_date IS NOT NULL AND due_date < date('now')""")
        overdue_count = c.fetchone()[0]
        c.execute("""SELECT id, hostname, ip, os, received_at FROM reports
                     WHERE id IN (SELECT MAX(id) FROM reports GROUP BY hostname)
                     ORDER BY received_at DESC LIMIT 10""")
        recent_reports = [dict(row) for row in c.fetchall()]
        c.execute("""SELECT package_name, cves_found, cvss_max FROM cve_cache
                     WHERE cves_found > 0 ORDER BY cves_found DESC LIMIT 10""")
        vulnerable_packages = [dict(row) for row in c.fetchall()]
        c.execute("""
            SELECT snapshot_date, vulnerable_packages, critical_count, has_exploit_count
            FROM vulnerability_snapshots
            ORDER BY snapshot_date DESC LIMIT 30
        """)
        snapshots = [dict(row) for row in reversed(c.fetchall())]

    return templates.TemplateResponse(request, "dashboard.html", {
        "active_page": "dashboard",
        "stats": {
            "reports_count": reports_count,
            "hosts_count": hosts_count,
            "software_count": software_count,
            "vulnerable_count": vulnerable_count,
            "new_count": new_count,
            "in_task_count": in_task_count,
            "ignore_count": ignore_count,
            "overdue_count": overdue_count,
        },
        "recent_reports": recent_reports,
        "vulnerable_packages": vulnerable_packages,
        "snapshots": snapshots,
    })


@app.get("/hosts")
async def hosts_page(request: Request):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT h.hostname,
                   r.ip, r.os, r.received_at,
                   IFNULL(s.software_count, 0)         AS software_count,
                   IFNULL(hm.criticality, 1)           AS criticality,
                   IFNULL(vr.risky_count, 0)           AS risky_count,
                   IFNULL(vr.top_risk,   0.0)          AS top_risk,
                   IFNULL(t.tags, '')                  AS tags
            FROM (
                SELECT hostname FROM reports
                UNION SELECT hostname FROM software
                UNION SELECT host AS hostname FROM hosts
            ) h
            LEFT JOIN (
                SELECT * FROM reports
                WHERE id IN (SELECT MAX(id) FROM reports GROUP BY hostname)
            ) r ON r.hostname = h.hostname
            LEFT JOIN (
                SELECT hostname, COUNT(*) AS software_count FROM software GROUP BY hostname
            ) s ON s.hostname = h.hostname
            LEFT JOIN hosts hm ON hm.host = h.hostname
            LEFT JOIN (
                SELECT host,
                       COUNT(*) AS risky_count,
                       MAX(risk_score) AS top_risk
                FROM vuln_risk_host
                WHERE risk_score > 0
                GROUP BY host
            ) vr ON vr.host = h.hostname
            LEFT JOIN (
                SELECT host, GROUP_CONCAT(tag, ',') AS tags
                FROM host_tags GROUP BY host
            ) t ON t.host = h.hostname
            ORDER BY h.hostname
        """)
        raw_hosts = c.fetchall()
        hosts = []
        for row in raw_hosts:
            d = dict(row)
            d["tags"] = [t for t in (d.get("tags") or "").split(",") if t]
            hosts.append(d)

    return templates.TemplateResponse(request, "hosts.html", {
        "active_page": "hosts",
        "hosts": hosts,
    })


@app.get("/packages")
async def packages_page(request: Request):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT hostname FROM reports ORDER BY hostname")
        hostnames = [row[0] for row in c.fetchall()]

    return templates.TemplateResponse(request, "packages.html", {
        "active_page": "packages",
        "hostnames": hostnames,
    })


@app.post("/api/hosts/tags")
async def set_host_tags(request: Request):
    """Replace all tags for a host. Body: {hostname, tags: [...]}"""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    hostname = body.get("hostname")
    tags = body.get("tags", [])
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname required")
    tags = [t.strip().lower() for t in tags if t.strip()][:10]  # max 10 tags
    with get_db() as conn:
        conn.execute("DELETE FROM host_tags WHERE host=?", (hostname,))
        for tag in tags:
            conn.execute("INSERT OR IGNORE INTO host_tags (host, tag) VALUES (?, ?)", (hostname, tag))
        conn.commit()
    return JSONResponse({"ok": True, "tags": tags})


@app.post("/api/hosts/criticality")
async def set_host_criticality(request: Request):
    """Set or update host criticality (JSON body: {hostname, criticality})."""
    try:
        body = await request.json()
        hostname = body.get("hostname")
        criticality = int(body.get("criticality", 1))
        if not hostname:
            raise ValueError("hostname required")

        with get_db() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO hosts (host, criticality, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
                " ON CONFLICT(host) DO UPDATE SET criticality=excluded.criticality, updated_at=CURRENT_TIMESTAMP",
                (hostname, criticality),
            )
            conn.commit()

        return JSONResponse({"ok": True})
    except Exception as e:
        logger.error(f"Ошибка при установке критичности: {e}")
        return JSONResponse({"error": str(e)}, status_code=400)


@app.get("/software-management")
async def software_management_page(request: Request):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'new'")
        new_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'in_task'")
        in_task_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'ignore'")
        ignore_count = c.fetchone()[0]

    return templates.TemplateResponse(request, "software_management.html", {
        "active_page": "software-management",
        "new_count": new_count,
        "in_task_count": in_task_count,
        "ignore_count": ignore_count,
    })



def normalize_package_name(name: str) -> str:
    """Normalize package names to reduce noise and allow grouping.

    Rules:
    - lowercase
    - strip architecture suffix after ':' (eg. ':amd64')
    - collapse known introspection prefixes (gir1.2-*) into family name 'gir1.2'
    - trim whitespace
    """
    if not name:
        return ""
    n = name.lower().strip()
    # remove arch suffix like ':amd64'
    if ':' in n:
        n = n.split(':', 1)[0]
    # skip common noisy suffix packages (docs, locales, debug symbols, dev packages)
    NOISE_SUFFIXES = ['-doc', '-dbg', '-locale', '-locales', '-man', '-symbols', '-common', '-data', '-dev']
    for s in NOISE_SUFFIXES:
        if n.endswith(s):
            return ""
    # group GObject-introspection bindings into family to reduce noise
    GROUP_PREFIXES = ["gir1.2-", "gir1-", "gir-"]
    for p in GROUP_PREFIXES:
        if n.startswith(p):
            return p.rstrip('-')
    return n


def sla_days_for_cvss(cvss: float) -> int:
    """Return SLA deadline in days based on CVSS score."""
    if cvss >= 9.0: return 7
    if cvss >= 7.0: return 30
    if cvss >= 4.0: return 90
    return 180


def take_snapshot(snapshot_date: str = None) -> bool:
    """Compute and store a daily vulnerability snapshot.

    Uses INSERT OR IGNORE so calling it twice on the same date is safe.
    Returns True if a new row was inserted, False if already existed.
    """
    if snapshot_date is None:
        snapshot_date = date.today().isoformat()
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id FROM vulnerability_snapshots WHERE snapshot_date = ?",
                (snapshot_date,)
            ).fetchone()
            if row:
                return False  # already taken today

            total = conn.execute(
                "SELECT COUNT(DISTINCT name || '|' || COALESCE(version,'')) FROM software"
            ).fetchone()[0] or 0
            vulnerable = conn.execute(
                "SELECT COUNT(*) FROM software_management WHERE cves_found > 0"
            ).fetchone()[0] or 0
            critical = conn.execute(
                "SELECT COUNT(*) FROM software_management WHERE cvss_max >= 9"
            ).fetchone()[0] or 0
            high = conn.execute(
                "SELECT COUNT(*) FROM software_management WHERE cvss_max >= 7 AND cvss_max < 9"
            ).fetchone()[0] or 0
            in_task = conn.execute(
                "SELECT COUNT(*) FROM software_management WHERE status = 'in_task'"
            ).fetchone()[0] or 0
            overdue = conn.execute(
                "SELECT COUNT(*) FROM software_management"
                " WHERE status='in_task' AND due_date IS NOT NULL AND due_date < date('now')"
            ).fetchone()[0] or 0
            has_exploit = conn.execute(
                "SELECT COUNT(*) FROM software_management WHERE in_kev=1 OR ep_ss >= 0.7"
            ).fetchone()[0] or 0

            conn.execute("""
                INSERT OR IGNORE INTO vulnerability_snapshots
                    (snapshot_date, total_packages, vulnerable_packages,
                     critical_count, high_count, in_task_count, overdue_count, has_exploit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (snapshot_date, total, vulnerable, critical, high, in_task, overdue, has_exploit))
            conn.commit()
        logger.info(f"Snapshot taken for {snapshot_date}: vuln={vulnerable}, crit={critical}")
        return True
    except Exception as e:
        logger.error(f"take_snapshot failed: {e}")
        return False


# Initialize database on startup
init_db()


@app.post("/api/collect")
async def collect(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Неверный JSON")

    # Проверить API ключ если настроен
    if API_KEY:
        provided_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
        if provided_key != API_KEY:
            logger.warning(f"Неверный или отсутствующий API ключ от {request.client.host}")
            raise HTTPException(status_code=401, detail="Неверный или отсутствующий API ключ")
        logger.debug(f"API ключ проверен для {request.client.host}")

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

        # Insert software packages (normalize + deduplicate to reduce noise)
        software_list = payload.get("software", [])
        unique = {}
        for app_info in software_list:
            orig = (app_info.get("name") or "").strip()
            ver = app_info.get("version") or ""
            norm = normalize_package_name(orig)
            if not norm:
                continue
            # keep first-seen original name/version for this normalized key
            if norm not in unique:
                unique[norm] = (orig, ver)

        # Aggressive family collapsing: map some families to generic names
        FAMILY_KEYS = {"lib": "lib", "python3": "python3", "python": "python", "gir1.2": "gir1.2"}

        for norm, (orig, ver) in unique.items():
            # if normalized key maps to a family, store the family name as the recorded package
            if norm.startswith("lib"):
                recorded_name = "lib"
                recorded_ver = ""
            elif norm.startswith("python3-") or norm == "python3":
                recorded_name = "python3"
                recorded_ver = ""
            elif norm.startswith("python-") or norm == "python":
                recorded_name = "python"
                recorded_ver = ""
            elif norm in FAMILY_KEYS:
                recorded_name = FAMILY_KEYS[norm]
                recorded_ver = ""
            else:
                recorded_name = orig
                recorded_ver = ver

            c.execute(
                """
                INSERT INTO software (report_id, hostname, name, version, family)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    payload.get("hostname", "unknown"),
                    orig,
                    recorded_ver,
                    recorded_name,
                ),
            )
        # Ensure host metadata row exists (upsert) so host appears in /hosts
        hostname_val = payload.get("hostname", "unknown")
        try:
            logger.debug(f"Upserting host metadata for '{hostname_val}'")
            c.execute(
                """
                INSERT INTO hosts (host, created_at, updated_at)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(host) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
                """,
                (hostname_val,)
            )
            logger.debug("Upsert executed")
        except Exception as e:
            logger.warning(f"Upsert failed (falling back): {e}")
            # Fallback for older SQLite versions without UPSERT syntax
            c.execute("SELECT host FROM hosts WHERE host = ?", (hostname_val,))
            existing = c.fetchone()
            logger.debug(f"Existing host row: {existing}")
            if not existing:
                c.execute("INSERT INTO hosts (host, created_at, updated_at) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", (hostname_val,))
                logger.debug("Inserted host row via fallback insert")
        # Log hosts count for debugging
        try:
            c.execute("SELECT COUNT(*) FROM hosts")
            hosts_count_now = c.fetchone()[0]
            logger.info(f"Hosts table row count after upsert: {hosts_count_now}")
        except Exception as e:
            logger.error(f"Error querying hosts count: {e}")
        conn.commit()

    logger.info(f"Отчёт получен от {host}: id={report_id}, software_count={len(software_list)}, сохранено в {path}")
    return JSONResponse({"status": "ok", "saved_to": path, "report_id": report_id})


@app.get("/api/hosts/ping")
async def ping_host(hostname: str):
    """
    Проверить Ping хоста - статус онлайн.
    Возвращает статус онлайн на основе ICMP/TCP ping.
    """
    if not hostname:
        raise HTTPException(status_code=400, detail="требуется hostname")
    
    try:
        # Пытаться разрешить hostname и подключиться к порту 22 (SSH) или 445 (SMB)
        # Если нет ответа в 2 секунды, считать оффлайн
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        # Сначала пробуем SSH (порт 22)
        try:
            result = sock.connect_ex((hostname, 22))
            sock.close()
            is_online = (result == 0)
        except socket.gaierror:
            # Разрешение hostname не удалось
            is_online = False
        except Exception:
            is_online = False
        
        logger.debug(f"Проверка ping для {hostname}: {'онлайн' if is_online else 'оффлайн'}")
        return JSONResponse({"hostname": hostname, "online": is_online})
    
    except Exception as e:
        logger.error(f"Ошибка при ping {hostname}: {e}")
        return JSONResponse({"hostname": hostname, "online": False})


@app.get("/api/reports")
async def get_reports(hostname: str = None, limit: int = 100):
    """Получить отчёты, опционально отфильтрованные по hostname."""
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


@app.get("/api/debug/hosts")
async def debug_list_hosts():
    """Debug: list hosts table contents."""
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT host, criticality, created_at, updated_at FROM hosts ORDER BY host")
            rows = [dict(r) for r in c.fetchall()]
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"hosts": rows})


@app.post("/api/debug/upsert-host")
async def debug_upsert_host(request: Request):
    """Debug: upsert a host by JSON payload {"host": "name"}."""
    try:
        data = await request.json()
        host = data.get("host")
        if not host:
            return JSONResponse({"error": "host required"}, status_code=400)
        with get_db() as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO hosts (host, created_at, updated_at) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT(host) DO UPDATE SET updated_at = CURRENT_TIMESTAMP", (host,))
            except Exception:
                c.execute("SELECT host FROM hosts WHERE host = ?", (host,))
                if not c.fetchone():
                    c.execute("INSERT INTO hosts (host, created_at, updated_at) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", (host,))
            conn.commit()
            c.execute("SELECT COUNT(*) FROM hosts")
            cnt = c.fetchone()[0]
        logger.info(f"Debug upsert host='{host}', hosts_count={cnt}")
        return JSONResponse({"status": "ok", "hosts_count": cnt})
    except Exception as e:
        logger.error(f"Debug upsert failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


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


def find_local_nvd_db():
    """Locate the local NVD DB file using common candidate paths."""
    local_db = os.environ.get("LOCAL_NVD_DB", "nvd_local.db")
    candidates = [
        local_db,
        os.path.join(os.getcwd(), local_db),
        os.path.join(os.path.dirname(__file__), '..', local_db),
        os.path.join(os.getcwd(), DATA_DIR, os.path.basename(local_db)),
        os.path.join('/data/reports', os.path.basename(local_db)),
        os.path.join('/app', local_db),
    ]
    for p in candidates:
        try:
            if os.path.exists(p):
                return os.path.abspath(p)
        except Exception:
            continue
    return None


@app.get("/api/package-cves")
async def package_cves(package_name: str, version: str = None, limit: int = 200):
    """Return CVEs for a package (optionally filtered by version) using local NVD DB."""
    if not package_name:
        raise HTTPException(status_code=400, detail="package_name required")

    nvd_db = find_local_nvd_db()
    if not nvd_db:
        return JSONResponse({"error": "local NVD DB not found"}, status_code=404)

    # Use version-aware matcher when version is provided
    if version:
        from services.matcher import match_package_to_cves
        raw = match_package_to_cves(package_name, version, nvd_db, limit=limit)
        found_cves = {r["cve_id"]: {
            "cve_id":      r["cve_id"],
            "cvss":        r.get("cvss_score"),
            "description": r.get("description", ""),
            "cpe_matches": [r.get("cpe23", "")] if r.get("cpe23") else [],
            "confidence":  r.get("confidence"),
            "ep_ss":       0.0,
            "in_kev":      False,
        } for r in raw}
    else:
        # Fallback: keyword search without version filtering
        keywords = get_cpe_keywords(package_name)
        found_cves = {}
        try:
            conn = sqlite3.connect(nvd_db)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            for kw in keywords:
                c.execute(
                    """SELECT DISTINCT cve.id AS id, cve.cvss_score AS cvss,
                              substr(cve.description,1,1000) AS description
                       FROM cve JOIN cpe_match ON cve.id = cpe_match.cve_id
                       WHERE cpe_match.cpe23 LIKE ? LIMIT ?""",
                    (f"%{kw}%", limit),
                )
                for r in c.fetchall():
                    cid = r["id"].upper()
                    if cid not in found_cves:
                        found_cves[cid] = {"cve_id": cid, "cvss": r["cvss"],
                                           "description": r["description"],
                                           "cpe_matches": [], "ep_ss": 0.0, "in_kev": False}
            if found_cves:
                ids = list(found_cves.keys())
                ph  = ",".join("?" for _ in ids)
                for r in c.execute(f"SELECT DISTINCT cve_id, cpe23 FROM cpe_match WHERE cve_id IN ({ph})", ids):
                    cid = r["cve_id"].upper()
                    if cid in found_cves:
                        found_cves[cid]["cpe_matches"].append(r["cpe23"])
            conn.close()
        except Exception as e:
            logger.error(f"Error querying local NVD DB for {package_name}: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    # Enrich with EPSS/KEV from vuln_risk
    if found_cves:
        ids = list(found_cves.keys())
        ph  = ",".join("?" for _ in ids)
        with get_db() as appconn:
            for row in appconn.execute(
                f"SELECT cve_id, ep_ss, in_kev FROM vuln_risk WHERE cve_id IN ({ph})", ids
            ):
                cid = row[0].upper()
                if cid in found_cves:
                    found_cves[cid]["ep_ss"]  = row[1] or 0.0
                    found_cves[cid]["in_kev"] = bool(row[2])

    # Compute has_exploit per CVE
    for cid, cve in found_cves.items():
        cve["has_exploit"] = bool(cve.get("in_kev") or (cve.get("ep_ss") or 0) >= 0.7)

    # Mark known false positives
    if found_cves:
        fp_rows = []
        with get_db() as conn:
            fp_rows = conn.execute(
                "SELECT cve_id FROM vuln_exceptions WHERE original_name=? AND version=?",
                (package_name, version or ""),
            ).fetchall()
        fp_set = {r[0].upper() for r in fp_rows}
        for cid in found_cves:
            found_cves[cid]["is_fp"] = cid in fp_set

    return JSONResponse({"package": package_name, "version": version,
                         "cves": list(found_cves.values())})


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
    """Scan selected packages for a host against local NVD DB with version range matching.

    Expects JSON: {"hostname": "...", "packages": [{"name": "...", "version": "..."}]}
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    hostname = payload.get("hostname")
    packages = payload.get("packages")
    if not hostname or not packages or not isinstance(packages, list):
        raise HTTPException(status_code=400, detail="hostname and packages[] required")

    nvd_db = find_local_nvd_db()
    if not nvd_db:
        raise HTTPException(status_code=500, detail="Local NVD DB not found")

    logger.info(f"Scan requested: host={hostname}, packages={len(packages)}")

    # Get host criticality once
    with get_db() as conn:
        row = conn.execute(
            "SELECT criticality FROM hosts WHERE host = ? LIMIT 1", (hostname,)
        ).fetchone()
        host_crit = row[0] if row and row[0] else 1

    vulnerable = []
    checked = 0

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version") or None
        if not name:
            continue
        checked += 1

        # Primary match: original name + version with range checking
        cves = match_package_to_cves(name, version, nvd_db)

        # Fallback: try NVD-normalized name if no results
        if not cves:
            norm = normalize_for_nvd(name)
            if norm and norm != name:
                cves = match_package_to_cves(norm, version, nvd_db)

        if not cves:
            continue

        cvss_max = max((c.get("cvss_score") or 0.0 for c in cves), default=0.0)

        # Batch-fetch EPSS/KEV for all found CVE IDs (one query instead of N)
        cve_ids = [c["cve_id"] for c in cves[:100]]
        placeholders = ",".join("?" for _ in cve_ids)
        with get_db() as conn:
            risk_rows = conn.execute(
                f"SELECT cve_id, ep_ss, in_kev, base_risk FROM vuln_risk WHERE cve_id IN ({placeholders})",
                cve_ids,
            ).fetchall()
        risk_map = {r[0]: r for r in risk_rows}

        enriched_cves = []
        ep_ss_max = 0.0
        kev_present = False
        now = datetime.now().isoformat()

        with get_db() as conn:
            for cve in cves[:100]:
                cve_id = cve["cve_id"]
                vr = risk_map.get(cve_id)
                if vr:
                    epss_val = vr[1] or 0.0
                    in_kev   = bool(vr[2])
                    base     = vr[3] or (epss_val * (2.0 if in_kev else 1.0))
                else:
                    epss_val = 0.0
                    in_kev   = False
                    base     = 0.0

                risk_score = float(base) * float(host_crit)
                try:
                    conn.execute(
                        """
                        INSERT INTO vuln_risk_host (host, cve_id, risk_score, computed_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(host, cve_id) DO UPDATE SET
                            risk_score  = excluded.risk_score,
                            computed_at = excluded.computed_at
                        """,
                        (hostname, cve_id, risk_score, now),
                    )
                except Exception:
                    pass

                enriched_cves.append({
                    "cve_id":     cve_id,
                    "cvss_score": cve.get("cvss_score"),
                    "confidence": cve.get("confidence"),
                    "ep_ss":      epss_val,
                    "in_kev":     in_kev,
                    "base_risk":  base,
                })
                if epss_val > ep_ss_max:
                    ep_ss_max = epss_val
                if in_kev:
                    kev_present = True

            conn.commit()

        vulnerable.append({
            "name":          name,
            "version":       version,
            "cves_found":    len(cves),
            "cvss_max":      cvss_max,
            "cves":          enriched_cves[:10],
            "ep_ss_max":     ep_ss_max,
            "kev_present":   kev_present,
        })
        logger.warning(
            f"Vulnerable: {hostname} / {name} {version} — {len(cves)} CVEs, CVSS max={cvss_max:.1f}"
        )

        # Update software_management with scan results keyed by (name, version)
        try:
            norm = normalize_for_nvd(name) or name
            ver  = version or ''
            with get_db() as conn2:
                conn2.execute(
                    """
                    INSERT INTO software_management
                        (original_name, version, normalized_for_nvd, status, comment,
                         ep_ss, in_kev, cves_found, cvss_max, last_checked)
                    VALUES (?, ?, ?, 'new', '', ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(original_name, version) DO UPDATE SET
                        ep_ss        = excluded.ep_ss,
                        in_kev       = excluded.in_kev,
                        cves_found   = excluded.cves_found,
                        cvss_max     = excluded.cvss_max,
                        last_checked = excluded.last_checked,
                        updated_at   = CURRENT_TIMESTAMP
                    """,
                    (name, ver, norm, ep_ss_max, 1 if kev_present else 0, len(cves), cvss_max),
                )
                conn2.commit()
        except Exception as e:
            logger.debug(f"software_management upsert failed for {name} {version}: {e}")

    logger.info(f"Scan complete: host={hostname}, checked={checked}, vulnerable={len(vulnerable)}")

    if NVD_LOG:
        print_nvd_log_summary()

    return JSONResponse({
        "hostname":          hostname,
        "checked":           checked,
        "vulnerable_count":  len(vulnerable),
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


@app.get("/api/vulns/risk")
async def get_vuln_risk(host: str = None, limit: int = 100):
    """Return risk-ranked CVEs for a host (or global list if host is omitted)."""
    with get_db() as conn:
        c = conn.cursor()
        if host:
            c.execute(
                """
                SELECT h.cve_id, vr.ep_ss, vr.in_kev, h.risk_score, cve.cvss_score, substr(cve.description,1,500) as description
                FROM vuln_risk_host h
                LEFT JOIN vuln_risk vr ON h.cve_id = vr.cve_id
                LEFT JOIN cve ON cve.id = h.cve_id
                WHERE h.host = ?
                ORDER BY h.risk_score DESC
                LIMIT ?
                """,
                (host, limit),
            )
            rows = c.fetchall()
            data = [
                {
                    "cve_id": r[0],
                    "ep_ss": r[1],
                    "in_kev": bool(r[2]),
                    "risk_score": r[3],
                    "cvss_score": r[4],
                    "description": r[5],
                }
                for r in rows
            ]
        else:
            # global list by base_risk
            c.execute(
                "SELECT cve_id, ep_ss, in_kev, base_risk, computed_at FROM vuln_risk ORDER BY base_risk DESC LIMIT ?",
                (limit,),
            )
            rows = c.fetchall()
            data = [
                {
                    "cve_id": r[0],
                    "ep_ss": r[1],
                    "in_kev": bool(r[2]),
                    "base_risk": r[3],
                    "computed_at": r[4],
                }
                for r in rows
            ]

    return JSONResponse({"host": host, "results": data})


@app.get("/host-risk", response_class=HTMLResponse)
async def host_risk_page(host: str = None, limit: int = 50):
    """Simple HTML page showing top risky CVEs for a host."""
    if not host:
        return HTMLResponse("<html><body><h3>Please provide ?host=...</h3></body></html>")

    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """
            SELECT h.cve_id, vr.ep_ss, vr.in_kev, h.risk_score, cve.cvss_score, substr(cve.description,1,400) as description
            FROM vuln_risk_host h
            LEFT JOIN vuln_risk vr ON h.cve_id = vr.cve_id
            LEFT JOIN cve ON cve.id = h.cve_id
            WHERE h.host = ?
            ORDER BY h.risk_score DESC
            LIMIT ?
            """,
            (host, limit),
        )
        rows = c.fetchall()

    html = [
        f"<html><head><title>Risk for {host}</title></head><body>",
        f"<h2>Top {len(rows)} risky CVEs for {host}</h2>",
        "<table border='1' style='border-collapse:collapse'><tr><th>CVE</th><th>Risk</th><th>EPSS</th><th>KEV</th><th>CVSS</th><th>Description</th></tr>",
    ]
    for r in rows:
        cve_id, ep_ss, in_kev, risk, cvss, desc = r
        html.append(
            f"<tr><td>{cve_id}</td><td>{risk:.6f}</td><td>{(ep_ss or 0):.6f}</td><td>{'YES' if in_kev else 'NO'}</td><td>{cvss}</td><td>{desc}</td></tr>"
        )

    html.append("</table></body></html>")
    return HTMLResponse('\n'.join(html))


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
    """Return (name, version) pairs found across all hosts, enriched with management status."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT
                s.name                                          AS original_name,
                COALESCE(s.version, '')                        AS version,
                GROUP_CONCAT(DISTINCT s.hostname)              AS hosts,
                COALESCE(m.normalized_for_nvd, s.name)        AS normalized_for_nvd,
                COALESCE(m.status, 'new')                      AS status,
                m.comment,
                COALESCE(m.ep_ss, 0.0)                        AS ep_ss,
                COALESCE(m.in_kev, 0)                         AS in_kev,
                COALESCE(m.cves_found, 0)                     AS cves_found,
                COALESCE(m.cvss_max, 0.0)                     AS cvss_max,
                m.last_checked,
                m.due_date
            FROM (
                SELECT DISTINCT name, COALESCE(version, '') AS version, hostname
                FROM software
            ) s
            LEFT JOIN software_management m
                ON m.original_name = s.name AND m.version = COALESCE(s.version, '')
            GROUP BY s.name, s.version
            ORDER BY s.name, s.version
        """)
        rows = c.fetchall()

    today = date.today().isoformat()
    result = []
    for row in rows:
        hosts_raw = row["hosts"] or ""
        due = row["due_date"]
        result.append({
            "original_name":    row["original_name"],
            "version":          row["version"],
            "hosts":            [h for h in hosts_raw.split(",") if h],
            "normalized_for_nvd": row["normalized_for_nvd"],
            "status":           row["status"],
            "comment":          row["comment"] or "",
            "ep_ss":            row["ep_ss"] or 0.0,
            "in_kev":           bool(row["in_kev"]),
            "cves_found":       row["cves_found"] or 0,
            "cvss_max":         row["cvss_max"] or 0.0,
            "last_checked":     row["last_checked"],
            "due_date":         due,
            "is_overdue":       bool(due and row["status"] == "in_task" and due < today),
            "has_exploit":      bool(row["in_kev"] or (row["ep_ss"] or 0) >= 0.7),
        })

    logger.debug(f"Retrieved {len(result)} (name, version) entries for software management")
    return JSONResponse(result)


@app.post("/api/software-management/update")
async def update_software_management(request: Request):
    """Update management settings for a (name, version) entry."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    original_name     = payload.get("original_name")
    version           = payload.get("version", "")
    normalized_for_nvd = payload.get("normalized_for_nvd")
    status            = payload.get("status")
    comment           = payload.get("comment", "")

    if not original_name:
        raise HTTPException(status_code=400, detail="original_name required")
    if status not in ("new", "in_task", "ignore", "fixed"):
        raise HTTPException(status_code=400, detail="status must be: new, in_task, ignore, or fixed")

    if not normalized_for_nvd:
        normalized_for_nvd = normalize_for_nvd(original_name)

    # Auto-compute SLA due_date when moving to in_task
    due_date_val = None
    if status == "in_task":
        with get_db() as conn:
            row = conn.execute(
                "SELECT cvss_max, due_date FROM software_management WHERE original_name=? AND version=?",
                (original_name, version)
            ).fetchone()
        existing_due = row["due_date"] if row else None
        # Keep existing due_date if already set; otherwise compute fresh
        if existing_due:
            due_date_val = existing_due
        else:
            cvss = float(row["cvss_max"] or 0.0) if row else 0.0
            days = sla_days_for_cvss(cvss)
            due_date_val = (date.today() + timedelta(days=days)).isoformat()

    with get_db() as conn:
        # Read old status before update for audit trail
        old_row = conn.execute(
            "SELECT status FROM software_management WHERE original_name=? AND version=?",
            (original_name, version)
        ).fetchone()
        old_status = old_row["status"] if old_row else None

        conn.execute("""
            INSERT INTO software_management
                (original_name, version, normalized_for_nvd, status, comment, due_date, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(original_name, version) DO UPDATE SET
                normalized_for_nvd = excluded.normalized_for_nvd,
                status             = excluded.status,
                comment            = excluded.comment,
                due_date           = CASE WHEN excluded.status = 'in_task'
                                          THEN COALESCE(software_management.due_date, excluded.due_date)
                                          ELSE NULL END,
                updated_at         = CURRENT_TIMESTAMP
        """, (original_name, version, normalized_for_nvd, status, comment, due_date_val))

        if old_status != status:
            conn.execute(
                "INSERT INTO status_history (original_name, version, old_status, new_status, comment)"
                " VALUES (?, ?, ?, ?, ?)",
                (original_name, version, old_status, status, comment)
            )
        conn.commit()

    return JSONResponse({"success": True, "original_name": original_name,
                         "version": version, "status": status, "due_date": due_date_val})


@app.post("/api/software-management/bulk-update")
async def bulk_update_software_management(request: Request):
    """Bulk update multiple (name, version) entries."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    packages = payload.get("packages", [])
    if not isinstance(packages, list) or len(packages) == 0:
        raise HTTPException(status_code=400, detail="packages must be a non-empty list")

    for pkg in packages:
        if not pkg.get("original_name"):
            raise HTTPException(status_code=400, detail="Each package must have original_name")
        if pkg.get("status") not in ("new", "in_task", "ignore", "fixed"):
            raise HTTPException(status_code=400, detail="Each package status must be: new, in_task, ignore, or fixed")

    today_str = date.today().isoformat()
    with get_db() as conn:
        # Pre-fetch existing status + cvss_max + due_date for all packages
        all_keys = [(pkg["original_name"], pkg.get("version", "")) for pkg in packages]
        existing_map = {}
        for n, v in all_keys:
            row = conn.execute(
                "SELECT status, cvss_max, due_date FROM software_management WHERE original_name=? AND version=?",
                (n, v)
            ).fetchone()
            existing_map[(n, v)] = row

        for pkg in packages:
            name    = pkg["original_name"]
            version = pkg.get("version", "")
            norm    = pkg.get("normalized_for_nvd") or normalize_for_nvd(name)
            status  = pkg["status"]
            comment = pkg.get("comment", "")
            old_row = existing_map.get((name, version))
            old_status = old_row["status"] if old_row else None

            due_date_val = None
            if status == "in_task":
                existing_due = old_row["due_date"] if old_row else None
                if existing_due:
                    due_date_val = existing_due
                else:
                    cvss = float(old_row["cvss_max"] or 0.0) if old_row else 0.0
                    days = sla_days_for_cvss(cvss)
                    due_date_val = (date.today() + timedelta(days=days)).isoformat()

            conn.execute("""
                INSERT INTO software_management
                    (original_name, version, normalized_for_nvd, status, comment, due_date, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(original_name, version) DO UPDATE SET
                    normalized_for_nvd = excluded.normalized_for_nvd,
                    status             = excluded.status,
                    comment            = excluded.comment,
                    due_date           = CASE WHEN excluded.status = 'in_task'
                                              THEN COALESCE(software_management.due_date, excluded.due_date)
                                              ELSE NULL END,
                    updated_at         = CURRENT_TIMESTAMP
            """, (name, version, norm, status, comment, due_date_val))

            if old_status != status:
                conn.execute(
                    "INSERT INTO status_history (original_name, version, old_status, new_status, comment)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (name, version, old_status, status, comment)
                )
        conn.commit()

    return JSONResponse({"success": True, "updated_count": len(packages)})


@app.post("/api/recheck")
async def recheck_package(request: Request):
    """Re-scan a package after a fix. If CVEs drop to 0 — auto-set status to 'fixed'."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    original_name = payload.get("original_name")
    version       = payload.get("version", "") or ""
    if not original_name:
        raise HTTPException(status_code=400, detail="original_name required")

    nvd_db = find_local_nvd_db()
    if not nvd_db:
        return JSONResponse({"error": "local NVD DB not found"}, status_code=404)

    result = _scan_one(original_name, version, nvd_db)
    new_status = None

    if result["cves_found"] == 0:
        # Auto-mark as fixed and record in audit trail
        with get_db() as conn:
            old_row = conn.execute(
                "SELECT status FROM software_management WHERE original_name=? AND version=?",
                (original_name, version)
            ).fetchone()
            old_status = old_row["status"] if old_row else "in_task"
            conn.execute("""
                UPDATE software_management
                SET status='fixed', due_date=NULL, updated_at=CURRENT_TIMESTAMP
                WHERE original_name=? AND version=?
            """, (original_name, version))
            conn.execute(
                "INSERT INTO status_history (original_name, version, old_status, new_status, comment)"
                " VALUES (?, ?, ?, 'fixed', 'Автоматически — CVE не обнаружены при перепроверке')",
                (original_name, version, old_status)
            )
            conn.commit()
        new_status = "fixed"

    logger.info(f"recheck {original_name} {version}: cves={result['cves_found']} → status={new_status or 'unchanged'}")
    return JSONResponse({**result, "auto_status": new_status})


def _scan_one(name: str, version: str, nvd_db: str) -> dict:
    """Scan a single (name, version) against local NVD DB and update software_management.

    Returns {"cves_found", "cvss_max", "ep_ss_max", "in_kev"}.
    Same logic as /api/scan-packages so results are always consistent.
    """
    ver = version or None
    cves = match_package_to_cves(name, ver, nvd_db, limit=200)
    if not cves:
        norm_name = normalize_for_nvd(name)
        if norm_name and norm_name != name:
            cves = match_package_to_cves(norm_name, ver, nvd_db, limit=200)

    cvss_max   = max((c.get("cvss_score") or 0.0 for c in cves), default=0.0)
    ep_ss_max  = 0.0
    kev_present = False

    if cves:
        cve_ids = [c["cve_id"] for c in cves[:100]]
        ph = ",".join("?" for _ in cve_ids)
        with get_db() as conn:
            for row in conn.execute(
                f"SELECT ep_ss, in_kev FROM vuln_risk WHERE cve_id IN ({ph})", cve_ids
            ):
                if row[0]: ep_ss_max = max(ep_ss_max, row[0])
                if row[1]: kev_present = True

    norm = normalize_for_nvd(name) or name
    ver_key = version or ''
    with get_db() as conn:
        conn.execute("""
            INSERT INTO software_management
                (original_name, version, normalized_for_nvd, status, comment,
                 ep_ss, in_kev, cves_found, cvss_max, last_checked)
            VALUES (?, ?, ?, 'new', '', ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(original_name, version) DO UPDATE SET
                ep_ss        = excluded.ep_ss,
                in_kev       = excluded.in_kev,
                cves_found   = excluded.cves_found,
                cvss_max     = excluded.cvss_max,
                last_checked = excluded.last_checked,
                updated_at   = CURRENT_TIMESTAMP
        """, (name, ver_key, norm, ep_ss_max, 1 if kev_present else 0, len(cves), cvss_max))
        conn.commit()

    return {"cves_found": len(cves), "cvss_max": cvss_max,
            "ep_ss_max": ep_ss_max, "in_kev": kev_present}


@app.post("/api/force-check")
async def force_check_package(request: Request):
    """Scan a single (name, version) using local NVD DB — same method as scan-packages."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    package_name = payload.get("package_name")
    version      = payload.get("version", "") or ""
    if not package_name:
        raise HTTPException(status_code=400, detail="package_name required")

    nvd_db = find_local_nvd_db()
    if not nvd_db:
        return JSONResponse({"error": "local NVD DB not found"}, status_code=404)

    result = _scan_one(package_name, version, nvd_db)
    logger.info(f"force-check {package_name} {version}: {result['cves_found']} CVEs")
    return JSONResponse(result)


@app.post("/api/software-management/scan-all")
async def scan_all_software():
    """Start a background scan of all (name, version) pairs in the software table."""
    with scan_all_state_lock:
        if scan_all_state["running"]:
            return JSONResponse({"status": "already_running", **scan_all_state})

    nvd_db = find_local_nvd_db()
    if not nvd_db:
        return JSONResponse({"error": "local NVD DB not found"}, status_code=404)

    with get_db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT name, COALESCE(version, '') AS version FROM software ORDER BY name"
        ).fetchall()
    total = len(rows)

    with scan_all_state_lock:
        scan_all_state.update({"running": True, "done": 0, "total": total, "errors": 0})

    def _run():
        for i, row in enumerate(rows):
            name, version = row[0], row[1]
            try:
                _scan_one(name, version, nvd_db)
            except Exception as e:
                logger.warning(f"scan-all error for {name} {version}: {e}")
                with scan_all_state_lock:
                    scan_all_state["errors"] += 1
            with scan_all_state_lock:
                scan_all_state["done"] = i + 1
        with scan_all_state_lock:
            scan_all_state["running"] = False
        logger.info(f"scan-all finished: {total} entries, {scan_all_state['errors']} errors")

    threading.Thread(target=_run, daemon=True).start()
    return JSONResponse({"status": "started", "total": total})


@app.get("/api/software-management/scan-status")
async def get_scan_all_status():
    with scan_all_state_lock:
        return JSONResponse(dict(scan_all_state))


@app.get("/api/export/pdf")
async def export_pdf():
    """Generate a PDF vulnerability report using fpdf2."""
    try:
        from fpdf import FPDF
        from pathlib import Path
        import fpdf as _fpdf_module
        _font_path = Path(_fpdf_module.__file__).parent / "fonts" / "DejaVuSansCondensed.ttf"
        _font_bold  = Path(_fpdf_module.__file__).parent / "fonts" / "DejaVuSansCondensed-Bold.ttf"
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed. Run: pip install fpdf2")

    today_str = date.today().isoformat()

    with get_db() as conn:
        total_pkgs   = conn.execute("SELECT COUNT(DISTINCT name||'|'||COALESCE(version,'')) FROM software").fetchone()[0] or 0
        vuln_pkgs    = conn.execute("SELECT COUNT(*) FROM software_management WHERE cves_found > 0").fetchone()[0] or 0
        critical_cnt = conn.execute("SELECT COUNT(*) FROM software_management WHERE cvss_max >= 9").fetchone()[0] or 0
        high_cnt     = conn.execute("SELECT COUNT(*) FROM software_management WHERE cvss_max >= 7 AND cvss_max < 9").fetchone()[0] or 0
        in_task_cnt  = conn.execute("SELECT COUNT(*) FROM software_management WHERE status='in_task'").fetchone()[0] or 0
        overdue_cnt  = conn.execute(
            "SELECT COUNT(*) FROM software_management WHERE status='in_task' AND due_date < date('now')"
        ).fetchone()[0] or 0
        fixed_cnt    = conn.execute("SELECT COUNT(*) FROM software_management WHERE status='fixed'").fetchone()[0] or 0
        hosts_cnt    = conn.execute("SELECT COUNT(DISTINCT hostname) FROM reports").fetchone()[0] or 0

        pkg_rows = conn.execute("""
            SELECT original_name, version, cves_found, cvss_max, ep_ss, in_kev,
                   status, due_date, last_checked
            FROM software_management
            WHERE cves_found > 0 AND status != 'ignore'
            ORDER BY cvss_max DESC, cves_found DESC
            LIMIT 100
        """).fetchall()

        nvd_db_path = find_local_nvd_db()
        if nvd_db_path:
            conn.execute(f"ATTACH DATABASE '{nvd_db_path}' AS nvd")
            top_cves = conn.execute("""
                SELECT h.cve_id, h.risk_score, vr.ep_ss, vr.in_kev,
                       nc.cvss_score, substr(nc.description,1,120) AS description
                FROM vuln_risk_host h
                LEFT JOIN vuln_risk vr ON h.cve_id = vr.cve_id
                LEFT JOIN nvd.cve nc ON nc.id = h.cve_id
                ORDER BY h.risk_score DESC LIMIT 10
            """).fetchall()
            conn.execute("DETACH DATABASE nvd")
        else:
            top_cves = conn.execute("""
                SELECT h.cve_id, h.risk_score, vr.ep_ss, vr.in_kev,
                       NULL as cvss_score, '' as description
                FROM vuln_risk_host h
                LEFT JOIN vuln_risk vr ON h.cve_id = vr.cve_id
                ORDER BY h.risk_score DESC LIMIT 10
            """).fetchall()

    class VulnReport(FPDF):
        def header(self):
            if _font_path.exists():
                self.set_font("dejavu_b", size=10)
            else:
                self.set_font("Helvetica", "B", 10)
            self.set_fill_color(102, 126, 234)
            self.set_text_color(255, 255, 255)
            self.cell(0, 10, "Vulnerability Report — Vuln Collector", fill=True, align="C")
            self.set_text_color(0, 0, 0)
            self.ln(2)

        def footer(self):
            self.set_y(-12)
            if _font_path.exists():
                self.set_font("dejavu", size=8)
            else:
                self.set_font("Helvetica", size=8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Generated {today_str}  |  Page {self.page_no()}", align="C")
            self.set_text_color(0, 0, 0)

    pdf = VulnReport(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)

    if _font_path.exists():
        pdf.add_font("dejavu",   fname=str(_font_path))
        if _font_bold.exists():
            pdf.add_font("dejavu_b", fname=str(_font_bold))
        else:
            pdf.add_font("dejavu_b", fname=str(_font_path))
        F_NORMAL = "dejavu"
        F_BOLD   = "dejavu_b"
    else:
        F_NORMAL = "Helvetica"
        F_BOLD   = "Helvetica"

    # ── Page 1: Summary ─────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font(F_BOLD, size=16)
    pdf.ln(4)
    pdf.cell(0, 12, "Отчёт об уязвимостях", align="C")
    pdf.ln(6)
    pdf.set_font(F_NORMAL, size=11)
    pdf.cell(0, 8, f"Дата формирования: {today_str}", align="C")
    pdf.ln(12)

    def summary_box(label, value, fill_rgb=(240, 240, 240)):
        pdf.set_fill_color(*fill_rgb)
        pdf.set_font(F_NORMAL, size=9)
        pdf.cell(52, 8, label, border=1, fill=True)
        pdf.set_font(F_BOLD, size=9)
        pdf.cell(28, 8, str(value), border=1, fill=True, align="C")
        pdf.set_fill_color(240, 240, 240)

    pdf.set_font(F_BOLD, size=11)
    pdf.cell(0, 8, "Сводка")
    pdf.ln(9)

    rows_pairs = [
        ("Всего хостов",            hosts_cnt,    (235,245,255)),
        ("Всего пакетов",           total_pkgs,   (235,245,255)),
        ("Уязвимых пакетов",        vuln_pkgs,    (255,235,235)),
        ("Критических (CVSS≥9)",    critical_cnt, (255,200,200)),
        ("Высоких (CVSS 7–9)",      high_cnt,     (255,220,180)),
        ("В работе",                in_task_cnt,  (255,245,210)),
        ("Просрочено SLA",          overdue_cnt,  (255,200,200)),
        ("Исправлено",              fixed_cnt,    (210,240,215)),
    ]
    for label, val, color in rows_pairs:
        summary_box(label, val, color)
        pdf.ln(9)

    # ── Page 2+: Vulnerable packages table ──────────────────────────
    pdf.add_page()
    pdf.set_font(F_BOLD, size=11)
    pdf.cell(0, 8, f"Уязвимые пакеты (топ {min(len(pkg_rows),100)} по CVSS)")
    pdf.ln(9)

    col_w = [62, 22, 16, 18, 16, 14, 22, 28]
    headers = ["Название", "Версия", "CVE", "CVSS", "EPSS", "KEV", "Статус", "SLA дедлайн"]
    pdf.set_fill_color(102, 126, 234)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(F_BOLD, size=8)
    for w, h in zip(col_w, headers):
        pdf.cell(w, 7, h, border=1, fill=True, align="C")
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    status_labels = {"new": "Новое", "in_task": "В работе", "ignore": "Игнор", "fixed": "Исправлено"}
    for i, row in enumerate(pkg_rows):
        fill = (i % 2 == 0)
        pdf.set_fill_color(248, 248, 255) if fill else pdf.set_fill_color(255, 255, 255)
        pdf.set_font(F_NORMAL, size=7)
        cvss = row["cvss_max"] or 0
        if cvss >= 9:
            pdf.set_text_color(180, 0, 0)
        elif cvss >= 7:
            pdf.set_text_color(200, 80, 0)
        else:
            pdf.set_text_color(0, 0, 0)
        vals = [
            str(row["original_name"] or "")[:30],
            str(row["version"] or "")[:10],
            str(row["cves_found"] or 0),
            f"{cvss:.1f}",
            f"{row['ep_ss']:.3f}" if row["ep_ss"] else "0.000",
            "ДА" if row["in_kev"] else "НЕТ",
            status_labels.get(row["status"], row["status"] or ""),
            str(row["due_date"] or ""),
        ]
        for w, v in zip(col_w, vals):
            pdf.cell(w, 6, v, border=1, fill=fill, align="C" if w <= 22 else "L")
        pdf.set_text_color(0, 0, 0)
        pdf.ln()

    # ── Top CVEs section ────────────────────────────────────────────
    if top_cves:
        pdf.ln(4)
        pdf.set_font(F_BOLD, size=11)
        pdf.cell(0, 8, "Топ-10 CVE по риску")
        pdf.ln(9)
        cve_col_w = [40, 20, 20, 16, 20, 151]
        cve_hdrs  = ["CVE ID", "Риск", "CVSS", "KEV", "EPSS", "Описание"]
        pdf.set_fill_color(102, 126, 234)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(F_BOLD, size=8)
        for w, h in zip(cve_col_w, cve_hdrs):
            pdf.cell(w, 7, h, border=1, fill=True, align="C")
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        for i, row in enumerate(top_cves):
            fill = (i % 2 == 0)
            pdf.set_fill_color(248, 248, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_font(F_NORMAL, size=7)
            cve_vals = [
                str(row["cve_id"] or ""),
                f"{row['risk_score']:.2f}" if row["risk_score"] else "0.00",
                f"{row['cvss_score']:.1f}" if row["cvss_score"] else "—",
                "ДА" if row["in_kev"] else "НЕТ",
                f"{row['ep_ss']:.3f}" if row["ep_ss"] else "0.000",
                str(row["description"] or "")[:90],
            ]
            for w, v in zip(cve_col_w, cve_vals):
                pdf.cell(w, 6, v, border=1, fill=fill)
            pdf.ln()

    pdf_bytes = bytes(pdf.output())
    filename  = f"vuln_report_{today_str}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/csv")
async def export_csv(filter: str = "all"):
    """Export software management data as CSV.

    Query param: filter = all | new | in_task | ignore
    """
    valid_filters = {"all", "new", "in_task", "ignore"}
    if filter not in valid_filters:
        raise HTTPException(status_code=400, detail=f"filter must be one of: {', '.join(valid_filters)}")

    today = date.today().isoformat()

    with get_db() as conn:
        query = """
            SELECT
                s.name                                      AS original_name,
                COALESCE(s.version, '')                    AS version,
                GROUP_CONCAT(DISTINCT s.hostname)          AS hosts,
                COALESCE(m.normalized_for_nvd, s.name)    AS normalized_for_nvd,
                COALESCE(m.status, 'new')                  AS status,
                COALESCE(m.comment, '')                    AS comment,
                COALESCE(m.ep_ss, 0.0)                    AS ep_ss,
                COALESCE(m.in_kev, 0)                     AS in_kev,
                COALESCE(m.cves_found, 0)                 AS cves_found,
                COALESCE(m.cvss_max, 0.0)                 AS cvss_max,
                m.last_checked,
                m.due_date
            FROM (
                SELECT DISTINCT name, COALESCE(version, '') AS version, hostname
                FROM software
            ) s
            LEFT JOIN software_management m
                ON m.original_name = s.name AND m.version = COALESCE(s.version, '')
        """
        params = []
        if filter != "all":
            query += " WHERE COALESCE(m.status, 'new') = ?"
            params.append(filter)
        query += " GROUP BY s.name, s.version ORDER BY s.name, s.version"

        rows = conn.execute(query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Название", "Версия", "Хосты", "Имя для NVD",
        "Статус", "CVE", "CVSS макс.", "EPSS", "KEV",
        "Последняя проверка", "Дедлайн SLA", "Просрочено", "Комментарий"
    ])
    for row in rows:
        due = row["due_date"]
        is_overdue = "Да" if (due and row["status"] == "in_task" and due < today) else "Нет"
        writer.writerow([
            row["original_name"],
            row["version"],
            row["hosts"] or "",
            row["normalized_for_nvd"],
            row["status"],
            row["cves_found"],
            f'{row["cvss_max"]:.1f}' if row["cvss_max"] else "0.0",
            f'{row["ep_ss"]:.3f}' if row["ep_ss"] else "0.000",
            "Да" if row["in_kev"] else "Нет",
            row["last_checked"] or "",
            due or "",
            is_overdue,
            row["comment"],
        ])

    filename = f'vuln_report_{filter}_{date.today().isoformat()}.csv'
    csv_bytes = output.getvalue().encode("utf-8-sig")
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/vuln-exceptions")
async def list_vuln_exceptions(original_name: str = None, version: str = None):
    """List false-positive exceptions, optionally filtered by package."""
    with get_db() as conn:
        if original_name is not None:
            rows = conn.execute(
                "SELECT cve_id, original_name, version, reason, created_at FROM vuln_exceptions"
                " WHERE original_name=? AND version=? ORDER BY cve_id",
                (original_name, version or ""),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT cve_id, original_name, version, reason, created_at FROM vuln_exceptions ORDER BY created_at DESC"
            ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/vuln-exceptions")
async def add_vuln_exception(request: Request):
    """Mark a CVE as false positive for a given (package, version)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    cve_id        = (body.get("cve_id") or "").strip().upper()
    original_name = body.get("original_name", "").strip()
    version       = body.get("version", "").strip()
    reason        = body.get("reason", "").strip()

    if not cve_id or not original_name:
        raise HTTPException(status_code=400, detail="cve_id and original_name required")

    with get_db() as conn:
        conn.execute(
            "INSERT INTO vuln_exceptions (cve_id, original_name, version, reason)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(cve_id, original_name, version) DO UPDATE SET reason=excluded.reason",
            (cve_id, original_name, version, reason),
        )
        conn.commit()

    logger.info(f"FP added: {cve_id} for {original_name} {version}")
    return JSONResponse({"ok": True, "cve_id": cve_id})


@app.delete("/api/vuln-exceptions")
async def remove_vuln_exception(request: Request):
    """Remove a false-positive mark."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    cve_id        = (body.get("cve_id") or "").strip().upper()
    original_name = body.get("original_name", "").strip()
    version       = body.get("version", "").strip()

    with get_db() as conn:
        conn.execute(
            "DELETE FROM vuln_exceptions WHERE cve_id=? AND original_name=? AND version=?",
            (cve_id, original_name, version),
        )
        conn.commit()

    return JSONResponse({"ok": True})


@app.get("/api/status-history")
async def get_status_history(original_name: str, version: str = ""):
    """Return status change history for a (name, version) pair."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT old_status, new_status, comment, changed_at
            FROM status_history
            WHERE original_name=? AND version=?
            ORDER BY changed_at DESC LIMIT 50
        """, (original_name, version)).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/snapshots/take")
async def api_take_snapshot():
    """Manually trigger a snapshot for today."""
    taken = take_snapshot()
    return JSONResponse({"ok": True, "new": taken, "date": date.today().isoformat()})


@app.get("/api/snapshots")
async def get_snapshots(days: int = 30):
    """Return last N days of vulnerability snapshots."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT snapshot_date, total_packages, vulnerable_packages,
                   critical_count, high_count, in_task_count,
                   overdue_count, has_exploit_count
            FROM vulnerability_snapshots
            ORDER BY snapshot_date DESC
            LIMIT ?
        """, (days,)).fetchall()
    return JSONResponse([dict(r) for r in reversed(rows)])


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
