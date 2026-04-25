"""
Risk scoring service.

Formula:
    risk_score = cvss_base
               × (1 + epss × 10)       # EPSS 0.5 → multiplier 6×
               × (3.0 if in_kev else 1.0)
               × host_criticality       # 1-5, set manually per host

Result is normalized to 0-100.
"""

import logging
import sqlite3
import csv
import gzip
import json
import os
import io
from datetime import datetime
from typing import Optional

try:
    import requests
    _has_requests = True
except ImportError:
    _has_requests = False

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def compute_risk(
    cvss:       float,
    epss:       float,
    in_kev:     bool,
    host_crit:  int = 1,
) -> float:
    """Return normalized risk score 0-100."""
    base        = float(cvss  or 0.0)
    epss_factor = 1.0 + float(epss or 0.0) * 10.0
    kev_factor  = 3.0 if in_kev else 1.0
    raw         = base * epss_factor * kev_factor * float(host_crit)
    return round(min(raw / 150.0 * 100.0, 100.0), 4)


# ---------------------------------------------------------------------------
# EPSS import
# ---------------------------------------------------------------------------

def import_epss(db_path: str, batch_size: int = 100) -> int:
    """Fetch EPSS scores from FIRST.org API only for CVEs present in our DB.

    Uses targeted API calls instead of downloading the full ~10 MB CSV.
    Returns number of rows upserted.
    """
    if not _has_requests:
        raise RuntimeError("requests library not available")

    # Collect all CVE IDs we have locally (from vuln_risk + nvd_local)
    cve_ids = _collect_local_cve_ids(db_path)
    if not cve_ids:
        logger.warning("No CVE IDs found in local DB — nothing to fetch EPSS for")
        return 0

    logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs via FIRST.org API")

    rows_done = 0
    conn = sqlite3.connect(db_path)
    try:
        for i in range(0, len(cve_ids), batch_size):
            chunk = cve_ids[i : i + batch_size]
            cve_param = ",".join(chunk)
            try:
                resp = requests.get(
                    EPSS_API_URL,
                    params={"cve": cve_param},
                    timeout=30,
                    headers={"User-Agent": "vuln-scanner/1.0"},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.warning(f"EPSS API batch {i//batch_size} failed: {e}")
                continue

            batch = []
            for entry in data.get("data", []):
                cve_id   = entry.get("cve", "").upper()
                epss_val = entry.get("epss")
                if cve_id and epss_val is not None:
                    batch.append((cve_id, float(epss_val)))

            if batch:
                _upsert_epss_batch(conn, batch)
                rows_done += len(batch)

            # small delay to be polite to the API
            time.sleep(0.5)

        conn.commit()
        logger.info(f"EPSS import done: {rows_done} scores upserted from {len(cve_ids)} CVEs")
    finally:
        conn.close()

    return rows_done


def _collect_local_cve_ids(db_path: str) -> list[str]:
    """Return all CVE IDs from vuln_risk + nvd_local DB."""
    ids: set[str] = set()

    # from vuln_risk (already tracked)
    try:
        conn = sqlite3.connect(db_path)
        for r in conn.execute("SELECT cve_id FROM vuln_risk"):
            ids.add(r[0].upper())
        conn.close()
    except Exception:
        pass

    # from nvd_local DB
    nvd_db = _find_nvd_db()
    if nvd_db:
        try:
            conn = sqlite3.connect(nvd_db)
            for r in conn.execute("SELECT id FROM cve"):
                ids.add(r[0].upper())
            conn.close()
        except Exception:
            pass

    return sorted(ids)


def _upsert_epss_batch(conn: sqlite3.Connection, batch: list):
    conn.executemany(
        """
        INSERT INTO vuln_risk (cve_id, ep_ss, base_risk, computed_at)
        VALUES (?, ?, 0, CURRENT_TIMESTAMP)
        ON CONFLICT(cve_id) DO UPDATE SET
            ep_ss       = excluded.ep_ss,
            computed_at = excluded.computed_at
        """,
        [(cve_id, epss) for cve_id, epss in batch],
    )


# ---------------------------------------------------------------------------
# KEV import
# ---------------------------------------------------------------------------

def import_kev(db_path: str) -> int:
    """Download CISA KEV list and mark CVEs in vuln_risk as in_kev=1.

    Returns number of KEV entries processed.
    """
    if not _has_requests:
        raise RuntimeError("requests library not available")

    logger.info(f"Downloading CISA KEV from {KEV_URL}")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()

    data        = resp.json()
    vulns       = data.get("vulnerabilities", [])
    kev_ids     = [v["cveID"].strip().upper() for v in vulns if v.get("cveID")]

    conn = sqlite3.connect(db_path)
    try:
        conn.executemany(
            """
            INSERT INTO vuln_risk (cve_id, in_kev, base_risk, computed_at)
            VALUES (?, 1, 0, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id) DO UPDATE SET
                in_kev      = 1,
                computed_at = excluded.computed_at
            """,
            [(cve_id,) for cve_id in kev_ids],
        )
        conn.commit()
        logger.info(f"KEV import done: {len(kev_ids)} entries upserted into {db_path}")
    finally:
        conn.close()

    return len(kev_ids)


# ---------------------------------------------------------------------------
# Recompute base_risk for all rows in vuln_risk
# ---------------------------------------------------------------------------

def recompute_base_risk(db_path: str) -> int:
    """Recalculate base_risk = compute_risk(cvss, epss, in_kev, host_crit=1)
    for every row in vuln_risk.

    CVSS is joined from nvd_local.db if available, otherwise treated as 5.0.
    Returns number of rows updated.
    """
    nvd_db = _find_nvd_db()

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT cve_id, ep_ss, in_kev FROM vuln_risk"
    ).fetchall()

    # Build cvss lookup from nvd_local if available
    cvss_map: dict[str, float] = {}
    if nvd_db:
        try:
            nvd_conn = sqlite3.connect(nvd_db)
            for r in nvd_conn.execute("SELECT id, cvss_score FROM cve WHERE cvss_score IS NOT NULL"):
                cvss_map[r[0].upper()] = float(r[1])
            nvd_conn.close()
        except Exception as e:
            logger.warning(f"Could not read cvss from nvd_local: {e}")

    updated = 0
    batch   = []
    for cve_id, epss, in_kev in rows:
        cvss       = cvss_map.get(cve_id, 5.0)  # default CVSS 5.0 if unknown
        base_risk  = compute_risk(cvss, epss or 0.0, bool(in_kev))
        batch.append((base_risk, datetime.now().isoformat(), cve_id))
        updated   += 1

        if len(batch) >= 5000:
            conn.executemany(
                "UPDATE vuln_risk SET base_risk=?, computed_at=? WHERE cve_id=?", batch
            )
            batch = []

    if batch:
        conn.executemany(
            "UPDATE vuln_risk SET base_risk=?, computed_at=? WHERE cve_id=?", batch
        )

    conn.commit()
    conn.close()
    logger.info(f"base_risk recomputed for {updated} CVEs")
    return updated


def _find_nvd_db() -> Optional[str]:
    candidates = [
        os.environ.get("LOCAL_NVD_DB", ""),
        "/data/reports/nvd_local.db",
        os.path.join(os.path.dirname(__file__), "..", "..", "nvd_local.db"),
        os.path.join(os.getcwd(), "nvd_local.db"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return os.path.abspath(p)
    return None
