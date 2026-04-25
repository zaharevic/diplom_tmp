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

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


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

def import_epss(db_path: str) -> int:
    """Download current EPSS scores and upsert into vuln_risk table.

    Returns number of rows upserted.
    """
    if not _has_requests:
        raise RuntimeError("requests library not available")

    logger.info(f"Downloading EPSS scores from {EPSS_URL}")
    resp = requests.get(EPSS_URL, timeout=300, stream=True)
    resp.raise_for_status()

    # Stream download to avoid OOM on large file (~10 MB compressed)
    raw_bytes = b""
    for chunk in resp.iter_content(chunk_size=65536):
        raw_bytes += chunk
    logger.info(f"EPSS download complete: {len(raw_bytes) // 1024} KB")

    rows_done = 0
    conn = sqlite3.connect(db_path)
    try:
        # CSV inside gzip; first line is a comment (#model_version,...), second is header
        content = gzip.decompress(raw_bytes).decode("utf-8")
        reader  = csv.reader(io.StringIO(content))

        batch = []
        for line in reader:
            # skip comment/header lines
            if not line or line[0].startswith("#") or line[0].lower() == "cve":
                continue
            cve_id    = line[0].strip().upper()
            try:
                epss_val  = float(line[1])
            except (IndexError, ValueError):
                continue

            batch.append((cve_id, epss_val))

            if len(batch) >= 5000:
                _upsert_epss_batch(conn, batch)
                rows_done += len(batch)
                batch = []

        if batch:
            _upsert_epss_batch(conn, batch)
            rows_done += len(batch)

        conn.commit()
        logger.info(f"EPSS import done: {rows_done} rows upserted into {db_path}")
    finally:
        conn.close()

    return rows_done


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
