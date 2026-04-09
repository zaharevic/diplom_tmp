#!/usr/bin/env python3
"""Import EPSS scores and CISA KEV list and update vuln_risk table.

Usage:
  python import_epss_kev.py --db /path/to/vuln_collector.db

This script fetches EPSS CSV and CISA KEV CSV (or reads local files) and upserts
rows into the `vuln_risk` table (creates if missing).
"""
import argparse
import csv
import sqlite3
import sys
import os
import datetime
import urllib.request
import io
import gzip


def fetch_url_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-collector/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    # handle gzipped content
    try:
        # quick check for gzip magic
        if data[:2] == b"\x1f\x8b":
            return gzip.decompress(data)
    except Exception:
        pass
    return data


def parse_epss_csv_bytes(bts):
    text = bts.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    epss = {}
    # try to find likely column names
    for row in reader:
        # common column names: 'cve', 'cve_id', 'cveId' and score fields like 'epss_probability', 'epss_score', 'probability'
        keys = {k.lower(): v for k, v in row.items()}
        cve = None
        score = None
        for k in keys:
            if k in ("cve", "cve id", "cve_id", "cveid"):
                cve = keys[k]
            if k in ("epss_probability", "epss score", "epss_score", "probability", "score"):
                score = keys[k]
        if not cve:
            # try to heuristically find a CVE-like value
            for v in row.values():
                if v and v.strip().upper().startswith("CVE-"):
                    cve = v.strip()
                    break
        if not score:
            # try other columns
            for k, v in row.items():
                if v and any(ch.isdigit() for ch in v) and ("epss" in k.lower() or "prob" in k.lower() or "score" in k.lower()):
                    score = v
                    break
        if cve:
            try:
                s = float(score) if score not in (None, "", "NA") else 0.0
            except Exception:
                s = 0.0
            epss[cve.strip().upper()] = float(s)
    return epss


def parse_kev_csv_bytes(bts):
    text = bts.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    kev_set = set()
    for row in reader:
        keys = {k.lower(): v for k, v in row.items()}
        cve = None
        for k in keys:
            if k in ("cveid", "cve id", "cve_id", "cve"):
                cve = keys[k]
                break
        if not cve:
            for v in row.values():
                if v and v.strip().upper().startswith("CVE-"):
                    cve = v.strip()
                    break
        if cve:
            kev_set.add(cve.strip().upper())
    return kev_set


def ensure_table(conn):
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_risk (
            cve_id TEXT PRIMARY KEY,
            ep_ss REAL DEFAULT 0,
            in_kev INTEGER DEFAULT 0,
            base_risk REAL DEFAULT 0,
            computed_at TEXT
        )
        """
    )
    conn.commit()


def upsert_vuln_risk(conn, cve, epss_score, in_kev):
    base = float(epss_score or 0.0) * (2.0 if in_kev else 1.0)
    now = datetime.datetime.utcnow().isoformat()
    c = conn.cursor()
    # Use INSERT OR REPLACE to upsert
    c.execute(
        """
        INSERT INTO vuln_risk (cve_id, ep_ss, in_kev, base_risk, computed_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            ep_ss=excluded.ep_ss,
            in_kev=excluded.in_kev,
            base_risk=excluded.base_risk,
            computed_at=excluded.computed_at
        """,
        (cve, float(epss_score or 0.0), 1 if in_kev else 0, base, now),
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=None, help="Path to vuln_collector.db (app DB)")
    p.add_argument("--epss-url", default="https://www.first.org/epss/epss_scores-current.csv", help="EPSS CSV URL")
    p.add_argument("--kev-url", default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv", help="CISA KEV CSV URL")
    p.add_argument("--epss-file", default=None, help="Use local EPSS file instead of fetching")
    p.add_argument("--kev-file", default=None, help="Use local KEV file instead of fetching")
    args = p.parse_args()

    db_path = args.db or os.environ.get("DB_PATH") or "/data/reports/vuln_collector.db"
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(2)

    # Fetch or read EPSS
    print("Loading EPSS data...")
    try:
        if args.epss_file:
            b = open(args.epss_file, "rb").read()
        else:
            b = fetch_url_bytes(args.epss_url)
    except Exception as e:
        print(f"Failed to load EPSS: {e}", file=sys.stderr)
        b = b""

    epss = parse_epss_csv_bytes(b) if b else {}
    print(f"EPSS rows parsed: {len(epss)}")

    # Fetch or read KEV
    print("Loading CISA KEV data...")
    try:
        if args.kev_file:
            kb = open(args.kev_file, "rb").read()
        else:
            kb = fetch_url_bytes(args.kev_url)
    except Exception as e:
        print(f"Failed to load KEV: {e}", file=sys.stderr)
        kb = b""

    kev = parse_kev_csv_bytes(kb) if kb else set()
    print(f"KEV entries parsed: {len(kev)}")

    # Upsert into DB
    conn = sqlite3.connect(db_path)
    try:
        ensure_table(conn)
        all_cves = set(epss.keys()) | set(kev)
        print(f"Updating {len(all_cves)} CVE rows in vuln_risk table...")
        for cve in sorted(all_cves):
            score = epss.get(cve, 0.0)
            in_kev = cve in kev
            upsert_vuln_risk(conn, cve, score, in_kev)
        conn.commit()
    finally:
        conn.close()

    print("vuln_risk update complete")


if __name__ == '__main__':
    main()
