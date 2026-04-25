#!/usr/bin/env python3
"""Import EPSS scores into vuln_risk table.
Supports CSV with columns containing CVE id and score.
Usage: python3 scripts/import_epss.py --db nvd_local.db --url <epss_csv_url>
Or: python3 scripts/import_epss.py --db nvd_local.db --file epss.csv
"""
import argparse
import csv
import sqlite3
import requests
import io
import sys
from datetime import datetime


def fetch_csv_from_url(url):
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.content.decode('utf-8', errors='replace')


def parse_epss_csv(text):
    # Try to detect headers; expect columns like 'cve_id' and 'epss' or similar
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for r in reader:
        # find CVE key and score key
        keys = {k.lower(): v for k, v in r.items()}
        cve = None
        score = None
        for k in ('cve', 'cve_id', 'cve id'):
            if k in keys and keys[k]:
                cve = keys[k].strip()
                break
        for k in ('epss', 'score', 'probability'):
            if k in keys and keys[k]:
                try:
                    score = float(keys[k])
                except Exception:
                    score = None
                break
        if not cve:
            # try first column as cve
            first_col = next(iter(r.values()))
            if first_col and first_col.upper().startswith('CVE-'):
                cve = first_col.strip()
        if cve and score is not None:
            rows.append((cve, score))
    return rows


def upsert_ep_ss(db, rows):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    for cve, score in rows:
        cur.execute('INSERT OR IGNORE INTO vuln_risk(cve_id, ep_ss, in_kev, base_risk, computed_at) VALUES(?,?,?,?,?)', (cve, score, 0, 0, now))
        cur.execute('UPDATE vuln_risk SET ep_ss = ?, computed_at = ? WHERE cve_id = ?', (score, now, cve))
    conn.commit()
    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='nvd_local.db')
    p.add_argument('--url', help='EPSS CSV URL')
    p.add_argument('--file', help='Local CSV file')
    args = p.parse_args()

    if not args.url and not args.file:
        print('Provide --url or --file', file=sys.stderr)
        sys.exit(2)

    if args.url:
        txt = fetch_csv_from_url(args.url)
    else:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
            txt = f.read()

    rows = parse_epss_csv(txt)
    if not rows:
        print('No EPSS rows parsed; check format', file=sys.stderr)
        sys.exit(1)

    upsert_ep_ss(args.db, rows)
    print(f'Imported {len(rows)} EPSS rows into {args.db}')


if __name__ == '__main__':
    main()
