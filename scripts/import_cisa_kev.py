#!/usr/bin/env python3
"""Import CISA KEV list and mark vuln_risk.in_kev=1 for listed CVEs.
Usage: python3 scripts/import_cisa_kev.py --db nvd_local.db --url <cisa_csv_url>
Or: python3 scripts/import_cisa_kev.py --db nvd_local.db --file kev.csv
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


def parse_cisa_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    cves = []
    for r in reader:
        # common column names: 'cveID', 'CVE ID', 'cve'
        for k, v in r.items():
            if k and 'cve' in k.lower() and v:
                cves.append(v.strip())
                break
    return cves


def mark_in_kev(db, cves):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    for cve in cves:
        cur.execute('INSERT OR IGNORE INTO vuln_risk(cve_id, ep_ss, in_kev, base_risk, computed_at) VALUES(?,?,?,?,?)', (cve, 0, 1, 0, now))
        cur.execute('UPDATE vuln_risk SET in_kev = 1, computed_at = ? WHERE cve_id = ?', (now, cve))
    conn.commit()
    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='nvd_local.db')
    p.add_argument('--url', help='CISA KEV CSV URL')
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

    cves = parse_cisa_csv(txt)
    if not cves:
        print('No CVEs parsed from CISA KEV CSV', file=sys.stderr)
        sys.exit(1)

    mark_in_kev(args.db, cves)
    print(f'Marked {len(cves)} CVEs as in KEV in {args.db}')


if __name__ == '__main__':
    main()
