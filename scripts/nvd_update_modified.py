#!/usr/bin/env python3
"""Download nvdcve-2.0-modified.json.gz and apply updates to local DB.

Usage: python nvd_update_modified.py --url <modified_feed_url> --db nvd_local.db
Intended to be run periodically (cron / Task Scheduler).
"""
import argparse
import gzip
import json
import sqlite3
import requests
import sys
import os

# Ensure project root is on sys.path so `from server import ...` works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.nvd import init_local_nvd_db, extract_cpe_matches


def download_and_decompress(url: str) -> bytes:
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return gzip.decompress(r.content)


def apply_modified_bytes(bts: bytes, db_path: str):
    doc = json.loads(bts)
    items = doc.get('vulnerabilities') or doc.get('CVE_Items') or []
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for item in items:
        cve_obj = item.get('cve') if isinstance(item, dict) and 'cve' in item else item
        cve_id = cve_obj.get('id') or cve_obj.get('CVE_data_meta', {}).get('ID')
        if not cve_id:
            try:
                cve_id = item['cve']['id']
            except Exception:
                continue

        # Update description and cvss if present
        descriptions = cve_obj.get('descriptions') or cve_obj.get('description', {}).get('description_data', [])
        desc = ''
        if descriptions:
            if isinstance(descriptions, list):
                for d in descriptions:
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')
                        break
                if not desc and descriptions:
                    desc = descriptions[0].get('value','')

        cvss = None
        metrics = cve_obj.get('metrics', {})
        if isinstance(metrics, dict) and metrics:
            try:
                for v in metrics.values():
                    if isinstance(v, list) and v:
                        maybe = v[0].get('cvssData', {}).get('baseScore')
                        if maybe is not None:
                            cvss = float(maybe)
                            break
            except Exception:
                cvss = None

        cur.execute("INSERT OR REPLACE INTO cve(id, publishedDate, lastModifiedDate, cvss_score, description) VALUES(?,?,?,?,?)",
                    (cve_id, None, None, cvss, desc))

        configurations = cve_obj.get('configurations') or {}
        nodes = []
        if isinstance(configurations, dict):
            nodes = configurations.get('nodes', [])
        elif isinstance(configurations, list):
            nodes = configurations

        for node in nodes:
            for match in extract_cpe_matches(node):
                cur.execute(
                    "SELECT 1 FROM cpe_match WHERE cve_id = ? AND cpe23 = ? LIMIT 1",
                    (cve_id, match['cpe23']),
                )
                if not cur.fetchone():
                    cur.execute(
                        """
                        INSERT INTO cpe_match(
                            cve_id, cpe23, vulnerable,
                            version_start_including, version_start_excluding,
                            version_end_including,   version_end_excluding
                        ) VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            cve_id,
                            match['cpe23'],
                            match['vulnerable'],
                            match['version_start_including'],
                            match['version_start_excluding'],
                            match['version_end_including'],
                            match['version_end_excluding'],
                        ),
                    )

    conn.commit()
    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', default='https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz')
    p.add_argument('--db', default='nvd_local.db')
    args = p.parse_args()

    init_local_nvd_db(args.db)
    print('Downloading', args.url)
    data = download_and_decompress(args.url)
    print('Applying updates to', args.db)
    apply_modified_bytes(data, args.db)
    print('Done')


if __name__ == '__main__':
    main()
