#!/usr/bin/env python3
"""Import NVD bulk feeds into local SQLite DB (simple prototype for diploma).

Usage: python nvd_import_full.py --feed-url <url> --db nvd_local.db
You can call it multiple times for different year files.
"""
import argparse
import gzip
import json
import sqlite3
import requests
import sys
import os
from io import BytesIO

# Ensure project root is on sys.path so `from server import ...` works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.nvd import init_local_nvd_db, extract_cpe_matches


def download_and_decompress(url: str) -> bytes:
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return gzip.decompress(r.content)


def import_feed_bytes(bts: bytes, db_path: str):
    doc = json.loads(bts)
    # JSON 2.0 uses 'vulnerabilities' top-level key
    items = doc.get('vulnerabilities') or doc.get('CVE_Items') or []
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for item in items:
        # Support both v2.0 and legacy structures
        cve_obj = item.get('cve') if isinstance(item, dict) and 'cve' in item else item
        cve_id = cve_obj.get('id') or cve_obj.get('CVE_data_meta', {}).get('ID')
        if not cve_id:
            # Try deeper structure
            try:
                cve_id = item['cve']['id']
            except Exception:
                continue

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
            elif isinstance(descriptions, dict):
                desc = descriptions.get('description', '')

        # cvss
        cvss = None
        metrics = cve_obj.get('metrics', {})
        if isinstance(metrics, dict) and metrics:
            try:
                # pick any cvss field
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

        configurations = cve_obj.get('configurations') or []
        nodes = []
        if isinstance(configurations, dict):
            nodes = configurations.get('nodes', [])
        elif isinstance(configurations, list):
            for cfg in configurations:
                nodes.extend(cfg.get('nodes', []))

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
    p.add_argument('--feed-url', required=True)
    p.add_argument('--db', default='nvd_local.db')
    args = p.parse_args()

    init_local_nvd_db(args.db)
    print('Downloading', args.feed_url)
    data = download_and_decompress(args.feed_url)
    print('Importing into', args.db)
    import_feed_bytes(data, args.db)
    print('Done')


if __name__ == '__main__':
    main()
