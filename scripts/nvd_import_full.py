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
from io import BytesIO
from server.nvd import init_local_nvd_db


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

        # Extract CPEs
        configurations = cve_obj.get('configurations') or cve_obj.get('configurations', {})
        nodes = []
        if isinstance(configurations, dict):
            nodes = configurations.get('nodes', [])
        elif isinstance(configurations, list):
            nodes = configurations

        for node in nodes:
            for cm in node.get('cpeMatch', []) if isinstance(node.get('cpeMatch', []), list) else []:
                cpe23 = cm.get('cpe23Uri') or cm.get('criteria')
                if cpe23:
                    cur.execute("INSERT INTO cpe_match(cve_id, cpe23) VALUES(?,?)", (cve_id, cpe23))

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
