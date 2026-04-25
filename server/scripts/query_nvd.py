#!/usr/bin/env python3
"""Query helper for `nvd_local.db`.

Usage examples:
  python3 scripts/query_nvd.py --cve CVE-2026-1642
  python3 scripts/query_nvd.py --package nginx --limit 100
"""
import argparse
import sqlite3
import sys


def query_cve_by_id(db, cve_id, limit=100):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM cve WHERE id = ?", (cve_id,))
    row = cur.fetchone()
    if not row:
        print(f"CVE {cve_id} not found in {db}")
    else:
        print("CVE:")
        print(f"  id: {row['id']}")
        print(f"  cvss_score: {row['cvss_score']}")
        print(f"  description: {row['description'][:400]}")
        print("")
        cur.execute("SELECT cpe23 FROM cpe_match WHERE cve_id = ? LIMIT ?", (cve_id, limit))
        cpes = cur.fetchall()
        print(f"CPE matches ({len(cpes)}):")
        for r in cpes:
            print("  ", r['cpe23'])
    con.close()


def query_by_package(db, package, limit=100):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    like = f"%{package}%"

    print(f"Looking for CPEs LIKE '{like}' in {db}")
    cur.execute("SELECT DISTINCT cpe23 FROM cpe_match WHERE cpe23 LIKE ? LIMIT ?", (like, limit))
    cpes = cur.fetchall()
    for r in cpes:
        print(r['cpe23'])

    print('\nCVEs matched via cpe_match:')
    cur.execute(
        "SELECT DISTINCT c.id, c.cvss_score, substr(c.description,1,200) as desc "
        "FROM cve c JOIN cpe_match m ON c.id = m.cve_id "
        "WHERE m.cpe23 LIKE ? ORDER BY c.cvss_score DESC LIMIT ?",
        (like, limit),
    )
    rows = cur.fetchall()
    for r in rows:
        print(f"{r['id']}  cvss={r['cvss_score']}  {r['desc']}")

    if not rows:
        print('\nNo results via cpe_match — falling back to description search (case-insensitive)')
        cur.execute("SELECT id, cvss_score, substr(description,1,200) as desc FROM cve WHERE description LIKE ? COLLATE NOCASE LIMIT ?", (like, limit))
        rows = cur.fetchall()
        for r in rows:
            print(f"{r['id']}  cvss={r['cvss_score']}  {r['desc']}")

    con.close()


def main(argv=None):
    p = argparse.ArgumentParser(description='Query nvd_local.db')
    p.add_argument('--db', default='nvd_local.db', help='Path to nvd_local.db')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--cve', help='CVE id to lookup (e.g. CVE-2026-1642)')
    g.add_argument('--package', help='Package name fragment to search for (e.g. nginx)')
    p.add_argument('--limit', type=int, default=100)
    args = p.parse_args(argv)

    if args.cve:
        query_cve_by_id(args.db, args.cve, args.limit)
    else:
        query_by_package(args.db, args.package, args.limit)


if __name__ == '__main__':
    main()
