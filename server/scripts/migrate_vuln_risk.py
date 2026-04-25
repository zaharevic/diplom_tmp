#!/usr/bin/env python3
"""Create vuln_risk and vuln_risk_host tables in nvd_local.db
Usage: python3 scripts/migrate_vuln_risk.py --db nvd_local.db
"""
import sqlite3
import argparse
import os

def migrate(db_path):
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS vuln_risk (
            cve_id TEXT PRIMARY KEY,
            ep_ss REAL DEFAULT 0,
            in_kev INTEGER DEFAULT 0,
            base_risk REAL DEFAULT 0,
            computed_at TEXT
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_vuln_risk_ep ON vuln_risk(ep_ss)')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS vuln_risk_host (
            host TEXT,
            cve_id TEXT,
            risk_score REAL,
            computed_at TEXT,
            PRIMARY KEY(host, cve_id)
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_vuln_risk_host ON vuln_risk_host(host)')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='nvd_local.db')
    args = p.parse_args()
    migrate(args.db)
    print('Migration completed on', args.db)
