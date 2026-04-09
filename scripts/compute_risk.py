#!/usr/bin/env python3
"""Compute Risk Score per host and per CVE.

Inputs:
 - --db nvd_local.db
 - --assets assets.json  (array of {"host":"10.0.0.5","criticality":"high","internet_facing":true})
 - --host-packages host_packages.json (map host -> ["nginx","openssl"]) to find packages on host

Outputs:
 - upserts vuln_risk.base_risk (per-cve default) and vuln_risk_host entries

Formula (MVP):
  CVSS_norm = cvss_score / 10.0
  KEV_factor = 2.0 if in_kev else 1.0
  AssetCriticality = {"low":0.5, "normal":1.0, "high":1.5, "critical":2.0}
  ExposureFactor = 1.5 if internet_facing else 1.0
  Risk = CVSS_norm * EPSS * KEV_factor * AssetCriticality * ExposureFactor
"""
import argparse
import json
import sqlite3
import os
from datetime import datetime

CRIT_MAP = {
    'low': 0.5,
    'normal': 1.0,
    'high': 1.5,
    'critical': 2.0,
}


def load_assets(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    out = {}
    # accept either list or dict
    if isinstance(data, list):
        for e in data:
            h = e.get('host') or e.get('ip')
            if not h:
                continue
            crit = e.get('criticality','normal').lower()
            out[h] = {
                'criticality': crit if crit in CRIT_MAP else 'normal',
                'internet_facing': bool(e.get('internet_facing', False)),
            }
    elif isinstance(data, dict):
        for h, v in data.items():
            crit = v.get('criticality','normal') if isinstance(v, dict) else 'normal'
            out[h] = {
                'criticality': crit.lower() if isinstance(crit, str) else 'normal',
                'internet_facing': bool(v.get('internet_facing', False)) if isinstance(v, dict) else False,
            }
    return out


def load_host_packages(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # expect mapping host -> list of package name fragments
    return data if isinstance(data, dict) else {}


def find_cves_for_package(cur, package_fragment, limit=1000):
    like = f"%{package_fragment}%"
    # search cpe_match for matches and return distinct cve ids
    cur.execute('SELECT DISTINCT cve_id FROM cpe_match WHERE cpe23 LIKE ? LIMIT ?', (like, limit))
    return [r[0] for r in cur.fetchall()]


def compute_for_host(db, host, packages, asset, cur, now):
    results = []
    crit_weight = CRIT_MAP.get(asset.get('criticality','normal'), 1.0)
    exposure = 1.5 if asset.get('internet_facing', False) else 1.0

    for pkg in packages:
        cves = find_cves_for_package(cur, pkg)
        for cve in cves:
            # get cve info and vuln_risk info
            cur.execute('SELECT cvss_score FROM cve WHERE id = ?', (cve,))
            row = cur.fetchone()
            cvss = float(row[0]) if row and row[0] is not None else 0.0

            cur.execute('SELECT ep_ss, in_kev FROM vuln_risk WHERE cve_id = ?', (cve,))
            vr = cur.fetchone()
            ep = float(vr[0]) if vr and vr[0] is not None else 0.01
            in_kev = int(vr[1]) if vr and vr[1] is not None else 0

            cvss_norm = cvss / 10.0
            kev_factor = 2.0 if in_kev else 1.0
            risk = cvss_norm * ep * kev_factor * crit_weight * exposure

            results.append({'host': host, 'cve': cve, 'cvss': cvss, 'ep_ss': ep, 'in_kev': in_kev, 'risk': risk})

    # persist per-host results
    for r in results:
        cur.execute('INSERT OR REPLACE INTO vuln_risk_host(host, cve_id, risk_score, computed_at) VALUES(?,?,?,?)', (r['host'], r['cve'], r['risk'], now))

    return results


def compute_all(db_path, assets_path, host_packages_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    assets = load_assets(assets_path)
    host_pkgs = load_host_packages(host_packages_path)
    now = datetime.utcnow().isoformat()

    all_results = []
    for host, pkgs in host_pkgs.items():
        asset = assets.get(host, {'criticality':'normal','internet_facing':False})
        res = compute_for_host(db_path, host, pkgs, asset, cur, now)
        all_results.extend(res)

    # Optionally compute base_risk per CVE (average across hosts or default asset)
    # Here compute base_risk as risk with normal asset and no exposure
    cur.execute('SELECT cve_id, ep_ss, in_kev FROM vuln_risk')
    rows = cur.fetchall()
    for cve_id, ep_ss, in_kev in rows:
        cvss = 0.0
        cur2 = conn.cursor()
        cur2.execute('SELECT cvss_score FROM cve WHERE id = ?', (cve_id,))
        r = cur2.fetchone()
        if r and r[0] is not None:
            cvss = float(r[0])
        cvss_norm = cvss / 10.0
        kev_factor = 2.0 if (in_kev or 0) else 1.0
        ep = float(ep_ss or 0.01)
        base_risk = cvss_norm * ep * kev_factor * 1.0 * 1.0
        cur2.execute('UPDATE vuln_risk SET base_risk = ?, computed_at = ? WHERE cve_id = ?', (base_risk, now, cve_id))

    conn.commit()
    conn.close()
    return all_results


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='nvd_local.db')
    p.add_argument('--assets', default='assets.json', help='Assets JSON file')
    p.add_argument('--host-packages', default='host_packages.json', help='Host->packages JSON')
    args = p.parse_args()
    res = compute_all(args.db, args.assets, args.host_packages)
    print(f'Computed risk for {len(res)} host-CVE pairs')
