"""
HTML page generators for vulnerability collector admin panel.
Separate pages for: login, dashboard, package selection, hosts management.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime

DB_PATH = "/data/reports/vuln_collector.db"


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def get_login_page() -> str:
    """Generate login page HTML."""
    with open('templates/login.html', 'r', encoding='utf-8') as f:
        return f.read()


def get_dashboard_page() -> str:
    """Generate main dashboard with statistics."""
    with get_db() as conn:
        c = conn.cursor()
        
        # Statistics
        c.execute("SELECT COUNT(*) FROM reports")
        reports_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(DISTINCT hostname || '|' || name || '|' || version) FROM software")
        software_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM cve_cache WHERE cves_found > 0")
        vulnerable_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(DISTINCT hostname) FROM reports")
        hosts_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'new'")
        new_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'in_task'")
        in_task_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'ignore'")
        ignore_count = c.fetchone()[0]
        
        # Recent reports
        c.execute("""
            SELECT id, hostname, ip, os, received_at 
            FROM reports 
            WHERE id IN (SELECT MAX(id) FROM reports GROUP BY hostname)
            ORDER BY received_at DESC LIMIT 10
        """)
        recent_reports = [dict(row) for row in c.fetchall()]
        
        # Top vulnerable packages
        c.execute("""
            SELECT package_name, cves_found, cvss_max 
            FROM cve_cache 
            WHERE cves_found > 0
            ORDER BY cves_found DESC LIMIT 10
        """)
        vulnerable_packages = [dict(row) for row in c.fetchall()]
    
    reports_rows = "".join([
        f'<tr><td>{r["id"]}</td><td>{r["hostname"]}</td><td>{r["ip"]}</td><td>{r["os"]}</td><td>{r["received_at"]}</td></tr>'
        for r in recent_reports
    ])
    
    vuln_rows = "".join([
        f'<tr><td>{p["package_name"]}</td><td>{p["cves_found"]}</td><td>{p["cvss_max"]:.1f}</td></tr>'
        for p in vulnerable_packages
    ])
    
    with open('templates/dashboard.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    return html.replace('{reports_count}', str(reports_count)) \
               .replace('{hosts_count}', str(hosts_count)) \
               .replace('{software_count}', str(software_count)) \
               .replace('{vulnerable_count}', str(vulnerable_count)) \
               .replace('{new_count}', str(new_count)) \
               .replace('{in_task_count}', str(in_task_count)) \
               .replace('{ignore_count}', str(ignore_count)) \
               .replace('{reports_rows}', reports_rows) \
               .replace('{vuln_rows}', vuln_rows)


def get_hosts_page() -> str:
    """Generate hosts management page with ping status."""
    with get_db() as conn:
        c = conn.cursor()
        # Build unified set of hostnames from reports, software and hosts metadata
        c.execute("""
            SELECT h.hostname, r.ip, r.os, r.received_at,
                   IFNULL(s.software_count, 0) AS software_count,
                   IFNULL(hm.criticality, 1) AS criticality
            FROM (
                SELECT hostname FROM reports
                UNION
                SELECT hostname FROM software
                UNION
                SELECT host AS hostname FROM hosts
            ) h
            LEFT JOIN (
                SELECT * FROM reports WHERE id IN (SELECT MAX(id) FROM reports GROUP BY hostname)
            ) r ON r.hostname = h.hostname
            LEFT JOIN (
                SELECT hostname, COUNT(*) AS software_count FROM software GROUP BY hostname
            ) s ON s.hostname = h.hostname
            LEFT JOIN hosts hm ON hm.host = h.hostname
            ORDER BY h.hostname
        """)
        hosts = [dict(row) for row in c.fetchall()]

        # For each host, fetch top risk score (if any)
        hosts_rows = ""
        for h in hosts:
            hostname = h['hostname']
            c.execute("SELECT COUNT(*) FROM vuln_risk_host WHERE host = ? AND risk_score > 0", (hostname,))
            risky_count = c.fetchone()[0]
            c.execute("SELECT MAX(risk_score) FROM vuln_risk_host WHERE host = ?", (hostname,))
            top_risk_row = c.fetchone()
            top_risk = top_risk_row[0] if top_risk_row and top_risk_row[0] is not None else 0

            # render criticality selector (1-5)
            crit = int(h.get('criticality', 1)) if h.get('criticality') is not None else 1
            crit_options = ''.join([f'<option value="{i}"{" selected" if i==crit else ""}>{i}</option>' for i in range(1,6)])

            hosts_rows += f'''<tr data-hostname="{h['hostname']}">
                <td>{h['hostname']}</td>
                <td>{h.get('ip') or ''}</td>
                <td>{h.get('os') or ''}</td>
                <td>{h.get('received_at') or ''}</td>
                <td><span class="ping-status" id="ping-{h['hostname']}">...</span></td>
                <td>{h['software_count']}</td>
                <td>{risky_count}</td>
                <td>{top_risk:.6f}</td>
                <td>
                    <form method="POST" action="/api/hosts/criticality" style="display:inline;margin:0;">
                        <input type="hidden" name="hostname" value="{h['hostname']}">
                        <select name="criticality" style="padding:4px 6px;">{crit_options}</select>
                        <button type="submit" style="padding:6px 10px; margin-left:6px; background:#2b6cb0; color:white; border:none; border-radius:4px;">Set</button>
                    </form>
                    <button onclick="viewSoftware('{h['hostname']}')" style="padding:6px 12px; background:#667eea; color:white; border:none; border-radius:5px; cursor:pointer; margin-left:8px;">View</button>
                </td>
            </tr>'''
    
    with open('templates/hosts.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    return html.replace('{hosts_table}', hosts_rows)


def get_packages_page() -> str:
    """Generate package selection page for scanning."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT hostname FROM reports ORDER BY hostname")
        hosts = [row[0] for row in c.fetchall()]
    
    hosts_options = "".join([
        f'<option value="{h}">{h}</option>' for h in hosts
    ])
    
    with open('templates/packages.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    return html.replace('{hosts_options}', hosts_options)


def get_software_management_page() -> str:
    """Generate software management page with NVD name customization and status tracking."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'new'")
        new_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'in_task'")
        in_task_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM software_management WHERE status = 'ignore'")
        ignore_count = c.fetchone()[0]
    
    with open('templates/software_management.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    return html.replace('{new_count}', str(new_count)) \
               .replace('{in_task_count}', str(in_task_count)) \
               .replace('{ignore_count}', str(ignore_count))

