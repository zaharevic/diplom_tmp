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
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Collector - Login</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }
            
            h1 {
                color: #333;
                margin-bottom: 30px;
                text-align: center;
                font-size: 28px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            label {
                display: block;
                color: #555;
                margin-bottom: 8px;
                font-weight: 500;
            }
            
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            
            button {
                width: 100%;
                padding: 12px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.3s;
            }
            
            button:hover {
                background: #764ba2;
            }
            
            .error {
                color: #d32f2f;
                margin-bottom: 20px;
                padding: 12px;
                background: #ffebee;
                border-radius: 5px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🛡️ Vulnerability Collector</h1>
            <form method="POST" action="/login">
                {error_html}
                <div class="form-group">
                    <label for="password">Admin Password</label>
                    <input type="password" id="password" name="password" autofocus required>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    """


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
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard - Vulnerability Collector</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            
            .navbar {{
                background: white;
                padding: 15px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 30px;
                border-radius: 5px;
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0 20px;
            }}
            
            .nav-logo {{
                font-size: 18px;
                font-weight: bold;
                color: #667eea;
            }}
            
            .nav-links {{
                display: flex;
                gap: 20px;
                list-style: none;
            }}
            
            .nav-links a {{
                text-decoration: none;
                color: #333;
                font-weight: 500;
                transition: color 0.3s;
            }}
            
            .nav-links a:hover {{
                color: #667eea;
            }}
            
            .nav-links a.active {{
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 3px;
            }}
            
            .logout-btn {{
                background: #d32f2f;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 500;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            h1 {{
                color: white;
                margin-bottom: 30px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }}
            
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                text-align: center;
            }}
            
            .stat-card h3 {{
                color: #667eea;
                font-size: 14px;
                text-transform: uppercase;
                margin-bottom: 10px;
            }}
            
            .stat-card .number {{
                font-size: 32px;
                font-weight: bold;
                color: #333;
            }}
            
            .section {{
                background: white;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            
            .section h2 {{
                color: #333;
                margin-bottom: 20px;
                font-size: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            
            th {{
                background: #f5f5f5;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #ddd;
            }}
            
            td {{
                padding: 12px;
                border-bottom: 1px solid #eee;
            }}
            
            tr:hover {{
                background: #f9f9f9;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <div class="nav-logo">🛡️ Vulnerability Collector</div>
                <ul class="nav-links">
                    <li><a href="/dashboard" class="active">Dashboard</a></li>
                    <li><a href="/hosts">Hosts</a></li>
                    <li><a href="/packages">Packages</a></li>
                </ul>
                <form method="POST" action="/logout" style="margin:0;">
                    <button class="logout-btn">Logout</button>
                </form>
            </div>
        </nav>
        
        <div class="container">
            <h1>📊 Dashboard</h1>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Reports</h3>
                    <div class="number">{reports_count}</div>
                </div>
                <div class="stat-card">
                    <h3>Hosts</h3>
                    <div class="number">{hosts_count}</div>
                </div>
                <div class="stat-card">
                    <h3>Software Packages</h3>
                    <div class="number">{software_count:,}</div>
                </div>
                <div class="stat-card">
                    <h3>Vulnerable Packages</h3>
                    <div class="number">{vulnerable_count}</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Recent Reports</h2>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Hostname</th>
                            <th>IP</th>
                            <th>OS</th>
                            <th>Received At</th>
                        </tr>
                    </thead>
                    <tbody>
                        {reports_rows if reports_rows else '<tr><td colspan="5">No reports</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>⚠️ Top Vulnerable Packages</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>CVEs Found</th>
                            <th>Max CVSS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows if vuln_rows else '<tr><td colspan="3">No vulnerable packages</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """


def get_hosts_page() -> str:
    """Generate hosts management page with ping status."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT r.hostname, r.ip, r.os, r.received_at,
                   (SELECT COUNT(*) FROM software WHERE hostname = r.hostname) as software_count
            FROM reports r
            WHERE r.id IN (SELECT MAX(id) FROM reports GROUP BY hostname)
            ORDER BY r.hostname
        """)
        hosts = [dict(row) for row in c.fetchall()]
    
    hosts_rows = "".join([
        f'''<tr data-hostname="{h['hostname']}">
            <td>{h['hostname']}</td>
            <td>{h['ip']}</td>
            <td>{h['os']}</td>
            <td>{h['received_at']}</td>
            <td><span class="ping-status" id="ping-{h['hostname']}">...</span></td>
            <td>{h['software_count']}</td>
            <td><button onclick="viewSoftware('{h['hostname']}')" style="padding:6px 12px; background:#667eea; color:white; border:none; border-radius:5px; cursor:pointer;">View</button></td>
        </tr>'''
        for h in hosts
    ])
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hosts - Vulnerability Collector</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            
            .navbar {{
                background: white;
                padding: 15px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 30px;
                border-radius: 5px;
            }}
            
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0 20px;
            }}
            
            .nav-logo {{
                font-size: 18px;
                font-weight: bold;
                color: #667eea;
            }}
            
            .nav-links {{
                display: flex;
                gap: 20px;
                list-style: none;
            }}
            
            .nav-links a {{
                text-decoration: none;
                color: #333;
                font-weight: 500;
            }}
            
            .nav-links a.active {{
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 3px;
            }}
            
            .logout-btn {{
                background: #d32f2f;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            h1 {{
                color: white;
                margin-bottom: 30px;
            }}
            
            .section {{
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            
            .section h2 {{
                color: #333;
                margin-bottom: 20px;
                font-size: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            
            th {{
                background: #f5f5f5;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #ddd;
            }}
            
            td {{
                padding: 12px;
                border-bottom: 1px solid #eee;
            }}
            
            tr:hover {{
                background: #f9f9f9;
            }}
            
            .ping-status {{
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: 600;
            }}
            
            .ping-status.online {{
                background: #c8e6c9;
                color: #2e7d32;
            }}
            
            .ping-status.offline {{
                background: #ffcdd2;
                color: #c62828;
            }}
            
            .ping-status.checking {{
                background: #fff9c4;
                color: #f57f17;
            }}
            
            .modal {{
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }}
            
            .modal.active {{
                display: flex;
            }}
            
            .modal-content {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                max-width: 600px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
            }}
            
            .modal-close {{
                float: right;
                font-size: 24px;
                cursor: pointer;
                color: #999;
            }}
            
            .modal-close:hover {{
                color: #333;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <div class="nav-logo">🛡️ Vulnerability Collector</div>
                <ul class="nav-links">
                    <li><a href="/dashboard">Dashboard</a></li>
                    <li><a href="/hosts" class="active">Hosts</a></li>
                    <li><a href="/packages">Packages</a></li>
                </ul>
                <form method="POST" action="/logout" style="margin:0;">
                    <button class="logout-btn">Logout</button>
                </form>
            </div>
        </nav>
        
        <div class="container">
            <h1>🖥️ Hosts Management</h1>
            
            <div class="section">
                <h2>Available Hosts (Ping Status Updated Every 5 Minutes)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Hostname</th>
                            <th>IP</th>
                            <th>OS</th>
                            <th>Last Report</th>
                            <th>Ping Status</th>
                            <th>Software Count</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {hosts_rows if hosts_rows else '<tr><td colspan="7">No hosts available</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="modal" id="softwareModal">
            <div class="modal-content">
                <span class="modal-close" onclick="closeSoftwareModal()">&times;</span>
                <h2 id="modalHostname"></h2>
                <table id="softwareTable">
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody id="softwareBody">
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            // Ping all hosts on page load
            function pingAllHosts() {{
                const rows = document.querySelectorAll('table tbody tr');
                rows.forEach(row => {{
                    const hostname = row.dataset.hostname;
                    pingHost(hostname);
                }});
            }}
            
            function pingHost(hostname) {{
                const statusEl = document.getElementById(`ping-${{hostname}}`);
                statusEl.textContent = 'Checking...';
                statusEl.className = 'ping-status checking';
                
                fetch(`/api/hosts/ping?hostname=${{encodeURIComponent(hostname)}}`)
                    .then(r => r.json())
                    .then(data => {{
                        if (data.online) {{
                            statusEl.textContent = '✓ Online';
                            statusEl.className = 'ping-status online';
                        }} else {{
                            statusEl.textContent = '✗ Offline';
                            statusEl.className = 'ping-status offline';
                        }}
                    }})
                    .catch(err => {{
                        statusEl.textContent = '? Error';
                        statusEl.className = 'ping-status offline';
                    }});
            }}
            
            function viewSoftware(hostname) {{
                fetch(`/api/scan-host?hostname=${{encodeURIComponent(hostname)}}`)
                    .then(r => r.json())
                    .then(data => {{
                        document.getElementById('modalHostname').textContent = `Software on ${{hostname}}`;
                        const tbody = document.getElementById('softwareBody');
                        tbody.innerHTML = '';
                        data.software.forEach(pkg => {{
                            const row = `<tr><td>${{pkg.name}}</td><td>${{pkg.version || 'N/A'}}</td></tr>`;
                            tbody.innerHTML += row;
                        }});
                        document.getElementById('softwareModal').classList.add('active');
                    }});
            }}
            
            function closeSoftwareModal() {{
                document.getElementById('softwareModal').classList.remove('active');
            }}
            
            // Ping hosts on load
            pingAllHosts();
            
            // Refresh ping every 5 minutes
            setInterval(pingAllHosts, 5 * 60 * 1000);
        </script>
    </body>
    </html>
    """


def get_packages_page() -> str:
    """Generate package selection page for scanning."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT hostname FROM reports ORDER BY hostname")
        hosts = [row[0] for row in c.fetchall()]
    
    hosts_options = "".join([
        f'<option value="{h}">{h}</option>' for h in hosts
    ])
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Packages - Vulnerability Collector</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            
            .navbar {{
                background: white;
                padding: 15px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 30px;
                border-radius: 5px;
            }}
            
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0 20px;
            }}
            
            .nav-logo {{
                font-size: 18px;
                font-weight: bold;
                color: #667eea;
            }}
            
            .nav-links {{
                display: flex;
                gap: 20px;
                list-style: none;
            }}
            
            .nav-links a {{
                text-decoration: none;
                color: #333;
                font-weight: 500;
            }}
            
            .nav-links a.active {{
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 3px;
            }}
            
            .logout-btn {{
                background: #d32f2f;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            h1 {{
                color: white;
                margin-bottom: 30px;
            }}
            
            .section {{
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            
            .section h2 {{
                color: #333;
                margin-bottom: 20px;
                font-size: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            
            .filter {{
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
                align-items: center;
            }}
            
            .filter select,
            .filter button {{
                padding: 10px 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }}
            
            .filter button {{
                background: #667eea;
                color: white;
                border: none;
                cursor: pointer;
                font-weight: 600;
            }}
            
            .filter button:hover {{
                background: #764ba2;
            }}
            
            .package-list {{
                max-height: 600px;
                overflow-y: auto;
            }}
            
            .package-item {{
                background: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 12px;
                margin-bottom: 8px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .package-item input[type="checkbox"] {{
                width: 20px;
                height: 20px;
                cursor: pointer;
            }}
            
            .package-item label {{
                flex: 1;
                cursor: pointer;
                margin: 0;
            }}
            
            .package-item.vulnerable {{
                background: #fff3e0;
                border-color: #ffb74d;
            }}
            
            .control-buttons {{
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }}
            
            .control-buttons button {{
                padding: 10px 15px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 500;
            }}
            
            .scan-btn {{
                background: #4caf50 !important;
                color: white !important;
                border: none !important;
            }}
            
            .scan-btn:hover {{
                background: #45a049 !important;
            }}
            
            .scan-results {{
                background: #f0f4ff;
                border: 1px solid #667eea;
                border-radius: 5px;
                padding: 15px;
                margin-top: 20px;
            }}
            
            .scan-results h3 {{
                color: #667eea;
                margin-bottom: 10px;
            }}
            
            .scan-results ul {{
                list-style-position: inside;
            }}
            
            .scan-results li {{
                margin-bottom: 8px;
            }}
            
            #scanStatus {{
                color: #666;
                font-size: 13px;
                margin-top: 10px;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <div class="nav-logo">🛡️ Vulnerability Collector</div>
                <ul class="nav-links">
                    <li><a href="/dashboard">Dashboard</a></li>
                    <li><a href="/hosts">Hosts</a></li>
                    <li><a href="/packages" class="active">Packages</a></li>
                </ul>
                <form method="POST" action="/logout" style="margin:0;">
                    <button class="logout-btn">Logout</button>
                </form>
            </div>
        </nav>
        
        <div class="container">
            <h1>📦 Package Scanning</h1>
            
            <div class="section">
                <h2>Select Host & Packages to Scan</h2>
                
                <div class="filter">
                    <select id="hostSelect" onchange="loadPackages()">
                        <option value="">Select a host...</option>
                        {hosts_options}
                    </select>
                </div>
                
                <div id="packageSection" style="display:none;">
                    <div class="control-buttons">
                        <button onclick="selectAll(true)">✓ Select All</button>
                        <button onclick="selectAll(false)">✕ Deselect All</button>
                        <button class="scan-btn" onclick="scanSelected()">🔍 Scan Selected Packages</button>
                    </div>
                    
                    <div id="statusDiv"></div>
                    
                    <div class="package-list" id="packageList">
                        <p style="text-align:center; color:#999;">Loading packages...</p>
                    </div>
                    
                    <div id="scanResults"></div>
                </div>
            </div>
        </div>
        
        <script>
            async function loadPackages() {{
                const hostname = document.getElementById('hostSelect').value;
                if (!hostname) {{
                    document.getElementById('packageSection').style.display = 'none';
                    return;
                }}
                
                const packageList = document.getElementById('packageList');
                packageList.innerHTML = '<p style="text-align:center;">Loading...</p>';
                
                try {{
                    const resp = await fetch(`/api/scan-host?hostname=${{encodeURIComponent(hostname)}}`);
                    const data = await resp.json();
                    const packages = data.software || [];
                    
                    packageList.innerHTML = '';
                    packages.forEach((pkg, idx) => {{
                        const safeId = pkg.name.replace(/[^a-z0-9_-]/gi, '_') + '_' + idx;
                        const item = `
                            <div class="package-item">
                                <input type="checkbox" id="${{safeId}}" class="pkg-checkbox" data-name="${{pkg.name}}" data-version="${{pkg.version || ''}}">
                                <label for="${{safeId}}">${{pkg.name}} <small style="color:#666;">v${{pkg.version || 'N/A'}}</small></label>
                            </div>
                        `;
                        packageList.innerHTML += item;
                    }});
                    
                    document.getElementById('packageSection').style.display = 'block';
                }} catch (err) {{
                    packageList.innerHTML = '<p style="color:#d32f2f;">Error loading packages</p>';
                }}
            }}
            
            function selectAll(state) {{
                document.querySelectorAll('.pkg-checkbox').forEach(chk => chk.checked = state);
            }}
            
            async function scanSelected() {{
                const hostname = document.getElementById('hostSelect').value;
                if (!hostname) return alert('Select a host first');
                
                const checked = Array.from(document.querySelectorAll('.pkg-checkbox')).filter(c => c.checked).map(c => ({{
                    name: c.dataset.name,
                    version: c.dataset.version || null
                }}));
                
                if (checked.length === 0) return alert('Select at least one package');
                
                const statusDiv = document.getElementById('statusDiv');
                statusDiv.innerHTML = '<div id="scanStatus" style="color:#667eea;">🔄 Starting scan...</div>';
                
                try {{
                    const resp = await fetch('/api/scan-packages', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ hostname, packages: checked }})
                    }});
                    
                    if (!resp.ok) throw new Error('Scan failed');
                    const result = await resp.json();
                    
                    let html = `<div class="scan-results">
                        <h3>✓ Scan Complete</h3>
                        <p>Checked: <strong>${{result.checked}}</strong> packages</p>
                        <p>Vulnerable: <strong>${{result.vulnerable_count}}</strong> packages</p>`;
                    
                    if (result.vulnerable_packages && result.vulnerable_packages.length) {{
                        html += '<h4>Vulnerable Packages:</h4><ul>';
                        result.vulnerable_packages.forEach(v => {{
                            html += `<li><strong>${{v.name}}</strong> v${{v.version || 'N/A'}} — ${{v.cves_found}} CVE(s), CVSS max: ${{v.cvss_max.toFixed(1)}}</li>`;
                        }});
                        html += '</ul>';
                    }} else {{
                        html += '<p style="color:green;">No vulnerabilities found!</p>';
                    }}
                    
                    html += '</div>';
                    document.getElementById('scanResults').innerHTML = html;
                    statusDiv.innerHTML = '';
                }} catch (err) {{
                    statusDiv.innerHTML = `<div id="scanStatus" style="color:#d32f2f;">❌ Error: ${{err.message}}</div>`;
                }}
            }}
        </script>
    </body>
    </html>
    """
