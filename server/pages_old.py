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
                    <li><a href="/software-management">Software Management</a></li>
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
    
    with open('templates/packages.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    return html.replace('{hosts_options}', hosts_options)
            
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
                    <li><a href="/software-management">Software Management</a></li>
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
            
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: white;
                padding: 15px;
                border-radius: 5px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            
            .stat-card .label {{
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                margin-bottom: 8px;
            }}
            
            .stat-card .number {{
                font-size: 28px;
                font-weight: bold;
                color: #667eea;
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
                font-size: 18px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            
            .filter-tabs {{
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }}
            
            .filter-btn {{
                padding: 8px 15px;
                border: 2px solid #ddd;
                background: white;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.3s;
            }}
            
            .filter-btn.active {{
                background: #667eea;
                color: white;
                border-color: #667eea;
            }}
            
            .bulk-actions {{
                display: none;
                background: #f0f0f0;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 15px;
                align-items: center;
                gap: 10px;
                flex-wrap: wrap;
            }}
            
            .bulk-actions.active {{
                display: flex;
            }}
            
            .bulk-selected {{
                font-weight: 600;
                color: #333;
                margin-right: 10px;
            }}
            
            .bulk-actions button {{
                padding: 8px 15px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                font-size: 13px;
            }}
            
            .btn-set-task {{
                background: #7b1fa2;
                color: white;
            }}
            
            .btn-set-ignore {{
                background: #e65100;
                color: white;
            }}
            
            .btn-set-new {{
                background: #1976d2;
                color: white;
            }}
            
            .btn-clear {{
                background: #999;
                color: white;
            }}
            
            .software-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            
            .software-table th {{
                background: #f5f5f5;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #ddd;
            }}
            
            .software-table td {{
                padding: 12px;
                border-bottom: 1px solid #eee;
            }}
            
            .software-table tr:hover {{
                background: #f9f9f9;
            }}
            
            .checkbox-col {{
                width: 40px;
                text-align: center;
            }}
            
            .checkbox-col input {{
                cursor: pointer;
                width: 18px;
                height: 18px;
            }}
            
            .action-btns {{
                display: flex;
                gap: 8px;
            }}
            
            .btn-small {{
                padding: 6px 12px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 3px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
            }}
            
            .btn-force {{
                background: #ff9800;
                color: white;
                border: none;
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
                max-width: 500px;
                width: 90%;
            }}
            
            .form-group {{
                margin-bottom: 15px;
            }}
            
            .form-group label {{
                display: block;
                margin-bottom: 5px;
                font-weight: 500;
                color: #333;
            }}
            
            .form-group input,
            .form-group select,
            .form-group textarea {{
                width: 100%;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }}
            
            .modal-buttons {{
                display: flex;
                gap: 10px;
                margin-top: 20px;
            }}
            
            .modal-buttons button {{
                flex: 1;
                padding: 10px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
            }}
            
            .btn-save {{
                background: #4caf50;
                color: white;
            }}
            
            .btn-cancel {{
                background: #ddd;
                color: #333;
            }}
            
            .status-badge {{
                display: inline-block;
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: 600;
            }}
            
            .status-new {{
                background: #e3f2fd;
                color: #1976d2;
            }}
            
            .status-in_task {{
                background: #f3e5f5;
                color: #7b1fa2;
            }}
            
            .status-ignore {{
                background: #ffe0b2;
                color: #e65100;
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
                    <li><a href="/packages">Packages</a></li>
                    <li><a href="/software-management" class="active">Software Management</a></li>
                </ul>
                <form method="POST" action="/logout" style="margin:0;">
                    <button class="logout-btn">Logout</button>
                </form>
            </div>
        </nav>
        
        <div class="container">
            <h1>🔧 Software Management</h1>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="label">New</div>
                    <div class="number">{new_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">In Task</div>
                    <div class="number">{in_task_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Ignored</div>
                    <div class="number">{ignore_count}</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📦 Manage Software</h2>
                
                <div class="filter-tabs">
                    <button class="filter-btn active" onclick="filterByStatus('all')">All</button>
                    <button class="filter-btn" onclick="filterByStatus('new')">New</button>
                    <button class="filter-btn" onclick="filterByStatus('in_task')">In Task</button>
                    <button class="filter-btn" onclick="filterByStatus('ignore')">Ignored</button>
                </div>
                
                <div class="bulk-actions" id="bulkActions">
                    <span class="bulk-selected"><span id="selectedCount">0</span> selected</span>
                    <button class="btn-set-task" onclick="applyBulkStatus('in_task')">📋 Set to In Task</button>
                    <button class="btn-set-ignore" onclick="applyBulkStatus('ignore')">⛔ Set to Ignore</button>
                    <button class="btn-set-new" onclick="applyBulkStatus('new')">✨ Set to New</button>
                    <button class="btn-clear" onclick="clearSelection()">Clear Selection</button>
                </div>
                
                <table class="software-table">
                    <thead>
                        <tr>
                            <th class="checkbox-col"><input type="checkbox" id="selectAll" onchange="toggleSelectAll(this.checked)"></th>
                            <th>Application Name</th>
                            <th>NVD Query Name</th>
                            <th>Status</th>
                            <th>CVEs Found</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="softwareBody">
                        <tr><td colspan="6" style="text-align:center; color:#999;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="modal" id="editModal">
            <div class="modal-content">
                <h2>Edit Software</h2>
                <div class="form-group">
                    <label>Application Name</label>
                    <input type="text" id="origName" disabled style="background:#f5f5f5;">
                </div>
                <div class="form-group">
                    <label>NVD Query Name</label>
                    <input type="text" id="nvdName" placeholder="Name to send to NVD API">
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select id="statusSelect">
                        <option value="new">New</option>
                        <option value="in_task">In Task</option>
                        <option value="ignore">Ignore</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Comment</label>
                    <textarea id="comment" placeholder="Optional notes" rows="3"></textarea>
                </div>
                <div class="modal-buttons">
                    <button class="btn-save" onclick="saveChanges()">Save</button>
                    <button class="btn-cancel" onclick="closeEditModal()">Cancel</button>
                </div>
            </div>
        </div>
        
        <script>
            let allSoftware = [];
            let currentFilter = 'all';
            let selectedPackages = new Set();
            
            async function loadSoftwareData() {{
                try {{
                    const resp = await fetch('/api/software-management');
                    allSoftware = await resp.json();
                }} catch (err) {{
                    console.error('Error loading software:', err);
                    document.getElementById('softwareBody').innerHTML = '<tr><td colspan="6" style="color:#d32f2f;">Error loading data</td></tr>';
                }}
            }}
            
            async function loadSoftware() {{
                await loadSoftwareData();
                selectedPackages.clear();
                document.getElementById('selectAll').checked = false;
                renderSoftware();
            }}
            
            function renderSoftware() {{
                const filtered = currentFilter === 'all' 
                    ? allSoftware 
                    : allSoftware.filter(s => s.status === currentFilter);
                
                const tbody = document.getElementById('softwareBody');
                if (filtered.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#999;">No software found</td></tr>';
                    updateBulkActionsUI();
                    return;
                }}
                
                tbody.innerHTML = filtered.map(sw => `
                    <tr>
                        <td class="checkbox-col">
                            <input type="checkbox" 
                                   data-name="${{sw.original_name}}" 
                                   onchange="togglePackage('${{sw.original_name}}', this.checked)">
                        </td>
                        <td><strong>${{sw.original_name}}</strong></td>
                        <td><code>${{sw.normalized_for_nvd}}</code></td>
                        <td><span class="status-badge status-${{sw.status}}">${{sw.status}}</span></td>
                        <td>${{sw.cached ? '<span style="color:#d32f2f; font-weight:600;">' + sw.cves_found + ' CVE(s)</span>' : '<span style="color:#999;">-</span>'}}</td>
                        <td>
                            <div class="action-btns">
                                <button class="btn-small btn-force" onclick="forceCheck('${{sw.original_name}}')">⚡ Force Check</button>
                            </div>
                        </td>
                    </tr>
                `).join('');
                
                // Restore checkboxes for selected packages
                selectedPackages.forEach(pkgName => {{
                    const checkbox = document.querySelector(`input[data-name="${{pkgName}}"]`);
                    if (checkbox) checkbox.checked = true;
                }});
                
                updateBulkActionsUI();
            }}
            
            function togglePackage(name, checked) {{
                if (checked) {{
                    selectedPackages.add(name);
                }} else {{
                    selectedPackages.delete(name);
                    document.getElementById('selectAll').checked = false;
                }}
                updateBulkActionsUI();
            }}
            
            function toggleSelectAll(checked) {{
                const filtered = currentFilter === 'all' 
                    ? allSoftware 
                    : allSoftware.filter(s => s.status === currentFilter);
                
                selectedPackages.clear();
                
                if (checked) {{
                    filtered.forEach(sw => selectedPackages.add(sw.original_name));
                    document.querySelectorAll('.checkbox-col input').forEach(cb => cb.checked = true);
                }} else {{
                    document.querySelectorAll('.checkbox-col input').forEach(cb => cb.checked = false);
                }}
                updateBulkActionsUI();
            }}
            
            function updateBulkActionsUI() {{
                const bulkPanel = document.getElementById('bulkActions');
                const count = selectedPackages.size;
                document.getElementById('selectedCount').textContent = count;
                
                if (count > 0) {{
                    bulkPanel.classList.add('active');
                }} else {{
                    bulkPanel.classList.remove('active');
                }}
            }}
            
            function clearSelection() {{
                selectedPackages.clear();
                document.getElementById('selectAll').checked = false;
                document.querySelectorAll('.checkbox-col input').forEach(cb => cb.checked = false);
                updateBulkActionsUI();
            }}
            
            async function applyBulkStatus(newStatus) {{
                if (selectedPackages.size === 0) {{
                    alert('⚠️ No applications selected');
                    return;
                }}
                
                const count = selectedPackages.size;
                const statusName = newStatus === 'in_task' ? 'In Task' : (newStatus === 'ignore' ? 'Ignore' : 'New');
                
                if (!confirm(`Set ${{count}} application(s) to ${{statusName}}?`)) return;
                
                try {{
                    // Build list of packages to update
                    const packages = Array.from(selectedPackages).map(pkgName => ({{
                        original_name: pkgName,
                        status: newStatus,
                        comment: ''
                    }}));
                    
                    const resp = await fetch('/api/software-management/bulk-update', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ packages: packages }})
                    }});
                    
                    if (resp.ok) {{
                        const result = await resp.json();
                        alert(`✓ Updated ${{result.updated_count}} application(s)`);
                        clearSelection();
                        await refreshSoftware();
                    }} else {{
                        const error = await resp.json();
                        alert('❌ Error: ' + (error.detail || 'Unknown error'));
                    }}
                }} catch (err) {{
                    alert('❌ Error: ' + err.message);
                }}
            }}
            
            function filterByStatus(status) {{
                currentFilter = status;
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');
                clearSelection();
                renderSoftware();
            }}
            
            function openEditModal(name, nvd, status, comment) {{
                document.getElementById('origName').value = name;
                document.getElementById('nvdName').value = nvd;
                document.getElementById('statusSelect').value = status;
                document.getElementById('comment').value = comment;
                document.getElementById('editModal').classList.add('active');
            }}
            
            function closeEditModal() {{
                document.getElementById('editModal').classList.remove('active');
            }}
            
            async function saveChanges() {{
                const origName = document.getElementById('origName').value;
                const nvdName = document.getElementById('nvdName').value;
                const status = document.getElementById('statusSelect').value;
                const comment = document.getElementById('comment').value;
                
                try {{
                    const resp = await fetch('/api/software-management/update', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            original_name: origName,
                            normalized_for_nvd: nvdName,
                            status: status,
                            comment: comment
                        }})
                    }});
                    
                    if (resp.ok) {{
                        alert('✓ Saved successfully');
                        closeEditModal();
                        loadSoftware();
                    }} else {{
                        alert('❌ Error saving changes');
                    }}
                }} catch (err) {{
                    alert('Error: ' + err.message);
                }}
            }}
            
            async function forceCheck(packageName) {{
                if (!confirm('Force recheck this package? (ignores cache)')) return;
                
                try {{
                    const resp = await fetch('/api/force-check', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ package_name: packageName }})
                    }});
                    
                    const result = await resp.json();
                    if (result.cves_found > 0) {{
                        alert(`✓ Found ${{result.cves_found}} CVE(s), max CVSS: ${{result.cvss_max.toFixed(1)}}`);
                    }} else {{
                        alert('✓ No vulnerabilities found');
                    }}
                    await refreshSoftware();
                }} catch (err) {{
                    alert('❌ Force check failed: ' + err.message);
                }}
            }}
            
            async function refreshSoftware() {{
                await loadSoftwareData();
                renderSoftware();
            }}
            
            // Load on page load
            loadSoftware();
            
            // Refresh every 60 seconds (without clearing selection)
            setInterval(refreshSoftware, 60000);
        </script>
    </body>
    </html>
    """

