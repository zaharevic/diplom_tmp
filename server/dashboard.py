"""
Simple web dashboard for viewing vulnerability database.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3
from contextlib import contextmanager

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


def get_dashboard_html():
    """Generate HTML dashboard with statistics and tables."""
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Get statistics
        c.execute("SELECT COUNT(*) FROM reports")
        reports_count = c.fetchone()[0]
        
        # Count unique software (distinct by hostname + name + version)
        c.execute("""
            SELECT COUNT(DISTINCT hostname || '|' || name || '|' || version) 
            FROM software
        """)
        software_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM cve_cache WHERE cves_found > 0")
        vulnerable_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(DISTINCT hostname) FROM reports")
        hosts_count = c.fetchone()[0]
        
        # Get recent reports (one per hostname, most recent)
        c.execute("""
            SELECT id, hostname, ip, os, received_at 
            FROM reports 
            WHERE id IN (
                SELECT MAX(id) FROM reports GROUP BY hostname
            )
            ORDER BY received_at DESC 
            LIMIT 10
        """)
        recent_reports = [dict(row) for row in c.fetchall()]
        
        # Get top vulnerable packages
        c.execute("""
            SELECT package_name, cves_found, cvss_max 
            FROM cve_cache 
            WHERE cves_found > 0
            ORDER BY cves_found DESC 
            LIMIT 10
        """)
        vulnerable_packages = [dict(row) for row in c.fetchall()]
        
        # Get hosts
        c.execute("""
            SELECT DISTINCT hostname 
            FROM reports 
            ORDER BY hostname
        """)
        hosts = [row[0] for row in c.fetchall()]
    
    hosts_options = "".join([f'<option value="{h}">{h}</option>' for h in hosts])
    
    reports_rows = "".join([
        f'''<tr>
            <td>{r['id']}</td>
            <td>{r['hostname']}</td>
            <td>{r['ip']}</td>
            <td>{r['os']}</td>
            <td>{r['received_at']}</td>
        </tr>''' for r in recent_reports
    ])
    
    vuln_rows = "".join([
        f'''<tr>
            <td>{p['package_name']}</td>
            <td>{p['cves_found']}</td>
            <td>{p['cvss_max']:.1f}</td>
        </tr>''' for p in vulnerable_packages
    ])
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Collector Dashboard</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
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
                margin-top: 10px;
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
            
            .filter {{
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }}
            
            .filter select,
            .filter input,
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
            
            .cvss-high {{
                color: #d32f2f;
                font-weight: 600;
            }}
            
            .cvss-medium {{
                color: #f57c00;
                font-weight: 600;
            }}
            
            .cvss-low {{
                color: #fbc02d;
                font-weight: 600;
            }}
            
            .footer {{
                color: white;
                text-align: center;
                margin-top: 30px;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Vulnerability Collector Dashboard</h1>
            
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
                        {reports_rows}
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
                        {vuln_rows}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🔍 Query Software by Host</h2>
                <div class="filter">
                    <select id="hostSelect" onchange="querySoftware()">
                        <option value="">Select a host...</option>
                        {hosts_options}
                    </select>
                </div>
                <div id="softwareTable" style="display: none;">
                    <div style="margin-bottom:10px; display:flex; gap:10px; align-items:center;">
                        <button class="btn-small btn-edit" id="scanSelectedBtn" onclick="scanSelected()" disabled>🔎 Scan Selected</button>
                        <button class="btn-small" onclick="selectAll(true)">Select All</button>
                        <button class="btn-small" onclick="selectAll(false)">Clear All</button>
                        <div id="scanStatus" style="margin-left:10px; color:#666; font-size:13px;"></div>
                    </div>

                    <table>
                        <thead>
                            <tr>
                                <th style="width:40px"></th>
                                <th>Package Name</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody id="softwareBody">
                        </tbody>
                    </table>
                    <div id="scanResults" style="margin-top:12px;"></div>
                </div>
                <div id="loading" style="display: none;">Loading...</div>
            </div>
            
            <div class="section">
                <h2>🛠️ Package Manager (NVD Query Optimization)</h2>
                <p style="margin-bottom: 15px; color: #666; font-size: 14px;">
                    ℹ️ Review package names and correct any that were poorly normalized. Click "✓ OK" to keep as-is, or "✏️ Edit" to correct the name and rescan NVD.
                </p>
                <div id="packagesContainer" style="max-height: 600px; overflow-y: auto;">
                    <p style="text-align: center; color: #999;">Loading packages...</p>
                </div>
            </div>
            
            <div class="footer">
                <p>Vulnerability Collector • Last updated: {recent_reports[0]['received_at'] if recent_reports else 'N/A'}</p>
            </div>
        </div>
        
        <style>
            .package-item {{
                background: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 10px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
            }}
            
            .package-item.vulnerable {{
                background: #fff3e0;
                border-color: #ffb74d;
            }}
            
            .package-info {{
                flex: 1;
            }}
            
            .package-original {{
                font-weight: 600;
                color: #333;
                margin-bottom: 5px;
            }}
            
            .package-normalized {{
                font-size: 12px;
                color: #666;
                margin-bottom: 3px;
            }}
            
            .package-cve {{
                font-size: 12px;
                color: #999;
            }}
            
            .package-cve.found {{
                color: #d32f2f;
                font-weight: 600;
            }}
            
            .package-actions {{
                display: flex;
                gap: 8px;
            }}
            
            .btn-small {{
                padding: 8px 12px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 5px;
                cursor: pointer;
                font-size: 13px;
                font-weight: 500;
                transition: all 0.2s;
            }}
            
            .btn-ok {{
                background: #4caf50;
                color: white;
                border: none;
            }}
            
            .btn-ok:hover {{
                background: #45a049;
            }}
            
            .btn-edit {{
                background: #2196f3;
                color: white;
                border: none;
            }}
            
            .btn-edit:hover {{
                background: #0b7dda;
            }}
            
            .edit-form {{
                display: none;
                background: #e3f2fd;
                padding: 12px;
                border-radius: 5px;
                margin-top: 10px;
            }}
            
            .edit-form input {{
                width: 100%;
                padding: 8px 12px;
                border: 1px solid #2196f3;
                border-radius: 4px;
                margin-bottom: 8px;
                font-size: 13px;
            }}
            
            .edit-form button {{
                padding: 6px 12px;
                margin-right: 5px;
                font-size: 12px;
            }}
            
            .btn-save {{
                background: #28a745;
                color: white;
                border: none;
                cursor: pointer;
            }}
            
            .btn-save:hover {{
                background: #218838;
            }}
            
            .btn-cancel {{
                background: #dc3545;
                color: white;
                border: none;
                cursor: pointer;
            }}
            
            .btn-cancel:hover {{
                background: #c82333;
            }}
            
            .status-message {{
                font-size: 12px;
                margin-top: 5px;
                padding: 8px;
                border-radius: 4px;
            }}
            
            .status-success {{
                background: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }}
            
            .status-error {{
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }}
            
            .status-loading {{
                background: #d1ecf1;
                color: #0c5460;
                border: 1px solid #bee5eb;
            }}
        </style>
        
        <script>
            async function loadPackages() {{
                try {{
                    const response = await fetch('/api/packages');
                    const packages = await response.json();
                    
                    const container = document.getElementById('packagesContainer');
                    container.innerHTML = '';
                    
                    packages.forEach(pkg => {{
                        const isVulnerable = pkg.cves_found > 0;
                        const item = document.createElement('div');
                        item.className = 'package-item' + (isVulnerable ? ' vulnerable' : '');
                        item.id = `pkg-${{pkg.original_name}}`;
                        
                        const cveStatus = isVulnerable 
                            ? `<span class="package-cve found">⚠️ ${{pkg.cves_found}} CVEs (CVSS: ${{pkg.cvss_max.toFixed(1)}})</span>`
                            : '<span class="package-cve">✓ No CVEs</span>';
                        
                        item.innerHTML = `
                            <div class="package-info">
                                <div class="package-original">📦 ${{pkg.original_name}}</div>
                                <div class="package-normalized">→ Normalized: <code>${{pkg.normalized_name}}</code></div>
                                <div>${{cveStatus}}</div>
                            </div>
                            <div class="package-actions">
                                <button class="btn-small btn-ok" onclick="markOk('${{pkg.original_name}}')">✓ OK</button>
                                <button class="btn-small btn-edit" onclick="toggleEdit('${{pkg.original_name}}')">✏️ Edit</button>
                            </div>
                            <div class="edit-form" id="form-${{pkg.original_name}}">
                                <input type="text" id="input-${{pkg.original_name}}" placeholder="Enter corrected name" value="${{pkg.original_name}}">
                                <button class="btn-small btn-save" onclick="savePackage('${{pkg.original_name}}')">💾 Save & Rescan</button>
                                <button class="btn-small btn-cancel" onclick="toggleEdit('${{pkg.original_name}}')">✕ Cancel</button>
                                <div id="status-${{pkg.original_name}}"></div>
                            </div>
                        `;
                        
                        container.appendChild(item);
                    }});
                    
                    if (packages.length === 0) {{
                        container.innerHTML = '<p style="text-align: center; color: #999;">No packages found</p>';
                    }}
                }} catch (error) {{
                    console.error('Error loading packages:', error);
                    document.getElementById('packagesContainer').innerHTML = '<p style="color: #d32f2f;">Error loading packages</p>';
                }}
            }}
            
            function toggleEdit(originalName) {{
                const form = document.getElementById(`form-${{originalName}}`);
                form.style.display = form.style.display === 'none' ? 'block' : 'none';
            }}
            
            async function savePackage(originalName) {{
                const newName = document.getElementById(`input-${{originalName}}`).value.trim();
                if (!newName) {{
                    alert('Please enter a package name');
                    return;
                }}
                
                const statusDiv = document.getElementById(`status-${{originalName}}`);
                statusDiv.className = 'status-message status-loading';
                statusDiv.textContent = '⏳ Rescanning...';
                
                try {{
                    const response = await fetch('/api/packages/rescan', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            original_name: originalName,
                            new_name: newName
                        }})
                    }});
                    
                    if (!response.ok) throw new Error('Rescan failed');
                    
                    const result = await response.json();
                    
                    statusDiv.className = 'status-message status-success';
                    statusDiv.innerHTML = `✓ Updated! Found ${{result.cve_result.cves_found}} CVE(s). Reloading...`;
                    
                    setTimeout(() => loadPackages(), 2000);
                }} catch (error) {{
                    console.error('Error:', error);
                    statusDiv.className = 'status-message status-error';
                    statusDiv.textContent = '✕ Error: ' + error.message;
                }}
            }}
            
            async function markOk(originalName) {{
                // Just close the edit form and show success
                const item = document.getElementById(`pkg-${{originalName}}`);
                item.style.opacity = '0.6';
                setTimeout(() => {{
                    item.style.opacity = '1';
                }}, 500);
            }}
            
            // Fetch software list for selected host (no scanning)
            async function querySoftware() {{
                const hostname = document.getElementById('hostSelect').value;
                const tbody = document.getElementById('softwareBody');
                const loading = document.getElementById('loading');
                const softwareTable = document.getElementById('softwareTable');
                tbody.innerHTML = '';
                document.getElementById('scanResults').innerHTML = '';
                if (!hostname) {{
                    softwareTable.style.display = 'none';
                    return;
                }}
                loading.style.display = 'block';
                try {{
                    const resp = await fetch(`/api/scan-host?hostname=${{encodeURIComponent(hostname)}}`);
                    const data = await resp.json();
                    const packages = data.software || [];
                    const scanBtn = document.getElementById('scanSelectedBtn');
                    scanBtn.disabled = true;
                    if (packages.length === 0) {{
                        tbody.innerHTML = '<tr><td colspan="3">No packages found</td></tr>';
                    }} else {{
                        packages.forEach(pkg => {{
                            const safeId = pkg.name.replace(/[^a-z0-9_-]/gi, '_');
                            const row = `<tr>
                                <td><input type="checkbox" class="pkg-chk" data-name="${{pkg.name}}" id="chk-${{safeId}}"></td>
                                <td>${{pkg.name}}</td>
                                <td>${{pkg.version || 'N/A'}}</td>
                            </tr>`;
                            tbody.innerHTML += row;
                        }});
                        document.querySelectorAll('.pkg-chk').forEach(chk => {{
                            chk.addEventListener('change', () => {{
                                const any = Array.from(document.querySelectorAll('.pkg-chk')).some(c => c.checked);
                                scanBtn.disabled = !any;
                            }});
                        }});
                    }}
                    softwareTable.style.display = 'block';
                }} catch (err) {{
                    console.error('Error fetching software:', err);
                    tbody.innerHTML = '<tr><td colspan="3">Error loading packages</td></tr>';
                    document.getElementById('scanStatus').textContent = 'Error loading packages';
                }} finally {{
                    loading.style.display = 'none';
                }}
            }}

            function selectAll(state) {{
                document.querySelectorAll('.pkg-chk').forEach(c => c.checked = state);
                const scanBtn = document.getElementById('scanSelectedBtn');
                scanBtn.disabled = !state;
            }}

            async function scanSelected() {{
                const hostname = document.getElementById('hostSelect').value;
                if (!hostname) return alert('Select a host first');
                const checked = Array.from(document.querySelectorAll('.pkg-chk')).filter(c => c.checked).map(c => ({name: c.dataset.name}));
                if (checked.length === 0) return alert('No packages selected');

                const status = document.getElementById('scanStatus');
                status.textContent = 'Starting scan...';
                const scanResultsDiv = document.getElementById('scanResults');
                scanResultsDiv.innerHTML = '';

                try {{
                    const resp = await fetch('/api/scan-packages', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({ hostname: hostname, packages: checked })
                    }});
                    if (!resp.ok) throw new Error('Scan failed');
                    const result = await resp.json();

                    status.textContent = `Checked ${result.checked}, vulnerable: ${result.vulnerable_count}`;
                    if (result.vulnerable_packages && result.vulnerable_packages.length) {{
                        let html = '<h3>Vulnerable Packages</h3><ul>';
                        result.vulnerable_packages.forEach(v => {{
                            html += `<li><strong>${{v.name}}</strong> ${{v.version || ''}} — ${{v.cves_found}} CVE(s), CVSS max: ${{v.cvss_max}}</li>`;
                        }});
                        html += '</ul>';
                        scanResultsDiv.innerHTML = html;
                    }} else {{
                        scanResultsDiv.innerHTML = '<div style="color:green;">No vulnerabilities found for selected packages.</div>';
                    }}
                }} catch (err) {{
                    console.error(err);
                    status.textContent = 'Error during scan';
                    scanResultsDiv.innerHTML = '<div style="color:#d32f2f;">Scan failed.</div>';
                }}
            }}
            
            // Load packages when page loads
            document.addEventListener('DOMContentLoaded', loadPackages);
            
            // Refresh packages every 30 seconds
            setInterval(loadPackages, 30000);
        </script>
    </body>
    </html>
    """
    
    return html


def create_dashboard_route(app: FastAPI):
    """Add dashboard route to FastAPI app."""
    
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        """Render vulnerability dashboard."""
        return get_dashboard_html()
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Redirect root to dashboard."""
        return get_dashboard_html()
