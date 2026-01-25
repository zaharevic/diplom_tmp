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
        
        c.execute("SELECT COUNT(*) FROM software")
        software_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM cve_cache WHERE cves_found > 0")
        vulnerable_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(DISTINCT hostname) FROM reports")
        hosts_count = c.fetchone()[0]
        
        # Get recent reports
        c.execute("""
            SELECT id, hostname, ip, os, received_at 
            FROM reports 
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
                    <table>
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
                <div id="loading" style="display: none;">Loading...</div>
            </div>
            
            <div class="footer">
                <p>Vulnerability Collector • Last updated: {recent_reports[0]['received_at'] if recent_reports else 'N/A'}</p>
            </div>
        </div>
        
        <script>
            async function querySoftware() {{
                const hostname = document.getElementById('hostSelect').value;
                if (!hostname) {{
                    document.getElementById('softwareTable').style.display = 'none';
                    return;
                }}
                
                document.getElementById('loading').style.display = 'block';
                document.getElementById('softwareTable').style.display = 'none';
                
                try {{
                    const response = await fetch(`/api/software?hostname=${{hostname}}&limit=500`);
                    const data = await response.json();
                    
                    const tbody = document.getElementById('softwareBody');
                    tbody.innerHTML = '';
                    
                    if (data.software.length === 0) {{
                        tbody.innerHTML = '<tr><td colspan="2">No packages found</td></tr>';
                    }} else {{
                        data.software.forEach(pkg => {{
                            const row = `<tr>
                                <td>${{pkg.name}}</td>
                                <td>${{pkg.version || 'N/A'}}</td>
                            </tr>`;
                            tbody.innerHTML += row;
                        }});
                    }}
                    
                    document.getElementById('softwareTable').style.display = 'block';
                }} catch (error) {{
                    console.error('Error:', error);
                    alert('Error loading software data');
                }} finally {{
                    document.getElementById('loading').style.display = 'none';
                }}
            }}
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
