#!/usr/bin/env bash
# Auto-import EPSS and CISA KEV feeds and update local DB.
# Configure URLs below or set EPSS_URL and KEV_URL env vars.

set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DB=${1:-nvd_local.db}
EPSS_URL=${EPSS_URL:-https://api.first.org/data/v1/epss} # placeholder; FIRST provides multiple formats
KEV_URL=${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv}

# Ensure scripts are executable
PY=python3

echo "Starting auto-import: DB=$DB"

# Fetch EPSS: FIRST provides JSON API; script expects CSV/rows — prefer to store CSV locally or convert.
# If you have a CSV EPSS feed, pass it via --file. Otherwise, download a CSV first.
# Here we attempt to download a CSV if EPSS_URL points to one.

echo "Importing EPSS from $EPSS_URL"
if curl -sSfL "$EPSS_URL" -o /tmp/epss_download; then
    # try to detect if it's JSON containing data -> convert to CSV minimal
    if head -c 1 /tmp/epss_download | grep -q '{'; then
        # attempt to extract CVE and probability if present
        python3 - <<'PY'
import json,csv,sys
j=json.load(open('/tmp/epss_download'))
# FIRST EPSS API returns {'data': [{'cve':'CVE-XXXX','epss':0.123}, ...]}
rows=j.get('data') if isinstance(j,dict) else j
if not rows:
    sys.exit(0)
with open('/tmp/epss_parsed.csv','w',newline='') as f:
    w=csv.writer(f)
    w.writerow(['cve','epss'])
    for r in rows:
        c=r.get('cve') or r.get('cveID') or r.get('CVE')
        s=r.get('epss') or r.get('probability') or r.get('score')
        if c and s is not None:
            w.writerow([c,s])
PY
        /bin/mv /tmp/epss_parsed.csv /tmp/epss_download.csv || true
        $PY "$SCRIPT_DIR/import_epss.py" --db "$DB" --file /tmp/epss_download.csv || true
    else
        # assume it's CSV already
        $PY "$SCRIPT_DIR/import_epss.py" --db "$DB" --file /tmp/epss_download || true
    fi
else
    echo "Failed to download EPSS from $EPSS_URL"
fi

# Import CISA KEV CSV
echo "Importing CISA KEV from $KEV_URL"
if curl -sSfL "$KEV_URL" -o /tmp/kev_download.csv; then
    $PY "$SCRIPT_DIR/import_cisa_kev.py" --db "$DB" --file /tmp/kev_download.csv || true
else
    echo "Failed to download KEV from $KEV_URL"
fi

# Optionally compute risk for hosts if host_packages.json exists
if [ -f "$SCRIPT_DIR/host_packages.json" ]; then
    echo "Computing risk scores using host_packages.json and assets.json"
    $PY "$SCRIPT_DIR/compute_risk.py" --db "$DB" --host-packages "$SCRIPT_DIR/host_packages.json" --assets "$SCRIPT_DIR/assets.json" || true
else
    echo "host_packages.json not found; skipping compute_risk"
fi

echo "Auto-import completed"
