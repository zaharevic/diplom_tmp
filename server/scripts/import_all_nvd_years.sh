#!/usr/bin/env bash
# Batch import NVD year feeds (2002..current year) and the modified feed.
# Usage: ./scripts/import_all_nvd_years.sh [start_year] [end_year]
# Example: ./scripts/import_all_nvd_years.sh 2002 2026
set -euo pipefail
START=${1:-2002}
END=${2:-$(date +%Y)}
DB=${3:-nvd_local.db}
SCRIPTDIR=$(cd "$(dirname "$0")" && pwd)
PY=python3

echo "Importing NVD feeds into $DB from $START to $END"
for year in $(seq $START $END); do
    URL="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.json.gz"
    echo "-> Importing year $year from $URL"
    $PY "$SCRIPTDIR/nvd_import_full.py" --feed-url "$URL" --db "$DB"
done

# Import the modified feed last
MODURL="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
echo "-> Importing modified feed from $MODURL"
$PY "$SCRIPTDIR/nvd_update_modified.py" --url "$MODURL" --db "$DB"

echo "All imports completed into $DB"
