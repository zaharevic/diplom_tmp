# PowerShell script to batch import NVD year feeds and modified feed
param(
    [int]$StartYear = 2002,
    [int]$EndYear = (Get-Date).Year,
    [string]$Db = 'nvd_local.db'
)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$python = 'python3'

Write-Host "Importing NVD feeds into $Db from $StartYear to $EndYear"
for ($y = $StartYear; $y -le $EndYear; $y++) {
    $url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
    Write-Host "-> Importing year $y from $url"
    & $python "$scriptDir\nvd_import_full.py" --feed-url $url --db $Db
}

$modUrl = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz'
Write-Host "-> Importing modified feed from $modUrl"
& $python "$scriptDir\nvd_update_modified.py" --url $modUrl --db $Db

Write-Host "All imports completed into $Db"
