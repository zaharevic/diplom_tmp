"""
NVD (National Vulnerability Database) integration with caching.
Handles CVE lookups with smart caching (24h TTL) and package name normalization.
"""

import sqlite3
import requests
import json
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from contextlib import contextmanager

# Configure logging
logger = logging.getLogger(__name__)

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalize_for_nvd(name: str) -> str:
    """
    Normalize package name for NVD API queries.
    NVD expects lowercase, alphanumeric + dash/underscore format.
    
    Examples:
    - "Python" -> "python"
    - "Microsoft Visual Studio" -> "visual_studio" or lookup mapping
    - "Lib@$h" -> "libh"
    """
    if not name:
        return ""
    
    # Convert to lowercase
    name = name.lower().strip()
    
    # Remove/replace common non-alphanumeric chars
    # Keep only letters, numbers, dash, underscore
    name = re.sub(r"[^a-z0-9\-_]", "_", name)
    
    # Remove trailing/leading underscores and dashes
    name = name.strip("_-")
    
    # Collapse multiple underscores
    name = re.sub(r"_+", "_", name)
    
    return name


def get_cpe_keywords(name: str) -> List[str]:
    """
    Generate alternative search keywords for NVD.
    Some packages have different names in NVD (e.g., "Python" vs "python", "OpenSSL" vs "openssl").
    """
    keywords = [normalize_for_nvd(name)]
    
    # Add common variations
    if "python" in keywords[0]:
        keywords.extend(["python", "cpython"])
    if "open" in keywords[0] and "ssl" in keywords[0]:
        keywords.extend(["openssl"])
    if "visual" in keywords[0] and "studio" in keywords[0]:
        keywords.append("visual_studio_code")
    
    return list(set(keywords))  # Remove duplicates


class NVDCache:
    """SQLite-based cache for NVD API queries with 24-hour TTL."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    @contextmanager
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize CVE cache table."""
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    version TEXT,
                    queried_at TEXT NOT NULL,
                    cves_found INTEGER DEFAULT 0,
                    cvss_max REAL,
                    cve_data TEXT,
                    UNIQUE(package_name, version)
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_name ON cve_cache(normalized_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_queried ON cve_cache(queried_at)")
            conn.commit()
    
    def is_cached_and_fresh(self, package_name: str, version: str = None) -> bool:
        """
        Check if package is in cache and within 24-hour TTL.
        Returns True if found and <24h old.
        """
        with self._get_conn() as conn:
            c = conn.cursor()
            query = "SELECT queried_at FROM cve_cache WHERE package_name = ?"
            params = [package_name]
            
            if version:
                query += " AND version = ?"
                params.append(version)
            
            c.execute(query, params)
            row = c.fetchone()
            
            if not row:
                return False
            
            queried_at = datetime.fromisoformat(row[0])
            age = datetime.now(timezone.utc) - queried_at
            return age < timedelta(hours=24)
    
    def get_cached_result(self, package_name: str, version: str = None) -> Optional[Dict]:
        """Get cached CVE data for package."""
        with self._get_conn() as conn:
            c = conn.cursor()
            query = "SELECT cves_found, cvss_max, cve_data FROM cve_cache WHERE package_name = ?"
            params = [package_name]
            
            if version:
                query += " AND version = ?"
                params.append(version)
            
            c.execute(query, params)
            row = c.fetchone()
            
            if not row:
                return None
            
            cve_data = json.loads(row[2]) if row[2] else []
            return {
                "cves_found": row[0],
                "cvss_max": row[1],
                "cves": cve_data,
            }
    
    def cache_result(self, package_name: str, version: str, cves: List[Dict]):
        """Store CVE query result in cache."""
        cvss_max = max([cve.get("cvss", 0) for cve in cves], default=0)
        cve_data = json.dumps(cves, ensure_ascii=False)
        
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT OR REPLACE INTO cve_cache 
                (package_name, normalized_name, version, queried_at, cves_found, cvss_max, cve_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    package_name,
                    normalize_for_nvd(package_name),
                    version,
                    datetime.now(timezone.utc).isoformat(),
                    len(cves),
                    cvss_max,
                    cve_data,
                ),
            )
            conn.commit()


class NVDClient:
    """NVD API client with caching support."""
    
    def __init__(self, db_path: str, api_key: Optional[str] = None):
        self.cache = NVDCache(db_path)
        self.api_key = api_key
        self.session = requests.Session()
    
    def _query_nvd_api(self, package_name: str, version: str = None) -> List[Dict]:
        """
        Query NVD API for CVEs matching package name and version.
        Returns list of CVE objects with CVSS scores.
        """
        try:
            normalized = normalize_for_nvd(package_name)
            
            # Try multiple keyword variations
            keywords = get_cpe_keywords(package_name)
            all_cves = []
            
            for keyword in keywords:
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 100,
                }
                if self.api_key:
                    params["apiKey"] = self.api_key
                
                logger.info(f"Querying NVD for: {keyword} (version: {version})")
                resp = self.session.get(NVD_API_URL, params=params, timeout=10)
                resp.raise_for_status()
                
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                logger.debug(f"NVD API returned {len(vulnerabilities)} vulnerabilities for {keyword}")
                
                # Parse CVEs and extract version-matching ones
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    
                    # Extract CVSS score
                    cvss = 0
                    metrics = cve.get("metrics", {})
                    if metrics.get("cvssV3"):
                        cvss = metrics["cvssV3"][0].get("baseScore", 0)
                    elif metrics.get("cvssV2"):
                        cvss = metrics["cvssV2"][0].get("baseScore", 0)
                    
                    # Parse affected versions
                    affected_versions = []
                    configurations = cve.get("configurations", [])
                    for config in configurations:
                        nodes = config.get("nodes", [])
                        for node in nodes:
                            cpe_matches = node.get("cpeMatch", [])
                            for cpe_match in cpe_matches:
                                cpe = cpe_match.get("criteria", "")
                                if keyword.lower() in cpe.lower():
                                    versions = cpe_match.get("versionStartIncluding"), cpe_match.get("versionEndIncluding")
                                    affected_versions.append({
                                        "start": versions[0],
                                        "end": versions[1],
                                    })
                    
                    if affected_versions or not version:  # Include if version info available or no version specified
                        all_cves.append({
                            "id": cve_id,
                            "description": cve.get("descriptions", [{}])[0].get("value", ""),
                            "cvss": cvss,
                            "affected_versions": affected_versions,
                            "published": cve.get("published", ""),
                        })
            
            return all_cves[:50]  # Return top 50
        
        except Exception as e:
            logger.error(f"Error querying NVD API for {package_name}: {e}")
            return []
    
    def check_package(self, package_name: str, version: str = None) -> Dict:
        """
        Check package for CVEs.
        Uses cache if available and <24h old, otherwise queries NVD API.
        
        Returns: {
            "package": package_name,
            "version": version,
            "cached": bool,
            "cves_found": int,
            "cvss_max": float,
            "cves": [ {...cve details...} ],
            "vulnerable": bool,
        }
        """
        # Check cache first
        if self.cache.is_cached_and_fresh(package_name, version):
            cached_result = self.cache.get_cached_result(package_name, version)
            return {
                "package": package_name,
                "version": version,
                "cached": True,
                "cves_found": cached_result["cves_found"],
                "cvss_max": cached_result["cvss_max"],
                "cves": cached_result["cves"],
                "vulnerable": cached_result["cves_found"] > 0,
            }
        
        # Query NVD API
        cves = self._query_nvd_api(package_name, version)
        self.cache.cache_result(package_name, version or "", cves)
        
        cvss_max = max([cve.get("cvss", 0) for cve in cves], default=0)
        
        return {
            "package": package_name,
            "version": version,
            "cached": False,
            "cves_found": len(cves),
            "cvss_max": cvss_max,
            "cves": cves,
            "vulnerable": len(cves) > 0,
        }
