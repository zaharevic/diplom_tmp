"""
NVD (National Vulnerability Database) integration with caching.
Handles CVE lookups with smart caching (24h TTL) and package name normalization.
"""

import sqlite3
import os
import requests
import json
import re
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from contextlib import contextmanager

# Configure logging
logger = logging.getLogger(__name__)

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Global statistics for NVD queries
nvd_stats = {
    "total_queries": 0,
    "cached_hits": 0,
    "api_calls": 0,
    "total_cves_found": 0,
    "start_time": None,
}

# Rate limiting: minimum delay between API requests (seconds)
NVD_REQUEST_DELAY = 5  # 5 seconds between requests
last_nvd_request_time = 0.0  # Timestamp of last NVD API request

# Verbose logging toggle (set NVD_VERBOSE=1 in environment or .env)
VERBOSE_NVD = os.environ.get("NVD_VERBOSE", "").lower() not in ("", "0", "false", "no")


def wait_for_rate_limit():
    """
    Enforce rate limiting: wait until NVD_REQUEST_DELAY seconds have passed since last request.
    This prevents overwhelming the NVD API.
    """
    global last_nvd_request_time
    
    now = time.time()
    elapsed = now - last_nvd_request_time
    
    if elapsed < NVD_REQUEST_DELAY:
        wait_time = NVD_REQUEST_DELAY - elapsed
        logger.info(f"[RATE LIMIT] Waiting {wait_time:.1f}s before next NVD request (max {NVD_REQUEST_DELAY}s between requests)")
        time.sleep(wait_time)
    
    last_nvd_request_time = time.time()


def normalize_for_nvd(name: str) -> str:
    """
    Normalize package name for NVD API queries.
    Extracts core product name, removes versions, architectures, and suffixes.
    
    Examples:
    - "7-zip_25_01_x64" -> "7-zip"
    - "Java 8 Update 401 64-bit" -> "java"
    - "Microsoft Edge" -> "microsoft edge"
    - "Python 3.11" -> "python"
    """
    if not name:
        return ""
    
    # Convert to lowercase
    name = name.lower().strip()
    
    # Remove architecture qualifiers
    name = re.sub(r'\b(x86|x64|x86-64|i686|arm|arm64|amd64|ia64|32-?bit|64-?bit)\b', '', name)
    
    # Remove common suffixes/qualifiers: update, patch, redistrib*, runtime, etc.
    name = re.sub(r'\b(update|patch|redistributable|runtime|bin|src|source|alpha|beta|rc|hotfix|sp\d+)\b', '', name)
    
    # Remove version patterns: numbers after dash/underscore/space followed by numbers
    # e.g., "java_8_update_401", "_2024", "-v1.2.3"
    name = re.sub(r'[\s_-]v?\d+[\d._]*\b', '', name)
    
    # Remove version info in parentheses: (v1.0), (2024), etc.
    name = re.sub(r'\s*\([^)]*\d+[^)]*\)', '', name)
    
    # Clean up special chars but preserve spaces and dashes for readability
    # Replace most special chars with spaces, keep alphanumerics, dash, underscore
    name = re.sub(r'[^a-z0-9\s\-_]', ' ', name)
    
    # Replace underscores with spaces for better matching
    name = name.replace('_', ' ')
    
    # Remove extra whitespace
    name = ' '.join(name.split())
    
    # Keep only the first 2-3 meaningful words for better NVD matching
    # This helps by not sending overly specific package names
    words = name.split()
    if len(words) > 3:
        # For package names like "microsoft office ltsc 2024 ru" -> keep "microsoft office"
        # For "visual c 2010 x64 redistributable" -> keep "visual c"
        # Get first N words that are not suspicious version indicators
        core_words = []
        for word in words[:4]:
            # Skip if word looks like it might be a leftover version/arch (all numbers or too short)
            if word and len(word) > 1 and not word.isdigit():
                core_words.append(word)
        name = ' '.join(core_words[:3]) if core_words else words[0]
    
    # Final cleanup: strip and return
    name = name.strip()
    
    return name if name else "unknown"


def get_cpe_keywords(name: str) -> List[str]:
    """
    Generate MINIMAL search keywords for NVD (max 3-4).
    Prioritizes: normalized name, then first word, then specific product name if identifiable.
    """
    normalized = normalize_for_nvd(name)
    
    # Start with normalized name as primary keyword
    keywords = [normalized]
    
    # Add first word if multi-word (often the main product)
    words = normalized.split()
    if len(words) > 1:
        keywords.append(words[0])
    
    # Add ONE specific alternative if identifiable
    lower = name.lower()
    
    # Only add specific alternatives if they're meaningfully different from normalized
    if 'java' in lower and 'python' not in lower:
        if 'jre' not in normalized:
            keywords.append('jre')
    elif 'git' in lower and 'git' not in normalized:
        keywords.append('git-scm')
    elif '7' in lower and 'zip' in lower:
        if '7zip' not in normalized and '7-zip' not in normalized:
            keywords.append('7-zip')
    
    # Remove duplicates
    seen = set()
    result = []
    for kw in keywords:
        if kw and kw.lower() not in seen:
            seen.add(kw.lower())
            result.append(kw)
    
    # Hard limit: never more than 3 keywords
    return result[:3]


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
        
        Implements exponential backoff for 429 (Too Many Requests) errors.
        Stops trying keywords once CVEs are found to conserve API quota.
        """
        try:
            normalized = normalize_for_nvd(package_name)
            
            # Try multiple keyword variations (but stop after first success)
            keywords = get_cpe_keywords(package_name)
            all_cves = {}  # Use dict to avoid duplicates by CVE ID
            
            if not keywords:
                logger.debug(f"No valid keywords for package: {package_name}")
                return []
            
            # Enforce rate limiting: 5 second delay before first request
            wait_for_rate_limit()
            
            for keyword_idx, keyword in enumerate(keywords):
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 50,
                }
                if self.api_key:
                    params["apiKey"] = self.api_key
                
                # Exponential backoff for rate limiting
                max_retries = 3
                retry_delay = 1  # Start with 1 second
                
                for attempt in range(max_retries):
                    try:
                        logger.info(f"Querying NVD for: {keyword} (version: {version})")
                        resp = self.session.get(NVD_API_URL, params=params, timeout=10)

                        # Log request/response details when verbose logging enabled
                        try:
                            req_url = resp.request.url if resp is not None and hasattr(resp, 'request') else None
                        except Exception:
                            req_url = None
                        if req_url:
                            logger.debug(f"NVD request URL: {req_url}")
                        logger.debug(f"NVD response status: {getattr(resp, 'status_code', 'N/A')}")
                        if VERBOSE_NVD:
                            # Truncate large bodies
                            body = getattr(resp, 'text', '')
                            logger.debug(f"NVD response body (truncated 4000 chars): {body[:4000]}")

                        if resp.status_code == 429:
                            # Rate limited
                            if attempt < max_retries - 1:
                                logger.warning(
                                    f"NVD API rate limit hit for {keyword}, "
                                    f"waiting {retry_delay}s before retry (attempt {attempt+1}/{max_retries})"
                                )
                                time.sleep(retry_delay)
                                retry_delay *= 2  # Exponential backoff
                                continue
                            else:
                                logger.error(f"NVD API rate limit exceeded for {keyword} after {max_retries} retries")
                                # Don't break here, try next keyword
                                break
                        
                        resp.raise_for_status()
                        
                        data = resp.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        logger.debug(f"NVD API returned {len(vulnerabilities)} vulnerabilities for {keyword}")
                        
                        # Parse CVEs
                        for vuln in vulnerabilities:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "")
                            
                            if cve_id in all_cves:
                                continue  # Skip duplicates
                            
                            # Extract CVSS score (prefer V3 over V2)
                            cvss = 0
                            metrics = cve.get("metrics", {})
                            if metrics.get("cvssV3") and len(metrics["cvssV3"]) > 0:
                                cvss = metrics["cvssV3"][0].get("baseScore", 0)
                            elif metrics.get("cvssV2") and len(metrics["cvssV2"]) > 0:
                                cvss = metrics["cvssV2"][0].get("baseScore", 0)
                            
                            # Get description
                            descriptions = cve.get("descriptions", [])
                            description = ""
                            if descriptions:
                                # Find English description
                                for desc in descriptions:
                                    if desc.get("lang") == "en":
                                        description = desc.get("value", "")
                                        break
                                if not description and descriptions:
                                    description = descriptions[0].get("value", "")
                            
                            # Parse affected versions from configurations
                            affected_versions = []
                            configurations = cve.get("configurations", [])
                            for config in configurations:
                                nodes = config.get("nodes", [])
                                for node in nodes:
                                    cpe_matches = node.get("cpeMatch", [])
                                    for cpe_match in cpe_matches:
                                        cpe = cpe_match.get("criteria", "")
                                        # Check if this CPE relates to our package
                                        if package_name.lower() in cpe.lower() or keyword.lower() in cpe.lower():
                                            version_start = cpe_match.get("versionStartIncluding")
                                            version_end = cpe_match.get("versionEndIncluding")
                                            version_start_exc = cpe_match.get("versionStartExcluding")
                                            version_end_exc = cpe_match.get("versionEndExcluding")
                                            
                                            affected_versions.append({
                                                "start": version_start,
                                                "end": version_end,
                                                "start_exc": version_start_exc,
                                                "end_exc": version_end_exc,
                                            })
                            
                            # Include CVE
                            all_cves[cve_id] = {
                                "id": cve_id,
                                "description": description,
                                "cvss": cvss,
                                "affected_versions": affected_versions,
                                "published": cve.get("published", ""),
                            }
                        
                        # Success, break retry loop
                        break
                    
                    except requests.exceptions.RequestException as e:
                        # Try to log response body if available
                        resp_text = None
                        try:
                            resp_text = e.response.text if hasattr(e, 'response') and e.response is not None else None
                        except Exception:
                            resp_text = None
                        logger.error(f"Error querying NVD API for {keyword}: {e}")
                        if VERBOSE_NVD and resp_text:
                            logger.debug(f"NVD error response body (truncated): {resp_text[:4000]}")
                        if "429" not in str(e):
                            break
                        # For 429, retry logic above handles it
                
                # *** KEY FIX: Stop trying keywords if we found CVEs ***
                if all_cves:
                    logger.debug(f"Found {len(all_cves)} CVEs with keyword '{keyword}', stopping search")
                    break
            
            logger.debug(f"Total unique CVEs found for {package_name}: {len(all_cves)}")
            return list(all_cves.values())[:50]  # Return top 50
        
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
        # Initialize stats on first call
        if nvd_stats["start_time"] is None:
            nvd_stats["start_time"] = time.time()
        
        nvd_stats["total_queries"] += 1
        
        # Check cache first
        if self.cache.is_cached_and_fresh(package_name, version):
            cached_result = self.cache.get_cached_result(package_name, version)
            nvd_stats["cached_hits"] += 1
            nvd_stats["total_cves_found"] += cached_result["cves_found"]
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
        nvd_stats["api_calls"] += 1
        cves = self._query_nvd_api(package_name, version)
        nvd_stats["total_cves_found"] += len(cves)
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

def get_nvd_stats():
    """Get NVD API statistics."""
    return nvd_stats.copy()


def print_nvd_log_summary():
    """Print summary of NVD API usage."""
    stats = nvd_stats
    
    if stats["start_time"] is None:
        return
    
    elapsed = time.time() - stats["start_time"]
    
    print("\n" + "="*70)
    print("NVD API STATISTICS")
    print("="*70)
    print(f"Total queries:        {stats['total_queries']}")
    print(f"Cache hits:           {stats['cached_hits']} ({stats['cached_hits']*100//max(1, stats['total_queries'])}%)")
    print(f"API calls:            {stats['api_calls']}")
    print(f"Total CVEs found:     {stats['total_cves_found']}")
    print(f"Elapsed time:         {elapsed:.2f}s")
    if stats['api_calls'] > 0:
        print(f"Avg CVEs per call:    {stats['total_cves_found']/stats['api_calls']:.1f}")
    print("="*70 + "\n")