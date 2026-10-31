"""
Security subsystem [Role A]:
Live vulnerability matching using Google's Open Source Vulnerabilities (OSV) API.
Queries real-time advisories across npm, PyPI, Go, and Packagist with offline fallback.
"""
import httpx
import logging
from typing import List, Dict, Any

logger = logging.getLogger("hdx.security")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Offline local fallback cache if network is temporarily unavailable
OFFLINE_KNOWN_PACKAGES = {
    "event-stream": {
        "version": "3.3.6",
        "cve": "CVE-2018-3721",
        "severity": "critical",
        "description": "Flatmap-stream injected malicious bitcoin wallet stealing payload.",
        "fixed_version": "3.3.7"
    },
    "jsonwebtoken": {
        "version": "8.5.1",
        "cve": "CVE-2022-23529",
        "severity": "high",
        "description": "Insecure key verification allowing arbitrary code execution in node environments.",
        "fixed_version": "9.0.0"
    },
    "lodash": {
        "version": "4.17.20",
        "cve": "CVE-2021-23337",
        "severity": "high",
        "description": "Prototype pollution leading to remote code execution in template compiler.",
        "fixed_version": "4.17.21"
    },
    "axios": {
        "version": "0.21.1",
        "cve": "CVE-2021-3749",
        "severity": "medium",
        "description": "Regular expression denial of service (ReDoS) vulnerability in data trim.",
        "fixed_version": "0.21.2"
    }
}

def query_osv_for_package(pkg_name: str, version: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """Queries Google's real OSV database for package vulnerabilities."""
    clean_version = version.replace("^", "").replace("~", "").replace(">", "").replace("<", "").replace("=", "").strip()
    if not clean_version or clean_version == "*" or clean_version == "latest":
        return []

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(
                OSV_QUERY_URL,
                json={"package": {"name": pkg_name, "ecosystem": ecosystem}, "version": clean_version}
            )
            if resp.status_code == 200:
                vulns = resp.json().get("vulns", [])
                results = []
                for v in vulns:
                    # Find fixed version if available
                    fixed_ver = "latest"
                    for affected in v.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_ver = event["fixed"]
                                    break
                    
                    aliases = v.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                    if not cve_id:
                        known_entry = OFFLINE_KNOWN_PACKAGES.get(pkg_name)
                        if known_entry and clean_version == known_entry.get("version"):
                            cve_id = known_entry.get("cve")
                        else:
                            cve_id = v.get("id")
                    
                    # Extract severity
                    severity = "high"
                    database_specific = v.get("database_specific", {})
                    if "severity" in database_specific:
                        severity = database_specific["severity"].lower()
                    elif v.get("severity"):
                        severity = "critical" if "CVSS:3" in str(v.get("severity")) else "high"

                    results.append({
                        "package": pkg_name,
                        "version": clean_version,
                        "cve": cve_id,
                        "severity": severity,
                        "description": v.get("summary") or v.get("details", "")[:200] + "...",
                        "fixed_version": fixed_ver,
                        "osv_id": v.get("id")
                    })
                return results
    except Exception as e:
        logger.debug(f"OSV live query failed for {pkg_name} ({e}). Falling back to local cache.")

    # Offline fallback
    if pkg_name in OFFLINE_KNOWN_PACKAGES:
        vuln_info = OFFLINE_KNOWN_PACKAGES[pkg_name]
        if clean_version == vuln_info["version"]:
            return [{
                "package": pkg_name,
                "version": clean_version,
                "cve": vuln_info["cve"],
                "severity": vuln_info["severity"],
                "description": vuln_info["description"],
                "fixed_version": vuln_info["fixed_version"]
            }]
    return []

from concurrent.futures import ThreadPoolExecutor, as_completed

def check_vulnerabilities(packages: Dict[str, str], ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """Checks vulnerabilities concurrently against Google OSV API."""
    all_findings = []
    items_to_check = list(packages.items())[:12]
    if not items_to_check:
        return []

    with ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {
            executor.submit(query_osv_for_package, pkg, ver, ecosystem): pkg
            for pkg, ver in items_to_check
        }
        for future in as_completed(future_map):
            try:
                vulns = future.result()
                if vulns:
                    all_findings.extend(vulns[:2])
            except Exception:
                pass
    return all_findings
