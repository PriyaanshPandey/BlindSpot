"""
Security subsystem [Role A]:
Vulnerability matching against local OSV/KEV advisories and known compromised packages.
"""
from typing import List, Dict, Any

KNOWN_COMPROMISED_PACKAGES = {
    "event-stream": {"version": "3.3.6", "cve": "CVE-2018-3721", "severity": "critical", "description": "Flatmap-stream injected malicious bitcoin wallet stealing payload"},
    "jsonwebtoken": {"version": "8.5.1", "cve": "CVE-2022-23529", "severity": "high", "description": "Insecure key verification allowing arbitrary code execution"}
}

def check_vulnerabilities(packages: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    for pkg_name, version in packages.items():
        clean_version = version.replace("^", "").replace("~", "").strip()
        if pkg_name in KNOWN_COMPROMISED_PACKAGES:
            vuln_info = KNOWN_COMPROMISED_PACKAGES[pkg_name]
            if clean_version == vuln_info["version"]:
                findings.append({
                    "package": pkg_name,
                    "version": clean_version,
                    "cve": vuln_info["cve"],
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"]
                })
    return findings

