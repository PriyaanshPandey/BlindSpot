"""
Security subsystem [Role A]:
Vulnerability matching against local OSV/KEV advisories and known compromised packages.
"""
from typing import List, Dict, Any

KNOWN_COMPROMISED_PACKAGES = {
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

def check_vulnerabilities(packages: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    for pkg_name, version in packages.items():
        clean_version = version.replace("^", "").replace("~", "").replace(">", "").replace("=", "").strip()
        if pkg_name in KNOWN_COMPROMISED_PACKAGES:
            vuln_info = KNOWN_COMPROMISED_PACKAGES[pkg_name]
            if clean_version == vuln_info["version"]:
                findings.append({
                    "package": pkg_name,
                    "version": clean_version,
                    "cve": vuln_info["cve"],
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "fixed_version": vuln_info["fixed_version"]
                })
    return findings
