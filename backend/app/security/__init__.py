"""
Security Subsystem [Role A]:
Vulnerability matching against curated security advisories and compromised packages.
Accurately identifies known supply-chain incidents without fabricating CVE IDs,
evaluates affected semver ranges, checks each package instance independently,
and explicitly distinguishes package presence from runtime execution proof.
"""

from typing import List, Dict, Any, Optional, Union, Tuple
from packaging.version import Version, InvalidVersion

# Curated registry of known compromised and vulnerable packages
CURATED_ADVISORIES: Dict[str, Dict[str, Any]] = {
    "event-stream": {
        "ecosystem": "npm",
        "affected_ranges": ["3.3.6"],
        "advisory_id": "GHSA-mh6f-8j2x-4483",
        "cve": None,  # No CVE assigned to this GitHub Security Advisory
        "classification": "vulnerability_compromised_package",
        "severity": "critical",
        "malicious_dependency": "flatmap-stream",
        "fixed_version": "4.0.0",
        "title": "Compromised Transitive Dependency via Malicious Maintainer Hijacking",
        "description": (
            "Package event-stream@3.3.6 was injected with malicious dependency flatmap-stream@0.1.1 "
            "designed to steal cryptocurrency keys from Copay Bitcoin wallet applications."
        ),
        "remediation_summary": "Upgrade event-stream to version 4.0.0 or remove flatmap-stream from lockfile.",
        "recommended_action": "Run `npm install event-stream@4.0.0` or remove event-stream."
    },
    "flatmap-stream": {
        "ecosystem": "npm",
        "affected_ranges": [">=0.0.0"],
        "advisory_id": "GHSA-mh6f-8j2x-4483",
        "exact_advisory_id": "GHSA-9x64-5r7x-2q53",
        "related_advisories": ["GHSA-9x64-5r7x-2q53"],
        "cve": None,
        "classification": "vulnerability_compromised_package",
        "severity": "critical",
        "malicious_dependency": None,
        "fixed_version": None,
        "title": "Malicious Cryptocurrency Wallet Stealing Package",
        "description": (
            "flatmap-stream was a deliberately malicious package published to target Copay Bitcoin "
            "wallets, injected into event-stream@3.3.6. Exact version 0.1.1 is tracked under "
            "GHSA-9x64-5r7x-2q53, while the broader compromised package advisory applies to all versions (>=0.0.0) "
            "under GHSA-mh6f-8j2x-4483."
        ),
        "remediation_summary": "Remove flatmap-stream completely from dependency tree.",
        "recommended_action": "Remove flatmap-stream completely from package.json/package-lock.json and upgrade or replace event-stream."
    },
    "jsonwebtoken": {
        "ecosystem": "npm",
        "affected_ranges": ["<=8.5.1"],
        "advisory_id": "GHSA-hjrf-2m68-5959",
        "cve": "CVE-2022-23541",
        "classification": "vulnerability_known_cve",
        "severity": "medium",
        "malicious_dependency": None,
        "fixed_version": "9.0.0",
        "title": "Insecure Key Verification in jsonwebtoken",
        "description": (
            "jsonwebtoken <=8.5.1 allows arbitrary code execution or key confusion "
            "when parsing crafted asymmetric keys (CVE-2022-23541)."
        ),
        "remediation_summary": "Upgrade jsonwebtoken to version 9.0.0 or higher.",
        "recommended_action": "Run `npm install jsonwebtoken@9.0.0`."
    }
}


def version_satisfies_range(version_str: str, range_rule: str) -> bool:
    """
    Evaluates whether version_str satisfies an affected semver range rule.
    Supports '<=8.5.1', '<9.0.0', '>=1.0.0', '==3.3.6', or exact version '3.3.6'.
    """
    clean_v = version_str.lstrip("v").lstrip("^").lstrip("~").strip()
    try:
        ver = Version(clean_v)
    except (InvalidVersion, TypeError):
        return clean_v == range_rule.strip()

    clauses = [c.strip() for c in range_rule.split(",") if c.strip()]
    for clause in clauses:
        if clause in ("*", ">=0", ">=0.0.0", ">=0.0"):
            continue
        if clause.startswith("<="):
            target = Version(clause[2:].lstrip("v").strip())
            if not (ver <= target):
                return False
        elif clause.startswith("<"):
            target = Version(clause[1:].lstrip("v").strip())
            if not (ver < target):
                return False
        elif clause.startswith(">="):
            target = Version(clause[2:].lstrip("v").strip())
            if not (ver >= target):
                return False
        elif clause.startswith(">"):
            target = Version(clause[1:].lstrip("v").strip())
            if not (ver > target):
                return False
        elif clause.startswith("=="):
            target = Version(clause[2:].lstrip("v").strip())
            if not (ver == target):
                return False
        else:
            try:
                target = Version(clause.lstrip("v").strip())
                if not (ver == target):
                    return False
            except InvalidVersion:
                if clean_v != clause:
                    return False
    return True


def check_vulnerabilities(
    packages: Union[Dict[str, str], List[Dict[str, Any]], List[Tuple[str, str]]],
    ecosystem: str = "npm",
    prefer_exact_advisory: bool = False
) -> List[Dict[str, Any]]:
    """
    Matches package instances against security advisories.
    Checks each package instance independently to support multiple installed versions
    without collapsing duplicates into a single mapping.
    Respects the supplied ecosystem argument.
    When prefer_exact_advisory=True, uses exact-version advisory IDs (e.g. GHSA-9x64 for flatmap-stream 0.1.1)
    rather than the broad incident advisory.
    """
    # Normalize input into a list of package items
    items: List[Dict[str, Any]] = []
    if isinstance(packages, dict):
        for name, version in packages.items():
            items.append({"name": name, "version": str(version), "path": f"node_modules/{name}"})
    elif isinstance(packages, list):
        for entry in packages:
            if isinstance(entry, dict):
                items.append({
                    "name": entry.get("name", ""),
                    "version": str(entry.get("version", "")),
                    "path": entry.get("path")
                })
            elif isinstance(entry, (tuple, list)) and len(entry) >= 2:
                items.append({
                    "name": str(entry[0]),
                    "version": str(entry[1]),
                    "path": str(entry[2]) if len(entry) > 2 else None
                })
            elif hasattr(entry, "name") and hasattr(entry, "version"):
                items.append({
                    "name": getattr(entry, "name"),
                    "version": str(getattr(entry, "version")),
                    "path": getattr(entry, "path", None)
                })

    findings: List[Dict[str, Any]] = []

    for item in items:
        pkg_name = item["name"]
        raw_version = item["version"]
        clean_version = raw_version.lstrip("v").lstrip("^").lstrip("~").strip()
        pkg_path = item.get("path")

        if pkg_name in CURATED_ADVISORIES:
            adv = CURATED_ADVISORIES[pkg_name]

            # Respect ecosystem
            if adv.get("ecosystem") != ecosystem:
                continue

            # Evaluate ranges
            is_vulnerable = any(
                version_satisfies_range(clean_version, r)
                for r in adv.get("affected_ranges", [])
            )

            if is_vulnerable:
                exact_adv_id = adv.get("exact_advisory_id")
                # Exact-version GHSA-9x64 applies specifically to version 0.1.1
                exact_applies = exact_adv_id is not None and (pkg_name != "flatmap-stream" or clean_version == "0.1.1")
                advisory_to_report = exact_adv_id if (prefer_exact_advisory and exact_applies) else adv["advisory_id"]

                finding = {
                    "package": pkg_name,
                    "version": clean_version,
                    "path": pkg_path,
                    "ecosystem": adv["ecosystem"],
                    "advisory_id": advisory_to_report,
                    "exact_advisory_id": exact_adv_id if exact_applies else None,
                    "related_advisories": adv.get("related_advisories", []),
                    "cve": adv["cve"],
                    "classification": adv["classification"],
                    "severity": adv["severity"],
                    "title": adv["title"],
                    "description": adv["description"],
                    "malicious_dependency": adv["malicious_dependency"],
                    "fixed_version": adv["fixed_version"],
                    "remediation": {
                        "summary": adv["remediation_summary"],
                        "recommended_action": adv["recommended_action"]
                    },
                    "execution_status": "presence_detected_unexecuted",
                    "execution_proof": False,
                    "evidence_note": (
                        f"Package '{pkg_name}@{clean_version}' was identified in static project declarations. "
                        "Static presence flags historical supply chain compromise; it does not indicate "
                        "that malicious bytecode has executed in the runtime environment."
                    )
                }
                findings.append(finding)

    return findings
