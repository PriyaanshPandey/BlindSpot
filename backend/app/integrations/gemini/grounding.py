"""
Authoritative Grounding & Validation Layer for BlindSpot Gemini AI.
Ensures Gemini explanations are anchored strictly in deterministic scanner intelligence
and authoritative vulnerability databases (OSV, NVD, GitHub Advisory Database).
"""
import re
from typing import Dict, Any, List, Optional, Tuple
from packaging.version import parse as parse_version, InvalidVersion

# Canonical authoritative advisory registry for core packages and fixtures
CANONICAL_ADVISORIES: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("axios", "CVE-2020-28168"): {
        "package": "axios",
        "cve_id": "CVE-2020-28168",
        "aliases": ["GHSA-42xw-2xvc-rh8d"],
        "affected_range": "< 0.21.1",
        "fixed_version": "0.21.1",
        "severity": "critical",
        "cvss_score": 7.8,
        "advisory_source": "Google OSV / GitHub Advisory Database",
        "description": "Axios up to 0.21.0 allows Server-Side Request Forgery (SSRF) and header leakage via cross-origin redirects. Fixed in 0.21.1."
    },
    ("axios", "CVE-2021-3749"): {
        "package": "axios",
        "cve_id": "CVE-2021-3749",
        "aliases": ["GHSA-cph5-m8f7-6c5x"],
        "affected_range": "<= 0.21.1",
        "fixed_version": "0.21.2",
        "severity": "medium",
        "cvss_score": 5.3,
        "advisory_source": "Google OSV / NVD",
        "description": "Regular expression denial of service (ReDoS) vulnerability in data trim in axios <= 0.21.1. Fixed in 0.21.2."
    },
    ("lodash", "CVE-2021-23337"): {
        "package": "lodash",
        "cve_id": "CVE-2021-23337",
        "aliases": ["GHSA-35jh-r3h4-6jhm"],
        "affected_range": "< 4.17.21",
        "fixed_version": "4.17.21",
        "severity": "high",
        "cvss_score": 7.2,
        "advisory_source": "Google OSV / NVD",
        "description": "Command injection vulnerability in lodash template function before version 4.17.21. Fixed in 4.17.21."
    },
    ("jsonwebtoken", "CVE-2022-23529"): {
        "package": "jsonwebtoken",
        "cve_id": "CVE-2022-23529",
        "aliases": ["GHSA-qwph-4952-7xr6"],
        "affected_range": "<= 8.5.1",
        "fixed_version": "9.0.0",
        "severity": "high",
        "cvss_score": 7.6,
        "advisory_source": "Google OSV / GitHub Advisory Database",
        "description": "Insecure key verification in jsonwebtoken <= 8.5.1 allowing arbitrary code execution when untrusted keys are parsed. Fixed in 9.0.0."
    },
    ("event-stream", "CVE-2018-3721"): {
        "package": "event-stream",
        "cve_id": "CVE-2018-3721",
        "aliases": ["GHSA-4598-rh5w-9p43"],
        "affected_range": ">= 3.3.6, <= 3.3.6",
        "fixed_version": "3.3.7",
        "severity": "critical",
        "cvss_score": 9.8,
        "advisory_source": "Google OSV / npm Security Advisory",
        "description": "Malicious code injected via flatmap-stream targeting Copay bitcoin wallets. Fixed by removing dependency in 3.3.7."
    },
    ("flatmap-stream", "MAL-2018-001"): {
        "package": "flatmap-stream",
        "cve_id": "MAL-2018-001",
        "aliases": ["GHSA-5g6c-m655-75gk"],
        "affected_range": "*",
        "fixed_version": None,
        "severity": "critical",
        "cvss_score": 10.0,
        "advisory_source": "npm Security Advisory",
        "description": "Completely malicious package. Must be removed; no safe fixed release exists."
    }
}

CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
VERSION_RECOMMEND_REGEX = re.compile(r'(?:upgrade|update|install|to)\s+(?:version\s+|v)?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)


def clean_version_str(ver_raw: str) -> str:
    """Strips semver ranges and whitespace to extract base version."""
    return str(ver_raw).replace("^", "").replace("~", "").replace(">=", "").replace("<=", "").replace(">", "").replace("<", "").replace("=", "").strip()


def resolve_authoritative_advisory(
    package_name: str,
    installed_version: str,
    cve_id: Optional[str] = None,
    provided_details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Deterministically resolves authoritative advisory details for a package version.
    Determines whether the installed version is actually vulnerable or already fixed.
    """
    clean_pkg = package_name.lower().replace("pkg:trans:", "").replace("pkg:", "").replace("ext:", "").strip()
    clean_ver = clean_version_str(installed_version)

    # 1. Check Canonical Advisories by (package, cve_id)
    canonical = None
    if cve_id:
        canonical = CANONICAL_ADVISORIES.get((clean_pkg, cve_id.upper()))
        if not canonical:
            # Check by package alone if single CVE exists
            for (p, c), adv in CANONICAL_ADVISORIES.items():
                if p == clean_pkg and (c == cve_id.upper() or cve_id.upper() in [a.upper() for a in adv.get("aliases", [])]):
                    canonical = adv
                    break

    # 2. Extract from provided_details or offline database
    if not canonical:
        from app.security import OFFLINE_KNOWN_PACKAGES
        offline_entry = OFFLINE_KNOWN_PACKAGES.get(clean_pkg)
        if offline_entry and (not cve_id or cve_id.upper() == offline_entry.get("cve", "").upper()):
            canonical = {
                "package": clean_pkg,
                "cve_id": offline_entry.get("cve"),
                "aliases": [],
                "affected_range": f"<= {offline_entry.get('version')}",
                "fixed_version": offline_entry.get("fixed_version"),
                "severity": offline_entry.get("severity", "high"),
                "cvss_score": 9.8 if offline_entry.get("severity") == "critical" else 7.5,
                "advisory_source": "BlindSpot Local Security Database",
                "description": offline_entry.get("description", "Vulnerability detected in package.")
            }

    # 3. Incorporate explicitly provided security details if caller passed them
    prov = provided_details or {}
    eff_cve = cve_id or (canonical.get("cve_id") if canonical else prov.get("cve_id"))
    eff_fixed = prov.get("fixed_version") or (canonical.get("fixed_version") if canonical else None)
    eff_range = prov.get("affected_version_range") or (canonical.get("affected_range") if canonical else None)
    eff_sev = prov.get("severity") or (canonical.get("severity") if canonical else "medium")
    eff_cvss = prov.get("cvss_score") or (canonical.get("cvss_score") if canonical else None)
    eff_source = prov.get("advisory_source") or (canonical.get("advisory_source") if canonical else "Authoritative Scanner Intelligence")
    eff_desc = prov.get("advisory_description") or (canonical.get("description") if canonical else prov.get("description", ""))

    # 4. Check for unverified or incorrect CVE
    if cve_id and canonical is None and not prov.get("cve_id"):
        # The caller supplied an unrecognized CVE for this package
        return {
            "package_name": clean_pkg,
            "installed_version": clean_ver,
            "cve_id": cve_id,
            "aliases": [],
            "affected_version_range": "unverified",
            "fixed_version": None,
            "severity": eff_sev,
            "cvss_score": eff_cvss,
            "advisory_source": "Unverified Source",
            "advisory_description": f"No authoritative advisory found for {clean_pkg} matching '{cve_id}'. Verification is required.",
            "is_verified_vulnerable": False,
            "verification_status": "UNVERIFIED_ADVISORY",
            "unverified_notes": f"Advisory {cve_id} is unconfirmed for package {clean_pkg}. Verification with authoritative registry is required."
        }

    # 5. Check if fixed version is missing (e.g. 0-day or no published fix)
    if not eff_fixed or eff_fixed in ["None", "REMOVED", "unverified"]:
        is_vuln = True
        return {
            "package_name": clean_pkg,
            "installed_version": clean_ver,
            "cve_id": eff_cve,
            "aliases": canonical.get("aliases", []) if canonical else [],
            "affected_version_range": eff_range or "all versions",
            "fixed_version": None,
            "severity": eff_sev,
            "cvss_score": eff_cvss,
            "advisory_source": eff_source,
            "advisory_description": eff_desc,
            "is_verified_vulnerable": is_vuln,
            "verification_status": "MISSING_FIX_INFORMATION",
            "unverified_notes": "No authoritative fixed version is currently published. Maintainer verification is required before taking remediation action."
        }

    # 6. Semver comparison between installed version and fixed version
    is_vulnerable = True
    verification_status = "VERIFIED_VULNERABLE"
    unverified_notes = None

    try:
        inst_parsed = parse_version(clean_ver)
        fixed_parsed = parse_version(clean_version_str(eff_fixed))

        if inst_parsed >= fixed_parsed:
            # Package version is already at or above the fixed version!
            is_vulnerable = False
            verification_status = "ALREADY_FIXED"
            unverified_notes = f"Installed version {clean_ver} meets or exceeds authoritative fixed version {eff_fixed}. It is not affected."
        else:
            is_vulnerable = True
            verification_status = "VERIFIED_VULNERABLE"
    except (InvalidVersion, Exception):
        # Fallback to string equality if not semver
        if clean_ver == eff_fixed:
            is_vulnerable = False
            verification_status = "ALREADY_FIXED"
        else:
            is_vulnerable = True
            verification_status = "VERIFIED_VULNERABLE"

    return {
        "package_name": clean_pkg,
        "installed_version": clean_ver,
        "cve_id": eff_cve,
        "aliases": canonical.get("aliases", []) if canonical else [],
        "affected_version_range": eff_range or (f"< {eff_fixed}" if eff_fixed else "unverified"),
        "fixed_version": eff_fixed,
        "severity": eff_sev,
        "cvss_score": eff_cvss or (9.8 if eff_sev == "critical" else 7.5),
        "advisory_source": eff_source,
        "advisory_description": eff_desc,
        "is_verified_vulnerable": is_vulnerable,
        "verification_status": verification_status,
        "unverified_notes": unverified_notes
    }


def validate_and_ground_explanation(
    gemini_data: Dict[str, Any],
    authoritative: Dict[str, Any],
    audience: str = "builder"
) -> Dict[str, Any]:
    """
    Post-Generation Validation Layer:
    Compares Gemini's output against the authoritative scanner ground truth.
    Flags and rejects hallucinated CVEs, contradicted version claims, and unverified upgrade paths.
    """
    pkg = authoritative["package_name"]
    inst_ver = authoritative["installed_version"]
    auth_cve = authoritative["cve_id"]
    auth_fixed = authoritative["fixed_version"]
    auth_range = authoritative["affected_version_range"]
    is_vuln = authoritative["is_verified_vulnerable"]
    status = authoritative["verification_status"]

    validation_flags: List[str] = []
    unsupported_claims: List[str] = []

    raw_summary = str(gemini_data.get("summary", "")).strip()
    raw_why = str(gemini_data.get("why_it_matters", "")).strip()
    raw_tech = str(gemini_data.get("technical_impact", "")).strip()
    raw_steps = list(gemini_data.get("safe_remediation_steps", []))

    all_text = f"{raw_summary} {raw_why} {raw_tech} {' '.join(str(s) for s in raw_steps)}"

    # Check 1: Hallucinated / Extra CVEs
    mentioned_cves = set(m.upper() for m in CVE_REGEX.findall(all_text))
    allowed_cves = {auth_cve.upper()} if auth_cve else set()
    for alias in authoritative.get("aliases", []):
        allowed_cves.add(alias.upper())

    hallucinated_cves = mentioned_cves - allowed_cves
    if hallucinated_cves:
        for bad_cve in hallucinated_cves:
            flag = f"HALLUCINATED_CVE: '{bad_cve}' mentioned in AI output but absent from authoritative advisory."
            validation_flags.append(flag)
            unsupported_claims.append(f"AI referenced unverified vulnerability identifier {bad_cve}.")
            # Redact from summary and why_it_matters
            raw_summary = re.sub(re.escape(bad_cve), f"[UNVERIFIED_CVE: {bad_cve}]", raw_summary, flags=re.IGNORECASE)
            raw_why = re.sub(re.escape(bad_cve), f"[UNVERIFIED_CVE: {bad_cve}]", raw_why, flags=re.IGNORECASE)

    # Check 2: Unverified Advisory / Non-existent CVE
    if status == "UNVERIFIED_ADVISORY":
        validation_flags.append(f"UNVERIFIED_ADVISORY_DETECTED: Advisory {auth_cve} not found in authoritative vulnerability databases.")
        unsupported_claims.append(f"Advisory {auth_cve} cannot be verified against authoritative security databases.")
        raw_summary = f"Advisory {auth_cve} for package '{pkg}@{inst_ver}' could not be verified in authoritative security databases. Verification is required before taking action."
        raw_why = "Proceeding with unverified advisory information risks applying breaking dependency changes or introducing regressions."
        raw_steps = [
            f"Review package repository for '{pkg}' to verify if advisory {auth_cve} exists.",
            "Cross-reference CVE databases (NVD, OSV, GitHub Advisory Database).",
            "Do not alter production dependencies until the vulnerability is confirmed."
        ]

    # Check 3: Contradicting Version Status (Package is ALREADY FIXED)
    elif status == "ALREADY_FIXED" or not is_vuln:
        # Check if AI claims the installed version is vulnerable or advises upgrading
        claims_vuln = any(kw in raw_summary.lower() for kw in [
            f"{inst_ver} is vulnerable",
            f"{inst_ver} is affected",
            f"allows attacker",
            "upgrade to",
            "recommends upgrading"
        ])

        if claims_vuln:
            validation_flags.append(f"CONTRADICTION_DETECTED: AI treated version {inst_ver} as vulnerable, but authoritative advisory states it was fixed in {auth_fixed}.")
            unsupported_claims.append(f"AI claimed version {inst_ver} is vulnerable. Authoritative record confirms it is already fixed in {auth_fixed}.")

        # Enforce authoritative truth in summary
        grounded_summary = (
            f"Authoritative security intelligence ({authoritative['advisory_source']}) verifies that "
            f"'{pkg}@{inst_ver}' is ALREADY PATCHED against {auth_cve}. "
            f"The affected range was {auth_range}, and {auth_fixed} is the first safe fixed release."
        )
        grounded_why = (
            f"Your scanned version ({inst_ver}) satisfies or exceeds the minimum fixed version ({auth_fixed}). "
            f"No runtime exposure exists from {auth_cve} in this environment."
        )
        grounded_steps = [
            f"Verify that package.json and package-lock.json retain '{pkg}' at version >={auth_fixed}.",
            f"Reference official advisory {auth_cve} in security audit logs to confirm compliance.",
            "No code modifications or version bumps are required for this finding."
        ]
        raw_summary = grounded_summary
        raw_why = grounded_why
        raw_steps = grounded_steps

    # Check 4: Missing Fixed Version (0-day or unpatched)
    elif status == "MISSING_FIX_INFORMATION":
        # Ensure AI didn't invent an arbitrary fixed version
        invented_versions = []
        for step in raw_steps:
            for match in VERSION_RECOMMEND_REGEX.findall(str(step)):
                if match not in [inst_ver, "0.0.0"]:
                    invented_versions.append(match)

        if invented_versions:
            validation_flags.append(f"INVENTED_FIX_VERSION: AI suggested upgrading to unverified versions ({', '.join(invented_versions)}) when no fixed release is published.")
            unsupported_claims.append(f"AI recommended upgrading to unverified release {', '.join(invented_versions)}.")

        raw_steps = [
            f"No authoritative fixed release has been published for {auth_cve}.",
            "Maintainer verification and manual architectural isolation (e.g. circuit breaker or firewall) are required.",
            "Monitor upstream repository for an official patch release."
        ]

    # Check 5: Unsupported Upgrade Version Recommendation for Vulnerable Package
    elif is_vuln and auth_fixed:
        recommended_versions = []
        for step in raw_steps:
            for match in VERSION_RECOMMEND_REGEX.findall(str(step)):
                if match not in [inst_ver, auth_fixed]:
                    recommended_versions.append(match)

        if recommended_versions:
            validation_flags.append(f"UNSUPPORTED_UPGRADE_VERSION: AI recommended version {', '.join(recommended_versions)} differing from authoritative fixed version {auth_fixed}.")
            unsupported_claims.append(f"AI suggested version {', '.join(recommended_versions)} instead of authoritative fix {auth_fixed}.")
            # Correct remediation steps to enforce the authoritative fixed version
            raw_steps = [
                f"Upgrade '{pkg}' to the authoritative fixed release {auth_fixed} (or higher) using your package manager.",
                f"Verify that your build and automated test suites pass after upgrading {pkg}.",
                f"Audit dependencies to confirm {auth_cve} is no longer flagged by the scanner."
            ]

    # Clearly distinguish:
    # 1. Verified scanner finding
    # 2. AI-generated explanation
    # 3. AI-generated inference
    # 4. Unverified information
    verified_finding = {
        "package_name": pkg,
        "installed_version": inst_ver,
        "cve_id": auth_cve,
        "severity": authoritative["severity"],
        "affected_version_range": auth_range,
        "fixed_version": auth_fixed,
        "cvss_score": authoritative["cvss_score"],
        "advisory_source": authoritative["advisory_source"],
        "advisory_description": authoritative["advisory_description"],
        "is_verified_vulnerable": is_vuln,
        "verification_status": status
    }

    ai_explanation = {
        "summary": raw_summary,
        "why_it_matters": raw_why,
        "technical_impact": raw_tech
    }

    ai_inference = {
        "architectural_risk_scope": f"Cascading impact for journey '{authoritative.get('journey', 'Core Journey')}'",
        "inferred_blast_radius": "Component isolation recommended if external calls cannot be authenticated.",
        "ai_hypotheses": [
            f"Package '{pkg}' interaction in runtime paths should be verified against recent traces."
        ]
    }

    unverified_info = {
        "has_unverified_claims": len(unsupported_claims) > 0 or status in ["UNVERIFIED_ADVISORY", "MISSING_FIX_INFORMATION"],
        "unsupported_claims": unsupported_claims,
        "advisory_gaps": [authoritative["unverified_notes"]] if authoritative.get("unverified_notes") else []
    }

    validation_report = {
        "passed": len(validation_flags) == 0,
        "flags_count": len(validation_flags),
        "flags": validation_flags,
        "checked_against_authoritative": True,
        "source_of_truth": authoritative["advisory_source"]
    }

    return {
        "verified_scanner_finding": verified_finding,
        "ai_generated_explanation": ai_explanation,
        "ai_generated_inference": ai_inference,
        "unverified_information": unverified_info,
        "validation_report": validation_report,
        "summary": raw_summary,
        "why_it_matters": raw_why,
        "technical_impact": raw_tech,
        "safe_remediation_steps": raw_steps,
        "confidence_score": 0.99 if len(validation_flags) == 0 else 0.85
    }
