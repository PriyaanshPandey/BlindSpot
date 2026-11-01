"""
Adversarial & Grounding Verification Tests for BlindSpot Gemini AI Integration.
Guarantees that:
1. Deterministic vulnerability scanner and authoritative advisory databases are the sole source of truth.
2. Gemini explains verified findings, never determines vulnerability independently.
3. Post-generation validation rejects hallucinated CVEs, contradicted version claims, and unverified upgrade versions.
4. Authoritative advisory identifiers, affected ranges, and fixed versions are preserved exactly.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.integrations.gemini.grounding import (
    resolve_authoritative_advisory,
    validate_and_ground_explanation
)
from app.integrations.gemini import explain_finding


# Case 1: A Vulnerable Package Version
@pytest.mark.asyncio
async def test_adversarial_vulnerable_package_version():
    """Authoritative scanner finds lodash 4.17.20 is vulnerable (< 4.17.21)."""
    raw_finding = {
        "finding_id": "find-lodash-vuln",
        "title": "Command Injection in lodash",
        "package_name": "lodash",
        "version": "4.17.20",
        "cve_id": "CVE-2021-23337",
        "severity": "high",
        "journey_name": "Data Processing",
        "audience": "builder"
    }

    auth = resolve_authoritative_advisory("lodash", "4.17.20", "CVE-2021-23337")
    assert auth["is_verified_vulnerable"] is True
    assert auth["verification_status"] == "VERIFIED_VULNERABLE"
    assert auth["fixed_version"] == "4.17.21"
    assert "< 4.17.21" in auth["affected_version_range"]

    mock_gemini_response = {
        "summary": "Lodash before 4.17.21 contains command injection vulnerability in template function.",
        "why_it_matters": "Untrusted input passed to templates could execute arbitrary commands.",
        "technical_impact": "Direct code execution in Node runtime.",
        "safe_remediation_steps": ["Upgrade lodash to version 4.17.21."]
    }

    grounded = validate_and_ground_explanation(mock_gemini_response, auth, "builder")
    assert grounded["validation_report"]["passed"] is True
    assert grounded["verified_scanner_finding"]["is_verified_vulnerable"] is True
    assert grounded["verified_scanner_finding"]["fixed_version"] == "4.17.21"
    assert any("4.17.21" in s for s in grounded["safe_remediation_steps"])


# Case 2: A Version Already Fixed (The exact axios 0.21.1 prompt issue)
@pytest.mark.asyncio
async def test_adversarial_version_already_fixed():
    """
    Axios 0.21.1 with CVE-2020-28168.
    Authoritative advisory states 0.21.1 is the first fixed release.
    AI must NOT treat 0.21.1 as vulnerable or advise upgrading to 0.21.2.
    """
    raw_finding = {
        "package_name": "axios",
        "installed_version": "0.21.1",
        "cve_id": "CVE-2020-28168"
    }

    auth = resolve_authoritative_advisory("axios", "0.21.1", "CVE-2020-28168")
    assert auth["is_verified_vulnerable"] is False
    assert auth["verification_status"] == "ALREADY_FIXED"
    assert auth["fixed_version"] == "0.21.1"

    # Adversarial mock: Gemini hallucinates that 0.21.1 is vulnerable and tells user to upgrade to 0.21.2
    bad_gemini_response = {
        "summary": "Axios 0.21.1 is vulnerable to SSRF. Recommends upgrading to 0.21.2.",
        "why_it_matters": "Allows attacker to steal tokens.",
        "technical_impact": "Header leakage.",
        "safe_remediation_steps": ["Upgrade to version 0.21.2."]
    }

    grounded = validate_and_ground_explanation(bad_gemini_response, auth, "builder")

    # Post-generation validator MUST detect contradiction and override
    assert grounded["validation_report"]["passed"] is False
    assert any("CONTRADICTION_DETECTED" in f for f in grounded["validation_report"]["flags"])
    assert grounded["verified_scanner_finding"]["is_verified_vulnerable"] is False

    # Summary must state authoritative truth: ALREADY PATCHED
    assert "ALREADY PATCHED" in grounded["summary"] or "not vulnerable" in grounded["summary"].lower()
    assert "0.21.1" in grounded["summary"]
    # Remediation must NOT tell user to upgrade to 0.21.2
    assert not any("0.21.2" in s for s in grounded["safe_remediation_steps"])
    assert any("No code modifications or version bumps are required" in s or "0.21.1" in s for s in grounded["safe_remediation_steps"])


# Case 3: An Incorrect CVE Supplied to Gemini
@pytest.mark.asyncio
async def test_adversarial_incorrect_cve_supplied():
    """Caller passes non-existent / bogus CVE-9999-99999 for express."""
    auth = resolve_authoritative_advisory("express", "4.18.2", "CVE-9999-99999")
    assert auth["verification_status"] == "UNVERIFIED_ADVISORY"
    assert auth["is_verified_vulnerable"] is False

    mock_gemini_response = {
        "summary": "Express is vulnerable to remote exploit in CVE-9999-99999.",
        "why_it_matters": "Critical risk.",
        "technical_impact": "Full server takeover.",
        "safe_remediation_steps": ["Upgrade express immediately."]
    }

    grounded = validate_and_ground_explanation(mock_gemini_response, auth, "builder")
    assert grounded["validation_report"]["passed"] is False
    assert any("UNVERIFIED_ADVISORY" in f for f in grounded["validation_report"]["flags"])
    assert "verification is required" in grounded["summary"].lower()
    assert grounded["unverified_information"]["has_unverified_claims"] is True


# Case 4: Conflicting Advisory Sources
@pytest.mark.asyncio
async def test_adversarial_conflicting_advisory_sources():
    """Scanner has conflicting data from different feeds (e.g. OSV vs local DB)."""
    provided = {
        "cve_id": "CVE-2021-3749",
        "fixed_version": "0.21.2",
        "affected_version_range": "<= 0.21.1",
        "severity": "medium",
        "advisory_source": "Google OSV (Medium) vs NVD (High)",
        "advisory_description": "Disputed severity between OSV and NVD."
    }

    auth = resolve_authoritative_advisory("axios", "0.21.1", "CVE-2021-3749", provided_details=provided)
    assert auth["is_verified_vulnerable"] is True
    assert auth["verification_status"] == "VERIFIED_VULNERABLE"

    mock_gemini_response = {
        "summary": "Axios ReDoS vulnerability with conflicting severity ratings.",
        "why_it_matters": "Denial of service potential.",
        "technical_impact": "Event loop blocking.",
        "safe_remediation_steps": ["Upgrade axios to 0.21.2."]
    }

    grounded = validate_and_ground_explanation(mock_gemini_response, auth, "enterprise")
    assert grounded["verified_scanner_finding"]["advisory_source"] == "Google OSV (Medium) vs NVD (High)"
    assert grounded["verified_scanner_finding"]["fixed_version"] == "0.21.2"


# Case 5: Missing Fixed-Version Information (0-day or unpatched package)
@pytest.mark.asyncio
async def test_adversarial_missing_fixed_version():
    """Package flatmap-stream has no fixed release published (malicious package)."""
    auth = resolve_authoritative_advisory("flatmap-stream", "0.1.1", "MAL-2018-001")
    assert auth["verification_status"] == "MISSING_FIX_INFORMATION"
    assert auth["fixed_version"] is None

    # Gemini tries to invent a non-existent patch version "1.0.0"
    bad_gemini_response = {
        "summary": "Malicious package flatmap-stream injected in dependencies.",
        "why_it_matters": "Wallet key extraction.",
        "technical_impact": "Supply chain compromise.",
        "safe_remediation_steps": ["Upgrade flatmap-stream to version 1.0.0."]
    }

    grounded = validate_and_ground_explanation(bad_gemini_response, auth, "builder")
    assert grounded["validation_report"]["passed"] is False
    assert any("INVENTED_FIX_VERSION" in f for f in grounded["validation_report"]["flags"])
    # Validator must reject the invented version 1.0.0
    assert not any("1.0.0" in s for s in grounded["safe_remediation_steps"])
    assert any("No authoritative fixed release" in s for s in grounded["safe_remediation_steps"])


# Case 6: Gemini Inventing an Additional Vulnerability
@pytest.mark.asyncio
async def test_adversarial_gemini_inventing_additional_cve():
    """Gemini response hallucinates a completely unrelated CVE-2024-99999."""
    auth = resolve_authoritative_advisory("jsonwebtoken", "8.5.1", "CVE-2022-23529")

    bad_gemini_response = {
        "summary": "jsonwebtoken 8.5.1 has CVE-2022-23529 and also critical RCE in CVE-2024-99999.",
        "why_it_matters": "Allows remote root access via CVE-2024-99999.",
        "technical_impact": "Arbitrary code execution.",
        "safe_remediation_steps": ["Upgrade jsonwebtoken to 9.0.0."]
    }

    grounded = validate_and_ground_explanation(bad_gemini_response, auth, "builder")
    assert grounded["validation_report"]["passed"] is False
    assert any("HALLUCINATED_CVE" in f for f in grounded["validation_report"]["flags"])
    assert any("CVE-2024-99999" in u for u in grounded["unverified_information"]["unsupported_claims"])
    # Hallucinated CVE must be flagged/redacted from established summary
    assert "CVE-2024-99999" not in grounded["summary"] or "[UNVERIFIED_CVE" in grounded["summary"]


# Case 7: Gemini Recommending an Unsupported Upgrade Version
@pytest.mark.asyncio
async def test_adversarial_gemini_recommending_unsupported_version():
    """Authoritative fix is 4.17.21, but Gemini suggests arbitrary version 99.0.0."""
    auth = resolve_authoritative_advisory("lodash", "4.17.20", "CVE-2021-23337")

    bad_gemini_response = {
        "summary": "Lodash vulnerability in template compiler.",
        "why_it_matters": "Command injection.",
        "technical_impact": "RCE.",
        "safe_remediation_steps": ["Upgrade lodash to version 99.0.0 immediately."]
    }

    grounded = validate_and_ground_explanation(bad_gemini_response, auth, "builder")
    assert grounded["validation_report"]["passed"] is False
    assert any("UNSUPPORTED_UPGRADE_VERSION" in f for f in grounded["validation_report"]["flags"])
    assert any("99.0.0" in u for u in grounded["unverified_information"]["unsupported_claims"])
    # Remediations must be reset to the authoritative fixed version 4.17.21
    assert any("4.17.21" in s for s in grounded["safe_remediation_steps"])
    assert not any("99.0.0" in s for s in grounded["safe_remediation_steps"])


# Case 8: End-to-End explain_finding with Authoritative Grounding
@pytest.mark.asyncio
async def test_explain_finding_e2e_grounding_preservation():
    """Verify explain_finding embeds verified_scanner_finding and validation_report."""
    payload = {
        "finding_id": "find-grounded-001",
        "title": "Axios Fixed Finding",
        "package_name": "axios",
        "version": "0.21.1",
        "cve_id": "CVE-2020-28168",
        "severity": "critical",
        "journey_name": "Checkout Flow",
        "audience": "builder"
    }

    res = await explain_finding(payload)
    assert "verified_scanner_finding" in res
    assert "validation_report" in res
    assert "ai_generated_explanation" in res
    assert "unverified_information" in res

    # The package axios 0.21.1 is ALREADY_FIXED for CVE-2020-28168
    vf = res["verified_scanner_finding"]
    assert vf["is_verified_vulnerable"] is False
    assert vf["verification_status"] == "ALREADY_FIXED"
    assert vf["fixed_version"] == "0.21.1"

