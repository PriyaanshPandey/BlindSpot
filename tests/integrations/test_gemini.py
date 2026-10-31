import asyncio
import pytest
from app.integrations.gemini import (
    sanitize_context_for_gemini,
    get_fallback_explanation,
    explain_finding,
    enrich_vendor_profile
)

def test_sanitize_context_strips_sensitive_data():
    raw_dirty_input = {
        "finding_id": "find-123",
        "title": "Compromised package",
        "package_name": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        # Sensitive data that MUST be filtered out
        "source_code": "const secret = process.env.API_KEY;",
        "file_path": "/internal/secret/checkout.js",
        "internal_ip": "10.0.4.15",
        "aws_secret": "AKIAIOSFODNN7EXAMPLE"
    }
    
    sanitized = sanitize_context_for_gemini(raw_dirty_input)
    assert "source_code" not in sanitized
    assert "file_path" not in sanitized
    assert "internal_ip" not in sanitized
    assert "aws_secret" not in sanitized
    assert sanitized["target_package"] == "event-stream"
    assert sanitized["cve_id"] == "CVE-2018-3721"

def test_builder_audience_explanation():
    sanitized = {
        "finding_id": "find-001",
        "target_package": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        "affected_business_journey": "Customer Checkout",
        "audience": "builder"
    }
    exp = get_fallback_explanation(sanitized)
    assert exp["is_fallback"] is True
    assert exp["audience"] == "builder"
    assert "npm update" in exp["safe_remediation_steps"][0]

def test_enterprise_audience_explanation():
    sanitized = {
        "finding_id": "find-002",
        "target_package": "jsonwebtoken",
        "version": "8.5.1",
        "cve_id": "CVE-2022-23529",
        "severity": "high",
        "affected_business_journey": "User Authentication",
        "audience": "enterprise"
    }
    exp = get_fallback_explanation(sanitized)
    assert exp["is_fallback"] is True
    assert exp["audience"] == "enterprise"
    assert "blast-radius" in exp["why_it_matters"].lower()

def test_vendor_profile_enrichment():
    profile = asyncio.run(enrich_vendor_profile("stripe.com"))
    assert profile["vendor"] == "Stripe, Inc."
    assert "Amazon Web Services (AWS US-East-1)" in profile["disclosed_subprocessors"]
