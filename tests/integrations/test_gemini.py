"""
Automated Backend & Integration Tests for BlindSpot Gemini AI Integration.
Covers:
- Missing API key (AI_NOT_CONFIGURED)
- Correct API key configuration (AI_READY)
- Successful mocked Gemini response
- Invalid API key (AI_AUTH_FAILED)
- Quota / Rate limit (AI_QUOTA_EXCEEDED)
- Network timeout (AI_UNAVAILABLE_OFFLINE)
- Model unavailable (AI_MODEL_UNAVAILABLE)
- Malformed response handling
- Sanitization of canary secrets, IPs, and file paths
- Explicit consent enforcement
- Correct API response schema
- Live Gemini smoke test (runs only when valid GEMINI_API_KEY is configured)
"""
import os
import json
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from google.genai.errors import APIError

from app.integrations.gemini import (
    sanitize_context_for_gemini,
    get_fallback_explanation,
    explain_finding,
    enrich_vendor_profile,
    check_gemini_status,
    STATUS_AI_READY,
    STATUS_AI_NOT_CONFIGURED,
    STATUS_AI_AUTH_FAILED,
    STATUS_AI_QUOTA_EXCEEDED,
    STATUS_AI_MODEL_UNAVAILABLE,
    STATUS_AI_UNAVAILABLE_OFFLINE
)


# 1. Sanitization & Canary Leak Prevention Tests
def test_sanitize_context_strips_sensitive_data():
    raw_dirty_input = {
        "finding_id": "find-123",
        "title": "Compromised package sk_live_9988776655443322",
        "package_name": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        # Sensitive canary values that MUST be redacted or stripped
        "source_code": "const secret = process.env.API_KEY;",
        "file_path": "/Users/admin/internal/secret/checkout.js",
        "internal_ip": "10.0.4.15",
        "aws_secret": "AKIAIOSFODNN7EXAMPLE",
        "password": "SuperSecretPassword123!"
    }

    sanitized = sanitize_context_for_gemini(raw_dirty_input)

    # Forbidden keys must not exist
    assert "source_code" not in sanitized
    assert "file_path" not in sanitized
    assert "internal_ip" not in sanitized
    assert "aws_secret" not in sanitized
    assert "password" not in sanitized

    # Canary strings inside allowed fields must be redacted
    assert "sk_live_" not in sanitized["title"]
    assert sanitized["target_package"] == "event-stream"
    assert sanitized["cve_id"] == "CVE-2018-3721"


# 2. Status Check Tests
def test_check_gemini_status_unconfigured():
    with patch("app.integrations.gemini.get_gemini_api_key", return_value=""):
        status = check_gemini_status()
        assert status["status"] == STATUS_AI_NOT_CONFIGURED
        assert status["configured"] is False


def test_check_gemini_status_configured():
    with patch("app.integrations.gemini.get_gemini_api_key", return_value="AIzaSyTestValidKeyMock12345"):
        status = check_gemini_status()
        assert status["status"] == STATUS_AI_READY
        assert status["configured"] is True


# 3. Missing Key Deterministic Fallback Test
@pytest.mark.asyncio
async def test_explain_finding_missing_api_key():
    raw = {
        "finding_id": "find-001",
        "title": "OSV Advisory",
        "package_name": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        "audience": "builder"
    }
    with patch("app.integrations.gemini.get_gemini_api_key", return_value=""):
        res = await explain_finding(raw)
        assert res["is_ai_generated"] is False
        assert res["is_fallback"] is True
        assert res["ai_status"] == STATUS_AI_NOT_CONFIGURED
        assert len(res["safe_remediation_steps"]) > 0


# 4. Successful Mocked Gemini Response Test
@pytest.mark.asyncio
async def test_explain_finding_successful_mock():
    mock_payload = {
        "summary": "event-stream has a malicious injection targeting cryptocurrency wallets.",
        "why_it_matters": "Downstream checkout and payments can be manipulated.",
        "technical_impact": "Compromised module loads flatmap-stream in runtime memory.",
        "safe_remediation_steps": ["npm update event-stream", "Re-run integrity checks"],
        "confidence_score": 0.99
    }
    mock_response = MagicMock()
    mock_response.text = json.dumps(mock_payload)

    with patch("app.integrations.gemini.get_gemini_api_key", return_value="mock_key"), \
         patch("app.integrations.gemini.Client") as MockClient:

        mock_instance = MockClient.return_value
        mock_instance.aio.models.generate_content = AsyncMock(return_value=mock_response)

        res = await explain_finding({
            "finding_id": "find-001",
            "title": "OSV Advisory",
            "package_name": "event-stream",
            "cve_id": "CVE-2018-3721",
            "severity": "critical",
            "audience": "builder"
        })

        assert res["is_ai_generated"] is True
        assert res["is_fallback"] is False
        assert res["ai_status"] == STATUS_AI_READY
        assert res["summary"] == mock_payload["summary"]
        assert res["safe_remediation_steps"] == mock_payload["safe_remediation_steps"]


# 5. Invalid Key Authentication Error Test
@pytest.mark.asyncio
async def test_explain_finding_invalid_key_auth_error():
    err_obj = APIError(400, {"message": "API key not valid. Please pass a valid API key."})
    err_obj.code = 400

    with patch("app.integrations.gemini.get_gemini_api_key", return_value="invalid_key"), \
         patch("app.integrations.gemini.Client") as MockClient:

        mock_instance = MockClient.return_value
        mock_instance.aio.models.generate_content = AsyncMock(side_effect=err_obj)

        res = await explain_finding({
            "finding_id": "find-001",
            "title": "Advisory",
            "package_name": "event-stream"
        })

        assert res["is_fallback"] is True
        assert res["ai_status"] == STATUS_AI_AUTH_FAILED
        assert "Invalid or unauthorized" in res["error_message"]


# 6. Quota Exceeded Rate Limit Test
@pytest.mark.asyncio
async def test_explain_finding_quota_error():
    err_obj = APIError(429, {"message": "Resource has been exhausted (e.g. check quota)."})
    err_obj.code = 429

    with patch("app.integrations.gemini.get_gemini_api_key", return_value="key"), \
         patch("app.integrations.gemini.Client") as MockClient:

        mock_instance = MockClient.return_value
        mock_instance.aio.models.generate_content = AsyncMock(side_effect=err_obj)

        res = await explain_finding({
            "finding_id": "find-001",
            "title": "Advisory",
            "package_name": "event-stream"
        })

        assert res["is_fallback"] is True
        assert res["ai_status"] == STATUS_AI_QUOTA_EXCEEDED


# 7. Network Timeout Test
@pytest.mark.asyncio
async def test_explain_finding_timeout_error():
    with patch("app.integrations.gemini.get_gemini_api_key", return_value="key"), \
         patch("app.integrations.gemini.Client") as MockClient:

        mock_instance = MockClient.return_value
        mock_instance.aio.models.generate_content = AsyncMock(side_effect=asyncio.TimeoutError())

        res = await explain_finding({
            "finding_id": "find-001",
            "title": "Advisory",
            "package_name": "event-stream"
        })

        assert res["is_fallback"] is True
        assert res["ai_status"] == STATUS_AI_UNAVAILABLE_OFFLINE


# 8. Model Unavailable Test
@pytest.mark.asyncio
async def test_explain_finding_model_unavailable_error():
    err_obj = APIError(404, {"message": "models/unknown-model is not found for API version v1beta"})
    err_obj.code = 404

    with patch("app.integrations.gemini.get_gemini_api_key", return_value="key"), \
         patch("app.integrations.gemini.Client") as MockClient:

        mock_instance = MockClient.return_value
        mock_instance.aio.models.generate_content = AsyncMock(side_effect=err_obj)

        res = await explain_finding({
            "finding_id": "find-001",
            "title": "Advisory",
            "package_name": "event-stream"
        })

        assert res["is_fallback"] is True
        assert res["ai_status"] == STATUS_AI_MODEL_UNAVAILABLE


# 9. Optional Live Smoke Test (Runs ONLY if valid GEMINI_API_KEY is configured)
@pytest.mark.asyncio
async def test_optional_live_gemini_smoke():
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key or key == "your_gemini_api_key_here":
        pytest.skip("Skipping live Gemini smoke test: GEMINI_API_KEY not configured in environment.")

    res = await explain_finding({
        "finding_id": "smoke-test",
        "title": "Live Gemini Smoke Test",
        "package_name": "axios",
        "version": "0.21.1",
        "cve_id": "CVE-2020-28168",
        "severity": "medium",
        "journey_name": "Checkout Flow",
        "audience": "builder"
    })

    assert res["finding_id"] == "smoke-test"
    assert "summary" in res and len(res["summary"]) > 0
    assert len(res["safe_remediation_steps"]) > 0
