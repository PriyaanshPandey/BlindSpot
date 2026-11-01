"""
API Route tests for POST /api/v1/ai/chat (Ask BlindSpot).
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

from main import app
from app.db import db
from app.integrations.gemini import STATUS_AI_READY

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_scan_data():
    scan_id = "scan-route-test-1"
    db.in_memory_scans[scan_id] = {
        "scan_id": scan_id,
        "project_name": "Ecommerce API",
        "repo_path": "/demo/ecommerce-api"
    }
    db.in_memory_findings[scan_id] = [
        {
            "id": "finding-test-1",
            "scan_id": scan_id,
            "title": "Lodash Prototype Pollution",
            "package_name": "lodash",
            "installed_version": "4.17.15",
            "cve_id": "CVE-2021-23337",
            "severity": "high",
            "target_node_id": "pkg:lodash",
            "affected_journey_ids": ["Order Processing"],
            "security_details": {
                "cve_id": "CVE-2021-23337",
                "fixed_version": "4.17.21",
                "affected_version_range": "< 4.17.21"
            },
            "description": "Command injection vulnerability in lodash."
        }
    ]
    yield
    db.in_memory_scans.pop(scan_id, None)
    db.in_memory_findings.pop(scan_id, None)


def test_chat_route_rejects_missing_consent():
    """Verify that omitting user consent returns HTTP 400."""
    response = client.post(
        "/api/v1/ai/chat",
        json={
            "message": "Is lodash vulnerable?",
            "user_approved_transmission": False
        }
    )
    assert response.status_code == 400
    assert "User must approve transmission" in response.json()["detail"]


def test_chat_route_success_with_consent():
    """Verify that chatting with consent returns structured AIChatResponse."""
    mock_resp = MagicMock()
    mock_resp.text = "Lodash 4.17.15 is vulnerable to CVE-2021-23337. Upgrading to 4.17.21 resolves this issue."

    with patch("app.integrations.gemini.chat.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        response = client.post(
            "/api/v1/ai/chat",
            json={
                "message": "Why is lodash flagged in my scan?",
                "conversation_id": "session-123",
                "scan_id": "scan-route-test-1",
                "finding_id": "finding-test-1",
                "audience": "builder",
                "user_approved_transmission": True,
                "api_key": "test-key"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["conversation_id"] == "session-123"
        assert "CVE-2021-23337" in data["answer"]
        assert data["ai_status"] == STATUS_AI_READY
        assert data["is_ai_generated"] is True
        assert isinstance(data["references"], list)
        assert len(data["references"]) >= 1
        assert data["references"][0]["id"] == "finding-test-1"


def test_chat_route_follow_up():
    """Verify multi-turn history handling in API route."""
    mock_resp = MagicMock()
    mock_resp.text = "For the Order Processing journey, lodash handles template rendering."

    with patch("app.integrations.gemini.chat.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        response = client.post(
            "/api/v1/ai/chat",
            json={
                "message": "What does that mean for order processing?",
                "conversation_id": "session-123",
                "scan_id": "scan-route-test-1",
                "finding_id": "finding-test-1",
                "audience": "enterprise",
                "user_approved_transmission": True,
                "history": [
                    {"role": "user", "content": "Why is lodash flagged?"},
                    {"role": "assistant", "content": "Lodash 4.17.15 has CVE-2021-23337."}
                ],
                "api_key": "test-key"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "Order Processing" in data["answer"]
