import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_get_knowledge_manifest():
    response = client.get("/api/v1/knowledge/manifest")
    assert response.status_code == 200
    data = response.json()
    assert "active_bundle_id" in data
    assert "bundle_sha256" in data
    assert "DigitalOcean" in data["distribution_channel"]

def test_verify_knowledge_bundle_route():
    response = client.post("/api/v1/knowledge/verify", json={"simulate_tamper": False})
    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "verified"
    assert data["ed25519_verification"]["is_valid"] is True
    assert data["solana_verification"]["verified"] is True

def test_verify_knowledge_bundle_rejects_tamper():
    response = client.post("/api/v1/knowledge/verify", json={"simulate_tamper": True})
    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "tampered_or_invalid"
    assert data["ed25519_verification"]["is_valid"] is False

def test_explain_route_preview_and_execute():
    # 1. Preview
    preview_res = client.post("/api/v1/ai/preview-payload", json={
        "finding_id": "f-1",
        "title": "Compromised event-stream",
        "package_name": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        "audience": "builder"
    })
    assert preview_res.status_code == 200
    assert "payload_to_send" in preview_res.json()

    # 2. Explain
    explain_res = client.post("/api/v1/ai/explain", json={
        "finding_id": "f-1",
        "title": "Compromised event-stream",
        "package_name": "event-stream",
        "version": "3.3.6",
        "cve_id": "CVE-2018-3721",
        "severity": "critical",
        "audience": "builder",
        "user_approved_transmission": True
    })
    assert explain_res.status_code == 200
    data = explain_res.json()
    assert "summary" in data
    assert "safe_remediation_steps" in data

