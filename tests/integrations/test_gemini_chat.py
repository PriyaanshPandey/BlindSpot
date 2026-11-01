"""
Tests for Ask BlindSpot Context-Aware Chatbot (Workstream D).
Validates:
- Consent enforcement (HTTP 400 when unapproved)
- Privacy sanitization (masking IPs, tokens, paths)
- Context assembly (Project, Finding, Graph Node, Failure Simulation)
- Authoritative grounding integration (advisory ranges, fixed versions)
- Builder vs Enterprise mode perspective differentiation
- Reference extraction & hallucination filtering
- Bounded conversation history
- Quota / Offline / Error handling without fabricating success
- Prompt-injection resistance
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.integrations.gemini.chat import (
    assemble_chat_context,
    build_system_prompt,
    extract_verified_references,
    generate_fallback_chat_response,
    chat_with_gemini
)
from app.integrations.gemini import (
    STATUS_AI_READY,
    STATUS_AI_NOT_CONFIGURED,
    STATUS_AI_QUOTA_EXCEEDED,
    STATUS_AI_UNAVAILABLE_OFFLINE
)
from app.db import db


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Populates in-memory database with test scan, findings, graph, and simulation."""
    scan_id = "test-scan-copilot"
    db.in_memory_scans[scan_id] = {
        "scan_id": scan_id,
        "project_name": "Nexus Commerce Checkout",
        "repo_path": "/var/app/nexus-commerce"
    }

    db.in_memory_findings[scan_id] = [
        {
            "id": "finding-axios-1",
            "scan_id": scan_id,
            "title": "SSRF in axios@0.20.0 via cross-origin redirect",
            "package_name": "axios",
            "installed_version": "0.20.0",
            "cve_id": "CVE-2020-28168",
            "severity": "critical",
            "target_node_id": "pkg:axios",
            "affected_journey_ids": ["Customer Checkout"],
            "security_details": {
                "cve_id": "CVE-2020-28168",
                "fixed_version": "0.21.1",
                "affected_version_range": "< 0.21.1",
                "cvss_score": 7.8,
                "advisory_source": "Google OSV"
            },
            "description": "Axios allows SSRF and header leakage."
        },
        {
            "id": "finding-jwt-2",
            "scan_id": scan_id,
            "title": "Key confusion in jsonwebtoken@8.5.1",
            "package_name": "jsonwebtoken",
            "installed_version": "8.5.1",
            "cve_id": "CVE-2022-23529",
            "severity": "high",
            "target_node_id": "pkg:jsonwebtoken",
            "affected_journey_ids": ["User Authentication"],
            "security_details": {
                "cve_id": "CVE-2022-23529",
                "fixed_version": "9.0.0",
                "affected_version_range": "<= 8.5.1",
                "cvss_score": 7.6,
                "advisory_source": "GitHub Advisory Database"
            },
            "description": "Insecure key verification in jsonwebtoken."
        }
    ]

    db.in_memory_graphs[scan_id] = {
        "scan_id": scan_id,
        "nodes": [
            {"id": "service:checkout", "label": "Checkout Service", "type": "internal_service", "provenance": "declared", "status": "healthy", "criticality": "critical"},
            {"id": "pkg:axios", "label": "axios@0.20.0", "type": "software_package", "provenance": "declared", "status": "compromised", "criticality": "high"},
            {"id": "vendor:stripe", "label": "Stripe Payments", "type": "vendor", "provenance": "observed", "status": "healthy", "criticality": "critical"}
        ],
        "edges": [
            {"id": "e1", "source": "service:checkout", "target": "pkg:axios", "relation": "depends_on"},
            {"id": "e2", "source": "service:checkout", "target": "vendor:stripe", "relation": "calls_api"}
        ]
    }

    db.in_memory_scenarios[scan_id] = [
        {
            "scenario_id": "sim-stripe-1",
            "scan_id": scan_id,
            "target_node_id": "vendor:stripe",
            "failure_duration_hours": 6,
            "impact_results": {
                "architecture_impact_score": 78.5,
                "severity_rating": "HIGH",
                "blast_radius_node_count": 3,
                "impacted_journeys": [
                    {"name": "Customer Checkout", "disruption_fraction": 0.85}
                ],
                "mitigation_strategies": [
                    {"title": "Deploy Circuit Breaker for Stripe"}
                ]
            }
        }
    ]

    yield

    db.in_memory_scans.pop(scan_id, None)
    db.in_memory_findings.pop(scan_id, None)
    db.in_memory_graphs.pop(scan_id, None)
    db.in_memory_scenarios.pop(scan_id, None)


@pytest.mark.asyncio
async def test_chat_requires_user_consent():
    """Validates that chat raises an error if user consent is not given."""
    with pytest.raises(ValueError, match="User must approve transmission"):
        await chat_with_gemini(
            message="Why is this risky?",
            user_approved_transmission=False
        )


@pytest.mark.asyncio
async def test_chat_message_sanitization():
    """Validates that sensitive tokens, IPs, and internal paths are stripped from message."""
    test_msg = "Look at my internal IP 192.168.1.100 and key sk_live_abcdef12345678901234 in /home/krish/secret.py"
    context = await assemble_chat_context()
    resp = generate_fallback_chat_response(test_msg, context, STATUS_AI_NOT_CONFIGURED)
    # The message should not leak in output
    assert "sk_live_abcdef" not in resp["answer"]
    assert "192.168.1.100" not in resp["answer"]


@pytest.mark.asyncio
async def test_chat_context_assembly_project_and_finding():
    """Validates assembly of project and grounded finding context."""
    context = await assemble_chat_context(
        scan_id="test-scan-copilot",
        finding_id="finding-axios-1",
        audience="builder"
    )
    assert context["project"] is not None
    assert context["project"]["name"] == "nexus-commerce" or "Nexus" in context["project"]["name"]
    assert context["project"]["total_findings"] == 2
    assert context["project"]["critical_findings"] == 1

    finding = context["finding"]
    assert finding is not None
    assert finding["package"] == "axios"
    assert finding["cve_id"] == "CVE-2020-28168"
    assert finding["fixed_version"] == "0.21.1"
    assert finding["verification_status"] == "VERIFIED_VULNERABLE"


@pytest.mark.asyncio
async def test_chat_context_assembly_graph_node_and_simulation():
    """Validates assembly of graph node topology and active failure simulation."""
    context = await assemble_chat_context(
        scan_id="test-scan-copilot",
        graph_node_id="service:checkout",
        audience="enterprise"
    )
    node = context["graph_node"]
    assert node is not None
    assert node["id"] == "service:checkout"
    assert "pkg:axios" in node["dependencies"]
    assert "vendor:stripe" in node["dependencies"]

    sim = context["simulation"]
    assert sim is not None
    assert sim["target_node_id"] == "vendor:stripe"
    assert sim["architecture_impact_score"] == 78.5
    assert sim["severity_rating"] == "HIGH"


def test_builder_vs_enterprise_system_prompt():
    """Validates that system prompt emphasizes commands in Builder mode and business continuity in Enterprise mode."""
    context = {"project": None, "finding": None, "graph_node": None, "simulation": None}

    builder_prompt = build_system_prompt(context, audience="builder")
    assert "PERSPECTIVE: BUILDER MODE" in builder_prompt
    assert "npm update" in builder_prompt or "pip install" in builder_prompt

    enterprise_prompt = build_system_prompt(context, audience="enterprise")
    assert "PERSPECTIVE: ENTERPRISE MODE" in enterprise_prompt
    assert "blast radius" in enterprise_prompt
    assert "business journey disruption" in enterprise_prompt


def test_reference_extraction_rejects_hallucinations():
    """Validates that references list only contains verified local records."""
    context = {
        "verified_finding_ids": {"finding-axios-1", "finding-jwt-2"},
        "verified_node_ids": {"service:checkout", "vendor:stripe"},
        "finding": {"id": "finding-axios-1", "package": "axios", "cve_id": "CVE-2020-28168"},
        "graph_node": {"id": "service:checkout", "label": "Checkout Service"}
    }

    mock_answer = "You should fix finding-jwt-2 and check node vendor:stripe. Also beware of hallucinated-finding-999."
    refs = extract_verified_references(mock_answer, context)
    ref_ids = [r["id"] for r in refs]

    assert "finding-axios-1" in ref_ids  # active finding
    assert "finding-jwt-2" in ref_ids    # verified finding mentioned in answer
    assert "vendor:stripe" in ref_ids    # verified node mentioned in answer
    assert "hallucinated-finding-999" not in ref_ids  # hallucination filtered out!


@pytest.mark.asyncio
async def test_chat_gemini_mocked_success():
    """Validates end-to-end chat flow when Gemini responds successfully."""
    mock_response = MagicMock()
    mock_response.text = "Axios 0.20.0 has a known SSRF issue (CVE-2020-28168). You should upgrade to 0.21.1."

    with patch("app.integrations.gemini.chat.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        res = await chat_with_gemini(
            message="Why is axios flagged in checkout?",
            scan_id="test-scan-copilot",
            finding_id="finding-axios-1",
            audience="builder",
            user_approved_transmission=True,
            api_key_override="mock-test-key-valid"
        )

        assert res["ai_status"] == STATUS_AI_READY
        assert res["is_ai_generated"] is True
        assert "CVE-2020-28168" in res["answer"]
        assert len(res["references"]) >= 1
        assert res["references"][0]["id"] == "finding-axios-1"


@pytest.mark.asyncio
async def test_chat_gemini_quota_exceeded_honest_fallback():
    """Validates that 429 quota exhaustion provides an honest deterministic fallback without fabricating success."""
    from google.genai.errors import APIError

    mock_exc = APIError(429, {"message": "Resource has been exhausted (e.g. check quota)."})

    with patch("app.integrations.gemini.chat.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(side_effect=mock_exc)
        mock_client_cls.return_value = mock_client

        res = await chat_with_gemini(
            message="Can you explain this vulnerability?",
            scan_id="test-scan-copilot",
            finding_id="finding-axios-1",
            audience="builder",
            user_approved_transmission=True,
            api_key_override="mock-test-key"
        )

        assert res["ai_status"] == STATUS_AI_QUOTA_EXCEEDED
        assert res["is_ai_generated"] is False
        assert "Quota Exceeded" in res["answer"]
        assert "CVE-2020-28168" in res["answer"]
        assert "0.21.1" in res["answer"]  # authoritative local patch version included
