import os
import pytest
import asyncio
from app.db import db
from app.ingestion import scan_project_directory
from app.api.routes.scans import build_unified_graph
from app.integrations.gemini import explain_finding

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def test_scan_django_saas_live():
    target = os.path.join(WORKSPACE_ROOT, "test-projects", "django-saas")
    assert os.path.exists(target), f"Target {target} must exist"

    scan_data = scan_project_directory(target)
    assert "error" not in scan_data
    assert "dependencies" in scan_data
    deps = scan_data["dependencies"]

    # Verify real declared packages
    assert "django" in deps
    assert "stripe" in deps
    assert "celery" in deps

    # Verify observed hosts from .env and code
    observed = scan_data["observed_hosts"]
    assert any("segment" in h or "postmark" in h or "stripe" in h or "sentry" in h for h in observed)

    # Build graph & verify OSV vulnerability and blast radius scenarios
    scan_record = build_unified_graph(scan_data)
    scan_id = scan_record["scan_id"]
    graph = db.in_memory_graphs[scan_id]
    findings = db.in_memory_findings[scan_id]
    scenarios = db.in_memory_scenarios[scan_id]

    # Ensure nodes created
    node_labels = [n["label"] for n in graph["nodes"]]
    assert any("django" in l.lower() for l in node_labels)

    # Verify OSV findings for django 3.2.0
    django_vulns = [f for f in findings if "django" in f["title"].lower()]
    assert len(django_vulns) > 0, "OSV should report real CVEs for django 3.2.0"

    # Verify failure scenarios exist
    assert len(scenarios) > 0

def test_scan_nextjs_ai_portal_live():
    target = os.path.join(WORKSPACE_ROOT, "test-projects", "nextjs-ai-portal")
    assert os.path.exists(target), f"Target {target} must exist"

    scan_data = scan_project_directory(target)
    assert "error" not in scan_data
    deps = scan_data["dependencies"]

    # Verify packages
    assert "openai" in deps
    assert "jsonwebtoken" in deps
    assert "@supabase/supabase-js" in deps

    # Verify observed endpoints from code
    observed = scan_data["observed_hosts"]
    assert any("mixpanel" in h or "algolia" in h or "supabase" in h for h in observed)

    # Build graph & verify OSV vulnerability for jsonwebtoken 8.5.1
    scan_record = build_unified_graph(scan_data)
    scan_id = scan_record["scan_id"]
    findings = db.in_memory_findings[scan_id]
    jwt_vulns = [f for f in findings if "jsonwebtoken" in f["title"].lower()]
    assert len(jwt_vulns) > 0, "OSV should report real CVEs for jsonwebtoken@8.5.1"

def test_scan_fastapi_fintech_live():
    target = os.path.join(WORKSPACE_ROOT, "test-projects", "fastapi-fintech")
    assert os.path.exists(target), f"Target {target} must exist"

    scan_data = scan_project_directory(target)
    assert "error" not in scan_data
    deps = scan_data["dependencies"]

    assert "fastapi" in deps
    assert "razorpay" in deps
    assert "twilio" in deps

    observed = scan_data["observed_hosts"]
    assert any("veriff" in h or "sift" in h or "razorpay" in h or "twilio" in h for h in observed)

    scan_record = build_unified_graph(scan_data)
    scan_id = scan_record["scan_id"]
    graph = db.in_memory_graphs[scan_id]
    scenarios = db.in_memory_scenarios[scan_id]

    assert len(graph["nodes"]) >= 5
    assert len(scenarios) >= 1

def test_scan_ecommerce_monorepo_multiservice():
    target = os.path.join(WORKSPACE_ROOT, "test-projects", "ecommerce-monorepo")
    assert os.path.exists(target), f"Target {target} must exist"

    scan_data = scan_project_directory(target)
    assert "error" not in scan_data

    # Monorepo should detect multiple subservices
    services = scan_data["services"]
    assert len(services) >= 2, "Monorepo should detect frontend and backend subservices"

    deps = scan_data["dependencies"]
    assert "react" in deps
    assert "flask" in deps

    observed = scan_data["observed_hosts"]
    assert any("paypal" in h or "sendgrid" in h for h in observed)

    scan_record = build_unified_graph(scan_data)
    scan_id = scan_record["scan_id"]
    graph = db.in_memory_graphs[scan_id]
    assert len(graph["nodes"]) >= 8

def test_live_gemini_explain_on_real_finding():
    """Verify Gemini AI generates contextual risk assessment for live finding."""
    sample_context = {
        "finding_id": "find-live-01",
        "title": "Undocumented Third-Party Telemetry Endpoint Detected",
        "package_name": "telemetry.segment.io",
        "version": "v1",
        "severity": "medium",
        "journey_name": "Customer Checkout Flow",
        "audience": "builder"
    }
    
    explanation = asyncio.run(
        explain_finding(raw_context=sample_context)
    )
    assert explanation is not None
    assert "summary" in explanation
    assert len(explanation["summary"]) > 10
    assert "why_it_matters" in explanation
