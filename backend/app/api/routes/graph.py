from fastapi import APIRouter, HTTPException
from datetime import datetime
from app.db import db

router = APIRouter()

@router.get("/{scan_id}/graph")
async def get_scan_graph(scan_id: str, filter_layer: str = "all"):
    # Return dynamic graph stored during create_scan
    if scan_id in db.in_memory_graphs:
        return db.in_memory_graphs[scan_id]
        
    # Baseline demo graph fallback if someone requests an arbitrary/initial ID
    nodes = [
        {"id": "app:nexus-frontend", "label": "Nexus Web Storefront", "type": "application", "provenance": "declared", "status": "healthy", "criticality": "critical"},
        {"id": "service:nexus-api", "label": "Checkout API Gateway", "type": "internal_service", "provenance": "declared", "status": "healthy", "criticality": "critical"},
        {"id": "vendor:stripe", "label": "Stripe Payments", "type": "vendor", "provenance": "declared", "status": "healthy", "criticality": "critical"},
        {"id": "vendor:auth0", "label": "Auth0 Identity", "type": "vendor", "provenance": "declared", "status": "healthy", "criticality": "high"},
        {"id": "vendor:aws-us-east-1", "label": "AWS US-East-1 (Vendor Subprocessor)", "type": "infrastructure_resource", "provenance": "disclosed", "status": "healthy", "criticality": "critical"},
        {"id": "pkg:event-stream", "label": "npm: event-stream@3.3.6", "type": "software_package", "provenance": "declared", "status": "compromised", "criticality": "critical"},
        {"id": "unknown:analytics-cdn", "label": "telemetry.untrusted-cdn.net", "type": "external_api", "provenance": "observed", "status": "warning", "criticality": "high"},
        {"id": "journey:checkout", "label": "Journey: Customer Checkout", "type": "business_journey", "provenance": "inferred", "status": "healthy", "criticality": "critical"}
    ]

    edges = [
        {"id": "e1", "source": "app:nexus-frontend", "target": "service:nexus-api", "relation": "calls_api", "provenance": "declared", "confidence_score": 1.0},
        {"id": "e2", "source": "service:nexus-api", "target": "vendor:stripe", "relation": "calls_api", "provenance": "declared", "confidence_score": 1.0},
        {"id": "e3", "source": "service:nexus-api", "target": "vendor:auth0", "relation": "authenticates_via", "provenance": "declared", "confidence_score": 1.0},
        {"id": "e4", "source": "vendor:stripe", "target": "vendor:aws-us-east-1", "relation": "depends_on", "provenance": "vendor_passport", "confidence_score": 0.95},
        {"id": "e5", "source": "service:nexus-api", "target": "pkg:event-stream", "relation": "transitive_dependency", "provenance": "declared", "confidence_score": 1.0},
        {"id": "e6", "source": "app:nexus-frontend", "target": "unknown:analytics-cdn", "relation": "calls_api", "provenance": "observed", "confidence_score": 0.99},
        {"id": "e7", "source": "vendor:stripe", "target": "journey:checkout", "relation": "powers_journey", "provenance": "inferred", "confidence_score": 1.0}
    ]

    return {
        "scan_id": scan_id,
        "created_at": datetime.utcnow().isoformat(),
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "discrepancy_count": 1,
            "vulnerability_count": 1
        }
    }

@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    if scan_id in db.in_memory_findings:
        return db.in_memory_findings[scan_id]
        
    return [
        {
            "id": "find-001",
            "scan_id": scan_id,
            "type": "discrepancy_undeclared_endpoint",
            "title": "Undocumented External Endpoint Observed",
            "description": "Browser network crawling detected communication with telemetry.untrusted-cdn.net which is absent from declared infrastructure and architecture documentation.",
            "severity": "high",
            "target_node_id": "unknown:analytics-cdn",
            "affected_journey_ids": ["journey:checkout"],
            "evidence_references": ["trace:span-99120", "playwright:browser-network-log-01"],
            "remediation": {
                "summary": "Audit third-party frontend scripts",
                "recommended_action": "Remove unauthorized script tag from frontend/index.html or declare legitimate vendor with Content-Security-Policy (CSP) headers."
            }
        },
        {
            "id": "find-002",
            "scan_id": scan_id,
            "type": "vulnerability_compromised_package",
            "title": "Compromised Transitive Dependency Detected",
            "description": "Package event-stream@3.3.6 contains malicious code injection targeting cryptocurrency wallets and sensitive credentials (CVE-2018-3721).",
            "severity": "critical",
            "target_node_id": "pkg:event-stream",
            "affected_journey_ids": ["journey:checkout"],
            "security_details": {
                "cve_id": "CVE-2018-3721",
                "cvss_score": 9.8,
                "advisory_source": "OSV / GitHub Security Advisory",
                "fixed_version": "3.3.7"
            },
            "remediation": {
                "summary": "Upgrade package to non-compromised release",
                "recommended_action": "Run `npm install event-stream@3.3.7` or remove dependency."
            }
        }
    ]
