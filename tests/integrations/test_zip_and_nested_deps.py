import pytest
import io
import zipfile
import json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_zip_upload_and_multi_tier_nested_dependencies():
    """
    Creates an in-memory ZIP archive of a real-world repository with:
    - package.json (direct dependency: express)
    - package-lock.json with 3-tier depth: express -> body-parser -> raw-body
    - .env with external cloud services (Stripe, OpenAI)
    - Tests /api/v1/scans/upload-zip
    - Verifies 3 tiers of nested packages are present and properly connected
    """
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. package.json
        pkg_json = {
            "name": "enterprise-checkout-service",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.2",
                "axios": "^1.6.0"
            }
        }
        zf.writestr("package.json", json.dumps(pkg_json))

        # 2. package-lock.json v2/v3 with 3 tiers
        lock_json = {
            "name": "enterprise-checkout-service",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "body-parser": "1.20.2",
                        "send": "0.18.0"
                    }
                },
                "node_modules/body-parser": {
                    "version": "1.20.2",
                    "dependencies": {
                        "raw-body": "2.5.2",
                        "bytes": "3.1.2"
                    }
                },
                "node_modules/raw-body": {
                    "version": "2.5.2",
                    "dependencies": {}
                }
            }
        }
        zf.writestr("package-lock.json", json.dumps(lock_json))

        # 3. .env with external integrations
        env_content = "STRIPE_SECRET_KEY=sk_test_123\nOPENAI_API_KEY=sk-test-456\n"
        zf.writestr(".env", env_content)

    zip_buffer.seek(0)

    # Post to upload-zip endpoint
    response = client.post(
        "/api/v1/scans/upload-zip",
        files={"file": ("enterprise-checkout.zip", zip_buffer.getvalue(), "application/zip")}
    )

    assert response.status_code == 200, response.text
    scan_data = response.json()
    scan_id = scan_data["scan_id"]
    assert "enterprise-checkout" in scan_data["project_name"]

    # Fetch constructed graph
    graph_resp = client.get(f"/api/v1/scans/{scan_id}/graph")
    assert graph_resp.status_code == 200
    graph = graph_resp.json()
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]

    # 1. Verify Direct package node (Tier 1 of packages)
    assert "pkg:express" in nodes
    assert nodes["pkg:express"]["subtype"] == "direct"

    # 2. Verify Transitive package node (Tier 2 of packages)
    assert "pkg:trans:body-parser" in nodes
    assert nodes["pkg:trans:body-parser"]["subtype"] == "transitive"

    # 3. Verify Deep Transitive package node (Tier 3 of packages)
    assert "pkg:deep:raw-body" in nodes
    assert nodes["pkg:deep:raw-body"]["subtype"] == "deep_transitive"

    # 4. Verify Edge connections: express -> body-parser -> raw-body
    edge_pairs = [(e["source"], e["target"], e["relation"]) for e in edges]
    assert any(s == "pkg:express" and t == "pkg:trans:body-parser" and r == "depends_on_transitive" for s, t, r in edge_pairs)
    assert any(s == "pkg:trans:body-parser" and t == "pkg:deep:raw-body" and r == "depends_on_deep_transitive" for s, t, r in edge_pairs)

    # 5. Verify failure simulation weighted impact
    sim_resp = client.post(
        f"/api/v1/scans/{scan_id}/simulate",
        json={"target_node_id": "pkg:deep:raw-body", "failure_duration_hours": 2.0}
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert "impact_results" in sim_data
    impact = sim_data["impact_results"]
    assert impact["impact_percentage"] > 0
    assert "calculation_basis" in impact
    assert impact["impacted_packages_count"] >= 1
