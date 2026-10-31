"""
Integration test for Project Discovery & Schema Compliance [Role A].
Validates the end-to-end output of discover_project on demo/nexus-commerce
against contracts/graph-schema.json and contracts/evidence-schema.json.
"""

import os
import json
import pytest
import jsonschema
from app.ingestion import discover_project, DiscoveryResult


@pytest.fixture
def graph_schema():
    with open("contracts/graph-schema.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def evidence_schema():
    with open("contracts/evidence-schema.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_discover_nexus_commerce_end_to_end(graph_schema, evidence_schema):
    """
    Executes full discovery on demo/nexus-commerce with fixtures/runtime/traces.sample.json.
    Verifies node counts, edge directions, compromised status, and schema compliance.
    """
    result = discover_project(
        repo_path="demo/nexus-commerce",
        trace_file_path="fixtures/runtime/traces.sample.json"
    )

    assert isinstance(result, DiscoveryResult)
    assert result.project_name == "nexus-commerce"
    assert len(result.nodes) > 0
    assert len(result.edges) > 0
    assert len(result.evidence) > 0

    # 1. Verify NPM discovery
    node_labels = {n["label"]: n for n in result.nodes}
    assert any("npm:express@" in label for label in node_labels)
    assert any("npm:event-stream@" in label for label in node_labels)
    assert any("npm:flatmap-stream@" in label for label in node_labels)

    # 2. Verify Composer discovery
    assert any("composer:guzzlehttp/guzzle@" in label for label in node_labels)

    # 3. Verify Runtime Traces discovery
    assert any(n["id"] == "ext:api.stripe.com" for n in result.nodes)
    assert any(n["id"] == "ext:telemetry.untrusted-cdn.net" for n in result.nodes)

    # 4. Verify Compromised Package Status
    event_stream_node = next(n for n in result.nodes if "npm:event-stream@" in n["label"])
    assert event_stream_node["status"] == "compromised"
    assert event_stream_node["criticality"] == "critical"
    assert "vulnerability" in event_stream_node["metadata"]
    assert event_stream_node["metadata"]["vulnerability"]["advisory_id"] == "GHSA-mh6f-8j2x-4483"
    assert event_stream_node["metadata"]["vulnerability"]["cve"] is None

    # 5. Verify Edge Direction: Consumer -> Dependency
    for edge in result.edges:
        assert "source" in edge
        assert "target" in edge
        assert edge["relation"] in [
            "depends_on",
            "calls_api",
            "transitive_dependency",
            "hosted_on",
            "authenticates_via",
            "powers_journey",
            "routes_traffic_to"
        ]
        # Provenance must be valid enum
        assert edge["provenance"] in ["declared", "observed", "deployed", "vendor_passport"]
        # Inferred is strictly prohibited for edge provenance
        assert edge["provenance"] != "inferred"
        # Must have confidence score between 0.0 and 1.0
        assert 0.0 <= edge["confidence_score"] <= 1.0
        # Must have supporting evidence
        assert len(edge["evidence_ids"]) > 0

    # 6. Verify Node Existence Integrity: Every edge source and target must exist in node ID set
    node_id_set = {n["id"] for n in result.nodes}
    for edge in result.edges:
        assert edge["source"] in node_id_set, f"Edge source '{edge['source']}' does not exist in nodes"
        assert edge["target"] in node_id_set, f"Edge target '{edge['target']}' does not exist in nodes"

    # Verify Composer direct edges originate from actual root app node (app:nexus-commerce)
    composer_direct_edges = [
        e for e in result.edges
        if e.get("metadata", {}).get("ecosystem") == "composer" and e["relation"] == "depends_on"
    ]
    for edge in composer_direct_edges:
        assert edge["source"] == "app:nexus-commerce", (
            f"Composer direct edge source '{edge['source']}' must be actual root app:nexus-commerce"
        )

    # 7. Verify Evidence Bidirectional Integrity
    evidence_id_set = {ev["id"] for ev in result.evidence}
    for edge in result.edges:
        for ev_id in edge["evidence_ids"]:
            assert ev_id in evidence_id_set, f"Edge references missing evidence ID: {ev_id}"

    # 8. Validate Graph Schema Compliance (contracts/graph-schema.json)
    graph_payload = result.to_graph_schema_payload()
    jsonschema.validate(instance=graph_payload, schema=graph_schema)
    # Requirement 7: Provisional discrepancy count must be 0 prior to Person B reconciliation
    assert graph_payload["metadata"]["discrepancy_count"] == 0

    # 9. Validate Evidence Schema Compliance for every record (contracts/evidence-schema.json)
    for ev in result.evidence:
        jsonschema.validate(instance=ev, schema=evidence_schema)


def test_discover_isolated_empty_project(tmp_path, graph_schema):
    """Verifies safe behavior on an empty project directory with no manifests."""
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()

    result = discover_project(str(empty_repo))
    assert result.project_name == "empty_repo"
    # Should contain only the application root node
    assert len(result.nodes) == 1
    assert result.nodes[0]["type"] == "application"
    assert len(result.edges) == 0

    # Must still pass graph schema validation
    jsonschema.validate(instance=result.to_graph_schema_payload(), schema=graph_schema)


def test_manifest_only_npm_project(tmp_path, graph_schema, evidence_schema):
    """
    Verifies that package.json without package-lock.json emits declared dependency nodes
    with version=None and status='unknown', warns about missing lockfile,
    and establishes valid graph integrity.
    """
    repo = tmp_path / "npm_manifest_only"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({
        "name": "manifest-only-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.19.2",
            "lodash": "~4.17.21"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }))

    result = discover_project(str(repo))
    assert result.project_name == "manifest-only-app"

    # Warning must be present
    assert any("package-lock.json" in w for w in result.warnings)

    # Node validation
    node_id_set = {n["id"] for n in result.nodes}
    assert "app:manifest-only-app" in node_id_set
    assert "pkg:npm/express" in node_id_set
    assert "pkg:npm/lodash" in node_id_set
    assert "pkg:npm/jest" in node_id_set

    express_node = next(n for n in result.nodes if n["id"] == "pkg:npm/express")
    assert express_node["version"] is None
    assert express_node["status"] == "unknown"
    assert express_node["provenance"] == "declared"
    assert express_node["metadata"]["declared_range"] == "^4.19.2"

    # Edge validation: All edge sources and targets exist in node_id_set
    assert len(result.edges) == 3
    for edge in result.edges:
        assert edge["source"] in node_id_set
        assert edge["target"] in node_id_set
        assert edge["relation"] == "depends_on"
        assert edge["source"] == "app:manifest-only-app"

    # Schema validation
    jsonschema.validate(instance=result.to_graph_schema_payload(), schema=graph_schema)
    for ev in result.evidence:
        jsonschema.validate(instance=ev, schema=evidence_schema)


def test_manifest_only_composer_project(tmp_path, graph_schema, evidence_schema):
    """
    Verifies that composer.json without composer.lock emits declared dependency nodes
    with version=None and status='unknown', warns about missing lockfile,
    and establishes valid graph integrity.
    """
    repo = tmp_path / "composer_manifest_only"
    repo.mkdir()
    (repo / "composer.json").write_text(json.dumps({
        "name": "company/composer-service",
        "require": {
            "php": ">=8.1",
            "guzzlehttp/guzzle": "^7.8"
        },
        "require-dev": {
            "phpunit/phpunit": "^10.0"
        }
    }))

    result = discover_project(str(repo))
    # Warning must be recorded
    assert any("composer.lock" in w for w in result.warnings)

    node_id_set = {n["id"] for n in result.nodes}
    assert "pkg:composer/guzzlehttp/guzzle" in node_id_set
    assert "pkg:composer/phpunit/phpunit" in node_id_set
    # Platform requirement php must not be treated as a package node
    assert not any("php" == n.get("metadata", {}).get("declared_range") for n in result.nodes)

    guzzle_node = next(n for n in result.nodes if n["id"] == "pkg:composer/guzzlehttp/guzzle")
    assert guzzle_node["version"] is None
    assert guzzle_node["status"] == "unknown"
    assert guzzle_node["provenance"] == "declared"

    # All edges have valid source and target nodes
    assert len(result.edges) == 2
    for edge in result.edges:
        assert edge["source"] in node_id_set
        assert edge["target"] in node_id_set
        assert edge["relation"] == "depends_on"

    # Schema validation
    jsonschema.validate(instance=result.to_graph_schema_payload(), schema=graph_schema)
    for ev in result.evidence:
        jsonschema.validate(instance=ev, schema=evidence_schema)


def test_root_application_version_from_manifest_or_null(tmp_path, graph_schema):
    """
    Regression test for Requirement 6:
    Root application version must reflect the manifest version (e.g. 2.4.3),
    or null if no version is declared in the manifest.
    Never fabricate 1.0.0.
    """
    # 1. Project with package.json specifying version 2.4.3
    repo_with_ver = tmp_path / "repo_ver_243"
    repo_with_ver.mkdir()
    (repo_with_ver / "package.json").write_text(json.dumps({
        "name": "custom-service",
        "version": "2.4.3"
    }))

    res1 = discover_project(str(repo_with_ver))
    root_node1 = next(n for n in res1.nodes if n["id"] == "app:custom-service")
    assert root_node1["version"] == "2.4.3"
    payload1 = res1.to_graph_schema_payload()
    jsonschema.validate(instance=payload1, schema=graph_schema)
    assert payload1["metadata"]["discrepancy_count"] == 0

    # 2. Project with manifest without version
    repo_no_ver = tmp_path / "repo_no_ver"
    repo_no_ver.mkdir()
    (repo_no_ver / "package.json").write_text(json.dumps({
        "name": "unversioned-service"
    }))

    res2 = discover_project(str(repo_no_ver))
    root_node2 = next(n for n in res2.nodes if n["id"] == "app:unversioned-service")
    assert root_node2["version"] is None
    payload2 = res2.to_graph_schema_payload()
    jsonschema.validate(instance=payload2, schema=graph_schema)
    assert payload2["metadata"]["discrepancy_count"] == 0

