from app.analysis.reconciliation import DiscrepancyDetector
from app.graph import GraphEngine

def test_reconciliation_and_discrepancy_detection():
    detector = DiscrepancyDetector(scan_id="test-scan-reconcile")

    declared_pkgs = {"express": "^4.19.0", "jsonwebtoken": "8.5.1"}
    observed_hosts = ["api.stripe.com", "telemetry.untrusted-cdn.net"]
    vulns = [{
        "package": "jsonwebtoken",
        "version": "8.5.1",
        "cve": "CVE-2022-23541",
        "severity": "high",
        "description": "Insecure key verification allowing arbitrary code execution in node environments."
    }]

    engine = GraphEngine.from_evidence(
        scan_id="test-scan-reconcile",
        project_name="Test Store",
        dependencies=declared_pkgs,
        observed_hosts=observed_hosts,
        vulnerabilities=vulns
    )

    findings = detector.reconcile(
        declared_packages=declared_pkgs,
        observed_hosts=observed_hosts,
        vulnerabilities=vulns,
        graph_engine=engine
    )

    finding_types = [f["type"] for f in findings]

    # Check that compromised package vulnerability is found
    assert "vulnerability_compromised_package" in finding_types
    # Check that undeclared observed endpoint is found
    assert "discrepancy_undeclared_endpoint" in finding_types
    # Check single point of failure finding
    assert "single_point_of_failure" in finding_types

    # Verify severity and target nodes
    vuln_f = next(f for f in findings if f["type"] == "vulnerability_compromised_package")
    assert vuln_f["target_node_id"] == "pkg:jsonwebtoken"
    assert vuln_f["severity"] == "high"
    assert vuln_f["security_details"]["cve_id"] == "CVE-2022-23541"
    assert "jsonwebtoken@8.5.1" in vuln_f["title"]

    undoc_f = next(f for f in findings if f["type"] == "discrepancy_undeclared_endpoint")
    assert undoc_f["target_node_id"] == "ext:telemetry.untrusted-cdn.net"
    assert undoc_f["severity"] == "high"
