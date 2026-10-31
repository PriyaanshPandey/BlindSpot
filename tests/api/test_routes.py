try:
    import pytest
except ImportError:
    pass

import os

from app.models import ScanRequest, SimulationRequest
from fastapi import HTTPException
from app.api.routes.scans import create_scan, get_scan, list_scans
from app.api.routes.graph import get_scan_graph, get_scan_findings, get_scan_evidence
from app.api.routes.scenarios import simulate_failure, get_scenario
from main import health_check

def run_coro(coro):
    """Executes coroutines directly without requiring OS event loop socket binding."""
    while True:
        try:
            coro.send(None)
        except StopIteration as e:
            return e.value

def test_health_endpoint():
    res = run_coro(health_check())
    assert res["status"] == "healthy"
    assert "version" in res
    assert "operating_mode" in res

def test_full_scan_graph_simulation_lifecycle():
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "demo", "nexus-commerce"))
    trace_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "runtime", "traces.sample.json"))

    # 1. Trigger scan
    req = ScanRequest(
        repo_path=demo_path,
        trace_file_path=trace_path,
        enable_vendor_passports=True
    )
    scan_data = run_coro(create_scan(req))
    assert "scan_id" in scan_data
    scan_id = scan_data["scan_id"]
    assert scan_data["status"] == "completed"
    assert scan_data["summary"]["declared_dependencies"] > 0
    assert scan_data["summary"]["vulnerabilities_found"] >= 1
    assert scan_data["summary"]["discrepancies_found"] >= 1

    # 2. Retrieve graph with all valid filter layers
    graph_data = run_coro(get_scan_graph(scan_id, filter_layer="all"))
    assert graph_data["scan_id"] == scan_id
    assert len(graph_data["nodes"]) > 0
    assert len(graph_data["edges"]) > 0

    decl_graph = run_coro(get_scan_graph(scan_id, filter_layer="declared_only"))
    assert len(decl_graph["nodes"]) > 0

    obs_graph = run_coro(get_scan_graph(scan_id, filter_layer="observed_only"))
    assert len(obs_graph["nodes"]) > 0

    disc_graph = run_coro(get_scan_graph(scan_id, filter_layer="discrepancies_only"))
    assert len(disc_graph["nodes"]) > 0

    # 2b. Test invalid filter layer raises 422
    try:
        run_coro(get_scan_graph(scan_id, filter_layer="invalid_layer"))
        assert False, "Expected HTTP 422 for invalid filter_layer"
    except HTTPException as exc:
        assert exc.status_code == 422

    # 3. Retrieve findings
    findings = run_coro(get_scan_findings(scan_id))
    assert len(findings) > 0
    types = [f["type"] for f in findings]
    assert "vulnerability_compromised_package" in types
    assert "discrepancy_undeclared_endpoint" in types

    # 3b. Retrieve evidence
    evidence = run_coro(get_scan_evidence(scan_id))
    assert len(evidence) > 0

    # 4. Run Failure Simulation
    sim_req = SimulationRequest(
        target_node_id="vendor:stripe",
        failure_type="complete_outage",
        failure_duration_hours=4.0,
        hourly_transactions_override=1200.0,
        average_transaction_value_override=45.0
    )
    sim_res = run_coro(simulate_failure(scan_id, sim_req))
    assert "scenario_id" in sim_res
    scenario_id = sim_res["scenario_id"]
    assert sim_res["impact_results"]["blast_radius_node_count"] >= 2
    assert sim_res["impact_results"]["total_estimated_gross_exposure"] == 216000.0
    assert len(sim_res["impact_results"]["mitigation_strategies"]) > 0

    # 5. Retrieve saved scenario
    saved_scen = run_coro(get_scenario(scenario_id))
    assert saved_scen["scenario_id"] == scenario_id
