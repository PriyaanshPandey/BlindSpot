from app.graph import GraphEngine
from app.analysis.simulation import SimulationEngine
from app.models import SimulationRequest, FailureType

def test_failure_simulation_financial_calculation():
    engine = GraphEngine(scan_id="test-scan-sim")
    engine.add_node("app:frontend", "Frontend App", "application")
    engine.add_node("service:api", "API Service", "internal_service")
    engine.add_node("vendor:stripe", "Stripe Gateway", "vendor")
    engine.add_node("journey:checkout", "Customer Checkout", "business_journey")

    engine.add_edge("app:frontend", "service:api", "calls_api")
    engine.add_edge("service:api", "vendor:stripe", "calls_api")
    engine.add_edge("vendor:stripe", "journey:checkout", "powers_journey")
    engine.add_edge("service:api", "journey:checkout", "powers_journey")

    sim_engine = SimulationEngine(graph_engine=engine)
    req = SimulationRequest(
        target_node_id="vendor:stripe",
        failure_type="complete_outage",
        failure_duration_hours=4.0,
        hourly_transactions_override=1200.0,
        average_transaction_value_override=45.0
    )

    result = sim_engine.run_simulation(req, scan_id="test-scan-sim")

    # Formula: 1200 * 45 * 4.0 * 1.0 = 216,000.00
    impact = result["impact_results"]
    assert impact["total_estimated_gross_exposure"] == 216000.0
    assert "vendor:stripe" in impact["impacted_node_ids"]
    assert "service:api" in impact["impacted_node_ids"]
    assert "app:frontend" in impact["impacted_node_ids"]
    assert len(impact["mitigation_strategies"]) > 0

