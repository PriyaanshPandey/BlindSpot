from fastapi import APIRouter
import uuid
from app.models import SimulationRequest
from app.analysis import calculate_financial_exposure

router = APIRouter()

@router.post("/{scan_id}/simulate")
async def simulate_failure(scan_id: str, request: SimulationRequest):
    scenario_id = str(uuid.uuid4())
    
    # Calculate blast radius
    impacted_nodes = [request.target_node_id, "service:nexus-api", "app:nexus-frontend", "journey:checkout"]
    
    financials = calculate_financial_exposure(
        impacted_nodes=impacted_nodes,
        failure_duration_hours=request.failure_duration_hours,
        tx_override=request.hourly_transactions_override,
        avg_val_override=request.average_transaction_value_override
    )

    return {
        "scenario_id": scenario_id,
        "scan_id": scan_id,
        "name": f"Outage Simulation for {request.target_node_id}",
        "target_node_id": request.target_node_id,
        "simulation_parameters": request.model_dump(),
        "impact_results": {
            "blast_radius_node_count": len(impacted_nodes),
            "impacted_node_ids": impacted_nodes,
            **financials
        }
    }

