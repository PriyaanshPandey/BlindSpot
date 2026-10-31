from fastapi import APIRouter, HTTPException
import uuid
from typing import Optional, List
from datetime import datetime

from app.models import SimulationRequest
from app.db.repositories import GraphRepository, ScenarioRepository, ScanRepository
from app.graph import GraphEngine
from app.analysis.simulation import SimulationEngine

router = APIRouter()

@router.post("/{scan_id}/simulate")
async def simulate_failure(scan_id: str, request: SimulationRequest):
    # 1. Verify scan exists
    scan = await ScanRepository.get_scan(scan_id)
    graph_data = await GraphRepository.get_graph(scan_id)

    if not scan and not graph_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    engine = GraphEngine(scan_id=scan_id)
    if graph_data:
        engine.target_name = graph_data.get("metadata", {}).get("target_name", "Application")
        for node in graph_data.get("nodes", []):
            engine.add_node(
                node_id=node["id"],
                label=node["label"],
                node_type=node["type"],
                subtype=node.get("subtype"),
                version=node.get("version"),
                provenance=node.get("provenance", "declared"),
                status=node.get("status", "healthy"),
                criticality=node.get("criticality", "medium"),
                metadata=node.get("metadata")
            )
        for edge in graph_data.get("edges", []):
            engine.add_edge(
                source=edge["source"],
                target=edge["target"],
                relation=edge.get("relation", "depends_on"),
                provenance=edge.get("provenance", "declared"),
                confidence_score=edge.get("confidence_score", 1.0),
                evidence_ids=edge.get("evidence_ids"),
                metadata=edge.get("metadata"),
                edge_id=edge.get("id")
            )

    # Verify target node exists in graph
    if request.target_node_id not in engine.nx_graph:
        # Check if node exists; if not, raise 400 or add it
        logger = engine
    
    # 2. Run simulation engine
    sim_engine = SimulationEngine(graph_engine=engine)
    scenario_result = sim_engine.run_simulation(request=request, scan_id=scan_id)

    # 3. Persist scenario
    await ScenarioRepository.save_scenario(scenario_result)

    return scenario_result

@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    scenario = await ScenarioRepository.get_scenario(scenario_id)
    if scenario:
        return scenario
    raise HTTPException(status_code=404, detail="Scenario not found")
