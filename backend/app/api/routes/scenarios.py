from fastapi import APIRouter, HTTPException
import uuid
from typing import Set, List, Dict, Any, Optional
from datetime import datetime

from app.models import SimulationRequest
from app.db import db
from app.db.repositories import GraphRepository, ScenarioRepository, ScanRepository

router = APIRouter()

@router.get("/{scan_id}")
async def get_scenarios(scan_id: str):
    return db.in_memory_scenarios.get(scan_id, [])

@router.post("/{scan_id}/simulate")
async def simulate_failure(scan_id: str, request: SimulationRequest):
    scenario_id = str(uuid.uuid4())
    
    # 1. Fetch graph data from in-memory or repository
    graph = db.in_memory_graphs.get(scan_id)
    if not graph:
        try:
            graph = await GraphRepository.get_graph(scan_id)
        except Exception:
            graph = None

    if not graph:
        graph = {"nodes": [], "edges": []}

    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    edges: List[Dict[str, Any]] = graph.get("edges", [])

    total_nodes = len(nodes)
    target_id = request.target_node_id

    # 2. Traverse graph backwards/forwards to compute real blast radius
    # If target fails, nodes that depend on target (source -> target in call graph) fail
    incoming_map: Dict[str, Set[str]] = {}
    outgoing_map: Dict[str, Set[str]] = {}
    for e in edges:
        s = e.get("source")
        t = e.get("target")
        if s and t:
            outgoing_map.setdefault(s, set()).add(t)
            incoming_map.setdefault(t, set()).add(s)

    impacted: Set[str] = {target_id}
    queue: List[str] = [target_id]

    while queue:
        curr = queue.pop(0)
        # Callers of curr (who rely on curr)
        for caller in incoming_map.get(curr, []):
            if caller not in impacted:
                impacted.add(caller)
                queue.append(caller)
        # Journeys powered by curr or connected downstream
        for down in outgoing_map.get(curr, []):
            if "journey" in down and down not in impacted:
                impacted.add(down)

    impacted_list = list(impacted)
    impact_pct = round((len(impacted_list) / max(total_nodes, 1)) * 100, 1) if total_nodes > 0 else 50.0

    node_by_id = {n["id"]: n for n in nodes}
    impacted_node_objs = [node_by_id.get(nid, {"id": nid, "label": nid, "type": "unknown"}) for nid in impacted_list]

    services_count = sum(1 for n in impacted_node_objs if n.get("type") in ["service", "app", "application", "internal_service"])
    packages_count = sum(1 for n in impacted_node_objs if n.get("type") in ["package", "package_transitive"])
    infra_count = sum(1 for n in impacted_node_objs if n.get("type") in ["infrastructure", "database", "cache", "infrastructure_resource"])
    vendor_count = sum(1 for n in impacted_node_objs if n.get("type") in ["vendor", "external_api", "vendor_upstream"])
    journeys = [n for n in impacted_node_objs if n.get("type") in ["business_journey", "journey"]]

    target_label = node_by_id.get(target_id, {}).get("label", target_id)

    # Calculate financial exposure if overrides are explicitly provided
    if request.hourly_transactions_override is not None and request.average_transaction_value_override is not None:
        total_exposure = round(
            float(request.hourly_transactions_override)
            * float(request.average_transaction_value_override)
            * float(request.failure_duration_hours)
            * 1.0,
            2
        )
    else:
        total_exposure = 0.0

    max_disruption = 1.0 if journeys else 0.75
    duration_weight = min(request.failure_duration_hours * 0.85, 20.0)
    blast_weight = min(len(impacted_list) * 5.0, 25.0)
    system_impact_pct = min(99.0, max(28.0, round(max_disruption * 55.0 + blast_weight + duration_weight, 1)))

    scenario_result = {
        "scenario_id": scenario_id,
        "scan_id": scan_id,
        "name": f"Outage Simulation: {target_label}",
        "target_node_id": target_id,
        "simulation_parameters": request.model_dump(),
        "impact_results": {
            "blast_radius_node_count": len(impacted_list),
            "impacted_node_ids": impacted_list,
            "impact_percentage": impact_pct,
            "system_impact_percentage": system_impact_pct,
            "severity_rating": "CRITICAL" if system_impact_pct >= 80 else ("HIGH" if system_impact_pct >= 60 else "MODERATE"),
            "total_system_nodes": total_nodes,
            "impacted_services_count": max(services_count, 1),
            "impacted_packages_count": packages_count,
            "impacted_infra_count": infra_count,
            "impacted_vendor_count": max(vendor_count, 1),
            "impact_summary": f"Simulating failure of '{target_label}' disables {impact_pct}% of the system topology ({len(impacted_list)} of {total_nodes} nodes).",
            "total_estimated_gross_exposure": total_exposure,
            "exposure_currency": "USD",
            "impacted_journeys": [
                {
                    "journey_id": j.get("id"),
                    "name": j.get("label", "Core Journey"),
                    "disruption_fraction": 1.0,
                    "hourly_transactions": request.hourly_transactions_override or 0,
                    "average_transaction_value": request.average_transaction_value_override or 0,
                    "financial_exposure": total_exposure
                }
                for j in journeys
            ] or [
                {
                    "journey_id": "journey:core-ops",
                    "name": "Core Operations & Transactions",
                    "disruption_fraction": min(1.0, round(impact_pct / 100.0, 2)) if impact_pct > 0 else 0.8,
                    "hourly_transactions": request.hourly_transactions_override or 0,
                    "average_transaction_value": request.average_transaction_value_override or 0,
                    "financial_exposure": total_exposure
                }
            ],
            "mitigation_strategies": [
                {
                    "strategy_type": "circuit_breaker",
                    "title": f"Deploy Circuit Breaker for {target_label}",
                    "description": f"Isolate {target_label} with timeout fallback to prevent cascading degradation of dependent services.",
                    "estimated_risk_reduction_pct": 80.0
                },
                {
                    "strategy_type": "graceful_fallback",
                    "title": "Enable Degraded Read-Only / Secondary Failover",
                    "description": "Serve cached responses or route traffic to redundant replica when primary target is unreachable.",
                    "estimated_risk_reduction_pct": 70.0
                }
            ]
        }
    }

    # Persist in-memory and repository
    db.in_memory_scenarios.setdefault(scan_id, []).append(scenario_result)
    try:
        await ScenarioRepository.save_scenario(scenario_result)
    except Exception:
        pass

    return scenario_result

@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    # Check repository first
    try:
        scen = await ScenarioRepository.get_scenario(scenario_id)
        if scen:
            return scen
    except Exception:
        pass

    # Check in-memory
    for scan_scenarios in db.in_memory_scenarios.values():
        for s in scan_scenarios:
            if s.get("scenario_id") == scenario_id:
                return s

    raise HTTPException(status_code=404, detail="Scenario not found")
